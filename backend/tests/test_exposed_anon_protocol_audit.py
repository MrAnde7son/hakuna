"""Tests for the Exposed-Anon-Protocol Audit (Phase 4.1).

Relay broker is mocked at the dispatch boundary — no real FTP/VNC/DNS
sockets are opened. The backend tools are tested for correct dispatch
shape (method name, port, op, params), not for what the relay does
internally."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.models import Asset, RelayAgent, Scan

# Side-effect import — populates AUDITS + TOOL_REGISTRY.
import agents.agent_tools  # noqa: F401


# ── Audit registration ───────────────────────────────────────────────


def test_exposed_anon_protocol_audit_registered():
    from agents.audit_registry import get_audit, list_audits

    assert "exposed_anon_protocol" in list_audits()
    audit = get_audit("exposed_anon_protocol")
    assert audit.label == "Exposed Anon-Protocol Audit"
    assert audit.safety_class == "anon_standard"
    assert audit.is_anonymous_capable() is True
    assert audit.requires_per_asset_consent() is False
    assert audit.relay_method == "anon_protocol_probe"
    assert audit.auto_trigger_policy == "auto_org_opt_in"
    assert "anonymous" in audit.auth_modes
    assert audit.credential_connector_ids == []
    assert set(audit.required_ports) == {21, 53, 88, 69, 5900}
    assert {m.key for m in audit.missions} == {"triage"}
    assert "cis_benchmarks" in audit.compliance_tags
    assert "pci_dss_4" in audit.compliance_tags


def test_exposed_anon_protocol_tool_palette_registered():
    from agents.agent_tools import TOOL_REGISTRY

    expected = {
        "ftp_anon_probe", "vnc_anon_probe", "dns_axfr_probe",
        "kerberos_anon_probe", "tftp_anon_probe",
    }
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"anon-protocol probe tools missing from TOOL_REGISTRY: {missing}"


def test_exposed_anon_protocol_mission_prompt_resolved():
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("exposed_anon_protocol_audit_triage")
    assert prompt, "exposed_anon_protocol_audit_triage prompt missing"
    assert "{preamble}" not in prompt, "preamble not resolved in triage mission"
    assert "exposed-anon-protocol auditor" in prompt
    assert 'protocol="exposed_anon_protocol"' in prompt
    assert 'mission="triage"' in prompt


# ── Dispatch wiring ──────────────────────────────────────────────────


@pytest.fixture
def anon_asset(db_session, test_org):
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="legacy-host-1", ip="10.20.30.40",
        fqdn="legacy.example.com",
        easm_data={"open_ports": [21, 53, 88, 5900]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_dispatch_audit_run_accepts_anonymous_for_exposed_anon_protocol(
    db_session, test_org, anon_asset,
):
    """The Phase 0 ``safety_class`` predicate must accept ``credential_id=None``
    for the new exposed_anon_protocol audit — confirms end-to-end dispatch
    validation."""
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        result = dispatch_audit_run(
            db=db_session,
            org=test_org,
            protocol="exposed_anon_protocol",
            mission="triage",
            asset_ids=[anon_asset.id],
            relay_agent_id="relay-x",
            credential_id=None,
        )

    assert result["protocol"] == "exposed_anon_protocol"
    assert result["mission"] == "triage"
    assert result["status"] == "running"

    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.scan_type == "exposed_anon_protocol_audit"
    assert scan.raw_metadata["credential_id"] is None


@pytest.mark.parametrize("tool_name,op,port", [
    ("ftp_anon_probe", "ftp", 21),
    ("vnc_anon_probe", "vnc", 5900),
    ("dns_axfr_probe", "dns_axfr", 53),
    ("kerberos_anon_probe", "kerberos", 88),
    ("tftp_anon_probe", "tftp", 69),
])
def test_each_anon_protocol_tool_dispatches_with_correct_op_and_port(
    db_session, anon_asset, tool_name, op, port,
):
    """Each probe tool must dispatch ``method=anon_protocol_probe`` with
    the matching op + default port. Single parametrized test keeps the
    full palette covered without 5 near-duplicate test functions."""
    import agents.tools.exposed_anon_protocol_tools as mod

    tool_fn = getattr(mod, f"{tool_name}_tool")
    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"_ok": True})

    with patch("agents.tools.exposed_anon_protocol_tools.get_relay_broker", return_value=fake_broker):
        tool_fn(db_session, {
            "asset_id": anon_asset.id,
            "_relay_agent_id": "relay-x",
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "anon_protocol_probe"
    assert call.kwargs["params"]["op"] == op
    assert call.kwargs["config"]["port"] == port
    # All ops are anonymous by spec — credentials must always be empty.
    assert call.kwargs["credentials"] == {}


def test_dns_axfr_probe_uses_asset_fqdn_as_default_zone(db_session, anon_asset):
    """The AXFR probe defaults the zone to the asset's fqdn so the agent
    doesn't have to reason about apex extraction. Explicit override via
    the ``zone`` param still wins."""
    from agents.tools.exposed_anon_protocol_tools import dns_axfr_probe_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"axfr_allowed": False, "zone": "x", "record_count": 0, "sample_records": []})

    with patch("agents.tools.exposed_anon_protocol_tools.get_relay_broker", return_value=fake_broker):
        dns_axfr_probe_tool(db_session, {
            "asset_id": anon_asset.id,
            "_relay_agent_id": "relay-x",
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["params"]["op_params"]["zone"] == "legacy.example.com"


def test_dns_axfr_probe_explicit_zone_param_wins(db_session, anon_asset):
    from agents.tools.exposed_anon_protocol_tools import dns_axfr_probe_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"axfr_allowed": False, "zone": "x", "record_count": 0, "sample_records": []})

    with patch("agents.tools.exposed_anon_protocol_tools.get_relay_broker", return_value=fake_broker):
        dns_axfr_probe_tool(db_session, {
            "asset_id": anon_asset.id,
            "_relay_agent_id": "relay-x",
            "zone": "internal.corp",
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["params"]["op_params"]["zone"] == "internal.corp"


def test_ftp_probe_raises_when_no_relay_supplied(db_session, anon_asset):
    """A run context missing ``_relay_agent_id`` must surface a clean
    ValueError so the LLM gets a real error rather than a broker stack."""
    from agents.tools.exposed_anon_protocol_tools import ftp_anon_probe_tool

    with pytest.raises(ValueError, match="relay_agent_id"):
        ftp_anon_probe_tool(db_session, {"asset_id": anon_asset.id})


def test_ftp_probe_raises_when_relay_disconnected(db_session, anon_asset):
    from agents.tools.exposed_anon_protocol_tools import ftp_anon_probe_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = False

    with patch("agents.tools.exposed_anon_protocol_tools.get_relay_broker", return_value=fake_broker):
        with pytest.raises(ConnectionError, match="not connected"):
            ftp_anon_probe_tool(db_session, {
                "asset_id": anon_asset.id,
                "_relay_agent_id": "relay-x",
            })


# ── Auto-trigger ─────────────────────────────────────────────────────


def test_auto_trigger_rule_for_anon_protocol_family_registered():
    """The Phase 4.1 AutoTriggerRule must be in the registry with the
    TCP-port set, the right family switch, and no per-asset consent."""
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES

    rule = next(
        (r for r in AUTO_TRIGGER_RULES if r.protocol == "exposed_anon_protocol"), None,
    )
    assert rule is not None, "exposed_anon_protocol rule missing from AUTO_TRIGGER_RULES"
    assert rule.mission == "triage"
    # UDP port 69 is intentionally NOT in the trigger list — the scanner
    # currently emits TCP-only port_change events. Phase 4.0 will add UDP.
    assert set(rule.ports) == {21, 53, 88, 5900}
    assert rule.enabled_setting_key == "auto_audit_anon_protocol"
    assert rule.requires_per_asset_consent is False


@pytest.fixture
def linked_anon_asset(db_session, test_org):
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="legacy-prod-1", ip="10.0.0.50",
        fqdn="legacy-prod-1.example.com",
        easm_data={"easm_asset_id": "scanner-uuid-anon-1", "open_ports": [21]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


@pytest.fixture
def connected_relay_for_org(db_session, test_org):
    relay = RelayAgent(
        org_id=test_org.id, name="anon-relay", token_hash="x",
        status="connected", last_seen_at=datetime.utcnow(),
    )
    db_session.add(relay)
    db_session.flush()
    return relay


def _port_change_event(scanner_asset_id: str, new_ports: list[int], hostname: str):
    return {
        "id": "evt-anon-1",
        "asset_id": scanner_asset_id,
        "event_type": "port_change",
        "payload": {
            "hostname": hostname,
            "new_ports": new_ports,
            "removed_ports": [],
        },
    }


def test_auto_trigger_does_nothing_without_anon_protocol_family_switch(
    db_session, test_org, linked_anon_asset, connected_relay_for_org,
):
    """Even with the legacy ``auto_audit_anon`` switch on, the
    anon-protocol family rule must NOT fire — its per-family switch is
    what controls it."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}  # legacy switch only
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-anon-1", [21], "legacy-prod-1"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_auto_trigger_dispatches_when_anon_protocol_switch_on(
    db_session, test_org, linked_anon_asset, connected_relay_for_org,
):
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon_protocol": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-anon-1", [21], "legacy-prod-1"),
        )

    assert n == 1
    scan = db_session.query(Scan).filter_by(scan_type="exposed_anon_protocol_audit").first()
    assert scan is not None
    md = scan.raw_metadata or {}
    assert md["protocol"] == "exposed_anon_protocol"
    assert md["mission"] == "triage"
    assert md["credential_id"] is None
    assert md["asset_ids"] == [linked_anon_asset.id]


def test_auto_trigger_collapses_multiple_anon_ports_into_single_run(
    db_session, test_org, linked_anon_asset, connected_relay_for_org,
):
    """A port_change event surfacing FTP + VNC + Kerberos at once must
    produce exactly one ``exposed_anon_protocol`` audit run — the single
    rule covers all family ports."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon_protocol": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-anon-1", [21, 88, 5900], "legacy-prod-1"),
        )

    assert n == 1
    scan_count = db_session.query(Scan).filter_by(
        scan_type="exposed_anon_protocol_audit"
    ).count()
    assert scan_count == 1


def test_auto_trigger_anon_protocol_independent_from_other_family_switches(
    db_session, test_org, linked_anon_asset, connected_relay_for_org,
):
    """An org with ``auto_audit_anon_protocol`` on but ``auto_audit_anon``
    off must NOT fire SMB on a 445 port — and vice versa. Confirms the
    per-family isolation."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon_protocol": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-anon-1", [21, 445], "legacy-prod-1"),
        )

    # One run — the anon-protocol one. SMB rule is gated by auto_audit_anon (off).
    assert n == 1
    types = {s.scan_type for s in db_session.query(Scan).all()}
    assert "exposed_anon_protocol_audit" in types
    assert "smb_audit" not in types
