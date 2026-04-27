"""Tests for the IPMI BMC Audit (Phase 4.2).

Relay broker is mocked at the dispatch boundary. RMCP+ packet
construction lives at the relay; this test file verifies only the
backend tool/audit/auto-trigger wiring."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.models import Asset, RelayAgent, Scan

import agents.agent_tools  # noqa: F401


# ── Audit registration ───────────────────────────────────────────────


def test_ipmi_bmc_audit_registered():
    from agents.audit_registry import get_audit, list_audits

    assert "ipmi_bmc" in list_audits()
    audit = get_audit("ipmi_bmc")
    assert audit.label == "IPMI BMC Audit"
    assert audit.safety_class == "anon_ipmi"
    assert audit.is_anonymous_capable() is True
    assert audit.requires_per_asset_consent() is False
    assert audit.relay_method == "ipmi_probe"
    assert audit.auto_trigger_policy == "auto_org_opt_in"
    assert audit.credential_connector_ids == []
    assert audit.required_ports == (623,)
    assert {m.key for m in audit.missions} == {"triage"}
    assert "nist_csf_pr_ac" in audit.compliance_tags
    assert "cis_benchmarks" in audit.compliance_tags


def test_ipmi_bmc_tool_palette_registered():
    from agents.agent_tools import TOOL_REGISTRY

    expected = {"ipmi_cipher_zero_probe", "ipmi_rakp_hash_probe"}
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"IPMI probe tools missing: {missing}"


def test_ipmi_bmc_mission_prompt_resolved():
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("ipmi_bmc_audit_triage")
    assert prompt
    assert "{preamble}" not in prompt
    assert "IPMI BMC auditor" in prompt
    assert 'protocol="ipmi_bmc"' in prompt
    assert 'mission="triage"' in prompt


# ── Dispatch wiring ──────────────────────────────────────────────────


@pytest.fixture
def bmc_asset(db_session, test_org):
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="bmc-1", ip="10.20.30.55",
        easm_data={"open_ports": [], "open_udp_ports": [623]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_dispatch_audit_run_accepts_anonymous_for_ipmi_bmc(
    db_session, test_org, bmc_asset,
):
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="ipmi_bmc", mission="triage",
            asset_ids=[bmc_asset.id],
            relay_agent_id="relay-x", credential_id=None,
        )

    assert result["protocol"] == "ipmi_bmc"
    assert result["mission"] == "triage"
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.scan_type == "ipmi_bmc_audit"
    assert scan.raw_metadata["credential_id"] is None


def test_cipher_zero_probe_dispatches_method_ipmi_probe_op_cipher_zero(
    db_session, bmc_asset,
):
    from agents.tools.ipmi_tools import ipmi_cipher_zero_probe_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={
        "cipher_zero_accepted": True, "bmc_responded": True,
        "session_id": "abcd1234", "status_code": 0,
    })

    with patch("agents.tools.ipmi_tools.get_relay_broker", return_value=fake_broker):
        result = ipmi_cipher_zero_probe_tool(db_session, {
            "asset_id": bmc_asset.id, "_relay_agent_id": "relay-x",
        })

    assert result["cipher_zero_accepted"] is True
    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "ipmi_probe"
    assert call.kwargs["params"]["op"] == "cipher_zero"
    assert call.kwargs["config"]["port"] == 623
    # Anonymous probe — credentials must always be empty.
    assert call.kwargs["credentials"] == {}


def test_rakp_hash_probe_forwards_username_to_relay(db_session, bmc_asset):
    """The username param flows through op_params so the relay can target a
    specific account. Default is `admin` when not supplied."""
    from agents.tools.ipmi_tools import ipmi_rakp_hash_probe_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={
        "hash_leaked": True, "username_tested": "root",
        "keac_hex": "deadbeef" * 5, "auth_algo": 1,
    })

    with patch("agents.tools.ipmi_tools.get_relay_broker", return_value=fake_broker):
        ipmi_rakp_hash_probe_tool(db_session, {
            "asset_id": bmc_asset.id,
            "_relay_agent_id": "relay-x",
            "username": "root",
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["params"]["op"] == "rakp_hash"
    assert call.kwargs["params"]["op_params"]["username"] == "root"


def test_rakp_hash_probe_defaults_username_admin(db_session, bmc_asset):
    from agents.tools.ipmi_tools import ipmi_rakp_hash_probe_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"hash_leaked": False, "username_tested": "admin"})

    with patch("agents.tools.ipmi_tools.get_relay_broker", return_value=fake_broker):
        ipmi_rakp_hash_probe_tool(db_session, {
            "asset_id": bmc_asset.id, "_relay_agent_id": "relay-x",
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["params"]["op_params"]["username"] == "admin"


# ── Auto-trigger ─────────────────────────────────────────────────────


def test_auto_trigger_rule_for_ipmi_registered():
    """The Phase 4.2 AutoTriggerRule must declare transport='udp' so the
    Phase 4.0 matcher only fires it on UDP-tagged port_change events."""
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES

    rule = next((r for r in AUTO_TRIGGER_RULES if r.protocol == "ipmi_bmc"), None)
    assert rule is not None, "ipmi_bmc rule missing from AUTO_TRIGGER_RULES"
    assert rule.mission == "triage"
    assert set(rule.ports) == {623}
    assert rule.transport == "udp"
    assert rule.enabled_setting_key == "auto_audit_ipmi"
    assert rule.requires_per_asset_consent is False


@pytest.fixture
def linked_bmc_asset(db_session, test_org):
    scan = Scan(filename="x", scan_type="manual", source_type="manual", org_id=test_org.id)
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="bmc-prod-1", ip="10.0.0.55",
        easm_data={"easm_asset_id": "scanner-uuid-bmc-1", "open_udp_ports": [623]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


@pytest.fixture
def connected_relay_for_org(db_session, test_org):
    relay = RelayAgent(
        org_id=test_org.id, name="ipmi-relay", token_hash="x",
        status="connected", last_seen_at=datetime.utcnow(),
    )
    db_session.add(relay)
    db_session.flush()
    return relay


def _udp_port_change_event(scanner_asset_id: str, new_ports: list[int], hostname: str):
    return {
        "id": "evt-ipmi-1",
        "asset_id": scanner_asset_id,
        "event_type": "port_change",
        "payload": {
            "hostname": hostname,
            "transport": "udp",
            "new_ports": new_ports,
            "removed_ports": [],
        },
    }


def test_auto_trigger_dispatches_ipmi_on_udp_623_event(
    db_session, test_org, linked_bmc_asset, connected_relay_for_org,
):
    """Phase 4.2 + 4.0 integration: a UDP port_change for 623 with the
    ``auto_audit_ipmi`` switch on must dispatch the IPMI audit."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_ipmi": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _udp_port_change_event("scanner-uuid-bmc-1", [623], "bmc-prod-1"),
        )

    assert n == 1
    scan = db_session.query(Scan).filter_by(scan_type="ipmi_bmc_audit").first()
    assert scan is not None
    md = scan.raw_metadata or {}
    assert md["protocol"] == "ipmi_bmc"
    assert md["mission"] == "triage"
    assert md["credential_id"] is None
    assert md["asset_ids"] == [linked_bmc_asset.id]


def test_auto_trigger_does_nothing_without_ipmi_switch(
    db_session, test_org, linked_bmc_asset, connected_relay_for_org,
):
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}  # legacy switch only
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _udp_port_change_event("scanner-uuid-bmc-1", [623], "bmc-prod-1"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_auto_trigger_does_not_fire_ipmi_on_tcp_event_for_623(
    db_session, test_org, linked_bmc_asset, connected_relay_for_org,
):
    """A TCP port_change event for port 623 (rare but possible if some
    asset reports it on TCP) must NOT fire the IPMI audit — IPMI is
    declared ``transport='udp'`` on the rule."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_ipmi": True}
    db_session.flush()

    tcp_event = {
        "id": "evt-bmc-tcp",
        "asset_id": "scanner-uuid-bmc-1",
        "event_type": "port_change",
        "payload": {
            "hostname": "bmc-prod-1",
            "transport": "tcp",
            "new_ports": [623],
            "removed_ports": [],
        },
    }
    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(db_session, test_org, tcp_event)

    assert n == 0
    mock_dispatch.assert_not_called()
