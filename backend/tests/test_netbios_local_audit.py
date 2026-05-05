"""Tests for the NetBIOS / LLMNR / mDNS LAN-local audit (Phase 4.3).

Covers backend tool palette, audit registration, mission prompt, the
new ``_lan_local_predicate`` (relay/asset same-subnet gate), and the
auto-trigger rule wiring."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.models import Asset, RelayAgent, Scan

import agents.agent_tools  # noqa: F401


# ── Audit registration ───────────────────────────────────────────────


def test_netbios_local_audit_registered():
    from agents.audit_registry import get_audit, list_audits

    assert "netbios_local" in list_audits()
    audit = get_audit("netbios_local")
    assert audit.safety_class == "anon_lan_local"
    assert audit.is_anonymous_capable() is True
    assert audit.relay_method == "netbios_probe"
    assert audit.required_ports == (137, 5355, 5353)
    assert "cis_benchmarks" in audit.compliance_tags


def test_netbios_local_tool_palette_registered():
    from agents.agent_tools import TOOL_REGISTRY

    expected = {"nbns_probe", "llmnr_probe", "mdns_probe"}
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"NetBIOS probe tools missing: {missing}"


def test_netbios_local_mission_prompt_resolved():
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("netbios_local_audit_triage")
    assert prompt
    assert "{preamble}" not in prompt
    assert "LAN-local name-resolution auditor" in prompt
    assert 'protocol="netbios_local"' in prompt


# ── Dispatch wiring ──────────────────────────────────────────────────


@pytest.fixture
def lan_asset(db_session, test_org):
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="ws-01", ip="10.0.0.42",
        easm_data={"open_udp_ports": [137, 5355]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


@pytest.mark.parametrize("tool_name,op,port", [
    ("nbns_probe", "nbns", 137),
    ("llmnr_probe", "llmnr", 5355),
    ("mdns_probe", "mdns", 5353),
])
def test_each_netbios_tool_dispatches_with_correct_op_and_port(
    db_session, lan_asset, tool_name, op, port,
):
    import agents.tools.netbios_local_tools as mod

    tool_fn = getattr(mod, f"{tool_name}_tool")
    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"_ok": True})

    with patch("agents.tools.netbios_local_tools.get_relay_broker", return_value=fake_broker):
        tool_fn(db_session, {
            "asset_id": lan_asset.id, "_relay_agent_id": "relay-x",
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "netbios_probe"
    assert call.kwargs["params"]["op"] == op
    assert call.kwargs["config"]["port"] == port
    assert call.kwargs["credentials"] == {}
    # Hostname is forwarded to the relay so LLMNR can build the right query.
    assert call.kwargs["params"]["op_params"]["hostname"] == "ws-01"


# ── Subnet predicate ─────────────────────────────────────────────────


def test_lan_local_predicate_fires_when_asset_ip_in_relay_cidr():
    """Same-/24: predicate accepts."""
    from services.audit_auto_trigger import _lan_local_predicate

    asset = MagicMock()
    asset.ip = "10.0.0.42"
    relay = MagicMock()
    relay.labels = {"local_interfaces": ["10.0.0.0/24"]}

    assert _lan_local_predicate(asset, relay) is True


def test_lan_local_predicate_rejects_when_asset_ip_outside_all_relay_cidrs():
    from services.audit_auto_trigger import _lan_local_predicate

    asset = MagicMock()
    asset.ip = "192.168.50.10"
    relay = MagicMock()
    relay.labels = {"local_interfaces": ["10.0.0.0/24", "172.16.0.0/16"]}

    assert _lan_local_predicate(asset, relay) is False


def test_lan_local_predicate_rejects_when_relay_has_no_local_interfaces():
    """Relays that haven't reported their interfaces yet must NOT fire
    the LAN-local audit — defensive default."""
    from services.audit_auto_trigger import _lan_local_predicate

    asset = MagicMock()
    asset.ip = "10.0.0.42"
    relay = MagicMock()
    relay.labels = {}  # registration didn't include local_interfaces yet

    assert _lan_local_predicate(asset, relay) is False


def test_lan_local_predicate_rejects_when_relay_is_none():
    from services.audit_auto_trigger import _lan_local_predicate

    asset = MagicMock()
    asset.ip = "10.0.0.42"
    assert _lan_local_predicate(asset, None) is False


def test_lan_local_predicate_tolerates_garbage_cidrs():
    """A misconfigured relay shouldn't crash the auto-trigger — bad CIDRs
    are skipped, valid ones are still considered."""
    from services.audit_auto_trigger import _lan_local_predicate

    asset = MagicMock()
    asset.ip = "10.0.0.42"
    relay = MagicMock()
    relay.labels = {"local_interfaces": ["not-a-cidr", "10.0.0.0/24"]}

    assert _lan_local_predicate(asset, relay) is True


# ── Auto-trigger ─────────────────────────────────────────────────────


def test_auto_trigger_rule_for_netbios_local_registered():
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES

    rule = next((r for r in AUTO_TRIGGER_RULES if r.protocol == "netbios_local"), None)
    assert rule is not None
    assert rule.mission == "triage"
    assert set(rule.ports) == {137, 5355, 5353}
    assert rule.transport == "udp"
    assert rule.enabled_setting_key == "auto_audit_netbios"
    assert rule.predicate is not None


@pytest.fixture
def linked_lan_asset(db_session, test_org):
    scan = Scan(filename="x", scan_type="manual", source_type="manual", org_id=test_org.id)
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="ws-01", ip="10.0.0.42",
        easm_data={"easm_asset_id": "scanner-uuid-lan-1", "open_udp_ports": [137]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def _udp_port_change_event(scanner_asset_id: str, new_ports: list[int], hostname: str):
    return {
        "id": "evt-lan-1",
        "asset_id": scanner_asset_id,
        "event_type": "port_change",
        "payload": {
            "hostname": hostname, "transport": "udp",
            "new_ports": new_ports, "removed_ports": [],
        },
    }


def test_auto_trigger_dispatches_netbios_when_relay_is_on_same_subnet(
    db_session, test_org, linked_lan_asset,
):
    """The full-stack happy path: relay reports its CIDR, asset is inside
    it, switch is on, UDP 137 newly opens → audit fires."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    relay = RelayAgent(
        org_id=test_org.id, name="lan-relay", token_hash="x",
        status="connected", last_seen_at=datetime.utcnow(),
        labels={"local_interfaces": ["10.0.0.0/24"]},
    )
    db_session.add(relay)
    test_org.settings = {"auto_audit_netbios": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _udp_port_change_event("scanner-uuid-lan-1", [137], "ws-01"),
        )

    assert n == 1
    scan = db_session.query(Scan).filter_by(scan_type="netbios_local_audit").first()
    assert scan is not None
    assert scan.raw_metadata["protocol"] == "netbios_local"


def test_auto_trigger_does_not_fire_netbios_when_relay_is_off_subnet(
    db_session, test_org, linked_lan_asset,
):
    """Switch on, UDP 137 opens, but relay's CIDR doesn't contain the
    asset — predicate rejects, no audit dispatched."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    relay = RelayAgent(
        org_id=test_org.id, name="lan-relay", token_hash="x",
        status="connected", last_seen_at=datetime.utcnow(),
        labels={"local_interfaces": ["192.168.99.0/24"]},  # wrong subnet
    )
    db_session.add(relay)
    test_org.settings = {"auto_audit_netbios": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _udp_port_change_event("scanner-uuid-lan-1", [137], "ws-01"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_auto_trigger_does_not_fire_netbios_when_relay_has_no_interfaces_metadata(
    db_session, test_org, linked_lan_asset,
):
    """A relay that hasn't yet reported its local_interfaces must not
    trigger LAN-local audits — defensive default. Once the relay-side
    registration code starts populating ``labels.local_interfaces``,
    the audit will start firing."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    relay = RelayAgent(
        org_id=test_org.id, name="lan-relay", token_hash="x",
        status="connected", last_seen_at=datetime.utcnow(),
        labels={},  # no interfaces reported
    )
    db_session.add(relay)
    test_org.settings = {"auto_audit_netbios": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _udp_port_change_event("scanner-uuid-lan-1", [137], "ws-01"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()
