"""Tests for the OT/ICS active-probe audit (Phase 5).

Relay broker is mocked at the dispatch boundary. PDU construction
lives at the relay; this file verifies backend tool/audit/auto-trigger
wiring + the per-asset OT consent gate at dispatch."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.models import Asset, RelayAgent, Scan

import agents.agent_tools  # noqa: F401


# ── Audit registration ───────────────────────────────────────────────


def test_ot_protocol_audit_registered():
    from agents.audit_registry import get_audit, list_audits

    assert "ot_protocol" in list_audits()
    audit = get_audit("ot_protocol")
    assert audit.label == "OT/ICS Protocol Audit (Read-Only)"
    assert audit.safety_class == "ot_safe"
    assert audit.is_anonymous_capable() is True
    assert audit.requires_per_asset_consent() is True
    assert audit.relay_method == "ot_protocol_probe"
    assert audit.auto_trigger_policy == "per_asset_consent"
    assert audit.cooldown_hours == 168
    assert audit.credential_connector_ids == []
    assert {m.key for m in audit.missions} == {"triage"}
    assert "iec_62443_3_3" in audit.compliance_tags
    assert "meti_ot_security_guideline_v3" in audit.compliance_tags


def test_ot_protocol_required_ports_cover_all_families():
    """Each protocol's well-known port must appear in required_ports so the
    audit_runner preflight doesn't refuse a kickoff against a multi-protocol
    asset that only has a subset open."""
    from agents.audit_registry import get_audit

    audit = get_audit("ot_protocol")
    required = set(audit.required_ports)
    for port in (502, 102, 44818, 47808, 4840, 5007, 9600, 2404, 34962):
        assert port in required, f"port {port} missing from ot_protocol.required_ports"


def test_ot_protocol_tool_palette_registered():
    from agents.agent_tools import TOOL_REGISTRY

    expected = {
        "modbus_read_device_id", "modbus_read_holding",
        "s7_read_szl",
        "enip_list_identity",
        "bacnet_read_property",
        "opcua_hello",
        "melsec_read_cpu_info",
        "omron_fins_read_cpu_unit",
        "iec104_interrogate",
        "profinet_dcp_unicast",
    }
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"OT probe tools missing: {missing}"


def test_ot_protocol_mission_prompt_resolved():
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("ot_protocol_audit_triage")
    assert prompt
    assert "{preamble}" not in prompt
    assert "OT/ICS protocol auditor" in prompt
    assert 'protocol="ot_protocol"' in prompt
    assert 'mission="triage"' in prompt


# ── Dispatch + consent gate ──────────────────────────────────────────


def _consented_easm(protocol: str = "ot_protocol", *, days_ago: int = 0) -> dict:
    granted = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {
        "ot_audit_consent": {
            protocol: {"granted_at": granted.isoformat()},
        },
        "open_ports": [502, 102, 44818],
    }


@pytest.fixture
def consented_plc_asset(db_session, test_org):
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="plc-1", ip="10.20.30.55",
        easm_data=_consented_easm(),
    )
    db_session.add(asset)
    db_session.flush()
    return asset


@pytest.fixture
def unconsented_plc_asset(db_session, test_org):
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="plc-2", ip="10.20.30.66",
        easm_data={"open_ports": [502]},  # no consent record
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_dispatch_refuses_ot_protocol_without_consent(
    db_session, test_org, unconsented_plc_asset,
):
    """Manual dispatch path must enforce per-asset consent for ot_safe
    audits — auto-trigger isn't the only way the audit gets kicked off."""
    from services.audit_runner import dispatch_audit_run, AuditDispatchError

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        with pytest.raises(AuditDispatchError, match="per-asset OT consent"):
            dispatch_audit_run(
                db=db_session, org=test_org,
                protocol="ot_protocol", mission="triage",
                asset_ids=[unconsented_plc_asset.id],
                relay_agent_id="relay-x", credential_id=None,
            )


def test_dispatch_accepts_ot_protocol_with_fresh_consent(
    db_session, test_org, consented_plc_asset,
):
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="ot_protocol", mission="triage",
            asset_ids=[consented_plc_asset.id],
            relay_agent_id="relay-x", credential_id=None,
        )

    assert result["protocol"] == "ot_protocol"
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.scan_type == "ot_protocol_audit"
    assert scan.raw_metadata["credential_id"] is None


def test_dispatch_refuses_ot_protocol_with_expired_consent(
    db_session, test_org, consented_plc_asset,
):
    """Consent older than 90 days is treated as no consent."""
    from services.audit_runner import dispatch_audit_run, AuditDispatchError

    consented_plc_asset.easm_data = _consented_easm(days_ago=120)
    db_session.flush()

    with pytest.raises(AuditDispatchError, match="per-asset OT consent"):
        dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="ot_protocol", mission="triage",
            asset_ids=[consented_plc_asset.id],
            relay_agent_id="relay-x", credential_id=None,
        )


# ── Tool dispatch wiring ─────────────────────────────────────────────


def test_modbus_read_device_id_dispatches_correct_op(db_session, consented_plc_asset):
    from agents.tools.ot_protocol_tools import modbus_read_device_id_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={
        "reachable": True, "vendor": "Schneider", "product_code": "M580",
    })

    with patch("agents.tools.ot_protocol_tools.get_relay_broker", return_value=fake_broker):
        result = modbus_read_device_id_tool(db_session, {
            "asset_id": consented_plc_asset.id, "_relay_agent_id": "relay-x",
        })

    assert result["reachable"] is True
    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "ot_protocol_probe"
    assert call.kwargs["params"]["op"] == "modbus_read_device_id"
    assert call.kwargs["config"]["port"] == 502
    assert call.kwargs["credentials"] == {}


def test_modbus_read_holding_clamps_count(db_session, consented_plc_asset):
    """Tool layer caps count at 16 even if the LLM asks for 1000."""
    from agents.tools.ot_protocol_tools import modbus_read_holding_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"reachable": True, "registers": [0] * 16})

    with patch("agents.tools.ot_protocol_tools.get_relay_broker", return_value=fake_broker):
        modbus_read_holding_tool(db_session, {
            "asset_id": consented_plc_asset.id,
            "_relay_agent_id": "relay-x",
            "start_addr": 0, "count": 1000, "unit_id": 1,
        })

    op_params = fake_broker.send_task.await_args.kwargs["params"]["op_params"]
    assert op_params["count"] == 16
    assert op_params["unit_id"] == 1


def test_s7_read_szl_forwards_rack_slot(db_session, consented_plc_asset):
    from agents.tools.ot_protocol_tools import s7_read_szl_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"reachable": True})

    with patch("agents.tools.ot_protocol_tools.get_relay_broker", return_value=fake_broker):
        s7_read_szl_tool(db_session, {
            "asset_id": consented_plc_asset.id,
            "_relay_agent_id": "relay-x",
            "rack": 0, "slot": 3,
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["params"]["op"] == "s7_read_szl"
    assert call.kwargs["params"]["op_params"]["slot"] == 3
    assert call.kwargs["config"]["port"] == 102


def test_iec104_default_port_2404(db_session, consented_plc_asset):
    from agents.tools.ot_protocol_tools import iec104_interrogate_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"reachable": False})

    with patch("agents.tools.ot_protocol_tools.get_relay_broker", return_value=fake_broker):
        iec104_interrogate_tool(db_session, {
            "asset_id": consented_plc_asset.id, "_relay_agent_id": "relay-x",
        })

    assert fake_broker.send_task.await_args.kwargs["config"]["port"] == 2404


def test_jp_protocols_default_ports(db_session, consented_plc_asset):
    """JP-vendor protocols use the right default ports — MELSEC 5007 (TCP),
    FINS 9600 (UDP at the relay's discretion)."""
    from agents.tools.ot_protocol_tools import (
        melsec_read_cpu_info_tool, omron_fins_read_cpu_unit_tool,
    )

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"reachable": False})

    with patch("agents.tools.ot_protocol_tools.get_relay_broker", return_value=fake_broker):
        melsec_read_cpu_info_tool(db_session, {
            "asset_id": consented_plc_asset.id, "_relay_agent_id": "relay-x",
        })
        assert fake_broker.send_task.await_args.kwargs["config"]["port"] == 5007

        omron_fins_read_cpu_unit_tool(db_session, {
            "asset_id": consented_plc_asset.id, "_relay_agent_id": "relay-x",
        })
        assert fake_broker.send_task.await_args.kwargs["config"]["port"] == 9600


# ── Auto-trigger ─────────────────────────────────────────────────────


def test_auto_trigger_rules_for_ot_registered():
    """Two rules — one TCP, one UDP — both consent-gated + ``auto_audit_ot``."""
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES

    rules = [r for r in AUTO_TRIGGER_RULES if r.protocol == "ot_protocol"]
    assert len(rules) == 2
    transports = {r.transport for r in rules}
    assert transports == {"tcp", "udp"}
    for r in rules:
        assert r.requires_per_asset_consent is True
        assert r.enabled_setting_key == "auto_audit_ot"
        assert r.cooldown == timedelta(days=7)
    tcp_rule = next(r for r in rules if r.transport == "tcp")
    udp_rule = next(r for r in rules if r.transport == "udp")
    assert {502, 102, 44818, 4840, 5007, 2404} <= set(tcp_rule.ports)
    assert {47808, 9600, 34962} <= set(udp_rule.ports)


@pytest.fixture
def linked_consented_plc(db_session, test_org):
    scan = Scan(filename="x", scan_type="manual", source_type="manual", org_id=test_org.id)
    db_session.add(scan)
    db_session.flush()
    granted = datetime.now(timezone.utc).isoformat()
    asset = Asset(
        scan_id=scan.id, hostname="plc-prod-1", ip="10.0.0.55",
        easm_data={
            "easm_asset_id": "scanner-uuid-plc-1",
            "open_ports": [502, 102],
            "ot_audit_consent": {
                "ot_protocol": {"granted_at": granted},
                "ot_passive": {"granted_at": granted},
            },
        },
    )
    db_session.add(asset)
    db_session.flush()
    return asset


@pytest.fixture
def connected_relay_for_org(db_session, test_org):
    relay = RelayAgent(
        org_id=test_org.id, name="ot-relay", token_hash="x",
        status="connected", last_seen_at=datetime.utcnow(),
    )
    db_session.add(relay)
    db_session.flush()
    return relay


def _tcp_port_change(scanner_id: str, ports: list[int], hostname: str):
    return {
        "id": "evt-ot-1",
        "asset_id": scanner_id,
        "event_type": "port_change",
        "payload": {
            "hostname": hostname, "transport": "tcp",
            "new_ports": ports, "removed_ports": [],
        },
    }


def _udp_port_change(scanner_id: str, ports: list[int], hostname: str):
    return {
        "id": "evt-ot-udp",
        "asset_id": scanner_id,
        "event_type": "port_change",
        "payload": {
            "hostname": hostname, "transport": "udp",
            "new_ports": ports, "removed_ports": [],
        },
    }


def test_auto_trigger_dispatches_ot_on_tcp_502_event(
    db_session, test_org, linked_consented_plc, connected_relay_for_org,
):
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_ot": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _tcp_port_change("scanner-uuid-plc-1", [502], "plc-prod-1"),
        )

    assert n == 1
    scan = db_session.query(Scan).filter_by(scan_type="ot_protocol_audit").first()
    assert scan is not None
    assert scan.raw_metadata["mission"] == "triage"


def test_auto_trigger_does_not_fire_ot_without_consent(
    db_session, test_org, linked_consented_plc, connected_relay_for_org,
):
    """Even with ``auto_audit_ot`` on, no consent record → no dispatch."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_ot": True}
    # Strip consent
    easm = dict(linked_consented_plc.easm_data)
    easm.pop("ot_audit_consent", None)
    linked_consented_plc.easm_data = easm
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _tcp_port_change("scanner-uuid-plc-1", [502], "plc-prod-1"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_auto_trigger_does_not_fire_ot_without_org_switch(
    db_session, test_org, linked_consented_plc, connected_relay_for_org,
):
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}  # legacy switch only
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _tcp_port_change("scanner-uuid-plc-1", [502], "plc-prod-1"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_auto_trigger_dispatches_ot_on_udp_47808_event(
    db_session, test_org, linked_consented_plc, connected_relay_for_org,
):
    """UDP-tagged port_change for BACnet 47808 fires the UDP OT rule."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_ot": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-2"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _udp_port_change("scanner-uuid-plc-1", [47808], "plc-prod-1"),
        )

    # ot_protocol fires (UDP rule); ot_passive ALSO matches the same UDP
    # port set, so we expect 2 dispatches when both consents are present.
    assert n == 2
    scans = db_session.query(Scan).filter(
        Scan.scan_type.in_(("ot_protocol_audit", "ot_passive_audit")),
    ).all()
    assert {s.scan_type for s in scans} == {"ot_protocol_audit", "ot_passive_audit"}
