"""Tests for the OT/ICS passive-only audit (Phase 5)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.models import Asset, Scan

import agents.agent_tools  # noqa: F401


def test_ot_passive_audit_registered():
    from agents.audit_registry import get_audit, list_audits

    assert "ot_passive" in list_audits()
    audit = get_audit("ot_passive")
    assert audit.safety_class == "ot_passive_only"
    assert audit.is_anonymous_capable() is True
    assert audit.requires_per_asset_consent() is True
    assert audit.relay_method == "ot_passive_probe"
    assert audit.cooldown_hours == 168
    assert {m.key for m in audit.missions} == {"triage"}
    assert "iec_62443_3_3" in audit.compliance_tags


def test_ot_passive_tool_palette_registered():
    from agents.agent_tools import TOOL_REGISTRY

    assert "ot_passive_listen" in TOOL_REGISTRY


def test_ot_passive_mission_prompt_resolved():
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("ot_passive_audit_triage")
    assert prompt
    assert "{preamble}" not in prompt
    assert "passive auditor" in prompt
    assert 'protocol="ot_passive"' in prompt


@pytest.fixture
def consented_dcs_asset(db_session, test_org):
    scan = Scan(
        filename="x", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    granted = datetime.now(timezone.utc).isoformat()
    asset = Asset(
        scan_id=scan.id, hostname="dcs-1", ip="10.20.30.99",
        easm_data={
            "ot_audit_consent": {
                "ot_passive": {"granted_at": granted},
            },
        },
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_ot_passive_listen_dispatches_method_ot_passive_probe(
    db_session, consented_dcs_asset,
):
    from agents.tools.ot_passive_tools import ot_passive_listen_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={
        "profile": "yokogawa_vnetip", "presence": True,
        "frames_observed": 3, "peers": ["10.0.0.5"], "duration_s": 5,
    })

    with patch("agents.tools.ot_passive_tools.get_relay_broker", return_value=fake_broker):
        result = ot_passive_listen_tool(db_session, {
            "asset_id": consented_dcs_asset.id,
            "_relay_agent_id": "relay-x",
            "profile": "yokogawa_vnetip",
            "duration_s": 5,
        })

    assert result["presence"] is True
    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "ot_passive_probe"
    assert call.kwargs["params"]["op"] == "passive_listen"
    assert call.kwargs["params"]["op_params"]["profile"] == "yokogawa_vnetip"


def test_ot_passive_listen_clamps_duration(db_session, consented_dcs_asset):
    """duration_s is clamped to ≤10 at the tool layer (relay clamps too)."""
    from agents.tools.ot_passive_tools import ot_passive_listen_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"presence": False})

    with patch("agents.tools.ot_passive_tools.get_relay_broker", return_value=fake_broker):
        ot_passive_listen_tool(db_session, {
            "asset_id": consented_dcs_asset.id,
            "_relay_agent_id": "relay-x",
            "profile": "cclink_ie",
            "duration_s": 600,
        })

    op_params = fake_broker.send_task.await_args.kwargs["params"]["op_params"]
    assert op_params["duration_s"] == 10  # clamped


def test_ot_passive_listen_rejects_unknown_profile(db_session, consented_dcs_asset):
    """Profile name is a closed allowlist; unknowns raise before dispatch."""
    from agents.tools.ot_passive_tools import ot_passive_listen_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True

    with patch("agents.tools.ot_passive_tools.get_relay_broker", return_value=fake_broker):
        with pytest.raises(ValueError, match="unknown profile"):
            ot_passive_listen_tool(db_session, {
                "asset_id": consented_dcs_asset.id,
                "_relay_agent_id": "relay-x",
                "profile": "rogue_profile",
                "duration_s": 5,
            })


def test_dispatch_refuses_ot_passive_without_consent(db_session, test_org):
    """Same consent gate applies to ot_passive."""
    from services.audit_runner import dispatch_audit_run, AuditDispatchError

    scan = Scan(filename="x", scan_type="manual", source_type="manual", org_id=test_org.id)
    db_session.add(scan)
    db_session.flush()
    asset = Asset(scan_id=scan.id, hostname="no-consent", ip="10.0.0.99", easm_data={})
    db_session.add(asset)
    db_session.flush()

    with pytest.raises(AuditDispatchError, match="per-asset OT consent"):
        dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="ot_passive", mission="triage",
            asset_ids=[asset.id],
            relay_agent_id="relay-x", credential_id=None,
        )


def test_auto_trigger_rule_for_ot_passive():
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES

    rule = next((r for r in AUTO_TRIGGER_RULES if r.protocol == "ot_passive"), None)
    assert rule is not None
    assert rule.transport == "udp"
    assert rule.requires_per_asset_consent is True
    assert rule.enabled_setting_key == "auto_audit_ot"
