"""Tests for the Protocol Audit runner + registry + emit_finding tool.

The LLM + relay are mocked. We're testing the dispatch wiring (scan row,
scratch agents, memory context, registry) and the emit_finding write path.
The actual ReAct loop is covered by agent_engine tests upstream.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from models.models import Agent, Asset, Finding, Scan


# ── Registry + tool palette ──────────────────────────────────────────


def test_registry_populates_wmi_audit():
    """Loading agent_tools (which side-effect-imports agents.tools) must
    populate the AUDITS registry with the WMI protocol audit."""
    import agents.agent_tools  # noqa: F401 — triggers tool + audit registration
    from agents.audit_registry import AUDITS, get_audit, list_audits

    assert "wmi" in AUDITS
    assert list_audits() == ["wmi"]

    wmi = get_audit("wmi")
    assert wmi.label == "WMI Audit"
    assert wmi.relay_method == "wmi_query"
    assert "basic" in wmi.auth_modes
    assert {m.key for m in wmi.missions} == {
        "identity", "privesc", "software_cve", "network_hygiene", "explore",
    }


def test_wmi_tool_palette_registered():
    """The 10 WMI enumeration tools + emit_finding must live in TOOL_REGISTRY."""
    from agents.agent_tools import TOOL_REGISTRY

    expected = {
        "wmi_list_local_users", "wmi_get_user",
        "wmi_list_local_groups", "wmi_list_group_members",
        "wmi_list_services", "wmi_find_unquoted_service_paths",
        "wmi_get_password_policy", "wmi_get_computer_system",
        "wmi_list_software", "wmi_list_patches",
        "emit_finding",
    }
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"tools missing from TOOL_REGISTRY: {missing}"


def test_mission_prompts_resolved():
    """Each mission's prompt should have {preamble} expanded at import time."""
    from agents.agent_prompts import ENHANCED_PROMPTS

    for key in (
        "wmi_audit_identity",
        "wmi_audit_privesc",
        "wmi_audit_software_cve",
        "wmi_audit_network_hygiene",
        "wmi_audit_explore",
    ):
        prompt = ENHANCED_PROMPTS[key]
        assert "{preamble}" not in prompt, f"{key} still has unresolved preamble"
        assert "Windows host auditor" in prompt, f"{key} missing shared preamble"


def test_protocol_audit_templates_registered():
    """AGENT_TEMPLATES gets one entry per (protocol, mission) tuple."""
    from routes.agent_routes import AGENT_TEMPLATES

    template_ids = {t["id"] for t in AGENT_TEMPLATES}
    for mission in ("identity", "privesc", "software_cve", "network_hygiene", "explore"):
        assert f"wmi_audit_{mission}" in template_ids, f"wmi_audit_{mission} template missing"

    # Each audit template should carry the full tool palette.
    ident = next(t for t in AGENT_TEMPLATES if t["id"] == "wmi_audit_identity")
    assert "emit_finding" in ident["tools"]
    assert "wmi_get_password_policy" in ident["tools"]
    assert ident["guardrails"]["autonomy_level"] == "autonomous"


# ── dispatch_audit_run ───────────────────────────────────────────────


@pytest.fixture
def audit_asset(db_session, test_org):
    """One windows asset ready for a WMI audit."""
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="winhost-1", ip="10.0.0.5",
        os="Windows Server 2022",
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_dispatch_audit_run_creates_scan_and_scratch_agents(db_session, test_org, audit_asset):
    from services.audit_runner import dispatch_audit_run

    # Stub the background dispatcher — we're asserting wiring, not execution.
    with patch("services.audit_runner._dispatch_background_run") as mock_dispatch:
        result = dispatch_audit_run(
            db=db_session,
            org=test_org,
            protocol="wmi",
            mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1",
            credential_id="cred-1",
        )

    assert result["protocol"] == "wmi"
    assert result["mission"] == "identity"
    assert result["status"] == "running"
    assert len(result["runs"]) == 1
    run_meta = result["runs"][0]
    assert run_meta["asset_id"] == audit_asset.id
    assert run_meta["agent_id"] > 0

    # Scan row exists with the audit metadata.
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.scan_type == "wmi_audit"
    assert scan.source_type == "wmi_audit"
    assert scan.status == "running"
    assert scan.raw_metadata["protocol"] == "wmi"
    assert scan.raw_metadata["mission"] == "identity"
    assert scan.raw_metadata["asset_ids"] == [audit_asset.id]
    assert scan.raw_metadata["scratch_agent_ids"] == [run_meta["agent_id"]]

    # Scratch agent carries the run context in memory so tools see
    # relay_agent_id / credential_id without them being in the LLM's schema.
    agent = db_session.query(Agent).filter_by(id=run_meta["agent_id"]).first()
    assert agent is not None
    ctx = agent.memory["_run_ctx"]
    assert ctx["_relay_agent_id"] == "relay-1"
    assert ctx["_credential_id"] == "cred-1"
    assert ctx["_protocol"] == "wmi"
    assert ctx["_mission"] == "identity"
    assert ctx["_asset_id"] == audit_asset.id
    assert agent.guardrails["max_steps"] == 20      # identity mission default
    assert agent.guardrails["autonomy_level"] == "autonomous"

    # Background job was dispatched once per asset.
    assert mock_dispatch.call_count == 1


def test_dispatch_audit_run_rejects_unknown_protocol(db_session, test_org, audit_asset):
    from services.audit_runner import AuditDispatchError, dispatch_audit_run

    with pytest.raises(AuditDispatchError, match="unknown protocol"):
        dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="not_a_thing", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )


def test_dispatch_audit_run_rejects_unknown_mission(db_session, test_org, audit_asset):
    from services.audit_runner import AuditDispatchError, dispatch_audit_run

    with pytest.raises(AuditDispatchError, match="unknown mission"):
        dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="not_a_mission",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )


def test_dispatch_audit_run_rejects_missing_inputs(db_session, test_org, audit_asset):
    from services.audit_runner import AuditDispatchError, dispatch_audit_run

    with pytest.raises(AuditDispatchError, match="asset_ids"):
        dispatch_audit_run(
            db=db_session, org=test_org, protocol="wmi", mission="identity",
            asset_ids=[], relay_agent_id="relay-1", credential_id="cred-1",
        )
    with pytest.raises(AuditDispatchError, match="relay_agent_id"):
        dispatch_audit_run(
            db=db_session, org=test_org, protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id], relay_agent_id="", credential_id="cred-1",
        )
    with pytest.raises(AuditDispatchError, match="credential_id"):
        dispatch_audit_run(
            db=db_session, org=test_org, protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id], relay_agent_id="relay-1", credential_id="",
        )


# ── emit_finding tool ────────────────────────────────────────────────


def test_emit_finding_writes_finding_row(db_session, audit_asset):
    from agents.agent_tools import TOOL_REGISTRY

    tool = TOOL_REGISTRY["emit_finding"]["fn"]
    result = tool(db_session, {
        "protocol": "wmi",
        "mission": "identity",
        "asset_id": audit_asset.id,
        "finding_type": "weak_password_policy",
        "severity": "high",
        "title": "Password policy below baseline",
        "description": "MinimumPasswordLength=8 is below the 14-character baseline for privileged hosts.",
        "evidence": {
            "min_length": 8,
            "lockout_threshold": 0,
            "tool_calls": [{"name": "wmi_get_password_policy", "asset_id": audit_asset.id}],
        },
        "recommended_fix": "Set MinimumPasswordLength=14 and LockoutThreshold=10 via GPO.",
        "cves": [],
        "_agent_id": 42,
        "_agent_run_id": 7,
    })

    assert result["status"] == "emitted"
    assert result["severity"] == 3       # high

    finding = db_session.query(Finding).filter_by(id=result["finding_id"]).first()
    assert finding is not None
    assert finding.asset_id == audit_asset.id
    assert finding.source_type == "wmi_audit"
    assert finding.plugin_id == "hakuna_wmi_audit_identity_weak_password_policy"
    assert finding.plugin_family == "WMI Audit"
    assert finding.severity == 3
    assert finding.severity_label == "High"
    assert finding.custom_fields == {
        "finding_type": "weak_password_policy",
        "mission": "identity",
        "protocol": "wmi",
    }
    # Evidence is rendered as plugin_output text + agent_run_id stamped in.
    assert "min_length: 8" in (finding.plugin_output or "")
    validation = finding.llm_validation or {}
    assert validation["verdict"] == "true_positive"
    assert validation["validator"] == "agent"


def test_emit_finding_rejects_missing_required_fields(db_session, audit_asset):
    from agents.agent_tools import TOOL_REGISTRY

    tool = TOOL_REGISTRY["emit_finding"]["fn"]
    out = tool(db_session, {
        "protocol": "wmi", "mission": "identity",
        # asset_id / finding_type / title missing
    })
    assert "error" in out


# ── Pre-flight token quota enforcement ───────────────────────────────


def test_audit_run_route_pre_flight_quota_check(db_session, test_org, audit_asset):
    """POST /api/audits/run must 429 up-front when the org is over its token quota,
    instead of silently dispatching N background runs that will individually fail.
    """
    from fastapi.testclient import TestClient
    from core.auth import create_access_token
    from core.database import get_db
    from unittest.mock import patch
    import app as main_app

    # Seed org usage ABOVE the free limit (500K tokens).
    test_org.subscription_tier = "free"
    test_org.ai_tokens_used = 999_999
    db_session.flush()

    # Override the request DB session to our test session.
    main_app.app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(main_app.app)

    # Minimal auth user — use the test_org's id.
    from models.models import User
    user = User(
        email="quota@test.com",
        hashed_password="x",
        display_name="Quota Tester",
        role="org_admin",
        org_id=test_org.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    token = create_access_token(user.id, test_org.id, user.role)
    headers = {"Authorization": f"Bearer {token}", "X-Org-Context": str(test_org.id)}

    # Stub the dispatcher so a successful path wouldn't actually fire LLM jobs —
    # we want to prove the quota 429 fires BEFORE dispatch.
    with patch("routes.audit_routes.dispatch_audit_run") as mock_dispatch:
        resp = client.post("/api/audits/run", headers=headers, json={
            "protocol": "wmi",
            "mission": "identity",
            "asset_ids": [audit_asset.id],
            "credential_id": "any",
            "relay_agent_id": "relay-1",
        })

    assert resp.status_code == 429, f"expected 429, got {resp.status_code}: {resp.text}"
    assert "quota" in resp.text.lower()
    mock_dispatch.assert_not_called()
    main_app.app.dependency_overrides.clear()
