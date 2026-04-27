"""Tests for the Protocol Audit runner + registry + emit_finding tool.

The LLM + relay are mocked. We're testing the dispatch wiring (scan row,
scratch agents, memory context, registry) and the emit_finding write path.
The actual ReAct loop is covered by agent_engine tests upstream.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from models.models import Agent, Asset, Finding, Scan

# Side-effect import: each agents/tools/*_tools.py module calls
# `register_audit(...)` on import, populating `agents.audit_registry.AUDITS`.
# Without this, individual tests that touch `dispatch_audit_run` before
# `test_registry_populates_all_audits` has run see an empty registry and fail
# with "unknown protocol 'wmi'". Making it a top-of-file import means any
# test file ordering works.
import agents.agent_tools  # noqa: F401


# ── Registry + tool palette ──────────────────────────────────────────


def test_registry_populates_all_audits():
    """Loading agent_tools (which side-effect-imports agents.tools) must
    populate the AUDITS registry with every protocol audit."""
    import agents.agent_tools  # noqa: F401 — triggers tool + audit registration
    from agents.audit_registry import AUDITS, get_audit, list_audits

    assert "wmi" in AUDITS
    assert "ldap" in AUDITS
    assert "smb" in AUDITS
    assert set(list_audits()) == {
        "wmi", "ldap", "smb", "snmp", "ssh",
        "aws", "azure", "gcp",
        "exposed_datastore",  # Phase 1a
        "easm_fingerprint",  # Phase 2 (scanner-driven, mode=fingerprint)
        "exposed_ai_service",  # Phase 3 (gap-fill AI service audit)
        "managed_ai_saas",  # Phase 3.5 slice 0 (OpenAI / Anthropic admin APIs)
    }

    wmi = get_audit("wmi")
    assert wmi.label == "WMI Audit"
    assert wmi.relay_method == "wmi_query"
    assert "basic" in wmi.auth_modes
    assert {m.key for m in wmi.missions} == {
        "identity", "privesc", "software_cve", "network_hygiene", "explore",
    }

    ldap = get_audit("ldap")
    assert ldap.label == "LDAP Audit"
    assert ldap.relay_method == "ldap_query"
    assert {m.key for m in ldap.missions} == {
        "identity", "ad_structure", "acl_audit", "explore",
    }

    smb = get_audit("smb")
    assert smb.label == "SMB Audit"
    assert smb.relay_method == "smb_query"
    assert "anonymous" in smb.auth_modes
    assert {m.key for m in smb.missions} == {
        "share_audit", "signing_coercion", "null_session", "explore",
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


def test_ldap_tool_palette_registered():
    from agents.agent_tools import TOOL_REGISTRY

    expected = {
        "ldap_get_domain_info", "ldap_get_password_policy",
        "ldap_find_kerberoastable", "ldap_find_asrep_roastable",
        "ldap_list_privileged_groups", "ldap_get_group_members",
        "ldap_get_user",
        "ldap_find_unconstrained_delegation", "ldap_find_constrained_delegation",
        "ldap_find_rbcd", "ldap_get_object_acl",
        "ldap_list_trusts", "ldap_list_ous", "ldap_list_computers",
        "ldap_raw_search",
    }
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"LDAP tools missing from TOOL_REGISTRY: {missing}"


def test_smb_tool_palette_registered():
    from agents.agent_tools import TOOL_REGISTRY

    expected = {
        "smb_get_server_info", "smb_check_signing",
        "smb_list_shares", "smb_list_share_contents",
        "smb_check_null_session", "smb_list_shares_anonymous",
        "smb_samr_enum_users_anonymous", "smb_check_guest_access",
        "smb_check_named_pipe",
    }
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"SMB tools missing from TOOL_REGISTRY: {missing}"


def test_mission_prompts_resolved():
    """Each mission's prompt should have {preamble} expanded at import time."""
    from agents.agent_prompts import ENHANCED_PROMPTS

    wmi_keys = [
        "wmi_audit_identity", "wmi_audit_privesc",
        "wmi_audit_software_cve", "wmi_audit_network_hygiene",
        "wmi_audit_explore",
    ]
    ldap_keys = [
        "ldap_audit_identity", "ldap_audit_ad_structure",
        "ldap_audit_acl_audit", "ldap_audit_explore",
    ]
    smb_keys = [
        "smb_audit_share_audit", "smb_audit_signing_coercion",
        "smb_audit_null_session", "smb_audit_explore",
    ]

    for key in wmi_keys + ldap_keys + smb_keys:
        prompt = ENHANCED_PROMPTS[key]
        assert "{preamble}" not in prompt, f"{key} still has unresolved preamble"

    # Each preamble family stamps its own persona line — verify the right
    # preamble was chosen per protocol.
    for k in wmi_keys:
        assert "Windows host auditor" in ENHANCED_PROMPTS[k]
    for k in ldap_keys:
        assert "Active Directory auditor" in ENHANCED_PROMPTS[k]
    for k in smb_keys:
        assert "SMB auditor" in ENHANCED_PROMPTS[k]


def test_protocol_audit_templates_registered():
    """AGENT_TEMPLATES gets one entry per (protocol, mission) tuple for every audit."""
    from routes.agent_routes import AGENT_TEMPLATES

    template_ids = {t["id"] for t in AGENT_TEMPLATES}
    expected = (
        [f"wmi_audit_{m}" for m in ("identity", "privesc", "software_cve", "network_hygiene", "explore")]
        + [f"ldap_audit_{m}" for m in ("identity", "ad_structure", "acl_audit", "explore")]
        + [f"smb_audit_{m}" for m in ("share_audit", "signing_coercion", "null_session", "explore")]
    )
    for tid in expected:
        assert tid in template_ids, f"{tid} template missing"

    # Each audit template should carry emit_finding + its own protocol tool.
    wmi_ident = next(t for t in AGENT_TEMPLATES if t["id"] == "wmi_audit_identity")
    assert "emit_finding" in wmi_ident["tools"]
    assert "wmi_get_password_policy" in wmi_ident["tools"]
    assert wmi_ident["guardrails"]["autonomy_level"] == "autonomous"

    ldap_ident = next(t for t in AGENT_TEMPLATES if t["id"] == "ldap_audit_identity")
    assert "ldap_find_kerberoastable" in ldap_ident["tools"]
    assert "emit_finding" in ldap_ident["tools"]

    smb_share = next(t for t in AGENT_TEMPLATES if t["id"] == "smb_audit_share_audit")
    assert "smb_list_shares" in smb_share["tools"]
    assert "emit_finding" in smb_share["tools"]


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


def test_dispatch_audit_run_ldap(db_session, test_org, audit_asset):
    """LDAP audit uses a different relay method + tool palette but same orchestrator."""
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run") as mock_dispatch:
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="ldap", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-dc",
            credential_id="dc-admin",
        )
    assert result["protocol"] == "ldap"
    assert result["mission"] == "identity"
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.scan_type == "ldap_audit"
    agent = db_session.query(Agent).filter_by(id=result["runs"][0]["agent_id"]).first()
    # Scratch agent gets the LDAP palette, not WMI.
    assert "ldap_find_kerberoastable" in agent.tools
    assert "wmi_get_password_policy" not in agent.tools
    assert mock_dispatch.call_count == 1


def test_dispatch_audit_run_smb(db_session, test_org, audit_asset):
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run") as mock_dispatch:
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="smb", mission="signing_coercion",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1",
            credential_id="windows-admin",
        )
    assert result["protocol"] == "smb"
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.scan_type == "smb_audit"
    agent = db_session.query(Agent).filter_by(id=result["runs"][0]["agent_id"]).first()
    assert "smb_check_signing" in agent.tools
    assert "smb_check_named_pipe" in agent.tools
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


# ── Free-form targets flow ───────────────────────────────────────────


def test_dispatch_audit_run_with_free_form_targets_creates_assets(db_session, test_org):
    """Free-form targets path upserts Asset rows and dispatches as usual."""
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run") as mock_dispatch:
        result = dispatch_audit_run(
            db=db_session, org=test_org, protocol="ldap", mission="identity",
            targets=["dc1.corp.local", "10.0.0.99"],
            relay_agent_id="relay-dc", credential_id="dc-admin",
        )

    assert len(result["runs"]) == 2
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.raw_metadata["ad_hoc_targets"] == ["dc1.corp.local", "10.0.0.99"]
    assert len(scan.raw_metadata["asset_ids"]) == 2

    # Created assets carry the parsed identity so rescan/dedup can match them.
    assets = db_session.query(Asset).filter(
        Asset.id.in_(scan.raw_metadata["asset_ids"])
    ).all()
    hostnames = {a.hostname for a in assets if a.hostname}
    ips = {a.ip for a in assets if a.ip}
    assert "dc1.corp.local" in hostnames
    assert "10.0.0.99" in ips
    assert mock_dispatch.call_count == 2


def test_dispatch_audit_run_with_targets_reuses_existing_asset(db_session, test_org, audit_asset):
    """An existing asset matching the target's IP is reused, not duplicated."""
    from services.audit_runner import dispatch_audit_run

    before_count = db_session.query(Asset).count()

    with patch("services.audit_runner._dispatch_background_run"):
        result = dispatch_audit_run(
            db=db_session, org=test_org, protocol="wmi", mission="identity",
            targets=[audit_asset.ip],              # matches audit_asset.ip
            relay_agent_id="relay-1", credential_id="cred-1",
        )

    after_count = db_session.query(Asset).count()
    assert after_count == before_count              # no new asset created
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.raw_metadata["asset_ids"] == [audit_asset.id]


def test_dispatch_audit_run_strips_port_from_identity(db_session, test_org):
    """Free-form targets like ``ssh:2222`` must not embed the port in the
    asset's hostname/fqdn/ip fields — the port goes to easm_data so the UI
    stays clean and protocol tools still pick it up at dispatch."""
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run"):
        result = dispatch_audit_run(
            db=db_session, org=test_org, protocol="ssh", mission="explore",
            targets=["ssh:2222", "10.0.0.5:1389"],
            relay_agent_id="relay-1", credential_id="cred-1",
        )

    assets = db_session.query(Asset).filter(
        Asset.id.in_(result["runs"][i]["asset_id"] for i in range(2))
    ).all()
    by_port = {(a.easm_data or {}).get("audit_target_port"): a for a in assets}
    assert 2222 in by_port and 1389 in by_port
    # The identity fields never contain the ":port" suffix.
    for a in assets:
        for field in (a.hostname, a.fqdn, a.ip):
            if field:
                assert ":" not in field
    assert by_port[2222].hostname == "ssh"
    assert by_port[1389].ip == "10.0.0.5"


def test_dispatch_audit_run_rejects_both_sources(db_session, test_org, audit_asset):
    """asset_ids + targets together is an error — exactly one allowed."""
    from services.audit_runner import AuditDispatchError, dispatch_audit_run

    with pytest.raises(AuditDispatchError, match="exactly one"):
        dispatch_audit_run(
            db=db_session, org=test_org, protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id], targets=["10.0.0.1"],
            relay_agent_id="relay-1", credential_id="cred-1",
        )


def test_dispatch_audit_run_rejects_neither_source(db_session, test_org):
    from services.audit_runner import AuditDispatchError, dispatch_audit_run

    with pytest.raises(AuditDispatchError, match="exactly one"):
        dispatch_audit_run(
            db=db_session, org=test_org, protocol="wmi", mission="identity",
            relay_agent_id="relay-1", credential_id="cred-1",
        )


# ── Background dispatch routing ──────────────────────────────────────


def test_dispatch_enqueues_on_audits_queue(monkeypatch):
    """Dispatch always enqueues the scratch-agent Celery task on the `audits`
    queue with countdown=1 (race guard: the API request's final commit may
    land after the worker picks up the task; the delay absorbs that window).
    Returns the task id so the caller can persist it for cancel/revoke.

    There's no legacy in-process fallback — bringing up the `audits` compose
    profile is the single way to run audits.
    """
    from services import audit_runner

    enqueued = {}

    class FakeResult:
        id = "fake-task-id-42"

    class FakeTask:
        def apply_async(self, args, queue, countdown, **kwargs):
            # Absorb optional kwargs (`ignore_result`, etc.) so the test
            # stays stable when we add more apply_async options.
            enqueued["args"] = args
            enqueued["queue"] = queue
            enqueued["countdown"] = countdown
            enqueued["kwargs"] = kwargs
            return FakeResult()

    import services.audit_worker as worker_mod
    monkeypatch.setattr(worker_mod, "run_scratch_agent_task", FakeTask())

    task_id = audit_runner._dispatch_background_run(agent_id=42, user_input="hi", wallclock_s=120)

    assert enqueued["queue"] == "audits"
    assert enqueued["countdown"] == 1
    assert enqueued["args"] == (42, "hi", 120)
    assert task_id == "fake-task-id-42"


def test_dispatch_audit_run_persists_task_ids(db_session, test_org, audit_asset):
    """Task ids land on scan.raw_metadata.task_ids so the cancel endpoint can
    revoke them — without this, Stop has no handle to reach running LLM loops."""
    from services import audit_runner
    from services.audit_runner import dispatch_audit_run
    from models.models import Scan as _Scan

    class FakeResult:
        def __init__(self, tid): self.id = tid
    class FakeTask:
        def __init__(self): self._n = 0
        def apply_async(self, args, queue, countdown, **kwargs):
            self._n += 1
            return FakeResult(f"task-{self._n}")

    import services.audit_worker as worker_mod
    worker_mod.run_scratch_agent_task = FakeTask()

    result = dispatch_audit_run(
        db=db_session, org=test_org,
        protocol="wmi", mission="identity",
        asset_ids=[audit_asset.id],
        relay_agent_id="relay-1", credential_id="cred-1",
    )
    scan = db_session.query(_Scan).filter_by(id=result["scan_id"]).first()
    task_ids = scan.raw_metadata.get("task_ids") or {}
    agent_id = result["runs"][0]["agent_id"]
    assert str(agent_id) in {str(k) for k in task_ids.keys()}
    assert list(task_ids.values())[0].startswith("task-")


def test_dispatch_raises_worker_unavailable_when_broker_down(monkeypatch):
    """If the Celery broker can't be reached, translate to a typed error so
    the route returns 503 instead of a bare 500. Caller-actionable message."""
    from services import audit_runner

    class BrokenTask:
        def apply_async(self, args, queue, countdown, **kwargs):
            raise ConnectionRefusedError("redis://broker unavailable")

    import services.audit_worker as worker_mod
    monkeypatch.setattr(worker_mod, "run_scratch_agent_task", BrokenTask())

    with pytest.raises(audit_runner.AuditWorkerUnavailableError, match="worker queue unavailable"):
        audit_runner._dispatch_background_run(agent_id=42, user_input="x", wallclock_s=60)


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
    # plugin_family is sourced from the closed registry in agents/tools/emit_finding.py
    # so compliance mappings can rely on a stable taxonomy across protocols.
    assert finding.plugin_family == "Audit: Windows"
    assert finding.severity == 3
    assert finding.severity_label == "High"
    # compliance_evaluable is set per-emission based on whether CVE/CWE was supplied;
    # this test omits both, so the flag is False (still persisted, just not evaluable).
    assert finding.custom_fields == {
        "finding_type": "weak_password_policy",
        "mission": "identity",
        "protocol": "wmi",
        "compliance_evaluable": False,
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


# ── Rescan (in-place) ────────────────────────────────────────────────


def test_rescan_audit_scan_reuses_same_row(db_session, test_org, audit_asset):
    """Rescanning an audit scan must update the existing Scan row, not create
    a new one. Mirrors rescan_vm_scan — the scan list shouldn't grow a second
    entry per rerun."""
    from services.audit_runner import dispatch_audit_run, rescan_audit_scan

    with patch("services.audit_runner._dispatch_background_run"):
        first = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )

    scan = db_session.query(Scan).filter_by(id=first["scan_id"]).first()
    original_scan_id = scan.id
    original_scratch_agents = list(scan.raw_metadata["scratch_agent_ids"])

    with patch("services.audit_runner._dispatch_background_run"):
        second = rescan_audit_scan(
            db=db_session, org=test_org, scan=scan,
        )

    assert second["scan_id"] == original_scan_id, "rescan must reuse the same Scan.id"
    # Only one Scan row for this mission in the org.
    assert db_session.query(Scan).filter_by(
        scan_type="wmi_audit", org_id=test_org.id,
    ).count() == 1
    # New batch of scratch agents replaced the old ones.
    new_scratch_agents = list(scan.raw_metadata["scratch_agent_ids"])
    assert new_scratch_agents != original_scratch_agents
    assert len(new_scratch_agents) == 1
    # Status is rotated back to running.
    assert scan.status == "running"
    assert scan.raw_metadata["status"] == "running"


def test_rescan_audit_scan_archives_prior_run(db_session, test_org, audit_asset):
    """The outgoing run's scratch_agent_ids, status, and params land in
    raw_metadata.run_history so the history endpoint can still surface past
    AgentRuns."""
    from services.audit_runner import dispatch_audit_run, rescan_audit_scan

    with patch("services.audit_runner._dispatch_background_run"):
        first = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )

    scan = db_session.query(Scan).filter_by(id=first["scan_id"]).first()
    first_batch = list(scan.raw_metadata["scratch_agent_ids"])
    md = dict(scan.raw_metadata)
    md["task_ids"] = {str(first_batch[0]): "fake-task-1"}
    scan.raw_metadata = md
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run"):
        rescan_audit_scan(
            db=db_session, org=test_org, scan=scan,
        )

    run_history = scan.raw_metadata.get("run_history") or []
    assert len(run_history) == 1, "exactly one archived run after one rescan"
    archived = run_history[0]
    assert archived["scratch_agent_ids"] == first_batch
    assert archived["task_ids"] == {str(first_batch[0]): "fake-task-1"}
    assert archived["mission"] == "identity"
    assert archived["asset_ids"] == [audit_asset.id]


def test_rescan_audit_scan_applies_overrides(db_session, test_org, audit_asset):
    """Mission, credential_id, relay_agent_id overrides all take effect on rescan."""
    from services.audit_runner import dispatch_audit_run, rescan_audit_scan

    with patch("services.audit_runner._dispatch_background_run"):
        first = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )

    scan = db_session.query(Scan).filter_by(id=first["scan_id"]).first()

    with patch("services.audit_runner._dispatch_background_run"):
        rescan_audit_scan(
            db=db_session, org=test_org, scan=scan,
            mission="privesc",
            credential_id="cred-2",
            relay_agent_id="relay-2",
        )

    assert scan.raw_metadata["mission"] == "privesc"
    assert scan.raw_metadata["credential_id"] == "cred-2"
    assert scan.raw_metadata["relay_agent_id"] == "relay-2"
    new_agent_id = scan.raw_metadata["scratch_agent_ids"][0]
    new_agent = db_session.query(Agent).filter_by(id=new_agent_id).first()
    ctx = new_agent.memory["_run_ctx"]
    assert ctx["_mission"] == "privesc"
    assert ctx["_credential_id"] == "cred-2"
    assert ctx["_relay_agent_id"] == "relay-2"


def test_audit_scan_history_flattens_run_history(db_session, test_org, audit_asset):
    """The history endpoint returns AgentRuns from both the current run and
    every archived run in raw_metadata.run_history."""
    from fastapi.testclient import TestClient
    from core.auth import create_access_token
    from core.database import get_db
    from models.models import AgentRun, User
    from services.audit_runner import dispatch_audit_run, rescan_audit_scan
    import app as main_app

    with patch("services.audit_runner._dispatch_background_run"):
        first = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )
    scan = db_session.query(Scan).filter_by(id=first["scan_id"]).first()
    first_agent_id = scan.raw_metadata["scratch_agent_ids"][0]
    db_session.add(AgentRun(
        agent_id=first_agent_id, input="first", status="done",
        steps_used=3,
    ))
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run"):
        rescan_audit_scan(db=db_session, org=test_org, scan=scan)
    second_agent_id = scan.raw_metadata["scratch_agent_ids"][0]
    db_session.add(AgentRun(
        agent_id=second_agent_id, input="second", status="running",
        steps_used=1,
    ))
    db_session.flush()

    user = User(
        email="history@test.com", hashed_password="x",
        display_name="History Tester", role="org_admin",
        org_id=test_org.id, is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    token = create_access_token(user.id, test_org.id, user.role)
    headers = {"Authorization": f"Bearer {token}", "X-Org-Context": str(test_org.id)}

    main_app.app.dependency_overrides[get_db] = lambda: db_session
    try:
        client = TestClient(main_app.app)
        resp = client.get(f"/api/audits/scans/{scan.id}/history", headers=headers)
    finally:
        main_app.app.dependency_overrides.clear()

    assert resp.status_code == 200, resp.text
    body = resp.json()
    agent_ids_in_runs = {r["agent_id"] for r in body["runs"]}
    assert first_agent_id in agent_ids_in_runs, "archived run's agent missing"
    assert second_agent_id in agent_ids_in_runs, "current run's agent missing"
    assert body["related_scan_ids"] == [scan.id]


# ── Worker: scan finalization ────────────────────────────────────────


def test_finalize_scan_if_complete_flips_to_completed(db_session, test_org, audit_asset):
    """When every scratch agent for a scan's current run hits a terminal
    AgentRun, _finalize_scan_if_complete flips Scan.status to 'completed'
    (≥1 success → completed)."""
    from models.models import AgentRun
    from services.audit_runner import dispatch_audit_run
    from services.audit_worker import _finalize_scan_if_complete

    with patch("services.audit_runner._dispatch_background_run"):
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    agent_id = scan.raw_metadata["scratch_agent_ids"][0]
    assert scan.status == "running"

    _finalize_scan_if_complete(db_session, agent_id)
    db_session.refresh(scan)
    assert scan.status == "running"

    db_session.add(AgentRun(
        agent_id=agent_id, input="x", status="done", steps_used=5,
    ))
    db_session.flush()

    _finalize_scan_if_complete(db_session, agent_id)
    db_session.refresh(scan)
    assert scan.status == "completed"
    assert scan.raw_metadata["status"] == "completed"


def test_finalize_scan_if_complete_marks_failed_when_all_fail(db_session, test_org, audit_asset):
    """If every scratch agent's latest AgentRun is non-'done', the scan
    finalizes as 'failed' — addresses the bug where a worker error (e.g. no
    Anthropic key) left scans stuck on 'Scanning…' forever."""
    from models.models import AgentRun
    from services.audit_runner import dispatch_audit_run
    from services.audit_worker import _finalize_scan_if_complete

    with patch("services.audit_runner._dispatch_background_run"):
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    agent_id = scan.raw_metadata["scratch_agent_ids"][0]

    db_session.add(AgentRun(
        agent_id=agent_id, input="x", status="failed",
        error="Anthropic API key not configured",
    ))
    db_session.flush()

    _finalize_scan_if_complete(db_session, agent_id)
    db_session.refresh(scan)
    assert scan.status == "failed"
    assert scan.raw_metadata["status"] == "failed"


def test_finalize_scan_if_complete_waits_for_all_agents(db_session, test_org):
    """Multi-asset scan: finalize must wait until every scratch agent is
    terminal before flipping the scan."""
    from models.models import Asset, AgentRun
    from services.audit_runner import dispatch_audit_run
    from services.audit_worker import _finalize_scan_if_complete

    placeholder_scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(placeholder_scan)
    db_session.flush()
    a1 = Asset(scan_id=placeholder_scan.id, hostname="h1", ip="10.0.0.1", os="Windows")
    a2 = Asset(scan_id=placeholder_scan.id, hostname="h2", ip="10.0.0.2", os="Windows")
    db_session.add_all([a1, a2])
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run"):
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="identity",
            asset_ids=[a1.id, a2.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    scratch_agent_ids = scan.raw_metadata["scratch_agent_ids"]
    assert len(scratch_agent_ids) == 2

    db_session.add(AgentRun(
        agent_id=scratch_agent_ids[0], input="x", status="done", steps_used=3,
    ))
    db_session.flush()
    _finalize_scan_if_complete(db_session, scratch_agent_ids[0])
    db_session.refresh(scan)
    assert scan.status == "running"

    db_session.add(AgentRun(
        agent_id=scratch_agent_ids[1], input="x", status="done", steps_used=2,
    ))
    db_session.flush()
    _finalize_scan_if_complete(db_session, scratch_agent_ids[1])
    db_session.refresh(scan)
    assert scan.status == "completed"


def test_finalize_scan_if_complete_preserves_cancelled(db_session, test_org, audit_asset):
    """A user-cancelled scan must stay 'cancelled' even if the worker later
    flushes a terminal AgentRun (SIGTERM race)."""
    from models.models import AgentRun
    from services.audit_runner import dispatch_audit_run
    from services.audit_worker import _finalize_scan_if_complete

    with patch("services.audit_runner._dispatch_background_run"):
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="wmi", mission="identity",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id="cred-1",
        )
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    agent_id = scan.raw_metadata["scratch_agent_ids"][0]
    scan.status = "cancelled"
    md = dict(scan.raw_metadata)
    md["status"] = "cancelled"
    scan.raw_metadata = md
    db_session.flush()

    db_session.add(AgentRun(
        agent_id=agent_id, input="x", status="done", steps_used=1,
    ))
    db_session.flush()

    _finalize_scan_if_complete(db_session, agent_id)
    db_session.refresh(scan)
    assert scan.status == "cancelled"
    assert scan.raw_metadata["status"] == "cancelled"


# ── Preflight (open_ports → unreachable short-circuit) ───────────────


def test_registry_required_ports_coverage():
    """Every audit protocol that speaks over TCP must declare its ports
    so the preflight has signal. SNMP lists 161 even though the probe is
    UDP-only — the check matches against asset.open_ports which stores
    both families."""
    from agents.audit_registry import AUDITS
    assert 445 in AUDITS["smb"].required_ports
    assert 389 in AUDITS["ldap"].required_ports
    assert 22 in AUDITS["ssh"].required_ports
    assert 135 in AUDITS["wmi"].required_ports
    assert 161 in AUDITS["snmp"].required_ports


def test_preflight_skips_when_no_open_ports_known(db_session, test_org, audit_asset):
    """Conservative: an asset that's never been discovery-scanned has an
    empty open_ports list. We must NOT false-flag it as unreachable —
    the audit dispatches normally and the tools handle actual
    reachability at runtime."""
    from services.audit_runner import _preflight_audit_asset
    from agents.audit_registry import AUDITS

    audit_asset.easm_data = None
    db_session.flush()
    ok, reason = _preflight_audit_asset(audit_asset, AUDITS["smb"])
    assert ok is True
    assert reason is None


def test_preflight_passes_when_required_port_observed(db_session, audit_asset):
    """Positive case: 445 showed up in discovery, SMB audit proceeds."""
    from services.audit_runner import _preflight_audit_asset
    from agents.audit_registry import AUDITS

    audit_asset.easm_data = {"open_ports": [80, 443, 445]}
    db_session.flush()
    ok, reason = _preflight_audit_asset(audit_asset, AUDITS["smb"])
    assert ok is True
    assert reason is None


def test_preflight_fails_when_all_required_ports_closed(db_session, audit_asset):
    """Positive evidence of closed ports — SMB audit against a host
    whose discovery found only 80/443 open should bail."""
    from services.audit_runner import _preflight_audit_asset
    from agents.audit_registry import AUDITS

    audit_asset.easm_data = {"open_ports": [80, 443]}
    db_session.flush()
    ok, reason = _preflight_audit_asset(audit_asset, AUDITS["smb"])
    assert ok is False
    assert reason is not None
    assert "SMB" in reason
    # Reason must name the target and the observed open ports so the UI
    # can render something useful without the user chasing logs.
    assert (audit_asset.hostname or audit_asset.ip) in reason
    assert "80" in reason


def test_preflight_allows_any_required_port(db_session, audit_asset):
    """LDAP has multiple candidate ports (389 + 636 + GC). Any one open
    is enough for the audit to run."""
    from services.audit_runner import _preflight_audit_asset
    from agents.audit_registry import AUDITS

    # Only LDAPS (636) is open — common for hardened DCs.
    audit_asset.easm_data = {"open_ports": [636]}
    db_session.flush()
    ok, reason = _preflight_audit_asset(audit_asset, AUDITS["ldap"])
    assert ok is True
    assert reason is None


def test_dispatch_skips_background_when_preflight_fails(db_session, test_org, audit_asset):
    """End-to-end wiring: dispatching an SMB audit against an asset with
    open_ports=[80] records an unreachable AgentRun and does NOT enqueue
    a Celery task. Prevents the scratch agent from burning LLM tokens
    against a target its own discovery said was closed."""
    from services.audit_runner import dispatch_audit_run
    from models.models import AgentRun

    audit_asset.easm_data = {"open_ports": [80, 443]}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run") as mock_dispatch:
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="smb", mission="share_audit",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id=None,
        )

    # Scratch agent was still created (so the UI can link to it), but no
    # background job fired and the AgentRun terminates immediately as
    # failed with the reachability reason.
    assert mock_dispatch.call_count == 0
    assert result["runs"][0]["status"] == "unreachable"
    assert result["runs"][0]["error"]
    agent_id = result["runs"][0]["agent_id"]
    run = db_session.query(AgentRun).filter_by(agent_id=agent_id).first()
    assert run is not None
    assert run.status == "failed"
    assert "SMB" in (run.error or "")


def test_dispatch_proceeds_when_required_port_open(db_session, test_org, audit_asset):
    """Control case — the same dispatch path with 445 in open_ports
    runs normally and enqueues the Celery task."""
    from services.audit_runner import dispatch_audit_run

    audit_asset.easm_data = {"open_ports": [80, 445]}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run") as mock_dispatch:
        result = dispatch_audit_run(
            db=db_session, org=test_org,
            protocol="smb", mission="share_audit",
            asset_ids=[audit_asset.id],
            relay_agent_id="relay-1", credential_id=None,
        )

    assert mock_dispatch.call_count == 1
    assert result["runs"][0]["status"] == "pending"
