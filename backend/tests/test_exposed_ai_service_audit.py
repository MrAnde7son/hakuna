"""Tests for the Exposed-AI-Service Audit registration, tool palette,
mission prompts, and auto-trigger wiring (Phase 3, gap-fill scope).

The relay broker is mocked at the dispatch boundary — we don't attempt
real network connections to a Jupyter/Ray/MLflow/etc. The backend tools
are tested for correct dispatch shape (method name, port, op), not for
what the relay does internally."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.models import Asset, RelayAgent, Scan

# Side-effect import — populates AUDITS + TOOL_REGISTRY.
import agents.agent_tools  # noqa: F401


# ── Audit registration ───────────────────────────────────────────────


def test_exposed_ai_service_audit_registered():
    """Phase 3 registration must surface in the audit registry with the
    right safety class, anonymous capability, and both missions wired."""
    from agents.audit_registry import get_audit, list_audits

    assert "exposed_ai_service" in list_audits()
    audit = get_audit("exposed_ai_service")
    assert audit.label == "Exposed AI Service Audit"
    assert audit.safety_class == "anon_ai_exposure"
    assert audit.is_anonymous_capable() is True
    assert audit.requires_per_asset_consent() is False
    assert audit.relay_method == "ai_service_probe"
    assert audit.auto_trigger_policy == "auto_org_opt_in"
    assert "anonymous" in audit.auth_modes
    assert audit.credential_connector_ids == []
    assert {m.key for m in audit.missions} == {"triage", "prompt_injection_probe"}
    assert "nist_ai_rmf" in audit.compliance_tags
    assert "iso_42001" in audit.compliance_tags
    # Required ports cover the gap-fill triage set + canary ports
    expected_ports = {8888, 8265, 5000, 6006, 8080, 1234, 3000, 11434, 8000}
    assert set(audit.required_ports) == expected_ports


def test_exposed_ai_service_tool_palette_registered():
    """Every gap-fill probe + every canary tool must be in TOOL_REGISTRY."""
    from agents.agent_tools import TOOL_REGISTRY

    expected = {
        # Triage tools (gap-fill)
        "jupyter_check_auth", "ray_dashboard_info", "mlflow_list_experiments",
        "tensorboard_list_runs", "tgi_info", "lmstudio_models",
        "openwebui_status", "langfuse_status",
        # Prompt-injection-probe tools (consent-gated)
        "ollama_capability_probe", "vllm_capability_probe", "mcp_enumerate_tools",
    }
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"AI-service tools missing from TOOL_REGISTRY: {missing}"


def test_exposed_ai_service_mission_prompts_resolved():
    """Both mission prompts must have their preamble substituted at import
    time — otherwise the agent receives a literal '{preamble}' marker."""
    from agents.agent_prompts import ENHANCED_PROMPTS

    triage = ENHANCED_PROMPTS.get("exposed_ai_service_audit_triage")
    pip = ENHANCED_PROMPTS.get("exposed_ai_service_audit_prompt_injection_probe")
    assert triage, "triage prompt missing"
    assert pip, "prompt_injection_probe prompt missing"
    for prompt in (triage, pip):
        assert "{preamble}" not in prompt
        assert "exposed-AI-service auditor" in prompt
    assert 'protocol="exposed_ai_service"' in triage
    assert 'mission="triage"' in triage
    assert 'mission="prompt_injection_probe"' in pip


def test_canary_tools_only_invited_in_prompt_injection_probe_mission():
    """Both prompts mention the canary tools in the shared safety rules
    section (the preamble), but the canary tools must only appear in the
    prompt_injection_probe mission's *checklist* — i.e. as something the
    agent is instructed to call. The triage prompt must not invite use."""
    from agents.agent_prompts import ENHANCED_PROMPTS

    triage = ENHANCED_PROMPTS["exposed_ai_service_audit_triage"]
    pip = ENHANCED_PROMPTS["exposed_ai_service_audit_prompt_injection_probe"]

    # The triage mission's checklist (post-preamble content) must not
    # include canary tools as actions to take. The preamble — shared
    # between both prompts — does mention them, but only in the safety
    # rules ("Canary inference is consent-gated"). Find the checklist
    # section and assert the canary names don't appear there.
    triage_checklist = triage.split("## Mission:", 1)[-1]
    assert "ollama_capability_probe" not in triage_checklist
    assert "vllm_capability_probe" not in triage_checklist
    assert "mcp_enumerate_tools" not in triage_checklist

    pip_checklist = pip.split("## Mission:", 1)[-1]
    assert "ollama_capability_probe" in pip_checklist
    assert "vllm_capability_probe" in pip_checklist
    assert "mcp_enumerate_tools" in pip_checklist


# ── Dispatch wiring ──────────────────────────────────────────────────


@pytest.fixture
def ai_asset(db_session, test_org):
    """Asset that looks like a Jupyter host: open port 8888 + AI-typed."""
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="jupyter-host-1", ip="10.20.30.50",
        asset_type="ai_inference",
        easm_data={"open_ports": [8888, 6006, 5000]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_dispatch_audit_run_accepts_anonymous_for_exposed_ai_service(
    db_session, test_org, ai_asset,
):
    """The Phase 0 ``safety_class`` predicate must accept ``credential_id=None``
    for the new exposed_ai_service audit — same wiring as exposed_datastore."""
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        result = dispatch_audit_run(
            db=db_session,
            org=test_org,
            protocol="exposed_ai_service",
            mission="triage",
            asset_ids=[ai_asset.id],
            relay_agent_id="relay-x",
            credential_id=None,
        )

    assert result["protocol"] == "exposed_ai_service"
    assert result["mission"] == "triage"
    assert result["status"] == "running"

    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.scan_type == "exposed_ai_service_audit"
    assert scan.raw_metadata["credential_id"] is None


def test_dispatch_accepts_prompt_injection_probe_mission(
    db_session, test_org, ai_asset,
):
    """The deeper mission must be dispatchable too — its consent gate is at
    the auto-trigger layer, not at dispatch validation."""
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        result = dispatch_audit_run(
            db=db_session,
            org=test_org,
            protocol="exposed_ai_service",
            mission="prompt_injection_probe",
            asset_ids=[ai_asset.id],
            relay_agent_id="relay-x",
            credential_id=None,
        )

    assert result["mission"] == "prompt_injection_probe"


def test_jupyter_check_auth_dispatches_method_ai_service_probe_op_jupyter(
    db_session, ai_asset,
):
    """Backend Jupyter tool must dispatch ``method=ai_service_probe`` with
    ``op="jupyter"`` and the standard port — the contract the relay handler
    depends on."""
    from agents.tools.exposed_ai_service_tools import jupyter_check_auth_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={
        "auth_required": False, "version": "7.0.6", "kernels_endpoint_open": True,
    })

    with patch(
        "agents.tools.exposed_ai_service_tools.get_relay_broker",
        return_value=fake_broker,
    ):
        result = jupyter_check_auth_tool(db_session, {
            "asset_id": ai_asset.id,
            "_relay_agent_id": "relay-x",
        })

    assert result["auth_required"] is False
    fake_broker.send_task.assert_awaited_once()
    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "ai_service_probe"
    assert call.kwargs["params"]["op"] == "jupyter"
    assert call.kwargs["config"]["target"] == "10.20.30.50"
    assert call.kwargs["config"]["port"] == 8888
    # Anonymous probe — credentials must always be empty
    assert call.kwargs["credentials"] == {}


@pytest.mark.parametrize("tool_name,op,port", [
    ("jupyter_check_auth", "jupyter", 8888),
    ("ray_dashboard_info", "ray", 8265),
    ("mlflow_list_experiments", "mlflow", 5000),
    ("tensorboard_list_runs", "tensorboard", 6006),
    ("tgi_info", "tgi", 8080),
    ("lmstudio_models", "lmstudio", 1234),
    ("openwebui_status", "openwebui", 3000),
    ("langfuse_status", "langfuse", 3000),
    ("ollama_capability_probe", "ollama_canary", 11434),
    ("vllm_capability_probe", "vllm_canary", 8000),
])
def test_each_ai_tool_dispatches_with_correct_op_and_port(
    db_session, ai_asset, tool_name, op, port,
):
    """Each probe tool must call the relay with the matching op + default
    port. Parametrized for compactness."""
    import agents.tools.exposed_ai_service_tools as mod

    tool_fn = getattr(mod, f"{tool_name}_tool")
    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"_ok": True})

    with patch(
        "agents.tools.exposed_ai_service_tools.get_relay_broker",
        return_value=fake_broker,
    ):
        tool_fn(db_session, {
            "asset_id": ai_asset.id,
            "_relay_agent_id": "relay-x",
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "ai_service_probe"
    assert call.kwargs["params"]["op"] == op
    assert call.kwargs["config"]["port"] == port


def test_mcp_enumerate_tools_uses_supplied_port(db_session, ai_asset):
    """MCP has no canonical port — the agent must be able to supply one,
    and that port reaches the relay verbatim."""
    from agents.tools.exposed_ai_service_tools import mcp_enumerate_tools_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"reachable": True, "tools": []})

    with patch(
        "agents.tools.exposed_ai_service_tools.get_relay_broker",
        return_value=fake_broker,
    ):
        mcp_enumerate_tools_tool(db_session, {
            "asset_id": ai_asset.id,
            "_relay_agent_id": "relay-x",
            "port": 3010,
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["params"]["op"] == "mcp"
    assert call.kwargs["config"]["port"] == 3010


def test_ai_service_probe_raises_when_no_relay_supplied(db_session, ai_asset):
    """Run context missing ``_relay_agent_id`` surfaces ValueError."""
    from agents.tools.exposed_ai_service_tools import jupyter_check_auth_tool

    with pytest.raises(ValueError, match="relay_agent_id"):
        jupyter_check_auth_tool(db_session, {"asset_id": ai_asset.id})


def test_ai_service_probe_raises_when_relay_disconnected(db_session, ai_asset):
    """Disconnected relay surfaces ConnectionError."""
    from agents.tools.exposed_ai_service_tools import jupyter_check_auth_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = False

    with patch(
        "agents.tools.exposed_ai_service_tools.get_relay_broker",
        return_value=fake_broker,
    ):
        with pytest.raises(ConnectionError, match="not connected"):
            jupyter_check_auth_tool(db_session, {
                "asset_id": ai_asset.id,
                "_relay_agent_id": "relay-x",
            })


# ── Auto-trigger ──────────────────────────────────────────────────────


def test_auto_trigger_rule_for_ai_family_registered():
    """Phase 3 AutoTriggerRule must be in the registry with the gap-fill
    port set, the per-family ``auto_audit_ai`` switch, and a predicate."""
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES

    rule = next(
        (r for r in AUTO_TRIGGER_RULES if r.protocol == "exposed_ai_service"), None,
    )
    assert rule is not None, "exposed_ai_service rule missing from AUTO_TRIGGER_RULES"
    assert rule.mission == "triage"
    # Gap-fill ports only — 11434 (Ollama) and 8000 (vLLM) live with the
    # scanner's ai_exposure stage and must NOT auto-fire this audit.
    assert set(rule.ports) == {8888, 8265, 5000, 6006, 8080, 1234, 3000}
    assert 11434 not in rule.ports
    assert 8000 not in rule.ports
    assert rule.enabled_setting_key == "auto_audit_ai"
    assert rule.requires_per_asset_consent is False
    assert rule.predicate is not None, "predicate required for port-collision gating"


def test_auto_trigger_predicate_fires_on_unambiguous_ai_port():
    """An asset with port 8888 (Jupyter) open should fire even with no
    asset_type set — that port has no realistic non-AI collision."""
    from services.audit_auto_trigger import _ai_service_predicate

    asset = MagicMock(spec=Asset)
    asset.asset_type = None
    asset.easm_data = {"open_ports": [8888]}
    assert _ai_service_predicate(asset) is True


def test_auto_trigger_predicate_blocks_ambiguous_port_without_ai_type():
    """Port 3000 alone with no AI-typed classification = generic web app.
    The predicate must NOT fire — that's the whole point of the gate."""
    from services.audit_auto_trigger import _ai_service_predicate

    asset = MagicMock(spec=Asset)
    asset.asset_type = "web_app"
    asset.easm_data = {"open_ports": [3000]}
    assert _ai_service_predicate(asset) is False


def test_auto_trigger_predicate_fires_on_ai_typed_asset():
    """Port 3000 + asset_type=ai_inference = OpenWebUI / Langfuse → fire."""
    from services.audit_auto_trigger import _ai_service_predicate

    asset = MagicMock(spec=Asset)
    asset.asset_type = "ai_inference"
    asset.easm_data = {"open_ports": [3000]}
    assert _ai_service_predicate(asset) is True


def test_auto_trigger_predicate_reads_asset_type_from_easm_data_fallback():
    """If asset_type column is empty but easm_data carries it, still fire."""
    from services.audit_auto_trigger import _ai_service_predicate

    asset = MagicMock(spec=Asset)
    asset.asset_type = None
    asset.easm_data = {"open_ports": [3000], "asset_type": "vector_db"}
    assert _ai_service_predicate(asset) is True


@pytest.fixture
def linked_ai_asset(db_session, test_org):
    """Asset stamped with the scanner-side UUID + AI classification so the
    auto-trigger bridge can map a port_change event back to it and the
    predicate accepts it."""
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="ml-host-1", ip="10.0.0.51",
        asset_type="ai_inference",
        easm_data={"easm_asset_id": "scanner-uuid-ai-1", "open_ports": [8888]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


@pytest.fixture
def connected_relay_for_ai_org(db_session, test_org):
    relay = RelayAgent(
        org_id=test_org.id,
        name="ai-relay",
        token_hash="x",
        status="connected",
        last_seen_at=datetime.utcnow(),
    )
    db_session.add(relay)
    db_session.flush()
    return relay


def _port_change_event(scanner_asset_id: str, new_ports: list[int], hostname: str):
    return {
        "id": "evt-ai-1",
        "asset_id": scanner_asset_id,
        "event_type": "port_change",
        "created_at": "2026-04-27T00:00:00+00:00",
        "payload": {
            "hostname": hostname,
            "new_ports": new_ports,
            "removed_ports": [],
        },
    }


def test_auto_trigger_does_nothing_without_ai_family_switch(
    db_session, test_org, linked_ai_asset, connected_relay_for_ai_org,
):
    """Other family switches must not bleed in — the AI rule is gated solely
    by ``auto_audit_ai``."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True, "auto_audit_datastore": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-ai-1", [8888], "ml-host-1"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_auto_trigger_dispatches_when_ai_switch_on_and_unambiguous_port(
    db_session, test_org, linked_ai_asset, connected_relay_for_ai_org,
):
    """``auto_audit_ai=True`` + a freshly-opened Jupyter port must trigger
    the exposed_ai_service triage audit. Jupyter is unambiguous so the
    predicate accepts it without needing an AI-typed asset_type."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_ai": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-ai-1", [8888], "ml-host-1"),
        )

    assert n == 1
    scan = db_session.query(Scan).filter_by(scan_type="exposed_ai_service_audit").first()
    assert scan is not None
    md = scan.raw_metadata or {}
    assert md["protocol"] == "exposed_ai_service"
    assert md["mission"] == "triage"
    assert md["credential_id"] is None
    assert md["asset_ids"] == [linked_ai_asset.id]


def test_auto_trigger_skips_ambiguous_port_when_asset_not_ai_typed(
    db_session, test_org, connected_relay_for_ai_org,
):
    """Port 3000 + asset_type=web_app → predicate blocks → no run."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    web_asset = Asset(
        scan_id=scan.id, hostname="web-host-1", ip="10.0.0.52",
        asset_type="web_app",
        easm_data={"easm_asset_id": "scanner-uuid-web-1", "open_ports": [3000]},
    )
    db_session.add(web_asset)
    test_org.settings = {"auto_audit_ai": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-web-1", [3000], "web-host-1"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_auto_trigger_excludes_scanner_covered_ports(
    db_session, test_org, connected_relay_for_ai_org,
):
    """Ports 11434 (Ollama) and 8000 (vLLM) belong to the scanner's
    ai_exposure stage. A port_change event introducing only those ports
    must NOT auto-fire the audit (would just double-emit)."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    ollama_asset = Asset(
        scan_id=scan.id, hostname="ollama-1", ip="10.0.0.53",
        asset_type="ai_inference",
        easm_data={"easm_asset_id": "scanner-uuid-oll-1", "open_ports": [11434, 8000]},
    )
    db_session.add(ollama_asset)
    test_org.settings = {"auto_audit_ai": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-oll-1", [11434, 8000], "ollama-1"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()
