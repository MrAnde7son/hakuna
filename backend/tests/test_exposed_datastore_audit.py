"""Tests for the Exposed-Datastore Audit registration, tool palette,
mission prompt, and auto-trigger wiring (Phase 1a).

Relay broker is mocked at the dispatch boundary — we don't attempt any
real network connections to a Redis/Mongo/etc. The backend tools are
tested for correct dispatch shape (method name, port, op, params), not
for what the relay does internally."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.models import Asset, RelayAgent, Scan

# Side-effect import — populates AUDITS + TOOL_REGISTRY.
import agents.agent_tools  # noqa: F401


# ── Audit registration ───────────────────────────────────────────────


def test_exposed_datastore_audit_registered():
    """The Phase 1a registration must surface in the audit registry with
    the right safety class, anonymous capability, and mission set so the
    audit_runner accepts dispatch without a credential."""
    from agents.audit_registry import get_audit, list_audits

    assert "exposed_datastore" in list_audits()
    audit = get_audit("exposed_datastore")
    assert audit.label == "Exposed Datastore Audit"
    assert audit.safety_class == "anon_datastore"
    assert audit.is_anonymous_capable() is True
    assert audit.requires_per_asset_consent() is False
    assert audit.relay_method == "datastore_probe"
    assert audit.auto_trigger_policy == "auto_org_opt_in"
    assert "anonymous" in audit.auth_modes
    assert audit.credential_connector_ids == []
    # Required ports cover all Phase 1a + 1b datastores so preflight matches
    assert set(audit.required_ports) == {
        # Phase 1a
        6379, 27017, 9200, 2375, 6443, 2379,
        # Phase 1b
        11211, 5601, 10250, 5984,
    }
    assert {m.key for m in audit.missions} == {"triage"}
    assert "cis_benchmarks" in audit.compliance_tags


def test_exposed_datastore_tool_palette_registered():
    """Every probe tool plus the shared finding/scratchpad tools must be in
    TOOL_REGISTRY so the agent engine can resolve them at run time."""
    from agents.agent_tools import TOOL_REGISTRY

    expected = {
        # Phase 1a
        "redis_probe", "mongo_probe", "elastic_probe",
        "docker_api_probe", "k8s_api_probe", "etcd_probe",
        # Phase 1b
        "memcached_probe", "kibana_probe", "kubelet_probe", "couchdb_probe",
    }
    missing = expected - set(TOOL_REGISTRY.keys())
    assert not missing, f"datastore probe tools missing from TOOL_REGISTRY: {missing}"


def test_exposed_datastore_mission_prompt_resolved():
    """The mission prompt must have its preamble substituted at import time
    — otherwise the agent receives a literal '{preamble}' marker."""
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("exposed_datastore_audit_triage")
    assert prompt, "exposed_datastore_audit_triage prompt missing"
    assert "{preamble}" not in prompt, "preamble not resolved in triage mission"
    assert "exposed-datastore auditor" in prompt, "preamble persona not present"
    assert 'protocol="exposed_datastore"' in prompt
    assert 'mission="triage"' in prompt


# ── Dispatch wiring ──────────────────────────────────────────────────


@pytest.fixture
def datastore_asset(db_session, test_org):
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="db-host-1", ip="10.20.30.40",
        easm_data={"open_ports": [6379, 27017, 9200]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_dispatch_audit_run_accepts_anonymous_for_exposed_datastore(
    db_session, test_org, datastore_asset,
):
    """The Phase 0 ``safety_class`` predicate must accept ``credential_id=None``
    for the new exposed_datastore audit. Confirms the registration is wired
    end-to-end through dispatch validation."""
    from services.audit_runner import dispatch_audit_run

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        result = dispatch_audit_run(
            db=db_session,
            org=test_org,
            protocol="exposed_datastore",
            mission="triage",
            asset_ids=[datastore_asset.id],
            relay_agent_id="relay-x",
            credential_id=None,
        )

    assert result["protocol"] == "exposed_datastore"
    assert result["mission"] == "triage"
    assert result["status"] == "running"

    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.scan_type == "exposed_datastore_audit"
    assert scan.raw_metadata["credential_id"] is None


def test_redis_probe_tool_dispatches_method_datastore_probe_op_redis(db_session, datastore_asset):
    """The backend Redis probe tool must dispatch ``method=datastore_probe``
    with ``op="redis"`` and the standard port — that's the contract the
    relay-side handler depends on."""
    from agents.tools.exposed_datastore_tools import redis_probe_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={
        "auth_required": False, "version": "7.2.4", "role": "master", "os": "Linux",
    })

    with patch("agents.tools.exposed_datastore_tools.get_relay_broker", return_value=fake_broker):
        result = redis_probe_tool(db_session, {
            "asset_id": datastore_asset.id,
            "_relay_agent_id": "relay-x",
            "_org_id": 1,
        })

    assert result["auth_required"] is False
    assert result["version"] == "7.2.4"
    fake_broker.send_task.assert_awaited_once()
    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "datastore_probe"
    assert call.kwargs["params"]["op"] == "redis"
    assert call.kwargs["config"]["target"] == "10.20.30.40"
    assert call.kwargs["config"]["port"] == 6379
    # Anonymous probe — credentials must be empty regardless of context
    assert call.kwargs["credentials"] == {}


@pytest.mark.parametrize("tool_name,op,port", [
    # Phase 1a
    ("mongo_probe", "mongo", 27017),
    ("elastic_probe", "elastic", 9200),
    ("docker_api_probe", "docker", 2375),
    ("k8s_api_probe", "k8s", 6443),
    ("etcd_probe", "etcd", 2379),
    # Phase 1b
    ("memcached_probe", "memcached", 11211),
    ("kibana_probe", "kibana", 5601),
    ("kubelet_probe", "kubelet", 10250),
    ("couchdb_probe", "couchdb", 5984),
])
def test_each_datastore_tool_dispatches_with_correct_op_and_port(
    db_session, datastore_asset, tool_name, op, port,
):
    """Each probe tool must call the relay with the matching op + default
    port. Parametrized to keep the test count down while covering the
    full palette."""
    import agents.tools.exposed_datastore_tools as mod

    tool_fn = getattr(mod, f"{tool_name}_tool")
    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = True
    fake_broker.send_task = AsyncMock(return_value={"_ok": True})

    with patch("agents.tools.exposed_datastore_tools.get_relay_broker", return_value=fake_broker):
        tool_fn(db_session, {
            "asset_id": datastore_asset.id,
            "_relay_agent_id": "relay-x",
        })

    call = fake_broker.send_task.await_args
    assert call.kwargs["method"] == "datastore_probe"
    assert call.kwargs["params"]["op"] == op
    assert call.kwargs["config"]["port"] == port


def test_redis_probe_raises_when_no_relay_supplied(db_session, datastore_asset):
    """A run context missing ``_relay_agent_id`` must surface a clean
    ValueError so the LLM gets a real error message rather than a
    cryptic broker exception."""
    from agents.tools.exposed_datastore_tools import redis_probe_tool

    with pytest.raises(ValueError, match="relay_agent_id"):
        redis_probe_tool(db_session, {"asset_id": datastore_asset.id})


def test_redis_probe_raises_when_relay_disconnected(db_session, datastore_asset):
    """Disconnected relay surfaces a ConnectionError — also actionable."""
    from agents.tools.exposed_datastore_tools import redis_probe_tool

    fake_broker = MagicMock()
    fake_broker.is_connected.return_value = False

    with patch("agents.tools.exposed_datastore_tools.get_relay_broker", return_value=fake_broker):
        with pytest.raises(ConnectionError, match="not connected"):
            redis_probe_tool(db_session, {
                "asset_id": datastore_asset.id,
                "_relay_agent_id": "relay-x",
            })


# ── Auto-trigger ──────────────────────────────────────────────────────


def test_auto_trigger_rule_for_datastore_family_registered():
    """The Phase 1a AutoTriggerRule must be in the registry with the right
    port set, mission, and the per-family ``auto_audit_datastore`` switch."""
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES

    rule = next(
        (r for r in AUTO_TRIGGER_RULES if r.protocol == "exposed_datastore"), None,
    )
    assert rule is not None, "exposed_datastore rule missing from AUTO_TRIGGER_RULES"
    assert rule.mission == "triage"
    assert set(rule.ports) == {
        # Phase 1a
        6379, 27017, 9200, 2375, 6443, 2379,
        # Phase 1b
        11211, 5601, 10250, 5984,
    }
    assert rule.enabled_setting_key == "auto_audit_datastore"
    assert rule.requires_per_asset_consent is False


@pytest.mark.parametrize("port", [11211, 5601, 10250, 5984])
def test_phase_1b_ports_trigger_exposed_datastore_audit(
    db_session, test_org, port,
):
    """Each Phase 1b port (Memcached/Kibana/kubelet/CouchDB) must auto-fire
    the exposed_datastore audit when its port newly opens — same single-rule
    collapse as Phase 1a ports."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    scan = Scan(filename="x", scan_type="manual", source_type="manual", org_id=test_org.id)
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname=f"host-{port}", ip="10.0.0.99",
        easm_data={"easm_asset_id": f"scanner-uuid-{port}", "open_ports": [port]},
    )
    relay = RelayAgent(
        org_id=test_org.id, name="r", token_hash="x", status="connected",
        last_seen_at=datetime.utcnow(),
    )
    db_session.add_all([asset, relay])
    test_org.settings = {"auto_audit_datastore": True}
    db_session.flush()

    event = {
        "id": f"evt-{port}",
        "asset_id": f"scanner-uuid-{port}",
        "event_type": "port_change",
        "payload": {"hostname": f"host-{port}", "new_ports": [port], "removed_ports": []},
    }
    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(db_session, test_org, event)

    assert n == 1
    scan = db_session.query(Scan).filter_by(scan_type="exposed_datastore_audit").first()
    assert scan is not None
    assert scan.raw_metadata["mission"] == "triage"


@pytest.fixture
def linked_datastore_asset(db_session, test_org):
    """Asset stamped with the scanner-side UUID so the bridge can map a
    port_change event back to it. Open ports list seeded so the dispatched
    audit's preflight passes."""
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="redis-prod-1", ip="10.0.0.50",
        easm_data={"easm_asset_id": "scanner-uuid-ds-1", "open_ports": [6379]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


@pytest.fixture
def connected_relay_for_org(db_session, test_org):
    relay = RelayAgent(
        org_id=test_org.id,
        name="datastore-relay",
        token_hash="x",
        status="connected",
        last_seen_at=datetime.utcnow(),
    )
    db_session.add(relay)
    db_session.flush()
    return relay


def _port_change_event(scanner_asset_id: str, new_ports: list[int], hostname: str):
    return {
        "id": "evt-ds-1",
        "asset_id": scanner_asset_id,
        "event_type": "port_change",
        "created_at": "2026-04-26T00:00:00+00:00",
        "payload": {
            "hostname": hostname,
            "new_ports": new_ports,
            "removed_ports": [],
        },
    }


def test_auto_trigger_skipped_when_datastore_family_explicitly_off(
    db_session, test_org, linked_datastore_asset, connected_relay_for_org,
):
    """``auto_audit_datastore=False`` opts out the family even when the
    legacy ``auto_audit_anon`` switch is on. Confirms the per-family switch
    overrides the family-level default."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True, "auto_audit_datastore": False}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-ds-1", [6379], "redis-prod-1"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_auto_trigger_dispatches_when_datastore_switch_on(
    db_session, test_org, linked_datastore_asset, connected_relay_for_org,
):
    """With ``auto_audit_datastore`` flipped on, a newly-opened Redis port
    must trigger the exposed_datastore triage audit."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_datastore": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-ds-1", [6379], "redis-prod-1"),
        )

    assert n == 1

    scan = db_session.query(Scan).filter_by(scan_type="exposed_datastore_audit").first()
    assert scan is not None
    md = scan.raw_metadata or {}
    assert md["protocol"] == "exposed_datastore"
    assert md["mission"] == "triage"
    assert md["credential_id"] is None
    assert md["asset_ids"] == [linked_datastore_asset.id]


def test_auto_trigger_collapses_multiple_datastore_ports_into_single_run(
    db_session, test_org, linked_datastore_asset, connected_relay_for_org,
):
    """A port_change event that adds Redis + MongoDB at once must produce
    exactly one ``exposed_datastore`` audit run — the single rule covers
    all family ports."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_datastore": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event(
                "scanner-uuid-ds-1", [6379, 27017, 9200], "redis-prod-1",
            ),
        )

    assert n == 1
    scan_count = db_session.query(Scan).filter_by(
        scan_type="exposed_datastore_audit"
    ).count()
    assert scan_count == 1


def test_auto_trigger_legacy_and_family_switches_are_independent(
    db_session, test_org, linked_datastore_asset, connected_relay_for_org,
):
    """An org with ``auto_audit_datastore`` on but ``auto_audit_anon``
    explicitly off must NOT auto-fire SMB/SNMP — and vice versa. Confirms
    the per-family isolation under default-ON semantics: each family's
    explicit ``False`` wins over the other family's ``True``."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_datastore": True, "auto_audit_anon": False}
    # Add 445 (SMB) alongside 6379 (Redis) — only the datastore should fire.
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-ds-1", [6379, 445], "redis-prod-1"),
        )

    # One run — the Redis one. SMB rule is gated by auto_audit_anon (False).
    assert n == 1
    types = {s.scan_type for s in db_session.query(Scan).all()}
    assert "exposed_datastore_audit" in types
    assert "smb_audit" not in types
