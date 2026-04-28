"""SNMP tool tests — verifying the cred fallback flow.

When no `credential_id` is bound to the audit run, `snmp_probe_default_communities`
should stash any accepted community into `agent.memory["_run_ctx"]["_snmp_community"]`,
and subsequent SNMP tools should read from that fallback instead of erroring with
"credential_id missing from audit context".
"""

from __future__ import annotations

from unittest.mock import patch

# Side-effect import populates TOOL_REGISTRY + AUDITS.
import agents.agent_tools  # noqa: F401

from models.models import Agent, Asset, Scan


def _make_asset(db, org_id):
    scan = Scan(filename="ph", scan_type="manual", source_type="manual", org_id=org_id)
    db.add(scan)
    db.flush()
    asset = Asset(scan_id=scan.id, ip="10.0.0.5", hostname="switch-01", os="ios")
    db.add(asset)
    db.flush()
    return asset


def _make_agent(db, org_id, asset_id, *, credential_id=None, community=None):
    run_ctx = {
        "_relay_agent_id": "relay-1",
        "_credential_id": credential_id,
        "_asset_id": asset_id,
        "_protocol": "snmp",
        "_mission": "device_posture",
    }
    if community is not None:
        run_ctx["_snmp_community"] = community
    agent = Agent(
        org_id=org_id,
        name="snmp scratch",
        system_prompt="x",
        tools=["snmp_probe_default_communities", "snmp_get", "snmp_walk"],
        guardrails={"max_steps": 5, "scratch": True},
        memory={"_run_ctx": run_ctx},
        model="claude-sonnet-4-6",
    )
    db.add(agent)
    db.flush()
    return agent


def _make_relay_broker(send_result):
    class _StubBroker:
        def is_connected(self, _agent_id):
            return True

        async def send_task(self, **_kwargs):
            return send_result

    return _StubBroker()


def test_probe_stashes_accepted_community_into_run_ctx(db_session, test_org):
    from agents.agent_tools import TOOL_REGISTRY

    asset = _make_asset(db_session, test_org.id)
    agent = _make_agent(db_session, test_org.id, asset.id, credential_id=None)

    probe_result = {
        "accepted_communities": ["public"],
        "tried": ["public", "private"],
        "_errors": {},
    }
    with patch(
        "agents.tools.snmp_tools.get_relay_broker",
        return_value=_make_relay_broker(probe_result),
    ):
        params = {
            "asset_id": asset.id,
            "_relay_agent_id": "relay-1",
            "_credential_id": None,
            "_org_id": test_org.id,
            "_agent_id": agent.id,
        }
        out = TOOL_REGISTRY["snmp_probe_default_communities"]["fn"](db_session, params)

    assert out["accepted_communities"] == ["public"]

    db_session.refresh(agent)
    assert agent.memory["_run_ctx"]["_snmp_community"] == "public"


def test_snmp_get_uses_fallback_community_when_no_cred(db_session, test_org):
    from agents.agent_tools import TOOL_REGISTRY

    asset = _make_asset(db_session, test_org.id)
    _make_agent(db_session, test_org.id, asset.id, credential_id=None, community="public")

    captured = {}

    class _StubBroker:
        def is_connected(self, _agent_id):
            return True

        async def send_task(self, **kwargs):
            captured.update(kwargs)
            return {"oid": "1.3.6.1.2.1.1.1.0", "value": "Cisco IOS Software"}

    with patch(
        "agents.tools.snmp_tools.get_relay_broker",
        return_value=_StubBroker(),
    ):
        params = {
            "asset_id": asset.id,
            "_relay_agent_id": "relay-1",
            "_credential_id": None,
            "_snmp_community": "public",
            "_org_id": test_org.id,
            "oid": "1.3.6.1.2.1.1.1.0",
        }
        out = TOOL_REGISTRY["snmp_get"]["fn"](db_session, params)

    assert out["value"] == "Cisco IOS Software"
    assert captured["credentials"]["community"] == "public"
    assert captured["credentials"]["version"] == "v2c"


def test_snmp_get_errors_clearly_with_no_cred_and_no_community(db_session, test_org):
    from agents.agent_tools import TOOL_REGISTRY

    asset = _make_asset(db_session, test_org.id)
    _make_agent(db_session, test_org.id, asset.id, credential_id=None)

    with patch(
        "agents.tools.snmp_tools.get_relay_broker",
        return_value=_make_relay_broker({}),
    ):
        params = {
            "asset_id": asset.id,
            "_relay_agent_id": "relay-1",
            "_credential_id": None,
            "_org_id": test_org.id,
            "oid": "1.3.6.1.2.1.1.1.0",
        }
        try:
            TOOL_REGISTRY["snmp_get"]["fn"](db_session, params)
        except ValueError as e:
            assert "snmp_probe_default_communities" in str(e)
        else:
            raise AssertionError("expected ValueError when no cred and no community")
