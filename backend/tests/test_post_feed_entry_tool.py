"""Tests for the ``post_feed_entry`` agent tool.

Validates the tool body in isolation (not through the agent engine):
input shape, idempotency window, severity normalization, org-context
requirement.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from agents.agent_tools import TOOL_REGISTRY
from models.models import OrgFeedEntry


def _post(db_session, org_id, agent_id=None, agent_run_id=None, **params):
    fn = TOOL_REGISTRY["post_feed_entry"]["fn"]
    return fn(db_session, {
        "_org_id": org_id,
        "_agent_id": agent_id,
        "_agent_run_id": agent_run_id,
        **params,
    })


def test_post_feed_entry_persists_agent_run_id_when_provided(db_session, test_org):
    """The engine injects ``_agent_run_id`` from the AgentRun into every
    tool call. post_feed_entry must persist it on OrgFeedEntry so the
    feed UI can deep-link to the agent's reasoning trace."""
    from models.models import Agent, AgentRun
    a = Agent(org_id=test_org.id, name="t", system_prompt="x")
    db_session.add(a)
    db_session.flush()
    r = AgentRun(agent_id=a.id, input="[event:scan_complete] x", status="done")
    db_session.add(r)
    db_session.flush()

    out = _post(
        db_session, test_org.id, agent_id=a.id, agent_run_id=r.id,
        kind="observation", headline="With run id",
    )
    row = db_session.query(OrgFeedEntry).filter(OrgFeedEntry.id == out["id"]).first()
    assert row.agent_run_id == r.id


def test_post_feed_entry_handles_missing_agent_run_id(db_session, test_org):
    """Backwards-compat: legacy callers (or tests) that don't pass
    ``_agent_run_id`` get an entry with ``agent_run_id=NULL``. The feed
    UI gracefully omits the trace link when this happens."""
    out = _post(
        db_session, test_org.id, agent_id=None, agent_run_id=None,
        kind="observation", headline="No run id",
    )
    row = db_session.query(OrgFeedEntry).filter(OrgFeedEntry.id == out["id"]).first()
    assert row.agent_run_id is None


def test_creates_entry_with_minimal_input(db_session, test_org):
    out = _post(db_session, test_org.id, kind="observation", headline="Hello")
    assert out["status"] == "open"
    assert out["kind"] == "observation"
    row = db_session.query(OrgFeedEntry).filter(OrgFeedEntry.id == out["id"]).first()
    assert row is not None
    assert row.org_id == test_org.id
    assert row.severity == "info"


def test_requires_org_context(db_session):
    out = _post(db_session, None, kind="observation", headline="x")
    assert "error" in out


def test_requires_headline(db_session, test_org):
    out = _post(db_session, test_org.id, kind="observation", headline="   ")
    assert "error" in out


def test_truncates_long_headline(db_session, test_org):
    long_headline = "x" * 400
    out = _post(db_session, test_org.id, kind="observation", headline=long_headline)
    row = db_session.query(OrgFeedEntry).filter(OrgFeedEntry.id == out["id"]).first()
    assert len(row.headline) <= 280
    assert row.headline.endswith("…")


def test_normalizes_unknown_kind_via_error(db_session, test_org):
    out = _post(db_session, test_org.id, kind="garbage", headline="x")
    assert "error" in out


def test_normalizes_unknown_severity_to_info(db_session, test_org):
    out = _post(db_session, test_org.id, kind="observation", headline="x", severity="ULTRA")
    row = db_session.query(OrgFeedEntry).filter(OrgFeedEntry.id == out["id"]).first()
    assert row.severity == "info"


def test_caps_proposed_actions_to_ten(db_session, test_org):
    actions = [{"label": f"a{i}", "kind": "navigate", "href": "/x"} for i in range(20)]
    out = _post(
        db_session, test_org.id,
        kind="action", headline="many actions", proposed_actions=actions,
    )
    row = db_session.query(OrgFeedEntry).filter(OrgFeedEntry.id == out["id"]).first()
    assert len(row.proposed_actions) == 10


def test_idempotency_window_collapses_duplicate(db_session, test_org):
    """Same agent + same headline within 5min returns the existing row."""
    from models.models import Agent
    a = Agent(org_id=test_org.id, name="t", system_prompt="x")
    db_session.add(a)
    db_session.flush()

    first = _post(db_session, test_org.id, agent_id=a.id, kind="observation", headline="dup")
    second = _post(db_session, test_org.id, agent_id=a.id, kind="observation", headline="dup")

    assert first["id"] == second["id"]
    assert second.get("duplicate") is True
    assert db_session.query(OrgFeedEntry).filter(
        OrgFeedEntry.org_id == test_org.id,
        OrgFeedEntry.headline == "dup",
    ).count() == 1


def test_idempotency_window_respects_age(db_session, test_org):
    """Older identical entry doesn't block a new one."""
    from models.models import Agent
    a = Agent(org_id=test_org.id, name="t", system_prompt="x")
    db_session.add(a)
    db_session.flush()

    first = _post(db_session, test_org.id, agent_id=a.id, kind="observation", headline="aged")
    row = db_session.query(OrgFeedEntry).filter(OrgFeedEntry.id == first["id"]).first()
    row.created_at = datetime.utcnow() - timedelta(minutes=10)
    db_session.flush()

    second = _post(db_session, test_org.id, agent_id=a.id, kind="observation", headline="aged")
    assert second["id"] != first["id"]
    assert second.get("duplicate") is not True
