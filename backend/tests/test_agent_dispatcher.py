"""Tests for ``services.agent_dispatcher``.

The job-queue side-effect is mocked — we assert the dispatcher's
control-flow decisions (lookup, debounce, rate limit) without spinning
up a real background thread.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from models.models import Agent, AgentRun
from services import agent_dispatcher


@pytest.fixture
def triage_agent(db_session, test_org):
    a = Agent(
        org_id=test_org.id,
        name="triage_scan_results",
        system_prompt="test",
        tools=["post_feed_entry"],
    )
    db_session.add(a)
    db_session.flush()
    return a


@pytest.fixture
def stub_queue():
    """Replace _queue_run with a stub so no background thread spawns."""
    with patch.object(agent_dispatcher, "_queue_run", return_value="job-stub") as m:
        yield m


def test_dispatch_no_event_type(db_session, test_org, stub_queue):
    out = agent_dispatcher.dispatch(db_session, event_type="", org_id=test_org.id, payload={})
    assert out["dispatched"] is False
    assert out["reason"] == "missing_context"
    stub_queue.assert_not_called()


def test_dispatch_unknown_event_type(db_session, test_org, stub_queue):
    out = agent_dispatcher.dispatch(
        db_session, event_type="never_heard_of_this", org_id=test_org.id, payload={},
    )
    assert out["dispatched"] is False
    assert out["reason"] == "no_mapping"


def test_dispatch_lazy_creates_agent_from_template(db_session, test_org, stub_queue):
    """When no agent exists for the org+event, the dispatcher silently
    creates one from feed_agent_templates.json and dispatches as usual.
    Removes the operator-visible 'configure an agent' friction.
    """
    out = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id, payload={"scan_id": 1},
    )
    assert out["dispatched"] is True
    assert out["agent_name"] == "triage_scan_results"
    stub_queue.assert_called_once()

    created = (
        db_session.query(Agent)
        .filter(Agent.org_id == test_org.id, Agent.name == "triage_scan_results")
        .first()
    )
    assert created is not None
    assert "post_feed_entry" in (created.tools or [])
    assert created.system_prompt   # template content was applied


def test_dispatch_no_template_returns_no_template_reason(db_session, test_org, stub_queue, monkeypatch):
    """A mapping for the event but no matching template → caller gets a
    distinct reason so it can log without confusing the no-agent path."""
    monkeypatch.setattr(agent_dispatcher, "load_templates_by_name", lambda: {})
    out = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id, payload={"scan_id": 1},
    )
    assert out["dispatched"] is False
    assert out["reason"] == "no_template"
    stub_queue.assert_not_called()


def test_dispatch_happy_path(db_session, test_org, triage_agent, stub_queue):
    out = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id, payload={"scan_id": 7},
    )
    assert out["dispatched"] is True
    assert out["agent_id"] == triage_agent.id
    assert out["agent_name"] == "triage_scan_results"
    assert out["job_id"] == "job-stub"
    stub_queue.assert_called_once()
    # The user_input passed to the queue carries the [event:NAME] tag and
    # the payload — the dispatcher promises this for downstream debounce.
    args, kwargs = stub_queue.call_args
    assert args[0] == triage_agent.id
    user_input = args[1]
    assert user_input.startswith("[event:scan_complete]")
    assert "scan_id" in user_input
    assert args[2] == "scan_complete"


def test_dispatch_debounces_recent_run(db_session, test_org, triage_agent, stub_queue):
    """A run created within the debounce window blocks a second dispatch."""
    recent = AgentRun(
        agent_id=triage_agent.id,
        input="[event:scan_complete] previous run",
        status="done",
    )
    db_session.add(recent)
    db_session.flush()

    out = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id, payload={"scan_id": 7},
    )
    assert out["dispatched"] is False
    assert out["reason"] == "debounced"
    stub_queue.assert_not_called()


def test_dispatch_rate_limited(db_session, test_org, triage_agent, stub_queue):
    """Past the per-hour cap, dispatch refuses even if outside debounce."""
    # Backdate runs so debounce doesn't trip first.
    base = datetime.utcnow() - timedelta(minutes=10)
    for i in range(agent_dispatcher._MAX_RUNS_PER_HOUR):
        r = AgentRun(
            agent_id=triage_agent.id,
            input=f"[event:scan_complete] historical {i}",
            status="done",
        )
        db_session.add(r)
        db_session.flush()
        r.created_at = base
        db_session.flush()

    out = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id, payload={},
    )
    assert out["dispatched"] is False
    assert out["reason"] == "rate_limited"


def test_dispatch_other_org_creates_its_own_agent(db_session, test_org, triage_agent, stub_queue):
    """An agent with the right name but wrong org_id isn't picked — the
    dispatcher lazy-creates a separate one for the new org. Org isolation
    is preserved (each org gets its own row)."""
    from models.models import Organization
    other = Organization(name="Other", slug="other-disp")
    db_session.add(other)
    db_session.flush()
    out = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=other.id, payload={"scan_id": 1},
    )
    assert out["dispatched"] is True
    # The agent in test_org is unchanged; a separate one was created in `other`.
    assert out["agent_id"] != triage_agent.id
    new_agent = (
        db_session.query(Agent)
        .filter(Agent.org_id == other.id, Agent.name == "triage_scan_results")
        .first()
    )
    assert new_agent is not None


# ── Per-key debounce ──────────────────────────────────────────────


def test_per_key_debounce_keeps_distinct_keys_independent(db_session, test_org, triage_agent, stub_queue):
    """Two different scan_ids in the same window should each fire — the
    per-(agent, event_type) debounce alone would collapse them, but the
    dedup_key promotes per-(agent, event_type, key) granularity."""
    out1 = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id,
        payload={"scan_id": 1}, dedup_key=1,
    )
    # Fake a recent run for scan_id=1 the way run_agent would record it.
    AgentRun.__table__  # touch to ensure mapper loaded
    db_session.add(AgentRun(
        agent_id=triage_agent.id,
        input="[event:scan_complete][key:1] previous run",
        status="done",
    ))
    db_session.flush()

    # Same scan_id again → debounced.
    out_same = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id,
        payload={"scan_id": 1}, dedup_key=1,
    )
    assert out_same["dispatched"] is False
    assert out_same["reason"] == "debounced"

    # Different scan_id → should dispatch.
    out_other = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id,
        payload={"scan_id": 2}, dedup_key=2,
    )
    assert out_other["dispatched"] is True


def test_per_key_debounce_user_input_carries_key_tag(db_session, test_org, triage_agent, stub_queue):
    """The user_input handed to run_agent must carry [key:V] so future
    debounce queries can find it. Without this tag, _is_debounced won't
    match on subsequent ticks."""
    agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id,
        payload={"scan_id": 42}, dedup_key=42,
    )
    args, _ = stub_queue.call_args
    user_input = args[1]
    assert user_input.startswith("[event:scan_complete][key:42]")


def test_dispatch_without_dedup_key_uses_legacy_per_event_debounce(db_session, test_org, triage_agent, stub_queue):
    """Backwards compat: emit sites that don't pass a dedup_key still
    get per-event-type debounce (the original behavior)."""
    db_session.add(AgentRun(
        agent_id=triage_agent.id,
        input="[event:scan_complete] previous run (no key)",
        status="done",
    ))
    db_session.flush()
    out = agent_dispatcher.dispatch(
        db_session, event_type="scan_complete", org_id=test_org.id,
        payload={"scan_id": 99},
        # no dedup_key
    )
    assert out["dispatched"] is False
    assert out["reason"] == "debounced"


