"""Tests for the org feed routes — list, unread count, mark read, decision.

Org isolation is the load-bearing assertion: a user in org A must not see
entries written into org B by an MSP sibling.
"""
from __future__ import annotations

import pytest

from models.models import Agent, Organization, OrgFeedEntry, User


@pytest.fixture
def feed_agent(db_session, test_org):
    a = Agent(
        org_id=test_org.id,
        name="triage_scan_results",
        system_prompt="test",
        tools=["post_feed_entry"],
    )
    db_session.add(a)
    db_session.flush()
    return a


def _mk_entry(db_session, *, org_id, agent_id=None, headline="Test entry", **kw):
    e = OrgFeedEntry(
        org_id=org_id,
        agent_id=agent_id,
        kind=kw.pop("kind", "observation"),
        headline=headline,
        body_md=kw.pop("body_md", "details"),
        severity=kw.pop("severity", "info"),
        status=kw.pop("status", "open"),
        proposed_actions=kw.pop("proposed_actions", []),
        event_type=kw.pop("event_type", None),
        event_ref=kw.pop("event_ref", {}),
        read_by=kw.pop("read_by", []),
    )
    db_session.add(e)
    db_session.flush()
    return e


def test_list_feed_returns_org_entries_newest_first(
    db_session, authed_client, test_org, feed_agent,
):
    older = _mk_entry(db_session, org_id=test_org.id, agent_id=feed_agent.id, headline="older")
    newer = _mk_entry(db_session, org_id=test_org.id, agent_id=feed_agent.id, headline="newer")
    # Force a deterministic order (created_at default to now() — bump newer's pk
    # tiebreak via flush order; SQLite created_at granularity is seconds).
    from datetime import datetime, timedelta
    older.created_at = datetime.utcnow() - timedelta(minutes=5)
    newer.created_at = datetime.utcnow()
    db_session.flush()

    resp = authed_client.get("/api/feed")
    assert resp.status_code == 200
    headlines = [e["headline"] for e in resp.json()]
    assert headlines == ["newer", "older"]
    assert resp.json()[0]["agent_name"] == "triage_scan_results"


def test_list_feed_isolates_other_orgs(db_session, authed_client, test_org):
    other = Organization(name="Other", slug="other")
    db_session.add(other)
    db_session.flush()
    _mk_entry(db_session, org_id=other.id, headline="other org leak test")
    _mk_entry(db_session, org_id=test_org.id, headline="my org entry")

    resp = authed_client.get("/api/feed")
    assert resp.status_code == 200
    headlines = [e["headline"] for e in resp.json()]
    assert "my org entry" in headlines
    assert "other org leak test" not in headlines


def test_filter_by_status_and_severity(db_session, authed_client, test_org):
    _mk_entry(db_session, org_id=test_org.id, headline="open-info", status="open", severity="info")
    _mk_entry(db_session, org_id=test_org.id, headline="acted-info", status="acted", severity="info")
    _mk_entry(db_session, org_id=test_org.id, headline="open-crit", status="open", severity="critical")

    open_only = authed_client.get("/api/feed?status=open").json()
    assert {e["headline"] for e in open_only} == {"open-info", "open-crit"}

    crit_only = authed_client.get("/api/feed?severity=critical").json()
    assert {e["headline"] for e in crit_only} == {"open-crit"}


def test_unread_count_excludes_already_read(db_session, authed_client, test_org, test_user):
    _mk_entry(db_session, org_id=test_org.id, headline="unread")
    _mk_entry(db_session, org_id=test_org.id, headline="read", read_by=[test_user.id])

    resp = authed_client.get("/api/feed/unread-count")
    assert resp.status_code == 200
    assert resp.json() == {"count": 1}


def test_unread_count_only_counts_open_status(db_session, authed_client, test_org):
    _mk_entry(db_session, org_id=test_org.id, headline="open", status="open")
    _mk_entry(db_session, org_id=test_org.id, headline="dismissed", status="dismissed")

    resp = authed_client.get("/api/feed/unread-count")
    assert resp.json() == {"count": 1}


def test_mark_read_idempotent(db_session, authed_client, test_org, test_user):
    e = _mk_entry(db_session, org_id=test_org.id, headline="x")

    r1 = authed_client.post(f"/api/feed/{e.id}/read")
    r2 = authed_client.post(f"/api/feed/{e.id}/read")
    assert r1.status_code == 200
    assert r2.status_code == 200
    db_session.refresh(e)
    assert e.read_by == [test_user.id]   # not duplicated


def test_mark_read_404_for_other_org_entry(db_session, authed_client):
    other = Organization(name="Other2", slug="other2")
    db_session.add(other)
    db_session.flush()
    e = _mk_entry(db_session, org_id=other.id, headline="not yours")
    resp = authed_client.post(f"/api/feed/{e.id}/read")
    assert resp.status_code == 404


def test_decision_status_updates_and_marks_read(db_session, authed_client, test_org, test_user):
    e = _mk_entry(db_session, org_id=test_org.id, headline="needs-decision")
    resp = authed_client.post(f"/api/feed/{e.id}/decision", json={"status": "acted"})
    assert resp.status_code == 200
    db_session.refresh(e)
    assert e.status == "acted"
    assert test_user.id in e.read_by


def test_decision_rejects_invalid_status(db_session, authed_client, test_org):
    e = _mk_entry(db_session, org_id=test_org.id, headline="x")
    resp = authed_client.post(f"/api/feed/{e.id}/decision", json={"status": "garbage"})
    assert resp.status_code == 400
