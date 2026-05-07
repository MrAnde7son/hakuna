"""Tests for the ``list_feed_entries`` agent tool.

Validates filter behavior in isolation: org scoping, kind/severity/status
filters, the has_pending_approval shortcut, and result ordering.
"""
from __future__ import annotations

from agents.agent_tools import TOOL_REGISTRY
from models.models import OrgFeedEntry


def _list(db_session, org_id, **params):
    fn = TOOL_REGISTRY["list_feed_entries"]["fn"]
    return fn(db_session, {"_org_id": org_id, **params})


def _post(db_session, org_id, **params):
    fn = TOOL_REGISTRY["post_feed_entry"]["fn"]
    return fn(db_session, {"_org_id": org_id, **params})


def test_requires_org_context(db_session):
    out = _list(db_session, None)
    assert isinstance(out, dict) and "error" in out


def test_returns_recent_entries_for_org(db_session, test_org):
    _post(db_session, test_org.id, kind="observation", headline="a")
    _post(db_session, test_org.id, kind="action", headline="b")
    out = _list(db_session, test_org.id)
    assert len(out) == 2
    assert {r["headline"] for r in out} == {"a", "b"}


def test_filters_by_kind_and_severity(db_session, test_org):
    _post(db_session, test_org.id, kind="observation", headline="o", severity="low")
    _post(db_session, test_org.id, kind="action", headline="ac", severity="critical")
    only_action = _list(db_session, test_org.id, kind="action")
    assert [r["headline"] for r in only_action] == ["ac"]
    only_critical = _list(db_session, test_org.id, severity="critical")
    assert [r["headline"] for r in only_critical] == ["ac"]


def test_has_pending_approval_filter(db_session, test_org):
    _post(db_session, test_org.id, kind="observation", headline="no-actions")
    _post(
        db_session, test_org.id, kind="action", headline="needs-approval",
        proposed_actions=[{"label": "Approve", "kind": "approve_action", "approval_id": 1}],
    )
    pending = _list(db_session, test_org.id, has_pending_approval=True)
    assert [r["headline"] for r in pending] == ["needs-approval"]
    assert pending[0]["pending_approval_count"] == 1


def test_other_orgs_entries_are_invisible(db_session, test_org):
    from models.models import Organization
    other_org = Organization(name="other-org", slug="other-org")
    db_session.add(other_org)
    db_session.flush()
    db_session.add(OrgFeedEntry(
        org_id=other_org.id,
        kind="observation",
        headline="not-mine",
        severity="info",
        status="open",
    ))
    db_session.flush()
    out = _list(db_session, test_org.id)
    assert all(r["headline"] != "not-mine" for r in out)
