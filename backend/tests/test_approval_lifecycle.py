"""Tests for services/approval_lifecycle.py.

Covers the three lifecycle hooks:
  1. clear_approval_notification — drops the bell entry on decide/expire
  2. expire_stale_approvals     — auto-rejects pending approvals past TTL
  3. escalate_overdue_approvals — pushes overdue ones to Slack once
"""
from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from models.models import (
    Agent, AgentApproval, AgentRun, IntegrationConfig, Notification,
)
from services.approval_lifecycle import (
    clear_approval_notification,
    escalate_overdue_approvals,
    expire_stale_approvals,
)


def _mk_pending_approval(db, *, org_id, requested_at=None, tool="ldap_modify"):
    agent = Agent(
        org_id=org_id, name="scratch", system_prompt="x",
        tools=[tool], guardrails={}, model="claude-sonnet-4-6",
    )
    db.add(agent)
    db.flush()
    run = AgentRun(
        agent_id=agent.id, input="audit", status="awaiting_approval",
    )
    db.add(run)
    db.flush()
    approval = AgentApproval(
        org_id=org_id, agent_run_id=run.id, agent_id=agent.id,
        tool_name=tool, tool_input={"asset_id": 1, "_approval_reason": "writes registry"},
        provider="anthropic", model_name="claude-sonnet-4-6",
        current_step=1, tool_use_id="tu_1", status="pending",
        requested_at=requested_at or datetime.utcnow(),
    )
    db.add(approval)
    db.flush()
    notif = Notification(
        org_id=org_id, category="approval_required",
        title="action needs approval", body=tool,
        link=f"/agents?approvals=1&run={run.id}",
        entity_type="agent_approval", entity_id=approval.id,
    )
    db.add(notif)
    db.flush()
    return agent, run, approval, notif


# ── clear_approval_notification ───────────────────────────────────────

def test_clear_approval_notification_removes_only_matching(db_session, test_org):
    _, _, approval, notif = _mk_pending_approval(db_session, org_id=test_org.id)
    other = Notification(
        org_id=test_org.id, category="scan_complete",
        title="other", body="x",
    )
    db_session.add(other)
    db_session.flush()
    notif_id, other_id, approval_id = notif.id, other.id, approval.id

    removed = clear_approval_notification(db_session, approval_id)
    db_session.commit()
    db_session.expire_all()

    assert removed == 1
    assert db_session.query(Notification).filter_by(id=notif_id).first() is None
    # Unrelated notification untouched.
    assert db_session.query(Notification).filter_by(id=other_id).first() is not None


def test_clear_approval_notification_no_match_returns_zero(db_session):
    assert clear_approval_notification(db_session, approval_id=999_999) == 0


# ── expire_stale_approvals ────────────────────────────────────────────

def test_expire_stale_approvals_marks_old_pending_as_expired(db_session, test_org):
    fresh_at = datetime.utcnow() - timedelta(hours=1)
    stale_at = datetime.utcnow() - timedelta(hours=48)
    _, _, fresh, _ = _mk_pending_approval(db_session, org_id=test_org.id, requested_at=fresh_at)
    _, stale_run, stale, stale_notif = _mk_pending_approval(
        db_session, org_id=test_org.id, requested_at=stale_at,
    )

    stale_notif_id = stale_notif.id
    n = expire_stale_approvals(db_session, hours=24)

    assert n == 1
    db_session.expire_all()
    db_session.refresh(stale)
    db_session.refresh(stale_run)
    db_session.refresh(fresh)
    assert stale.status == "expired"
    assert stale.decided_at is not None
    assert "24h" in (stale.rejection_reason or "")
    assert stale_run.status == "failed"
    assert stale_run.error and "timed out" in stale_run.error
    assert fresh.status == "pending"  # untouched
    # Notification on the expired one is gone.
    assert db_session.query(Notification).filter_by(id=stale_notif_id).first() is None


def test_expire_stale_approvals_zero_hours_is_noop(db_session, test_org):
    _mk_pending_approval(db_session, org_id=test_org.id,
                         requested_at=datetime.utcnow() - timedelta(days=10))
    assert expire_stale_approvals(db_session, hours=0) == 0


def test_expire_stale_approvals_skips_already_decided(db_session, test_org):
    _, _, approval, _ = _mk_pending_approval(
        db_session, org_id=test_org.id,
        requested_at=datetime.utcnow() - timedelta(days=2),
    )
    approval.status = "approved"
    db_session.flush()

    assert expire_stale_approvals(db_session, hours=24) == 0
    db_session.refresh(approval)
    assert approval.status == "approved"  # unchanged


# ── escalate_overdue_approvals ────────────────────────────────────────

def _add_slack_integration(db, *, org_id, webhook="https://hooks.slack/abc"):
    cfg = IntegrationConfig(
        org_id=org_id, provider="slack", display_name="Slack",
        is_enabled=True, config={"webhook_url": webhook, "default_channel": "#sec"},
    )
    db.add(cfg)
    db.flush()
    return cfg


def test_escalate_sends_to_slack_once(db_session, test_org):
    _add_slack_integration(db_session, org_id=test_org.id)
    requested = datetime.utcnow() - timedelta(minutes=90)
    _, _, approval, _ = _mk_pending_approval(
        db_session, org_id=test_org.id, requested_at=requested,
    )

    with patch("services.approval_lifecycle.requests.post") as post:
        post.return_value.status_code = 200
        n = escalate_overdue_approvals(db_session, minutes=60)

    assert n == 1
    assert post.call_count == 1
    db_session.refresh(approval)
    assert approval.escalated_at is not None

    # Second sweep is a no-op (escalated_at is set).
    with patch("services.approval_lifecycle.requests.post") as post2:
        post2.return_value.status_code = 200
        n2 = escalate_overdue_approvals(db_session, minutes=60)
    assert n2 == 0
    assert post2.call_count == 0


def test_escalate_skips_when_no_slack_configured(db_session, test_org):
    _, _, approval, _ = _mk_pending_approval(
        db_session, org_id=test_org.id,
        requested_at=datetime.utcnow() - timedelta(minutes=90),
    )

    with patch("services.approval_lifecycle.requests.post") as post:
        n = escalate_overdue_approvals(db_session, minutes=60)

    assert n == 0
    assert post.call_count == 0
    db_session.refresh(approval)
    assert approval.escalated_at is None  # never escalated


def test_escalate_failed_slack_post_does_not_set_escalated_at(db_session, test_org):
    _add_slack_integration(db_session, org_id=test_org.id)
    _, _, approval, _ = _mk_pending_approval(
        db_session, org_id=test_org.id,
        requested_at=datetime.utcnow() - timedelta(minutes=90),
    )

    with patch("services.approval_lifecycle.requests.post") as post:
        post.return_value.status_code = 500
        n = escalate_overdue_approvals(db_session, minutes=60)

    assert n == 0
    db_session.refresh(approval)
    # Failed delivery leaves escalated_at NULL so the next sweep retries.
    assert approval.escalated_at is None


def test_escalate_only_picks_overdue(db_session, test_org):
    _add_slack_integration(db_session, org_id=test_org.id)
    fresh_at = datetime.utcnow() - timedelta(minutes=10)
    overdue_at = datetime.utcnow() - timedelta(minutes=90)
    _, _, fresh, _ = _mk_pending_approval(
        db_session, org_id=test_org.id, requested_at=fresh_at,
    )
    _, _, overdue, _ = _mk_pending_approval(
        db_session, org_id=test_org.id, requested_at=overdue_at,
    )

    with patch("services.approval_lifecycle.requests.post") as post:
        post.return_value.status_code = 200
        n = escalate_overdue_approvals(db_session, minutes=60)

    assert n == 1
    db_session.refresh(fresh)
    db_session.refresh(overdue)
    assert fresh.escalated_at is None
    assert overdue.escalated_at is not None
