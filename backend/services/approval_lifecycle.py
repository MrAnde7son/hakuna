"""Lifecycle helpers for AgentApproval rows.

Three concerns live here:

1. **clear_approval_notification(approval_id)** — invoked when an approval
   is decided manually or auto-expired. Removes the in-app notification
   that pointed at the approval since the action is no longer pending.

2. **expire_stale_approvals(hours)** — periodic job. Pending approvals
   older than ``hours`` are marked ``expired``; their parent agent run
   transitions from ``awaiting_approval`` → ``failed`` with a clear
   error so the scan list doesn't show a permanently-stuck row.

3. **escalate_overdue_approvals(minutes)** — periodic job. Pending
   approvals older than ``minutes`` that haven't been escalated yet
   get pushed to the org's Slack integration (if configured). The
   ``escalated_at`` column prevents re-sending.

All three are safe to call concurrently — each operates on its own
filtered subset and uses ``status`` / ``escalated_at`` as a guard.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

import requests
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from models.models import AgentApproval, AgentRun, IntegrationConfig, Notification

logger = logging.getLogger(__name__)


# ── Notification cleanup ─────────────────────────────────────────────

def clear_approval_notification(db: Session, approval_id: int) -> int:
    """Delete the bell notification(s) tied to ``approval_id``.

    Returns the count removed (0 if none). Cascade on the FK already
    drops any per-user NotificationRead rows. Fire-and-forget — never
    raises (callers shouldn't block on UI cleanup).
    """
    try:
        n = (
            db.query(Notification)
            .filter(
                Notification.entity_type == "agent_approval",
                Notification.entity_id == approval_id,
            )
            .delete(synchronize_session=False)
        )
        return int(n or 0)
    except Exception:
        logger.exception("failed to clear approval notification %s", approval_id)
        return 0


# ── Auto-expiry ──────────────────────────────────────────────────────

def expire_stale_approvals(db: Session, hours: int) -> int:
    """Mark pending approvals older than ``hours`` as expired.

    The companion AgentRun transitions to ``failed`` so the scan list
    no longer shows it as gated. We deliberately don't try to resume
    the LLM with a "rejected" signal — the user already had ``hours``
    to act, and resuming would burn tokens for no value.

    Returns the number of approvals expired.
    """
    if hours <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    stale = (
        db.query(AgentApproval)
        .filter(
            AgentApproval.status == "pending",
            AgentApproval.requested_at < cutoff,
        )
        .all()
    )
    if not stale:
        return 0

    expired_count = 0
    for approval in stale:
        approval.status = "expired"
        approval.decided_at = datetime.utcnow()
        approval.rejection_reason = (
            f"Auto-expired after {hours}h with no decision"
        )
        run = (
            db.query(AgentRun)
            .filter(AgentRun.id == approval.agent_run_id)
            .first()
        )
        if run and run.status == "awaiting_approval":
            run.status = "failed"
            run.error = (
                f"Approval timed out after {hours}h with no decision "
                f"(tool: {approval.tool_name})"
            )
            run.finished_at = datetime.utcnow()
        clear_approval_notification(db, approval.id)
        expired_count += 1

    db.commit()
    if expired_count:
        logger.info("expired %d stale agent approval(s)", expired_count)
    return expired_count


# ── Escalation ───────────────────────────────────────────────────────

def _slack_config_for_org(db: Session, org_id: int) -> Optional[dict]:
    """Fetch the org's enabled Slack integration config, if any."""
    cfg = (
        db.query(IntegrationConfig)
        .filter(
            IntegrationConfig.org_id == org_id,
            IntegrationConfig.provider == "slack",
            IntegrationConfig.is_enabled == True,
        )
        .first()
    )
    return (cfg.config or {}) if cfg else None


def _send_slack_escalation(slack_cfg: dict, approval: AgentApproval) -> bool:
    """Post a single message to the configured Slack webhook.

    Returns True on a 2xx response, False otherwise. Network failures
    are swallowed so the periodic job keeps draining the queue.
    """
    webhook_url = slack_cfg.get("webhook_url")
    if not webhook_url:
        return False

    waited = datetime.utcnow() - approval.requested_at
    minutes = int(waited.total_seconds() // 60)
    text = (
        f":hourglass_flowing_sand: Hakuna agent action waiting for approval "
        f"({minutes}m and counting)\n"
        f"• Tool: `{approval.tool_name}`\n"
        f"• Run: #{approval.agent_run_id}\n"
        f"Review: open Hakuna → bell icon, or "
        f"`/agents?approvals=1&run={approval.agent_run_id}`"
    )
    payload = {"text": text}
    channel = slack_cfg.get("default_channel")
    if channel:
        payload["channel"] = channel
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        return 200 <= r.status_code < 300
    except Exception:
        logger.exception("slack escalation post failed")
        return False


def escalate_overdue_approvals(db: Session, minutes: int) -> int:
    """Push pending approvals older than ``minutes`` to Slack (if configured).

    Idempotent: ``escalated_at`` gates re-sends. Approvals in orgs without
    a Slack integration are silently skipped — escalation is best-effort.

    Returns the number of approvals successfully escalated.
    """
    if minutes <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    overdue = (
        db.query(AgentApproval)
        .filter(
            AgentApproval.status == "pending",
            AgentApproval.requested_at < cutoff,
            AgentApproval.escalated_at.is_(None),
        )
        .all()
    )
    if not overdue:
        return 0

    # Cache per-org Slack lookup since many approvals may share an org.
    slack_by_org: dict[int, Optional[dict]] = {}
    sent = 0
    for approval in overdue:
        org_id = approval.org_id
        if org_id is None:
            continue
        if org_id not in slack_by_org:
            slack_by_org[org_id] = _slack_config_for_org(db, org_id)
        cfg = slack_by_org[org_id]
        if not cfg:
            continue
        if _send_slack_escalation(cfg, approval):
            approval.escalated_at = datetime.utcnow()
            sent += 1

    if sent:
        db.commit()
        logger.info("escalated %d overdue agent approval(s) to Slack", sent)
    return sent
