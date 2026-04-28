"""Cancelling an audit scan must clear its pending approvals.

Before this fix, ``POST /api/scans/{id}/cancel`` only flipped AgentRuns in
``pending``/``running`` to ``cancelled`` — runs in ``awaiting_approval``
and their pending AgentApproval rows were left dangling, so the scan card
kept showing "Review action" and the global queue still surfaced the
gated calls.
"""
from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

from models.models import (
    Agent, AgentApproval, AgentRun, Notification, Scan,
)


def _seed_paused_audit(db, *, org_id):
    agent = Agent(
        org_id=org_id, name="ssh-audit", system_prompt="x",
        tools=["ssh_run_command"], guardrails={}, model="claude-sonnet-4-6",
    )
    db.add(agent)
    db.flush()
    # Scan status stays "running" even while the AgentRun underneath is
    # paused at awaiting_approval — that's the production bug shape.
    scan = Scan(
        filename="ssh-audit", scan_type="ssh_audit", source_type="ssh_audit",
        org_id=org_id, status="running",
        raw_metadata={
            "scratch_agent_ids": [agent.id],
            "task_ids": {str(agent.id): "fake-task-id"},
            "status": "running",
        },
    )
    db.add(scan)
    db.flush()
    run = AgentRun(
        agent_id=agent.id, input="audit", status="awaiting_approval",
    )
    db.add(run)
    db.flush()
    approval = AgentApproval(
        org_id=org_id, agent_run_id=run.id, agent_id=agent.id,
        tool_name="ssh_run_command", tool_input={"asset_id": 1, "command": "ls"},
        provider="anthropic", model_name="claude-sonnet-4-6",
        current_step=3, tool_use_id="tu_1", status="pending",
        requested_at=datetime.utcnow(),
    )
    db.add(approval)
    db.flush()
    notif = Notification(
        org_id=org_id, category="approval_required",
        title="approval", body="ssh_run_command",
        link=f"/agents?approvals=1&run={run.id}",
        entity_type="agent_approval", entity_id=approval.id,
    )
    db.add(notif)
    db.commit()
    return scan, run, approval, notif


def test_cancel_audit_expires_pending_approvals_and_clears_notifications(
    authed_client, db_session, test_org,
):
    scan, run, approval, notif = _seed_paused_audit(db_session, org_id=test_org.id)
    scan_id, run_id, approval_id, notif_id = scan.id, run.id, approval.id, notif.id

    with patch("services.audit_runner.revoke_audit_tasks", return_value={"revoked": [], "errors": {}}):
        resp = authed_client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 200, resp.text

    db_session.expire_all()
    refreshed_scan = db_session.query(Scan).filter_by(id=scan_id).first()
    refreshed_run = db_session.query(AgentRun).filter_by(id=run_id).first()
    refreshed_approval = db_session.query(AgentApproval).filter_by(id=approval_id).first()

    assert refreshed_scan.status == "cancelled"
    # Run was in awaiting_approval — must now be cancelled (this was the gap).
    assert refreshed_run.status == "cancelled"
    assert refreshed_run.finished_at is not None
    # Pending approval expired so it stops surfacing in the queue.
    assert refreshed_approval.status == "expired"
    assert refreshed_approval.rejection_reason == "Scan cancelled by user"
    # Notification cleared so the bell doesn't keep pointing at a dead approval.
    assert db_session.query(Notification).filter_by(id=notif_id).first() is None
