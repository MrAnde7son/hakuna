"""Celery task that runs one Protocol Audit scratch agent end-to-end.

Pulled out of [services/audit_runner.py]'s in-process ThreadPoolExecutor path so
LLM steps don't contend with the API's request handlers on the same process
and DB pool.

The task body is intentionally thin: find the Agent, call `run_agent`, persist
a `failed` AgentRun if dispatch itself explodes before the engine has a chance
to record its own run. The engine owns the happy path.
"""

from __future__ import annotations

import logging
from datetime import datetime

from services.celery_app import celery_app

logger = logging.getLogger(__name__)


# Terminal AgentRun statuses. Anything not in this set is treated as still
# in-flight when deciding whether the parent Scan can be finalized.
_TERMINAL_AGENT_RUN_STATUSES = frozenset({"done", "failed", "cancelled"})


def _finalize_scan_if_complete(db, agent_id: int) -> None:
    """If the Agent belongs to an audit scan and every scratch agent for that
    scan's *current* run has a terminal AgentRun, flip Scan.status to
    "completed" (≥1 succeeded) or "failed" (all failed) and mirror to
    raw_metadata.

    Idempotent: re-running on an already-terminal Scan is a no-op. Uses
    last-writer-wins semantics — safe under Celery concurrency because the
    terminal state is a pure function of the AgentRun rows, which only
    transition forward.

    "Scan succeeded" follows the VM convention: partial success still counts
    as completed. Explicit user cancellation is preserved (we don't overwrite
    ``cancelled``).
    """
    from models.models import Agent, AgentRun, Scan

    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        return
    ctx = (agent.memory or {}).get("_run_ctx") or {}
    scan_id = ctx.get("_scan_id")
    if not scan_id:
        return

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return
    if scan.status in ("completed", "failed", "cancelled"):
        return

    md = dict(scan.raw_metadata or {})
    scratch_agent_ids = md.get("scratch_agent_ids") or []
    if not scratch_agent_ids:
        return
    # Only the *latest* AgentRun per scratch agent matters — engines can in
    # principle create more than one row per agent, and the terminal state we
    # care about is the one the current run ended on.
    rows = (
        db.query(AgentRun)
        .filter(AgentRun.agent_id.in_(scratch_agent_ids))
        .order_by(AgentRun.id.desc())
        .all()
    )
    latest_by_agent: dict[int, AgentRun] = {}
    for r in rows:
        latest_by_agent.setdefault(r.agent_id, r)

    if len(latest_by_agent) < len(scratch_agent_ids):
        return
    if not all(r.status in _TERMINAL_AGENT_RUN_STATUSES for r in latest_by_agent.values()):
        return

    any_succeeded = any(r.status == "done" for r in latest_by_agent.values())
    new_status = "completed" if any_succeeded else "failed"
    scan.status = new_status
    md["status"] = new_status
    scan.raw_metadata = md

    # Run the full post-ingest pipeline now that every emit_finding for this
    # audit run has landed. finalize_batch already ran per-finding from the
    # emit_finding tool, but scan-level rollups (SLA, cross-scan dedup,
    # corporate-tree sync, control assessment, etc.) only belong at terminal
    # transition. Without this, audit scans would never pick up those
    # rollups and would drift from VM/EASM ingestion behaviour.
    try:
        from services.post_ingest import finalize_scan
        finalize_scan(db, scan_id=scan.id, org_id=scan.org_id)
    except Exception:
        logger.exception(
            "audit finalize: finalize_scan failed for scan_id=%s (non-fatal)",
            scan.id,
        )

    db.commit()


@celery_app.task(
    bind=True,
    name="audits.run_scratch_agent",
    max_retries=0,
)
def run_scratch_agent_task(self, agent_id: int, user_input: str, wallclock_s: int) -> dict:
    """Execute one scratch Agent to completion.

    `wallclock_s` is not enforced here today — the Celery `task_time_limit` in
    celery_app.conf is the upper bound. We still accept it so the task signature
    matches the in-process dispatcher and we can wire enforcement in later
    without changing every caller.
    """
    from core.database import SessionLocal
    from models.models import Agent, AgentRun
    from agents.agent_engine import run_agent

    bg_db = SessionLocal()
    try:
        agent = bg_db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            # Can happen if the scratch agent was deleted between dispatch and
            # pick-up — not worth retrying.
            logger.warning("audit task: agent=%s not found", agent_id)
            return {"status": "missing", "agent_id": agent_id}
        run = run_agent(agent, user_input, bg_db)
        # Flip the parent Scan's status if this was the last scratch agent
        # still running. Without this, audit scans hang on "Scanning…" in the
        # UI forever after the last LLM run returns.
        try:
            _finalize_scan_if_complete(bg_db, agent_id)
        except Exception:
            logger.exception("audit task agent=%s: finalize failed", agent_id)
            bg_db.rollback()
        return {
            "status": run.status,
            "agent_id": agent_id,
            "run_id": run.id,
            "steps": run.steps_used,
        }
    except Exception as e:
        # Surface the failure as an AgentRun row so the scan UI can render it
        # instead of hanging on "running" forever. Mirrors the rollback safety
        # net we already added to the in-process dispatcher.
        logger.exception("audit task agent=%s failed", agent_id)
        try:
            bg_db.rollback()
            has_run = (
                bg_db.query(AgentRun)
                .filter(AgentRun.agent_id == agent_id)
                .first()
            )
            if not has_run:
                bg_db.add(AgentRun(
                    agent_id=agent_id,
                    input=user_input,
                    status="failed",
                    error=f"worker failed before run started: {e}",
                    finished_at=datetime.utcnow(),
                ))
                bg_db.commit()
            # Finalize the Scan even on the error path — otherwise a run that
            # exploded before the engine recorded its own row leaves the scan
            # stuck in "running".
            _finalize_scan_if_complete(bg_db, agent_id)
        except Exception:
            logger.exception("audit task agent=%s: failed to record failure", agent_id)
        # Let Celery mark the task as failed — callers that poll result state
        # will see the exception, and acks_late ensures a crashed worker
        # requeues the job.
        raise
    finally:
        bg_db.close()


@celery_app.task(
    bind=True,
    name="audits.continue_agent_run",
    max_retries=0,
)
def continue_agent_run_task(self, run_id: int) -> dict:
    """Resume an audit AgentRun after a HITL approval decision.

    Pairs with `record_approval_decision` (called synchronously in the API
    handler) — by the time this task runs, the AgentRun is back in
    `running` state and the gated tool's outcome is encoded on the
    decided AgentApproval row. The Celery worker re-enters the LLM loop
    and drives the run to a terminal state.

    Routing approvals through the same queue that ran the initial
    dispatch keeps the full audit lifecycle visible in audit-worker logs,
    and lets the resume survive a backend restart.
    """
    from core.database import SessionLocal
    from agents.agent_engine import continue_after_decision

    bg_db = SessionLocal()
    try:
        run = continue_after_decision(run_id, bg_db)
        return {
            "status": run.status,
            "run_id": run.id,
            "agent_id": run.agent_id,
            "steps": run.steps_used,
        }
    except Exception:
        logger.exception("audit resume task run=%s failed", run_id)
        try:
            bg_db.rollback()
        except Exception:
            pass
        raise
    finally:
        bg_db.close()
