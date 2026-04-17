"""Validation agent scheduler.

Periodically finds critical/high findings that the static LLM validator
(#11) flagged as `needs_review` and kicks off a validator-agent run for
each one. The validator agent probes the target safely, collects evidence,
and requests a human approval before writing a verdict.

Scheduling is best-effort: at most `max_per_cycle` agent runs are launched
per tick (default 5) so one org's backlog doesn't monopolize the worker.
Each agent run is dispatched via services.job_manager so the scheduler
doesn't block.

The scheduler's per-org validator Agent is created lazily on first use —
it has guardrails `autonomy_level=conservative` so the verdict writer
tool (`update_finding_validation`) hits the HITL approval path.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.database import SessionLocal
from models.models import Agent, Finding

logger = logging.getLogger(__name__)


VALIDATOR_AGENT_NAME = "Vulnerability Validator (auto)"
VALIDATOR_AGENT_DESCRIPTION = (
    "Auto-created validator agent. Runs safe probes to confirm or refute "
    "exploitability of high/critical findings, then requests HITL approval."
)


def get_or_create_validator_agent(db: Session, org_id: int) -> Agent:
    """Return the per-org validator Agent, creating it on first use."""
    existing = db.query(Agent).filter(
        Agent.org_id == org_id,
        Agent.name == VALIDATOR_AGENT_NAME,
    ).first()
    if existing:
        return existing

    from agents.agent_prompts import ENHANCED_PROMPTS

    agent = Agent(
        org_id=org_id,
        name=VALIDATOR_AGENT_NAME,
        description=VALIDATOR_AGENT_DESCRIPTION,
        system_prompt=ENHANCED_PROMPTS["validator_agent"],
        tools=[
            "probe_url_status", "probe_tcp_connect",
            "fetch_response_headers", "check_response_body",
            "update_finding_validation",
            "get_finding_detail", "get_asset_profile",
            "fetch_url", "search_web",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        guardrails={
            "max_steps": 10,
            "read_only": False,
            "autonomy_level": "conservative",
        },
        memory={},
        model="claude-sonnet-4-6",
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    logger.info("org=%d created validator agent id=%d", org_id, agent.id)
    return agent


def dispatch_validation_for_finding(db: Session, finding_id: int) -> dict:
    """Kick off a validator agent run for a single finding.

    Returns {"job_id": ..., "agent_id": ..., "finding_id": ...} on success,
    or {"error": ...} on failure.
    """
    from services.job_manager import dispatch

    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        return {"error": f"finding {finding_id} not found"}

    asset = f.asset
    if not asset:
        return {"error": f"finding {finding_id} has no linked asset"}

    # Assets have no org_id column; it lives on the parent scan row.
    org_id = asset.scan.org_id if asset.scan else None
    if org_id is None:
        return {"error": f"finding {finding_id}'s asset has no owning scan/org"}
    agent = get_or_create_validator_agent(db, org_id)

    user_input = (
        f"Validate finding {finding_id}.\n\n"
        f"Plugin: {f.plugin_name or f.plugin_id}\n"
        f"Severity: {f.severity_label or f.severity}\n"
        f"Asset: {asset.hostname or asset.ip}\n"
        f"Port: {f.port}\n"
        f"CVEs: {f.cves or []}\n\n"
        f"Determine whether this finding is genuinely exploitable in the "
        f"target's current configuration. Use safe probes only, then call "
        f"update_finding_validation with your verdict."
    )

    agent_id = agent.id

    def _run():
        from agents.agent_engine import run_agent
        bg_db = SessionLocal()
        try:
            ag = bg_db.query(Agent).filter(Agent.id == agent_id).first()
            if not ag:
                return {"error": f"agent {agent_id} not found"}
            run = run_agent(ag, user_input, bg_db)
            return {
                "agent_run_id": run.id,
                "status": run.status,
                "steps": len(run.trace or []),
            }
        finally:
            bg_db.close()

    job = dispatch(f"validator_agent_{agent.id}_finding_{finding_id}", _run)
    return {
        "job_id": job.id,
        "agent_id": agent.id,
        "finding_id": finding_id,
        "status": job.status.value,
    }


def run_scheduler_cycle(max_per_cycle: int = 5, min_severity: int = 4) -> dict:
    """Find candidate findings and kick off validator runs.

    Candidates:
      - severity >= min_severity (default Critical/4, matches llm_vuln_validator)
      - source_type == 'vm_scanner' (Nuclei)
      - llm_validation.verdict == 'needs_review' (set by #11)
      - ctx_exploitability IS NULL (not yet validated by the agent)
      - workflow_status NOT IN (resolved, false_positive, accepted_risk)

    Processes at most max_per_cycle across all orgs per tick.
    """
    db: Session = SessionLocal()
    try:
        # Fetch candidates: need SQLite-safe JSON access.
        # Note: assets has no org_id column — org is scoped through scans.
        rows = db.execute(text("""
            SELECT f.id, s.org_id
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE f.severity >= :min_sev
              AND f.source_type = 'vm_scanner'
              AND f.llm_validation IS NOT NULL
              AND f.ctx_exploitability IS NULL
              AND f.workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
            ORDER BY f.severity DESC, f.priority_score DESC
            LIMIT :limit
        """), {"min_sev": min_severity, "limit": max_per_cycle * 5}).fetchall()

        # Filter to needs_review in Python (JSON access differs across dbs)
        dispatched = 0
        skipped = 0
        for row in rows:
            if dispatched >= max_per_cycle:
                break
            f = db.query(Finding).filter(Finding.id == row.id).first()
            if not f:
                continue
            verdict = (f.llm_validation or {}).get("verdict")
            if verdict != "needs_review":
                skipped += 1
                continue
            try:
                result = dispatch_validation_for_finding(db, row.id)
                if "error" in result:
                    skipped += 1
                else:
                    dispatched += 1
            except Exception as e:
                logger.warning("dispatch_validation failed for finding %d: %s", row.id, e)
                skipped += 1

        if dispatched:
            logger.info("Validation scheduler: dispatched=%d skipped=%d", dispatched, skipped)
        return {"dispatched": dispatched, "skipped": skipped, "at": datetime.utcnow().isoformat()}
    finally:
        db.close()


def start_validation_scheduler():
    """Register the scheduler with APScheduler (every 10 minutes).

    Called from app.py startup. Idempotent.
    """
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_scheduler_cycle,
        IntervalTrigger(minutes=10),
        id="validation_agent_scheduler",
        replace_existing=True,
        misfire_grace_time=300,
        coalesce=True,
    )
    scheduler.start()
    logger.info("Validation agent scheduler started (every 10 minutes)")
