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


VALIDATOR_TOOLS = [
    "probe_url_status", "probe_tcp_connect",
    "fetch_response_headers", "check_response_body",
    "update_finding_validation",
    "get_finding_detail", "get_asset_profile",
    "get_threat_cves", "list_exceptions",
    "fetch_url", "search_web",
    "read_scratchpad", "write_scratchpad", "request_clarification",
]


def get_or_create_validator_agent(db: Session, org_id: int) -> Agent:
    """Return the per-org validator Agent, creating it on first use.

    For existing auto-managed agents, reconciles the tool list and system
    prompt against the current definition so schema/prompt updates apply
    without a migration.
    """
    from agents.agent_prompts import ENHANCED_PROMPTS

    existing = db.query(Agent).filter(
        Agent.org_id == org_id,
        Agent.name == VALIDATOR_AGENT_NAME,
    ).first()
    if existing:
        desired_prompt = ENHANCED_PROMPTS["validator_agent"]
        changed = False
        if set(existing.tools or []) != set(VALIDATOR_TOOLS):
            existing.tools = VALIDATOR_TOOLS
            changed = True
        if existing.system_prompt != desired_prompt:
            existing.system_prompt = desired_prompt
            changed = True
        if changed:
            db.commit()
            db.refresh(existing)
        return existing

    agent = Agent(
        org_id=org_id,
        name=VALIDATOR_AGENT_NAME,
        description=VALIDATOR_AGENT_DESCRIPTION,
        system_prompt=ENHANCED_PROMPTS["validator_agent"],
        tools=list(VALIDATOR_TOOLS),
        guardrails={
            "max_steps": 10,
            "read_only": False,
            "autonomy_level": "conservative",
        },
        memory={},
        model="vertex/gemini-2.5-pro",
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

    org_id = asset.scan.org_id if asset.scan else None
    if not org_id:
        return {"error": f"finding {finding_id} asset has no scan/org context"}
    agent = get_or_create_validator_agent(db, org_id)

    llm_val = f.llm_validation or {}
    prior_reasoning = (llm_val.get("reasoning") or "").strip()

    context_lines = [
        f"Plugin: {f.plugin_name or f.plugin_id}",
        f"Severity: {f.severity_label or f.severity}",
        f"Asset: {asset.hostname or asset.ip}"
        + (f" (OS: {asset.os})" if asset.os else "")
        + (" [internet-facing]" if getattr(asset, "is_internet_facing", False) else ""),
        f"Port/Proto: {f.port}/{f.protocol or 'tcp'}",
        f"CVEs: {f.cves or []}",
        "",
        "Threat intel (denormalized on finding):",
        f"  KEV: {bool(f.is_kev)}  EPSS: {f.epss_score}  "
        f"Exploit available: {bool(f.exploit_available)}  "
        f"Maturity: {f.exploit_maturity or 'unknown'}  "
        f"Ransomware-linked: {bool(getattr(f, 'ransomware_linked', False))}  "
        f"Zero-day: {bool(getattr(f, 'zero_day', False))}",
        "",
        "Analyst-set context (trust these — they were entered by a human):",
        f"  Reachability: {f.ctx_reachability or 'unset'}",
        f"  Exploitability: {f.ctx_exploitability or 'unset'}",
        f"  Accessibility: {f.ctx_accessibility or 'unset'}",
        f"  Compensating controls: {f.ctx_compensating_control or 'none recorded'}",
    ]
    if prior_reasoning:
        context_lines += ["", "Prior LLM validator flagged this as needs_review:", f"  {prior_reasoning}"]

    user_input = (
        f"Validate finding {finding_id}.\n\n"
        + "\n".join(context_lines)
        + "\n\nDetermine whether this finding is genuinely exploitable in the "
        "target's current configuration. Before probing, check for existing "
        "exceptions/compensating controls (list_exceptions) and enrich CVE "
        "intel if needed (get_threat_cves). Use safe probes only, then call "
        "update_finding_validation with your verdict."
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
        # Fetch candidates; JSON filter runs in Python below.
        rows = db.execute(text("""
            SELECT f.id, s.org_id
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
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
