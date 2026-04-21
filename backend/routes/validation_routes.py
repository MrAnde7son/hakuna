"""API routes for the validation agent framework.

Exposes:
  - POST /api/validation/run/{finding_id}  — manually trigger a validator run
  - GET  /api/validation/status/{finding_id} — current verdict + agent run trace
  - GET  /api/validation/queue — findings currently needing validation

The scheduler service (services.validation_agent_scheduler) picks up
findings automatically; these routes let analysts trigger manual runs
or inspect what's happening.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.auth import get_accessible_org_ids, get_current_user
from core.database import get_db
from core.time_utils import iso_utc
from models.models import Agent, AgentRun, Asset, Finding, Scan

router = APIRouter(prefix="/api/validation", tags=["Validation"])


@router.post("/run/{finding_id}")
async def run_validation(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Manually trigger a validator agent run for a finding.

    The run executes in the background (via job_manager). Poll the status
    endpoint to check progress.
    """
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No org context")

    # Org filter: ensure this finding belongs to an accessible org
    # Asset doesn't have org_id directly — org is on the Scan table.
    finding = (
        db.query(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Finding.id == finding_id, Scan.org_id.in_(org_ids))
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Gate: only allow on high/critical
    if (finding.severity or 0) < 3:
        raise HTTPException(
            status_code=400,
            detail="Validation is only supported for high/critical findings (severity >= 3)",
        )

    from services.validation_agent_scheduler import dispatch_validation_for_finding

    result = dispatch_validation_for_finding(db, finding_id)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result


@router.get("/status/{finding_id}")
def get_validation_status(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Return current validation state for a finding.

    Response: {
        finding_id, verdict, confidence, reasoning, validator,
        validated_at, ctx_reachability, ctx_exploitability,
        recent_agent_runs: [{id, status, created_at, steps}]
    }
    """
    finding = (
        db.query(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Finding.id == finding_id, Scan.org_id.in_(org_ids))
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    validation = finding.llm_validation or {}

    # Pull recent validator agent runs for this org that referenced this finding.
    # Matching is done by substring search over the run's input text because
    # the validator agent receives `finding_id` in its user input.
    recent_runs = []
    asset = finding.asset
    if asset:
        validator_agents = (
            db.query(Agent)
            .filter(Agent.org_id == (asset.scan.org_id if asset.scan else None), Agent.name.like("Vulnerability Validator%"))
            .all()
        )
        validator_ids = [a.id for a in validator_agents]
        if validator_ids:
            runs = (
                db.query(AgentRun)
                .filter(
                    AgentRun.agent_id.in_(validator_ids),
                    AgentRun.input.like(f"%finding {finding_id}%"),
                )
                .order_by(AgentRun.created_at.desc())
                .limit(5)
                .all()
            )
            recent_runs = [
                {
                    "id": r.id,
                    "status": r.status,
                    "created_at": iso_utc(r.created_at),
                    "steps": len(r.trace or []),
                    "output": (r.output or "")[:500] if r.output else None,
                }
                for r in runs
            ]

    return {
        "finding_id": finding.id,
        "verdict": validation.get("verdict"),
        "confidence": validation.get("confidence"),
        "reasoning": validation.get("reasoning"),
        "validator": validation.get("validator"),
        "validated_at": validation.get("validated_at"),
        "ctx_reachability": finding.ctx_reachability,
        "ctx_exploitability": finding.ctx_exploitability,
        "recent_agent_runs": recent_runs,
    }


@router.get("/queue")
def get_validation_queue(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """List findings awaiting agent validation.

    Returns findings that:
      - severity >= 3 (high/critical)
      - source_type = 'vm_scanner' (Nuclei)
      - llm_validation.verdict = 'needs_review' (flagged by #11)
      - ctx_exploitability IS NULL (not yet validated by agent)

    This is the backlog that the scheduler pulls from.
    """
    rows = (
        db.query(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(
            Scan.org_id.in_(org_ids),
            Finding.severity >= 3,
            Finding.source_type == "vm_scanner",
            Finding.llm_validation.isnot(None),
            Finding.ctx_exploitability.is_(None),
            Finding.workflow_status.notin_(["resolved", "false_positive", "accepted_risk"]),
        )
        .order_by(Finding.severity.desc(), Finding.priority_score.desc())
        .limit(limit)
        .all()
    )

    items = []
    for f in rows:
        validation = f.llm_validation or {}
        if validation.get("verdict") != "needs_review":
            continue
        items.append({
            "finding_id": f.id,
            "plugin_name": f.plugin_name,
            "severity": f.severity,
            "severity_label": f.severity_label,
            "asset_id": f.asset_id,
            "asset_hostname": f.asset.hostname if f.asset else None,
            "asset_ip": str(f.asset.ip) if f.asset and f.asset.ip else None,
            "llm_reasoning": validation.get("reasoning"),
            "priority_score": f.priority_score,
        })

    return {"items": items, "count": len(items)}
