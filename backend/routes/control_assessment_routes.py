"""
Control Assessment — FastAPI routes
Prefix: /api/control-assessments
"""
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from core.time_utils import iso_utc
from models.models import (
    Finding, Asset, Scan,
    SecurityControlPolicy, SecurityControlPolicyAssignment, ControlAssessment,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/control-assessments", tags=["control-assessments"])


def _org_filter(query, model_cls, org_ids):
    if org_ids is None:
        return query
    return query.filter(model_cls.org_id.in_(org_ids))


# ── Assessments for a finding ──────────────────────────

@router.get("/finding/{finding_id}")
async def get_finding_assessments(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Get all control assessments for a specific finding."""
    q = db.query(ControlAssessment).filter(ControlAssessment.finding_id == finding_id)
    if org_ids is not None:
        q = q.filter(ControlAssessment.org_id.in_(org_ids))
    assessments = q.all()

    results = []
    for a in assessments:
        policy = db.query(SecurityControlPolicy).filter(SecurityControlPolicy.id == a.policy_id).first()
        results.append({
            "id": a.id,
            "verdict": a.verdict,
            "confidence": a.confidence,
            "explanation": a.explanation,
            "matched_techniques": a.matched_techniques or [],
            "assessed_at": iso_utc(a.assessed_at),
            "policy": {
                "id": policy.id,
                "product_key": policy.product_key,
                "product_name": policy.product_name,
                "vendor": policy.vendor,
                "policy_name": policy.policy_name,
                "policy_type": policy.policy_type,
            } if policy else None,
        })

    return {"items": results}


# ── Policies assigned to an asset ──────────────────────

@router.get("/asset/{asset_id}/policies")
async def get_asset_policies(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Get security policies assigned to an asset with assessment stats."""
    q = db.query(SecurityControlPolicyAssignment).filter(
        SecurityControlPolicyAssignment.asset_id == asset_id
    )
    if org_ids is not None:
        q = q.filter(SecurityControlPolicyAssignment.org_id.in_(org_ids))
    assignments = q.all()

    results = []
    for a in assignments:
        policy = db.query(SecurityControlPolicy).filter(SecurityControlPolicy.id == a.policy_id).first()
        if not policy:
            continue

        # Get assessment stats for this policy on this asset
        stats = {}
        for verdict in ["mitigated", "partially_mitigated", "not_mitigated", "unknown"]:
            stats[verdict] = db.query(func.count(ControlAssessment.id)).filter(
                ControlAssessment.asset_id == asset_id,
                ControlAssessment.policy_id == policy.id,
                ControlAssessment.verdict == verdict,
            ).scalar() or 0

        results.append({
            "id": a.id,
            "assignment_source": a.assignment_source,
            "source_group_name": a.source_group_name,
            "synced_at": iso_utc(a.synced_at),
            "policy": {
                "id": policy.id,
                "product_key": policy.product_key,
                "product_name": policy.product_name,
                "vendor": policy.vendor,
                "policy_name": policy.policy_name,
                "policy_type": policy.policy_type,
                "settings": policy.settings,
            },
            "assessment_stats": stats,
        })

    return {"items": results}


# ── Trigger assessment ─────────────────────────────────

@router.post("/run")
async def run_assessment(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Manually trigger control assessment."""
    import services.control_assessment as engine

    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(400, "Org context required")

    result = engine.assess_findings(db, org_id, scan_id=scan_id, asset_id=asset_id)
    db.commit()
    return result


# ── Dashboard stats ────────────────────────────────────

@router.get("/stats")
async def assessment_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Aggregate stats for dashboard widget."""
    q = db.query(
        Finding.control_mitigation_status,
        func.count(Finding.id),
    ).join(Scan, Finding.scan_id == Scan.id).filter(
        Finding.control_mitigation_status != None,
    )
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))

    rows = q.group_by(Finding.control_mitigation_status).all()
    stats = {status: count for status, count in rows}

    total_with_assessment = sum(stats.values())
    total_findings_q = db.query(func.count(Finding.id)).join(Scan, Finding.scan_id == Scan.id).filter(Finding.severity >= 2)
    if org_ids is not None:
        total_findings_q = total_findings_q.filter(Scan.org_id.in_(org_ids))
    total_findings = total_findings_q.scalar() or 0

    return {
        "mitigated": stats.get("mitigated", 0),
        "partially_mitigated": stats.get("partially_mitigated", 0),
        "not_mitigated": stats.get("not_mitigated", 0),
        "unknown": stats.get("unknown", 0),
        "assessed": total_with_assessment,
        "total_findings": total_findings,
        "coverage_pct": round(total_with_assessment / total_findings * 100, 1) if total_findings else 0,
    }
