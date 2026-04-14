"""Detection rules and alerts routes — /api/detection-rules/* and /api/alerts/*"""

import json
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from core.audit import log_audit
from models.models import DetectionRule, Alert

router = APIRouter()

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


# ── Pydantic schemas ────────────────────────────────────

class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    severity: str = "medium"
    query: dict = {}
    window_seconds: int = 300
    threshold: int = 1
    group_by: List[str] = []
    schedule_minutes: int = 5
    mitre_techniques: List[str] = []
    enabled: bool = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    query: Optional[dict] = None
    window_seconds: Optional[int] = None
    threshold: Optional[int] = None
    group_by: Optional[List[str]] = None
    schedule_minutes: Optional[int] = None
    mitre_techniques: Optional[List[str]] = None
    enabled: Optional[bool] = None


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[int] = None
    campaign_id: Optional[int] = None


def _rule_to_dict(r: DetectionRule) -> dict:
    return {
        "id": r.id, "org_id": r.org_id, "name": r.name, "description": r.description,
        "severity": r.severity, "enabled": r.enabled, "query": r.query,
        "window_seconds": r.window_seconds, "threshold": r.threshold,
        "group_by": r.group_by, "schedule_minutes": r.schedule_minutes,
        "mitre_techniques": r.mitre_techniques, "source": r.source,
        "sigma_rule_id": r.sigma_rule_id,
        "last_run_at": r.last_run_at.isoformat() if r.last_run_at else None,
        "last_alert_at": r.last_alert_at.isoformat() if r.last_alert_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _alert_to_dict(a: Alert) -> dict:
    return {
        "id": a.id, "org_id": a.org_id, "rule_id": a.rule_id,
        "fired_at": a.fired_at.isoformat() if a.fired_at else None,
        "severity": a.severity, "status": a.status, "event_count": a.event_count,
        "group_key": a.group_key, "first_event_id": a.first_event_id,
        "last_event_id": a.last_event_id, "context": a.context,
        "asset_id": a.asset_id, "assigned_to": a.assigned_to,
        "campaign_id": a.campaign_id,
        "rule_name": a.rule.name if a.rule else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


# ── Detection Rules CRUD ───────────────────────────────

@router.get("/api/detection-rules")
async def list_rules(
    enabled: Optional[bool] = None,
    severity: Optional[str] = None,
    page: int = 1, page_size: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    q = db.query(DetectionRule).filter(DetectionRule.org_id.in_(org_ids))
    if enabled is not None:
        q = q.filter(DetectionRule.enabled == enabled)
    if severity:
        q = q.filter(DetectionRule.severity == severity)
    total = q.count()
    rules = q.order_by(DetectionRule.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_rule_to_dict(r) for r in rules], "total": total, "page": page, "page_size": page_size}


@router.post("/api/detection-rules")
async def create_rule(
    body: RuleCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    if body.severity not in VALID_SEVERITIES:
        raise HTTPException(400, f"Invalid severity: {body.severity}")
    org_id = org_ids[0] if org_ids else current_user.org_id
    rule = DetectionRule(org_id=org_id, **body.dict())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _rule_to_dict(rule)


@router.get("/api/detection-rules/{rule_id}")
async def get_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id, DetectionRule.org_id.in_(org_ids)).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    return _rule_to_dict(rule)


@router.put("/api/detection-rules/{rule_id}")
async def update_rule(
    rule_id: int, body: RuleUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id, DetectionRule.org_id.in_(org_ids)).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    for field, val in body.dict(exclude_unset=True).items():
        setattr(rule, field, val)
    db.commit()
    db.refresh(rule)
    return _rule_to_dict(rule)


@router.delete("/api/detection-rules/{rule_id}")
async def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id, DetectionRule.org_id.in_(org_ids)).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    db.delete(rule)
    db.commit()
    return {"deleted": True}


# ── Test rule (dry-run) ────────────────────────────────

@router.post("/api/detection-rules/test")
async def test_rule(
    body: RuleCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Dry-run a rule against last 24h without creating alerts."""
    from services.detection_engine import _apply_rule_filters
    from datetime import timedelta

    org_id = org_ids[0] if org_ids else current_user.org_id
    from models.models import SIEMEvent
    window_start = datetime.utcnow() - timedelta(hours=24)

    q = db.query(SIEMEvent).filter(
        SIEMEvent.org_id == org_id,
        SIEMEvent.event_time >= window_start,
    )
    temp_rule = DetectionRule(query=body.query, threshold=body.threshold,
                              window_seconds=body.window_seconds, group_by=body.group_by)
    q = _apply_rule_filters(q, temp_rule)
    total = q.count()
    sample = q.order_by(SIEMEvent.event_time.desc()).limit(10).all()

    return {
        "would_fire": total >= body.threshold,
        "matching_events": total,
        "threshold": body.threshold,
        "sample": [{"id": e.id, "event_time": e.event_time.isoformat() if e.event_time else None,
                     "severity": e.severity, "message": (e.message or "")[:200]} for e in sample],
    }


# ── Sigma import ───────────────────────────────────────

@router.post("/api/detection-rules/import-sigma")
async def import_sigma(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Import Sigma YAML rules (multipart upload)."""
    from services.sigma_importer import bulk_import

    org_id = org_ids[0] if org_ids else current_user.org_id
    yaml_texts = []
    for f in files:
        content = await f.read()
        yaml_texts.append(content.decode("utf-8", errors="replace"))

    result = bulk_import(yaml_texts, org_id, db)
    return result


# ── Alerts ─────────────────────────────────────────────

@router.get("/api/alerts")
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[int] = None,
    sort_by: str = "fired_at",
    order: str = "desc",
    page: int = 1, page_size: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    q = db.query(Alert).filter(Alert.org_id.in_(org_ids))
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if rule_id:
        q = q.filter(Alert.rule_id == rule_id)

    total = q.count()
    sort_col = getattr(Alert, sort_by, Alert.fired_at)
    q = q.order_by(sort_col.desc() if order == "desc" else sort_col.asc())
    alerts = q.offset((page - 1) * page_size).limit(page_size).all()

    return {"items": [_alert_to_dict(a) for a in alerts], "total": total, "page": page, "page_size": page_size}


@router.get("/api/alerts/{alert_id}")
async def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id.in_(org_ids)).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    return _alert_to_dict(alert)


@router.patch("/api/alerts/{alert_id}")
async def update_alert(
    alert_id: int, body: AlertUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id.in_(org_ids)).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    for field, val in body.dict(exclude_unset=True).items():
        setattr(alert, field, val)
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    log_audit(db, "update", "alert", alert.id, entity_name=f"Alert #{alert.id}",
              changes=body.dict(exclude_unset=True), actor=current_user)
    return _alert_to_dict(alert)


@router.post("/api/alerts/{alert_id}/triage")
async def triage_alert(
    alert_id: int, body: AlertUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Assign, change status, or link to campaign."""
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id.in_(org_ids)).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    if body.status:
        alert.status = body.status
    if body.assigned_to is not None:
        alert.assigned_to = body.assigned_to
    if body.campaign_id is not None:
        alert.campaign_id = body.campaign_id
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return _alert_to_dict(alert)
