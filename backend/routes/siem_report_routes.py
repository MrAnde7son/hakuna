"""SIEM report endpoints — /api/reports/siem-*

Provides dashboard KPIs and widget data for SIEM report builder.
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from core.time_utils import iso_utc
from models.models import SIEMEvent, DetectionRule, Alert

router = APIRouter()


@router.get("/api/reports/siem-summary")
async def siem_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """SIEM dashboard KPIs."""
    now = datetime.utcnow()
    day_ago = now - timedelta(hours=24)

    eq = db.query(func.count(SIEMEvent.id)).filter(SIEMEvent.event_time >= day_ago)
    if org_ids is not None:
        eq = eq.filter(SIEMEvent.org_id.in_(org_ids))
    events_24h = eq.scalar() or 0

    aq = db.query(func.count(Alert.id)).filter(Alert.status == "open")
    if org_ids is not None:
        aq = aq.filter(Alert.org_id.in_(org_ids))
    alerts_open = aq.scalar() or 0

    rq = db.query(func.count(DetectionRule.id)).filter(DetectionRule.enabled == True)
    if org_ids is not None:
        rq = rq.filter(DetectionRule.org_id.in_(org_ids))
    rules_active = rq.scalar() or 0

    # MTTR: average time from alert creation to close (last 30 days)
    cq = db.query(Alert).filter(
        Alert.status.in_(["closed", "false_positive"]),
        Alert.created_at >= now - timedelta(days=30),
        Alert.updated_at.isnot(None),
    )
    if org_ids is not None:
        cq = cq.filter(Alert.org_id.in_(org_ids))
    closed_alerts = cq.all()
    mttr_minutes = 0
    if closed_alerts:
        total_minutes = sum(
            (a.updated_at - a.created_at).total_seconds() / 60
            for a in closed_alerts if a.updated_at and a.created_at
        )
        mttr_minutes = round(total_minutes / len(closed_alerts), 1)

    # Top 5 assets by alert count
    tq = db.query(
        Alert.asset_id, func.count(Alert.id).label("alert_count")
    ).filter(Alert.asset_id.isnot(None))
    if org_ids is not None:
        tq = tq.filter(Alert.org_id.in_(org_ids))
    top_assets = tq.group_by(Alert.asset_id).order_by(func.count(Alert.id).desc()).limit(5).all()

    return {
        "events_24h": events_24h,
        "alerts_open": alerts_open,
        "detection_rules_active": rules_active,
        "mttr_minutes": mttr_minutes,
        "top_5_assets_by_alerts": [
            {"asset_id": a[0], "alert_count": a[1]} for a in top_assets
        ],
    }


@router.get("/api/reports/siem-event-volume")
async def event_volume(
    hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Event volume over time, grouped by source_system (for stacked area chart)."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    vq = db.query(
        SIEMEvent.source_system,
        func.count(SIEMEvent.id).label("count"),
    ).filter(SIEMEvent.event_time >= cutoff)
    if org_ids is not None:
        vq = vq.filter(SIEMEvent.org_id.in_(org_ids))
    rows = vq.group_by(SIEMEvent.source_system).order_by(func.count(SIEMEvent.id).desc()).limit(10).all()

    return {
        "hours": hours,
        "sources": [{"source_system": r[0], "count": r[1]} for r in rows],
    }


@router.get("/api/reports/siem-noisy-sources")
async def noisy_sources(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Top sources by alert count with false-positive rate."""
    sources = db.query(
        DetectionRule.name,
        func.count(Alert.id).label("total_alerts"),
        func.sum(case((Alert.status == "false_positive", 1), else_=0)).label("fp_count"),
    ).join(Alert, Alert.rule_id == DetectionRule.id)
    if org_ids is not None:
        sources = sources.filter(Alert.org_id.in_(org_ids))
    sources = sources.group_by(DetectionRule.name).order_by(func.count(Alert.id).desc()).limit(10).all()

    result = []
    for row in sources:
        total = row[1] or 0
        fp = row[2] or 0
        result.append({
            "rule_name": row[0],
            "total_alerts": total,
            "false_positives": fp,
            "fp_rate": round(fp / total * 100, 1) if total > 0 else 0,
        })
    return result


@router.get("/api/reports/siem-alert-severity")
async def alert_severity_breakdown(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Alert breakdown by severity for pie chart widget."""
    q = db.query(
        Alert.severity, func.count(Alert.id).label("count")
    ).filter(Alert.status == "open")
    if org_ids is not None:
        q = q.filter(Alert.org_id.in_(org_ids))
    rows = q.group_by(Alert.severity).all()
    return [{"severity": r[0], "count": r[1]} for r in rows]


@router.get("/api/reports/siem-recent-alerts")
async def recent_alerts(
    limit: int = Query(default=15, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Recent open alerts for table widget."""
    from models.models import Asset

    q = db.query(Alert).filter(Alert.status == "open", Alert.suppressed == False)
    if org_ids is not None:
        q = q.filter(Alert.org_id.in_(org_ids))
    alerts = q.order_by(Alert.fired_at.desc()).limit(limit).all()

    # Resolve rule names and asset names
    rule_ids = {a.rule_id for a in alerts if a.rule_id}
    rules = {r.id: r for r in db.query(DetectionRule).filter(DetectionRule.id.in_(rule_ids)).all()} if rule_ids else {}
    asset_ids = {a.asset_id for a in alerts if a.asset_id}
    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()} if asset_ids else {}

    return [
        {
            "id": a.id,
            "rule_name": rules.get(a.rule_id, None) and rules[a.rule_id].name,
            "severity": a.severity,
            "event_count": a.event_count,
            "entity_value": a.entity_value,
            "asset_name": assets.get(a.asset_id, None) and (assets[a.asset_id].hostname or assets[a.asset_id].ip),
            "fired_at": iso_utc(a.fired_at),
        }
        for a in alerts
    ]
