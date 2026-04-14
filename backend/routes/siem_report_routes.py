"""SIEM report endpoints — /api/reports/siem-*

Provides dashboard KPIs and widget data for SIEM report builder.
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
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

    events_24h = db.query(func.count(SIEMEvent.id)).filter(
        SIEMEvent.org_id.in_(org_ids),
        SIEMEvent.event_time >= day_ago,
    ).scalar() or 0

    alerts_open = db.query(func.count(Alert.id)).filter(
        Alert.org_id.in_(org_ids),
        Alert.status == "open",
    ).scalar() or 0

    rules_active = db.query(func.count(DetectionRule.id)).filter(
        DetectionRule.org_id.in_(org_ids),
        DetectionRule.enabled == True,
    ).scalar() or 0

    # MTTR: average time from alert creation to close (last 30 days)
    closed_alerts = db.query(Alert).filter(
        Alert.org_id.in_(org_ids),
        Alert.status.in_(["closed", "false_positive"]),
        Alert.created_at >= now - timedelta(days=30),
        Alert.updated_at.isnot(None),
    ).all()
    mttr_minutes = 0
    if closed_alerts:
        total_minutes = sum(
            (a.updated_at - a.created_at).total_seconds() / 60
            for a in closed_alerts if a.updated_at and a.created_at
        )
        mttr_minutes = round(total_minutes / len(closed_alerts), 1)

    # Top 5 assets by alert count
    top_assets = db.query(
        Alert.asset_id, func.count(Alert.id).label("alert_count")
    ).filter(
        Alert.org_id.in_(org_ids),
        Alert.asset_id.isnot(None),
    ).group_by(Alert.asset_id).order_by(func.count(Alert.id).desc()).limit(5).all()

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

    rows = db.query(
        SIEMEvent.source_system,
        func.count(SIEMEvent.id).label("count"),
    ).filter(
        SIEMEvent.org_id.in_(org_ids),
        SIEMEvent.event_time >= cutoff,
    ).group_by(SIEMEvent.source_system).order_by(func.count(SIEMEvent.id).desc()).limit(10).all()

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
        func.sum(func.cast(Alert.status == "false_positive", db.bind.dialect.type_descriptor(type(1)) if hasattr(db.bind, 'dialect') else type(1))).label("fp_count"),
    ).join(Alert, Alert.rule_id == DetectionRule.id).filter(
        Alert.org_id.in_(org_ids),
    ).group_by(DetectionRule.name).order_by(func.count(Alert.id).desc()).limit(10).all()

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
