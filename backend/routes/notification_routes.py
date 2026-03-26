"""
Notification system — FastAPI routes
Prefix: /api/notifications
"""
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from models.models import (
    Notification, NotificationRead, UserPageVisit,
    Finding, Asset, Scan, User,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/notifications", tags=["notifications"])


# ── Schemas ──────────────────────────────────────────────

class PageVisitBody(BaseModel):
    page_key: str


# ── List notifications ───────────────────────────────────

@router.get("")
async def list_notifications(
    page: int = 1,
    page_size: int = 20,
    category: Optional[str] = None,
    unread_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """List notifications for the current user's org(s), newest first."""
    if current_user is None:
        raise HTTPException(401, "Authentication required")

    query = db.query(Notification)
    if org_ids is not None:
        query = query.filter(Notification.org_id.in_(org_ids))

    if category:
        query = query.filter(Notification.category == category)

    # Build a subquery of read notification IDs for this user
    read_ids_sq = (
        db.query(NotificationRead.notification_id)
        .filter(NotificationRead.user_id == current_user.id)
        .subquery()
    )

    if unread_only:
        query = query.filter(~Notification.id.in_(db.query(read_ids_sq.c.notification_id)))

    total = query.count()
    items = (
        query.order_by(desc(Notification.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    # Fetch which of these the user has read
    item_ids = [n.id for n in items]
    read_set = set()
    if item_ids:
        read_rows = (
            db.query(NotificationRead.notification_id)
            .filter(
                NotificationRead.user_id == current_user.id,
                NotificationRead.notification_id.in_(item_ids),
            )
            .all()
        )
        read_set = {r[0] for r in read_rows}

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": n.id,
                "category": n.category,
                "title": n.title,
                "body": n.body,
                "link": n.link,
                "entity_type": n.entity_type,
                "entity_id": n.entity_id,
                "metadata": n.metadata_,
                "created_at": n.created_at.isoformat() if n.created_at else None,
                "is_read": n.id in read_set,
            }
            for n in items
        ],
    }


# ── Unread count ─────────────────────────────────────────

@router.get("/unread-count")
async def unread_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Lightweight endpoint for the bell badge — returns unread count."""
    if current_user is None:
        raise HTTPException(401, "Authentication required")

    read_ids_sq = (
        db.query(NotificationRead.notification_id)
        .filter(NotificationRead.user_id == current_user.id)
        .subquery()
    )

    query = db.query(func.count(Notification.id)).filter(
        ~Notification.id.in_(db.query(read_ids_sq.c.notification_id))
    )
    if org_ids is not None:
        query = query.filter(Notification.org_id.in_(org_ids))

    count = query.scalar() or 0
    return {"count": count}


# ── Mark read ────────────────────────────────────────────

@router.post("/{notification_id}/read")
async def mark_read(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user is None:
        raise HTTPException(401, "Authentication required")

    existing = (
        db.query(NotificationRead)
        .filter(
            NotificationRead.user_id == current_user.id,
            NotificationRead.notification_id == notification_id,
        )
        .first()
    )
    if not existing:
        db.add(NotificationRead(user_id=current_user.id, notification_id=notification_id))
        db.commit()
    return {"ok": True}


@router.post("/read-all")
async def mark_all_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Mark all notifications as read for the current user."""
    if current_user is None:
        raise HTTPException(401, "Authentication required")

    # Get all unread notification IDs for user's orgs
    read_ids_sq = (
        db.query(NotificationRead.notification_id)
        .filter(NotificationRead.user_id == current_user.id)
        .subquery()
    )

    query = db.query(Notification.id).filter(
        ~Notification.id.in_(db.query(read_ids_sq.c.notification_id))
    )
    if org_ids is not None:
        query = query.filter(Notification.org_id.in_(org_ids))

    unread_ids = [r[0] for r in query.all()]
    for nid in unread_ids:
        db.add(NotificationRead(user_id=current_user.id, notification_id=nid))
    db.commit()
    return {"ok": True, "marked": len(unread_ids)}


# ── Page visits (for "new since" feature) ────────────────

@router.post("/page-visit")
async def record_page_visit(
    body: PageVisitBody,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Record that the user visited a page. Upserts the timestamp."""
    if current_user is None:
        raise HTTPException(401, "Authentication required")

    visit = (
        db.query(UserPageVisit)
        .filter(
            UserPageVisit.user_id == current_user.id,
            UserPageVisit.page_key == body.page_key,
        )
        .first()
    )
    if visit:
        visit.last_visited_at = datetime.utcnow()
    else:
        db.add(UserPageVisit(
            user_id=current_user.id,
            page_key=body.page_key,
            last_visited_at=datetime.utcnow(),
        ))
    db.commit()
    return {"ok": True}


@router.get("/new-since")
async def new_since_counts(
    pages: str = Query(..., description="Comma-separated page keys: findings,assets,threat_intel,campaigns:3"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Return counts of new items since the user's last visit per page."""
    if current_user is None:
        raise HTTPException(401, "Authentication required")

    page_keys = [p.strip() for p in pages.split(",") if p.strip()]
    result = {}

    # Fetch all relevant visit timestamps in one query
    visits = (
        db.query(UserPageVisit)
        .filter(
            UserPageVisit.user_id == current_user.id,
            UserPageVisit.page_key.in_(page_keys),
        )
        .all()
    )
    visit_map = {v.page_key: v.last_visited_at for v in visits}

    for key in page_keys:
        last_visit = visit_map.get(key)
        if last_visit is None:
            # Never visited — don't show a huge number, just 0
            result[key] = 0
            continue

        try:
            if key == "findings":
                # Count findings from scans created after last visit
                count = (
                    db.query(func.count(Finding.id))
                    .join(Scan, Finding.scan_id == Scan.id)
                    .filter(Scan.created_at > last_visit)
                )
                if org_ids is not None:
                    count = count.filter(Scan.org_id.in_(org_ids))
                result[key] = count.scalar() or 0

            elif key == "assets":
                # Count assets first seen after last visit
                count = db.query(func.count(Asset.id)).filter(
                    Asset.first_seen > last_visit,
                )
                if org_ids is not None:
                    count = count.join(Scan, Asset.scan_id == Scan.id).filter(
                        Scan.org_id.in_(org_ids)
                    )
                result[key] = count.scalar() or 0

            elif key == "threat_intel":
                # Count new KEV entries since last visit
                try:
                    from models.threat_intel_models import ThreatCVE
                    count = (
                        db.query(func.count(ThreatCVE.id))
                        .filter(ThreatCVE.in_kev == True, ThreatCVE.created_at > last_visit)
                        .scalar() or 0
                    )
                except Exception:
                    count = 0
                result[key] = count

            elif key.startswith("campaigns:"):
                # Count new campaign findings since last visit
                campaign_id = key.split(":")[1]
                from models.models import CampaignFinding
                count = (
                    db.query(func.count(CampaignFinding.id))
                    .filter(
                        CampaignFinding.campaign_id == int(campaign_id),
                        CampaignFinding.added_at > last_visit,
                    )
                    .scalar() or 0
                )
                result[key] = count

            else:
                result[key] = 0
        except Exception as e:
            logger.warning(f"new-since count failed for {key}: {e}")
            result[key] = 0

    return result
