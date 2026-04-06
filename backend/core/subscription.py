"""
Subscription-gating FastAPI dependencies.

All features are available on every tier. Free tier has reduced quotas
(scans, users, campaigns, AI tokens). Pro tier removes those limits.
"""
import logging

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from core.database import get_db
from core.auth import require_auth
from models.models import Organization, User, Scan, Campaign

logger = logging.getLogger(__name__)

FREE_SCAN_LIMIT = 3        # total scans (upload, integration, EASM, VM)
FREE_USER_LIMIT = 3
FREE_CAMPAIGN_LIMIT = 3


def _is_pro(org: Organization) -> bool:
    tier = org.subscription_tier or "free"
    return tier == "pro" and org.subscription_status in ("active", "trialing")


def _get_org(db: Session, user: User) -> Organization:
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


def get_subscription_tier(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
) -> str:
    """Return the current org's subscription tier."""
    org = _get_org(db, user)
    return org.subscription_tier or "free"


def require_pro(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
) -> User:
    """Raise 402 if the org is not on an active Pro subscription."""
    if user.role == "superadmin":
        return user
    org = _get_org(db, user)
    if _is_pro(org):
        return user
    raise HTTPException(402, "This feature requires a Pro subscription. Upgrade at /billing.")


def check_scan_limit(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
) -> User:
    """Allow scan creation if Pro, or if free tier hasn't exceeded 3 total scans."""
    if user.role == "superadmin":
        return user
    org = _get_org(db, user)
    if _is_pro(org):
        return user

    count = (
        db.query(func.count(Scan.id))
        .filter(Scan.org_id == org.id)
        .scalar()
    )
    if count >= FREE_SCAN_LIMIT:
        raise HTTPException(
            402,
            f"Free tier allows {FREE_SCAN_LIMIT} scans total. Upgrade to Pro for unlimited scans.",
        )
    return user


def check_campaign_limit(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
) -> User:
    """Allow campaign creation if Pro, or if free tier hasn't exceeded 3 campaigns."""
    if user.role == "superadmin":
        return user
    org = _get_org(db, user)
    if _is_pro(org):
        return user

    count = (
        db.query(func.count(Campaign.id))
        .filter(Campaign.org_id == org.id)
        .scalar()
    )
    if count >= FREE_CAMPAIGN_LIMIT:
        raise HTTPException(
            402,
            f"Free tier allows {FREE_CAMPAIGN_LIMIT} campaigns. Upgrade to Pro for unlimited campaigns.",
        )
    return user


def check_user_invite_limit(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
) -> User:
    """Allow invite if Pro, or if free tier hasn't exceeded user limit."""
    if user.role == "superadmin":
        return user
    org = _get_org(db, user)
    if _is_pro(org):
        return user

    user_count = db.query(func.count(User.id)).filter(User.org_id == org.id).scalar()
    if user_count >= FREE_USER_LIMIT:
        raise HTTPException(402, "Upgrade to Pro for unlimited users.")
    return user
