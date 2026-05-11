"""Identity discovery: consent grant/revoke, erasure (GDPR Art. 17), and
on-demand run-trigger endpoints.

Consent is a hard prerequisite — every other endpoint here also re-checks
the envelope via ``is_identity_discovery_permitted`` before doing anything
that touches LinkedIn data, so this router can't be bypassed by hitting an
endpoint out of order.

All write endpoints require ``org_admin`` or ``superadmin``. Identity data
is personal data with regulatory teeth; we don't want analysts toggling
processing flags or running erasure on behalf of others.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.auth import (
    get_accessible_org_ids,
    get_current_user,
    require_role,
)
from core.database import get_db
from models.models import (
    Asset,
    DataProcessingConsent,
    IdentitySuppression,
    Organization,
    Scan,
    User,
)
from services.identity_discovery import (
    IDENTITY_DISCOVERY_PURPOSE,
    canonicalize_linkedin_slug,
    is_identity_discovery_permitted,
    run_identity_discovery,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/identity-discovery", tags=["identity-discovery"])

# Default consent validity. Per-purpose so identity_discovery can have a
# shorter window than future, lower-risk purposes without code changes.
_CONSENT_VALIDITY = timedelta(days=365)


def _resolve_org_id(org_ids: list[int], user: User) -> int:
    if org_ids:
        return org_ids[0]
    if user.org_id:
        return user.org_id
    raise HTTPException(400, "No org context available")


# ── Request/response models ─────────────────────────────────────────


class ConsentGrantRequest(BaseModel):
    acknowledgment_text: str = Field(
        ...,
        min_length=20,
        description=(
            "Snapshot of the consent text the admin acknowledged. The UI "
            "sends back the exact wording it displayed so we have proof "
            "later even if the legal copy changes."
        ),
    )


class ConsentStatusResponse(BaseModel):
    enabled: bool
    permitted: bool
    granted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    granted_by_user_id: Optional[int] = None


class SuppressionRequest(BaseModel):
    linkedin_url: str = Field(..., description="Profile URL or slug to suppress.")
    reason: Optional[str] = Field(None, max_length=2000)


class RunResponse(BaseModel):
    status: str
    no_signal: Optional[bool] = None
    created: Optional[int] = None
    updated: Optional[int] = None
    stale_now: Optional[int] = None
    company_name: Optional[str] = None


# ── Endpoints ───────────────────────────────────────────────────────


@router.get("/consent", response_model=ConsentStatusResponse)
def get_consent_status(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    org_id = _resolve_org_id(org_ids, user)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    consent = (
        db.query(DataProcessingConsent)
        .filter(
            DataProcessingConsent.org_id == org_id,
            DataProcessingConsent.purpose == IDENTITY_DISCOVERY_PURPOSE,
            DataProcessingConsent.revoked_at.is_(None),
        )
        .order_by(DataProcessingConsent.granted_at.desc())
        .first()
    )
    return ConsentStatusResponse(
        enabled=bool(org and org.identity_discovery_enabled),
        permitted=is_identity_discovery_permitted(db, org_id),
        granted_at=consent.granted_at if consent else None,
        expires_at=consent.expires_at if consent else None,
        granted_by_user_id=consent.granted_by_user_id if consent else None,
    )


@router.post("/consent", response_model=ConsentStatusResponse)
def grant_consent(
    body: ConsentGrantRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("superadmin", "org_admin")),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Grant consent for ``identity_discovery`` and flip the kill switch on.

    Idempotent — granting again just supersedes the previous consent row
    with a fresh ``granted_at`` / ``expires_at``. Any previously revoked
    rows are left intact for audit.
    """
    org_id = _resolve_org_id(org_ids, user)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    now = datetime.utcnow()
    consent = DataProcessingConsent(
        org_id=org_id,
        purpose=IDENTITY_DISCOVERY_PURPOSE,
        granted_by_user_id=user.id,
        granted_at=now,
        expires_at=now + _CONSENT_VALIDITY,
        acknowledgment_text=body.acknowledgment_text,
    )
    db.add(consent)
    org.identity_discovery_enabled = True
    db.commit()

    logger.info(
        "Identity discovery consent granted org=%s by user=%s expires=%s",
        org_id, user.id, consent.expires_at,
    )
    return ConsentStatusResponse(
        enabled=True,
        permitted=True,
        granted_at=consent.granted_at,
        expires_at=consent.expires_at,
        granted_by_user_id=user.id,
    )


@router.delete("/consent", response_model=ConsentStatusResponse)
def revoke_consent(
    db: Session = Depends(get_db),
    user: User = Depends(require_role("superadmin", "org_admin")),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Revoke consent + flip the kill switch off.

    All non-revoked consent rows for this org are marked revoked — defensive
    against the (unlikely) state where multiple active rows coexist. The
    feature flag is also turned off so the gate fails fast.
    """
    org_id = _resolve_org_id(org_ids, user)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    now = datetime.utcnow()
    affected = (
        db.query(DataProcessingConsent)
        .filter(
            DataProcessingConsent.org_id == org_id,
            DataProcessingConsent.purpose == IDENTITY_DISCOVERY_PURPOSE,
            DataProcessingConsent.revoked_at.is_(None),
        )
        .update({"revoked_at": now}, synchronize_session=False)
    )
    org.identity_discovery_enabled = False
    db.commit()
    logger.info(
        "Identity discovery consent revoked org=%s by user=%s rows=%d",
        org_id, user.id, affected,
    )
    return ConsentStatusResponse(
        enabled=False,
        permitted=False,
        granted_at=None,
        expires_at=None,
        granted_by_user_id=None,
    )


@router.post("/suppressions", status_code=201)
def request_erasure(
    body: SuppressionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("superadmin", "org_admin")),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """GDPR Article 17 right-to-erasure entry point.

    Effects, in order:
    1. Canonicalize the input to a LinkedIn slug.
    2. Upsert an ``identity_suppressions`` row so future discovery runs
       skip the slug.
    3. Hard-delete any existing ``asset_type='identity'`` row matching that
       slug under this org — the user's data must actually leave the table,
       not wait for the next scheduled run.

    Idempotent: requesting erasure of an already-suppressed slug returns
    success with ``already_suppressed=True``.
    """
    org_id = _resolve_org_id(org_ids, user)
    slug = canonicalize_linkedin_slug(body.linkedin_url)
    if not slug:
        raise HTTPException(400, "Could not parse a LinkedIn profile slug from the input")

    existing = (
        db.query(IdentitySuppression)
        .filter(
            IdentitySuppression.org_id == org_id,
            IdentitySuppression.source == "linkedin",
            IdentitySuppression.slug == slug,
        )
        .first()
    )
    if existing:
        already = True
    else:
        already = False
        db.add(IdentitySuppression(
            org_id=org_id,
            source="linkedin",
            slug=slug,
            suppressed_by_user_id=user.id,
            reason=body.reason,
        ))

    # Hard-delete any existing identity asset matching this slug for this
    # org. Uses the scan-join org filter pattern (same as asset_routes.py)
    # rather than Asset.org_id, which isn't guaranteed on older schemas.
    deleted = 0
    candidates = (
        db.query(Asset)
        .join(Scan, Asset.scan_id == Scan.id)
        .filter(Scan.org_id == org_id, Asset.asset_type == "identity")
        .all()
    )
    for asset in candidates:
        ident = asset.asset_identity or {}
        if ident.get("source") == "linkedin" and ident.get("slug") == slug:
            db.delete(asset)
            deleted += 1

    db.commit()
    logger.info(
        "Identity suppression added org=%s slug=%s by user=%s deleted=%d already=%s",
        org_id, slug, user.id, deleted, already,
    )
    return {"slug": slug, "already_suppressed": already, "assets_deleted": deleted}


@router.delete("/suppressions/{slug}")
def lift_suppression(
    slug: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("superadmin", "org_admin")),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Admin-only escape hatch: remove a suppression entry.

    Used when an erasure was added by mistake. Does NOT re-create the
    asset — the next scheduled discovery run will rediscover it if the
    person is still in the SERP.
    """
    org_id = _resolve_org_id(org_ids, user)
    canonical = canonicalize_linkedin_slug(slug) or slug.strip().lower()
    affected = (
        db.query(IdentitySuppression)
        .filter(
            IdentitySuppression.org_id == org_id,
            IdentitySuppression.source == "linkedin",
            IdentitySuppression.slug == canonical,
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    if not affected:
        raise HTTPException(404, "No suppression entry for that slug")
    return {"slug": canonical, "removed": affected}


@router.post("/run", response_model=RunResponse)
def trigger_run(
    db: Session = Depends(get_db),
    user: User = Depends(require_role("superadmin", "org_admin")),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Run identity discovery for this org now.

    Convenience for admins who don't want to wait for the weekly cron.
    Still subject to the consent envelope — fails closed if consent is
    missing.
    """
    org_id = _resolve_org_id(org_ids, user)
    summary = run_identity_discovery(db, org_id)
    db.commit()
    return RunResponse(**summary)
