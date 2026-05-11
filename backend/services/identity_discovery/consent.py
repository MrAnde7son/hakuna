"""Consent envelope for identity discovery.

The discovery worker must hard-skip unless **both** of the following are
true for an org:

1. ``organizations.identity_discovery_enabled`` is True (admin kill switch).
2. An active ``DataProcessingConsent`` row exists for
   ``purpose='identity_discovery'`` — not revoked, not expired.

This module exposes a single boolean check used by the discovery service
and by any future caller that needs to gate the same behavior.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from models.models import DataProcessingConsent, Organization

IDENTITY_DISCOVERY_PURPOSE = "identity_discovery"


def is_identity_discovery_permitted(db: Session, org_id: int) -> bool:
    """Return True iff the org has both opted in and signed an active consent
    for ``identity_discovery``. Defaults to False — callers should fail closed.

    Inactive (suspended/closed) orgs are blocked here too, not just at the
    weekly dispatcher. This protects the on-demand ``POST /run`` endpoint:
    a token issued to a now-inactive org can still authenticate, but it
    must not trigger personal-data processing.
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org or not org.identity_discovery_enabled or not org.is_active:
        return False

    now = datetime.utcnow()
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
    if not consent:
        return False
    if consent.expires_at is not None and consent.expires_at <= now:
        return False
    return True
