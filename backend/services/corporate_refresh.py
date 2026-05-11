"""Monthly refresh of corporate-entity profile data.

The initial fetch happens automatically when an EASM scan completes
(``services/easm.py``). This service re-runs Wikidata sync for every org
that already has a linked entity so profile fields (industry, employee
band, founded year, homepage) stay current as Wikidata is updated.

Refresh is name-based via the existing ``sync_corporate_tree_to_db``
pipeline — same idempotent upsert path as the initial sync, so operator-set
onboarding values remain protected by ``effective_company_profile``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from models.models import Organization
from models.threat_intel_models import CorporateEntity

logger = logging.getLogger(__name__)

# Skip orgs whose corporate entity was updated within this window — the
# initial post-EASM sync would otherwise be undone moments later by the
# monthly cron. Also protects against accidental double-scheduling.
_MIN_AGE_BEFORE_REFRESH = timedelta(days=14)


def refresh_all_corporate_profiles(db: Session) -> dict:
    """Re-sync Wikidata for every org with an existing linked CorporateEntity.

    Returns ``{"refreshed": int, "skipped": int, "failed": int}``.
    """
    from threat_intel.wikidata_sync import sync_corporate_tree_to_db

    cutoff = datetime.utcnow() - _MIN_AGE_BEFORE_REFRESH
    # One row per (org_id, root entity) — prefer the parent entity if both
    # parent and subsidiary entities link to the same org.
    rows = (
        db.query(Organization.id, Organization.name, CorporateEntity.legal_name, CorporateEntity.updated_at)
        .join(CorporateEntity, CorporateEntity.org_id == Organization.id)
        .filter(Organization.is_active.is_(True))
        .order_by(
            Organization.id.asc(),
            (CorporateEntity.category == "parent").desc(),
            CorporateEntity.id.asc(),
        )
        .all()
    )

    seen_orgs: set[int] = set()
    refreshed = skipped = failed = 0

    for org_id, org_name, legal_name, updated_at in rows:
        if org_id in seen_orgs:
            continue
        seen_orgs.add(org_id)

        if updated_at and updated_at > cutoff:
            skipped += 1
            continue

        company_name = legal_name or org_name
        try:
            sync_corporate_tree_to_db(db, company_name, org_id=org_id)
            # Propagate fresh industry/employee_band into org_memory so
            # agents see the updated values without waiting for the next
            # onboarding event (which may never come for established orgs).
            # Wrapped separately — a memory-sync failure here must not roll
            # back the successful Wikidata write.
            try:
                from services.org_memory import sync_org_profile_to_memory
                sync_org_profile_to_memory(db, org_id)
            except Exception:
                logger.exception(
                    "Org memory sync failed after corporate refresh org=%s (non-fatal)",
                    org_id,
                )
            refreshed += 1
        except Exception:
            logger.exception(
                "Corporate refresh failed for org=%s name=%r (non-fatal)",
                org_id, company_name,
            )
            failed += 1
            db.rollback()

    logger.info(
        "Corporate refresh complete: refreshed=%d skipped=%d failed=%d",
        refreshed, skipped, failed,
    )
    return {"refreshed": refreshed, "skipped": skipped, "failed": failed}
