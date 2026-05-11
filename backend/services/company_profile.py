"""Effective company profile — merges onboarding-collected values with
Wikidata-fetched fallback so callers don't have to know about both sources.

Precedence (per field):
  1. ``Organization.settings['onboarding']['profile'][<field>]`` if non-empty
     — operator-entered values always win, even if stale.
  2. ``CorporateEntity`` linked by ``org_id`` — populated by the corporate
     enrichment task from Wikidata.
  3. ``None``.

The shape returned matches the onboarding profile vocabulary so the read
path is uniform: ``industry``, ``org_size``, ``founded_year``, ``homepage_url``,
plus ``_sources`` mapping each field to ``'onboarding' | 'corporate_entity' | None``
for downstream "is this user-confirmed?" checks.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from models.models import Organization
from models.threat_intel_models import CorporateEntity


_PROFILE_FIELDS = ("industry", "org_size", "founded_year", "homepage_url")

# CorporateEntity uses ``employee_count_band``; onboarding uses ``org_size``.
# Same band vocabulary, different column names — we expose ``org_size``.
_CE_FIELD_MAP = {
    "industry": "industry",
    "org_size": "employee_count_band",
    "founded_year": "founded_year",
    "homepage_url": "homepage_url",
}


def _onboarding_profile(org: Organization) -> dict[str, Any]:
    settings = org.settings or {}
    onboarding = settings.get("onboarding") or {}
    return onboarding.get("profile") or {}


def effective_company_profile(db: Session, org_id: int) -> dict[str, Any]:
    """Return ``{field: value, ..., '_sources': {field: source}}`` for ``org_id``.

    Missing fields are present with value ``None`` so callers can iterate
    a stable shape.
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return {f: None for f in _PROFILE_FIELDS} | {"_sources": {}}

    onboarding = _onboarding_profile(org)

    corp: CorporateEntity | None = (
        db.query(CorporateEntity)
        .filter(CorporateEntity.org_id == org_id)
        # If multiple corporate entities are linked (parent + subsidiaries),
        # prefer the one marked ``parent`` — that's the root of the tree.
        .order_by((CorporateEntity.category == "parent").desc(), CorporateEntity.id.asc())
        .first()
    )

    result: dict[str, Any] = {}
    sources: dict[str, str | None] = {}

    for field in _PROFILE_FIELDS:
        ob_val = onboarding.get(field)
        if ob_val not in (None, "", [], {}):
            result[field] = ob_val
            sources[field] = "onboarding"
            continue
        if corp is not None:
            ce_val = getattr(corp, _CE_FIELD_MAP[field], None)
            if ce_val not in (None, ""):
                result[field] = ce_val
                sources[field] = "corporate_entity"
                continue
        result[field] = None
        sources[field] = None

    result["_sources"] = sources
    return result
