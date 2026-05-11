"""Identity discovery orchestration.

Single entrypoint ``run_identity_discovery(db, org_id)`` that an APScheduler
job (or an admin API) calls. The function:

1. Hard-skips if consent is missing/revoked/expired or the feature flag
   is off — fails closed.
2. Resolves the company name to query against (operator-set onboarding
   value wins, else corporate-entity legal name, else org name).
3. Runs the configured ``IdentitySource``.
4. Hands the result to ``apply_discovery_result`` for upsert + lifecycle.

The source is injectable so a future caller can swap in Hunter/Apollo
without reaching into this module.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from models.models import Organization
from models.threat_intel_models import CorporateEntity

from .consent import is_identity_discovery_permitted
from .ddg_linkedin import DdgLinkedInSource
from .lifecycle import apply_discovery_result
from .sources import IdentitySource

logger = logging.getLogger(__name__)


def _name_from_easm_domain(easm_domain: str | None) -> str | None:
    """Derive a LinkedIn-search-friendly company name from an EASM domain.

    ``abirasecurity.com`` → ``abirasecurity``. DDGS tokenizes well enough
    that the apex-without-TLD usually surfaces the right LinkedIn results
    even when the actual company name is multi-word ("Abira Security").
    Strips a leading ``www.`` so domains like ``www.acme.co.uk`` resolve
    to ``acme`` rather than ``www``.
    """
    if not easm_domain:
        return None
    host = easm_domain.strip().lower()
    if host.startswith("www."):
        host = host[4:]
    label = host.split(".")[0]
    return label or None


def _resolve_company_name(db: Session, org_id: int, org: Organization) -> str | None:
    """Pick the name we'll query the source with.

    Precedence:
    1. Parent ``CorporateEntity.legal_name`` — Wikidata-verified, usually
       the cleanest match when available.
    2. The apex label of ``Organization.easm_domain`` — operator-attested
       at scan setup, so much higher signal than the display name. For
       ``abirasecurity.com`` this yields ``abirasecurity``, which DDGS
       tokenizes to surface "Abira Security" employees.
    3. ``Organization.name`` — last resort. Display names like "Other"
       or "Test Org" produce SERP noise, so we'd rather skip than query
       with one of those, but it's still worth trying when nothing else
       is available.
    """
    corp = (
        db.query(CorporateEntity)
        .filter(CorporateEntity.org_id == org_id)
        .order_by(
            (CorporateEntity.category == "parent").desc(),
            CorporateEntity.id.asc(),
        )
        .first()
    )
    if corp and corp.legal_name:
        return corp.legal_name

    domain_name = _name_from_easm_domain(getattr(org, "easm_domain", None))
    if domain_name:
        return domain_name

    return org.name or None


def run_identity_discovery(
    db: Session,
    org_id: int,
    *,
    source: IdentitySource | None = None,
    max_results: int = 25,
) -> dict:
    """Run one identity discovery cycle for ``org_id``.

    Returns the lifecycle summary from ``apply_discovery_result`` extended
    with a ``status`` field:

    * ``'skipped_no_consent'`` — kill switch off or consent missing/expired
    * ``'skipped_no_company_name'`` — couldn't resolve what to query
    * ``'ok'`` — ran end-to-end (whether or not records were found)
    """
    if not is_identity_discovery_permitted(db, org_id):
        logger.info(
            "Identity discovery skipped for org=%s: consent gate failed", org_id,
        )
        return {"status": "skipped_no_consent"}

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if org is None:
        return {"status": "skipped_no_consent"}

    company_name = _resolve_company_name(db, org_id, org)
    if not company_name:
        logger.info(
            "Identity discovery skipped for org=%s: no resolvable company name", org_id,
        )
        return {"status": "skipped_no_company_name"}

    src = source or DdgLinkedInSource()
    result = src.discover(company_name, max_results=max_results)
    summary = apply_discovery_result(
        db, org_id=org_id, source=src.name, result=result,
    )
    summary["status"] = "ok"
    summary["company_name"] = company_name
    return summary
