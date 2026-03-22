"""
EASM (External Attack Surface Management) routes.
Prefix: /api/easm
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, require_auth
from models.models import Organization, Scan, User
from services.easm import (
    extract_corporate_domain,
    trigger_easm_for_new_org,
    import_easm_assets_for_domain,
    scan_domain,
    refresh_easm_scan,
    get_easm_assets,
    get_easm_asset_stats,
    get_easm_events,
    get_easm_scan_status,
    trigger_easm_scan,
    add_easm_domain,
    get_easm_domains,
    get_easm_scan_runs,
    create_easm_org,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/easm", tags=["easm"])


def _get_org(db: Session, user: User) -> Organization:
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


def _require_easm_org_id(db: Session, org: Organization) -> str:
    """Return easm_org_id, recovering it from scan metadata if missing from the org record."""
    if org.easm_org_id:
        return org.easm_org_id
    easm_scan = db.query(Scan).filter(
        Scan.org_id == org.id,
        Scan.source_type == "easm",
    ).first()
    recovered = (easm_scan.raw_metadata or {}).get("hakuna_org_id") if easm_scan else None
    if recovered:
        org.easm_org_id = recovered
        db.commit()
        logger.info("Recovered easm_org_id %s for org %s from scan metadata", recovered, org.id)
        return recovered
    raise HTTPException(400, "EASM not configured for this organization")


@router.get("/status")
async def easm_status(db: Session = Depends(get_db), user: User = Depends(require_auth)):
    """Get EASM integration status for the current org."""
    org = _get_org(db, user)

    if not org.easm_org_id:
        return {
            "enabled": False,
            "domain": org.easm_domain,
            "message": "EASM not configured. Register with a corporate email to enable.",
        }

    stats = await get_easm_asset_stats(org.easm_org_id)
    return {
        "enabled": True,
        "domain": org.easm_domain,
        "hakuna_org_id": org.easm_org_id,
        "stats": stats,
    }


@router.post("/setup")
async def setup_easm(
    domain: str = Query(..., min_length=3),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Set up EASM for the current org: create hakuna org, add domain, trigger scan."""
    org = _get_org(db, user)

    if org.easm_org_id:
        raise HTTPException(400, "EASM is already configured for this organization")

    # Create hakuna org
    hakuna_org_id = await create_easm_org(org.name)
    if not hakuna_org_id:
        raise HTTPException(502, "Failed to create EASM org — hakuna-scanner may be unavailable")

    # Persist on org
    org.easm_org_id = hakuna_org_id
    org.easm_domain = domain
    db.commit()

    # Scan the domain (adds domain + triggers scan + creates scan record)
    result = await scan_domain(db, org, domain)

    # Apply weekly schedule
    if result and result.get("scan_id"):
        from models.models import Scan
        from services.easm_scheduler import register_scan
        scan = db.query(Scan).filter(Scan.id == result["scan_id"]).first()
        if scan:
            schedule = "0 2 * * 1"
            scan.schedule = schedule
            db.commit()
            register_scan(scan.id, schedule)

    return {
        "enabled": True,
        "domain": domain,
        "hakuna_org_id": hakuna_org_id,
        "scan_id": result.get("scan_id") if result else None,
    }


@router.post("/scan-domain")
async def scan_domain_endpoint(
    domain: str = Query(..., min_length=3),
    scan_type: str = Query("full", regex="^(full|discovery|enrichment)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Add a domain (if new), trigger scan, and create a per-domain scan record."""
    org = _get_org(db, user)
    _require_easm_org_id(db, org)

    result = await scan_domain(db, org, domain, scan_type)
    if result is None:
        raise HTTPException(502, "Failed to scan domain — hakuna-scanner may be unavailable")
    return result


@router.post("/rescan/{scan_id}")
async def rescan_by_scan_id(
    scan_id: int,
    scan_type: str = Query("full", regex="^(full|discovery|enrichment)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Re-trigger an existing EASM scan using the scan's org context.

    Superadmins can rescan any scan; org members can only rescan their own.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.source_type == "easm").first()
    if not scan:
        raise HTTPException(404, "EASM scan not found")
    if user.role != "superadmin" and scan.org_id != user.org_id:
        raise HTTPException(403, "Access denied")

    org = db.query(Organization).filter(Organization.id == scan.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    easm_org_id = _require_easm_org_id(db, org)
    domain = (scan.raw_metadata or {}).get("domain") or org.easm_domain
    if not domain:
        raise HTTPException(400, "No domain associated with this scan")

    result = await scan_domain(db, org, domain, scan_type)
    if result is None:
        raise HTTPException(502, "Failed to trigger scan — hakuna-scanner may be unavailable")
    return result


@router.post("/refresh/{scan_id}")
async def refresh_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Check hakuna scan status and import assets if completed."""
    org = _get_org(db, user)
    _require_easm_org_id(db, org)

    result = await refresh_easm_scan(db, org, scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return result


@router.post("/scan")
async def trigger_scan(
    scan_type: str = Query("full", regex="^(full|discovery|enrichment)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Manually trigger an EASM scan (all domains)."""
    org = _get_org(db, user)
    easm_org_id = _require_easm_org_id(db, org)

    scan_id = await trigger_easm_scan(easm_org_id, scan_type)
    if not scan_id:
        raise HTTPException(502, "Failed to trigger EASM scan — hakuna-scanner may be unavailable")

    return {"scan_id": scan_id, "scan_type": scan_type, "status": "queued"}


@router.get("/scans/{scan_id}")
async def scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Get status of a specific EASM scan."""
    org = _get_org(db, user)
    easm_org_id = _require_easm_org_id(db, org)

    status = await get_easm_scan_status(easm_org_id, scan_id)
    if not status:
        raise HTTPException(404, "Scan not found")
    return status


@router.get("/assets")
async def list_easm_assets(
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """List EASM-discovered assets (from hakuna-scanner, not yet imported)."""
    org = _get_org(db, user)
    easm_org_id = _require_easm_org_id(db, org)

    assets = await get_easm_assets(easm_org_id, limit=limit, offset=offset)
    if assets is None:
        raise HTTPException(502, "Failed to fetch EASM assets")
    return assets


@router.post("/import")
@router.post("/sync")
async def sync_assets(
    domain: Optional[str] = Query(None, min_length=3),
    scan_type: str = Query("full", regex="^(full|discovery|enrichment)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Import EASM-discovered assets. If domain is omitted, sync all configured domains."""
    org = _get_org(db, user)
    easm_org_id = _require_easm_org_id(db, org)

    if domain:
        domains_to_sync = [domain]
    else:
        # Sync all known domains for this org
        remote_domains = await get_easm_domains(easm_org_id) or []
        domains_to_sync = [d["domain"] if isinstance(d, dict) else d for d in remote_domains]
        # Always include the primary domain
        if org.easm_domain and org.easm_domain not in domains_to_sync:
            domains_to_sync.append(org.easm_domain)

    if not domains_to_sync:
        return {"synced": 0, "results": [], "message": "No domains configured"}

    results = []
    for d in domains_to_sync:
        result = await import_easm_assets_for_domain(db, org, d, scan_type=scan_type)
        if result:
            results.append(result)

    return {
        "synced": len(results),
        "results": results,
    }


@router.get("/events")
async def list_events(
    since: Optional[str] = None,
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Get recent EASM change events (new assets, IP changes, cert expirations, etc.)."""
    org = _get_org(db, user)
    easm_org_id = _require_easm_org_id(db, org)

    events = await get_easm_events(easm_org_id, since=since, limit=limit)
    if events is None:
        raise HTTPException(502, "Failed to fetch EASM events")
    return events


@router.get("/domains")
async def list_domains(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """List all target domains for the current org."""
    org = _get_org(db, user)
    easm_org_id = _require_easm_org_id(db, org)

    domains = await get_easm_domains(easm_org_id)
    if domains is None:
        raise HTTPException(502, "Failed to fetch domains")
    return domains


@router.get("/scan-runs")
async def list_scan_runs(
    limit: int = Query(10, le=50),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """List recent EASM scan runs with status."""
    org = _get_org(db, user)
    try:
        easm_org_id = _require_easm_org_id(db, org)
    except HTTPException:
        return []

    runs = await get_easm_scan_runs(easm_org_id, limit=limit)
    if runs is None:
        raise HTTPException(502, "Failed to fetch scan runs")
    return runs


@router.post("/domain")
async def add_domain(
    domain: str = Query(..., min_length=3),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Add an additional target domain for EASM scanning."""
    org = _get_org(db, user)
    easm_org_id = _require_easm_org_id(db, org)

    success = await add_easm_domain(easm_org_id, domain)
    if not success:
        raise HTTPException(502, "Failed to add domain")
    return {"domain": domain, "status": "added"}


# --- Breach Monitoring ---


@router.post("/breaches/sync")
def sync_breaches(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Sync HIBP breach catalog to local database (admin-level, periodic)."""
    from threat_intel.hibp_sync import sync_hibp_breaches_to_db
    result = sync_hibp_breaches_to_db(db)
    return result


@router.post("/breaches/check-domain")
def check_domain_breaches_endpoint(
    domain: str = Query(..., min_length=3),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Check which breaches in the catalog affect a specific domain."""
    from threat_intel.hibp_sync import check_domain_breaches
    org = _get_org(db, user)
    result = check_domain_breaches(db, org.id, domain)
    return result


@router.get("/breaches")
def list_domain_breaches(
    domain: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """List known breaches affecting the org's domains."""
    from models.threat_intel_models import DomainBreach, BreachRecord
    org = _get_org(db, user)

    query = db.query(DomainBreach).filter(DomainBreach.org_id == org.id)
    if domain:
        query = query.filter(DomainBreach.domain == domain)
    domain_breaches = query.order_by(DomainBreach.checked_at.desc()).all()

    results = []
    for db_entry in domain_breaches:
        # Enrich with breach catalog data if available
        breach_detail = db.query(BreachRecord).filter(
            BreachRecord.name == db_entry.breach_name
        ).first()

        results.append({
            "domain": db_entry.domain,
            "breach_name": db_entry.breach_name,
            "exposed_count": db_entry.exposed_count,
            "checked_at": db_entry.checked_at.isoformat() if db_entry.checked_at else None,
            "breach_date": breach_detail.breach_date if breach_detail else None,
            "title": breach_detail.title if breach_detail else db_entry.breach_name,
            "description": breach_detail.description if breach_detail else None,
            "pwn_count": breach_detail.pwn_count if breach_detail else None,
            "data_classes": breach_detail.data_classes if breach_detail else [],
            "is_verified": breach_detail.is_verified if breach_detail else None,
        })

    return results


# --- Corporate Structure (GLEIF) ---


@router.post("/corporate/sync")
def sync_corporate_structure(
    company_name: str = Query(..., min_length=2),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Search GLEIF for a company and import its corporate tree (parent + subsidiaries)."""
    from threat_intel.gleif_sync import sync_entity_tree_to_db
    org = _get_org(db, user)
    result = sync_entity_tree_to_db(db, company_name, org_id=org.id)
    return result


@router.get("/corporate/subsidiaries")
def list_subsidiaries(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """List known subsidiaries for the current org from GLEIF data."""
    from threat_intel.gleif_sync import get_subsidiaries_for_org
    org = _get_org(db, user)
    return get_subsidiaries_for_org(db, org.id)


@router.get("/corporate/search")
def search_corporate_entities(
    q: str = Query(..., min_length=2),
    limit: int = Query(10, le=50),
    user: User = Depends(require_auth),
):
    """Search GLEIF for entities matching a company name (live search, not cached)."""
    from threat_intel.gleif_sync import search_entities
    return search_entities(q, limit=limit)


@router.get("/corporate/entity/{lei}")
def get_corporate_entity(
    lei: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Get a specific corporate entity by LEI (from local DB or live from GLEIF)."""
    from models.threat_intel_models import CorporateEntity
    from threat_intel.gleif_sync import get_entity_by_lei

    # Try local DB first
    entity = db.query(CorporateEntity).filter(CorporateEntity.lei == lei).first()
    if entity:
        return {
            "lei": entity.lei,
            "legal_name": entity.legal_name,
            "trading_name": entity.trading_name,
            "jurisdiction": entity.legal_jurisdiction,
            "status": entity.entity_status,
            "direct_parent_lei": entity.direct_parent_lei,
            "direct_parent_name": entity.direct_parent_name,
            "ultimate_parent_lei": entity.ultimate_parent_lei,
            "ultimate_parent_name": entity.ultimate_parent_name,
            "country": entity.headquarters_country or entity.legal_address_country,
            "city": entity.headquarters_city or entity.legal_address_city,
            "associated_domains": entity.associated_domains or [],
            "source": "local",
        }

    # Fallback to live GLEIF
    live = get_entity_by_lei(lei)
    if not live:
        raise HTTPException(404, "Entity not found")
    live["source"] = "gleif_live"
    return live
