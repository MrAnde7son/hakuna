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
from models.models import Organization, User
from services.easm import (
    extract_corporate_domain,
    trigger_easm_for_new_org,
    import_easm_assets,
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

    # Add target domain
    if not await add_easm_domain(hakuna_org_id, domain):
        logger.warning(f"Failed to add domain '{domain}' to EASM org {hakuna_org_id}")

    # Trigger initial scan
    scan_id = await trigger_easm_scan(hakuna_org_id)

    # Persist on org
    org.easm_org_id = hakuna_org_id
    org.easm_domain = domain
    db.commit()

    return {
        "enabled": True,
        "domain": domain,
        "hakuna_org_id": hakuna_org_id,
        "scan_id": scan_id,
    }


@router.post("/scan")
async def trigger_scan(
    scan_type: str = Query("full", regex="^(full|discovery|enrichment)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Manually trigger an EASM scan."""
    org = _get_org(db, user)

    if not org.easm_org_id:
        raise HTTPException(400, "EASM not configured for this organization")

    scan_id = await trigger_easm_scan(org.easm_org_id, scan_type)
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
    if not org.easm_org_id:
        raise HTTPException(400, "EASM not configured")

    status = await get_easm_scan_status(org.easm_org_id, scan_id)
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
    if not org.easm_org_id:
        raise HTTPException(400, "EASM not configured")

    assets = await get_easm_assets(org.easm_org_id, limit=limit, offset=offset)
    if assets is None:
        raise HTTPException(502, "Failed to fetch EASM assets")
    return assets


@router.post("/import")
@router.post("/sync")
async def sync_assets(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Sync EASM-discovered assets into the main platform (idempotent upsert)."""
    org = _get_org(db, user)
    if not org.easm_org_id:
        raise HTTPException(400, "EASM not configured")

    result = await import_easm_assets(db, org)
    if result is None:
        raise HTTPException(502, "Failed to sync EASM assets")
    return result


@router.get("/events")
async def list_events(
    since: Optional[str] = None,
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Get recent EASM change events (new assets, IP changes, cert expirations, etc.)."""
    org = _get_org(db, user)
    if not org.easm_org_id:
        raise HTTPException(400, "EASM not configured")

    events = await get_easm_events(org.easm_org_id, since=since, limit=limit)
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
    if not org.easm_org_id:
        raise HTTPException(400, "EASM not configured")

    domains = await get_easm_domains(org.easm_org_id)
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
    if not org.easm_org_id:
        raise HTTPException(400, "EASM not configured")

    runs = await get_easm_scan_runs(org.easm_org_id, limit=limit)
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
    if not org.easm_org_id:
        raise HTTPException(400, "EASM not configured")

    success = await add_easm_domain(org.easm_org_id, domain)
    if not success:
        raise HTTPException(502, "Failed to add domain")
    return {"domain": domain, "status": "added"}
