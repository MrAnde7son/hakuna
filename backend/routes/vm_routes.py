"""
VM Scanner routes — trigger scans, check status.
Prefix: /api/vm
"""
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import require_auth
from models.models import Organization, User
from models.models import Scan
from services.vm_scanner import start_vm_scan, rescan_vm_scan, refresh_vm_scan, get_vm_health

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vm", tags=["vm-scanner"])


class VmScanRequest(BaseModel):
    targets: List[str]
    asset_ids: List[int] | None = None  # existing asset IDs to link findings to


def _get_org(db: Session, user: User) -> Organization:
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


@router.post("/scan")
async def create_vm_scan(
    body: VmScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Create a VM scan — creates a Scan record and dispatches to VM scanner container."""
    org = _get_org(db, user)

    targets = [t.strip() for t in body.targets if t.strip()]
    if not targets:
        raise HTTPException(400, "No valid targets provided")

    result = await start_vm_scan(db, org, targets, asset_ids=body.asset_ids)
    if not result:
        raise HTTPException(502, "Failed to start VM scan — scanner may be unavailable")
    return result


@router.post("/refresh/{scan_id}")
async def refresh_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Poll VM scan job statuses and update the Scan record."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.source_type == "vm_scanner").first()
    if not scan:
        raise HTTPException(404, "VM scan not found")
    if user.role != "superadmin" and scan.org_id != user.org_id:
        raise HTTPException(403, "Access denied")
    result = await refresh_vm_scan(db, scan_id)
    if result is None:
        raise HTTPException(404, "VM scan not found")
    return result


@router.post("/rescan/{scan_id}")
async def rescan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Re-run a VM scan with the same targets."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.source_type == "vm_scanner").first()
    if not scan:
        raise HTTPException(404, "VM scan not found")
    if user.role != "superadmin" and scan.org_id != user.org_id:
        raise HTTPException(403, "Access denied")

    result = await rescan_vm_scan(db, scan)
    if not result:
        raise HTTPException(502, "Failed to start VM scan — scanner may be unavailable or scan has no targets")
    return result


@router.get("/health")
async def health():
    """Check VM scanner container health."""
    result = await get_vm_health()
    if not result:
        raise HTTPException(502, "VM scanner is unavailable")
    return result
