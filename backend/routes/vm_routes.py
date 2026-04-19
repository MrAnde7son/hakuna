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
from core.subscription import check_scan_limit
from models.models import Organization, User
from models.models import Scan
from services.vm_scanner import start_vm_scan, rescan_vm_scan, refresh_vm_scan, get_vm_health

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vm", tags=["vm-scanner"])


class VmScanRequest(BaseModel):
    targets: List[str]
    asset_ids: List[int] | None = None  # existing asset IDs to link findings to
    credential_id: str | None = None  # IntegrationCredential.id for authenticated scans
    auth_profile_id: str | None = None  # AuthProfile.id — drives Playwright login
    # Specialist LLM agents are opt-in per scan because their cost is
    # measured in LLM tokens. Default False to avoid quiet regressions
    # when the scanner service picks up a new release.
    enable_agents: bool = False
    agent_categories: List[str] | None = None  # subset of injection/xss/ssrf/authn/authz


class VmRescanRequest(BaseModel):
    """Optional overrides for edit-and-rerun. Any field left as None keeps the
    scan's existing value; explicitly sending a field (even empty list / null)
    replaces it."""
    targets: List[str] | None = None
    credential_id: str | None = None
    auth_profile_id: str | None = None
    enable_agents: bool | None = None
    agent_categories: List[str] | None = None


def _get_org(db: Session, user: User) -> Organization:
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


@router.post("/scan", dependencies=[Depends(check_scan_limit)])
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

    result = await start_vm_scan(
        db, org, targets,
        asset_ids=body.asset_ids,
        credential_id=body.credential_id,
        auth_profile_id=body.auth_profile_id,
        enable_agents=body.enable_agents,
        agent_categories=body.agent_categories,
    )
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
    body: VmRescanRequest | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Re-run a VM scan. Body is optional — send overrides to edit-and-rerun
    (targets/credential/auth_profile) without creating a new scan row.
    Omit the body to replay the scan as-is."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.source_type == "vm_scanner").first()
    if not scan:
        raise HTTPException(404, "VM scan not found")
    if user.role != "superadmin" and scan.org_id != user.org_id:
        raise HTTPException(403, "Access denied")

    overrides_applied = body is not None and any(
        v is not None for v in (
            body.targets, body.credential_id, body.auth_profile_id,
            body.enable_agents, body.agent_categories,
        )
    )
    result = await rescan_vm_scan(
        db, scan,
        targets_override=(body.targets if body else None),
        credential_id_override=(body.credential_id if body else None),
        auth_profile_id_override=(body.auth_profile_id if body else None),
        enable_agents_override=(body.enable_agents if body else None),
        agent_categories_override=(body.agent_categories if body else None),
        overrides_applied=overrides_applied,
    )
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
