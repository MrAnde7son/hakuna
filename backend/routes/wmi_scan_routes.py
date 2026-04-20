"""WMI inventory scan routes — trigger credentialed Windows inventory sweeps
through the relay agent.

Prefix: /api/wmi
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.auth import require_auth
from core.database import get_db
from core.subscription import check_scan_limit
from models.models import Organization, User
from services.wmi_scanner import DEFAULT_PROFILES, start_wmi_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/wmi", tags=["wmi-inventory"])


class WmiScanRequest(BaseModel):
    asset_ids: list[int] = Field(..., min_length=1)
    credential_id: str                   # IntegrationCredential.id (auth_type=basic)
    relay_agent_id: str                  # RelayAgent.id — must be currently connected
    profiles: list[str] | None = None    # subset of DEFAULT_PROFILES; None = all
    per_host_timeout_s: int = 120
    concurrency: int = 5


def _get_org(db: Session, user: User) -> Organization:
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


@router.post("/scan", dependencies=[Depends(check_scan_limit)])
async def create_wmi_scan(
    body: WmiScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Dispatch a credentialed WMI inventory scan against the given assets.

    The relay agent identified by `relay_agent_id` must already be connected
    over the /ws/relay WebSocket — we do not queue tasks for disconnected
    agents. The credential must be an IntegrationCredential with
    auth_type=basic and values {username, password, domain?}.
    """
    org = _get_org(db, user)

    try:
        result = await start_wmi_scan(
            db, org,
            asset_ids=body.asset_ids,
            credential_id=body.credential_id,
            relay_agent_id=body.relay_agent_id,
            profiles=body.profiles,
            per_host_timeout_s=body.per_host_timeout_s,
            concurrency=body.concurrency,
        )
    except ConnectionError as e:
        # Relay agent offline — this is a common, expected failure mode
        # and deserves a 503 (retryable) rather than 500.
        raise HTTPException(503, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))

    return result


@router.get("/profiles")
def list_wmi_profiles(user: User = Depends(require_auth)):
    """Return the catalog of WMI profiles a scan can opt into.

    Used by the frontend credential/profile picker. Profile names are the
    contract shared with the relay agent's wmi_catalog.py.
    """
    return {"profiles": DEFAULT_PROFILES}
