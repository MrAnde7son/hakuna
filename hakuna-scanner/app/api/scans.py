"""Scan triggering and status endpoints."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.asset import ScanRun
from app.models.org import Org
from app.tasks.discovery import run_discovery_chain
from app.tasks.enrichment import run_enrichment_chain

router = APIRouter(prefix="/api/v1/orgs/{org_id}/scans", tags=["scans"])


class ScanRequest(BaseModel):
    scan_type: str = "full"  # discovery | enrichment | full


class ScanRunResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    scan_type: str
    status: str
    assets_found: int
    assets_changed: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None

    model_config = {"from_attributes": True}


@router.post("", response_model=ScanRunResponse, status_code=202)
async def trigger_scan(
    org_id: uuid.UUID,
    body: ScanRequest,
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Org, org_id)
    if not org:
        raise HTTPException(404, "Org not found")

    if body.scan_type not in ("discovery", "enrichment", "full"):
        raise HTTPException(400, "scan_type must be one of: discovery, enrichment, full")

    scan_run = ScanRun(org_id=org_id, scan_type=body.scan_type, status="queued")
    db.add(scan_run)
    await db.commit()
    await db.refresh(scan_run)

    org_str = str(org_id)
    run_str = str(scan_run.id)

    if body.scan_type == "discovery":
        run_discovery_chain.delay(org_str, run_str)
    elif body.scan_type == "enrichment":
        run_enrichment_chain.delay(org_str, run_str)
    else:  # full
        run_discovery_chain.apply_async(
            args=[org_str, run_str],
            link=run_enrichment_chain.si(org_str, None),
        )

    return scan_run


@router.get("", response_model=list[ScanRunResponse])
async def list_scans(
    org_id: uuid.UUID,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanRun)
        .where(ScanRun.org_id == org_id)
        .order_by(ScanRun.id.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanRunResponse)
async def get_scan(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanRun).where(ScanRun.id == scan_id, ScanRun.org_id == org_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan run not found")
    return scan
