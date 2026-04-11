"""Scan triggering and status endpoints."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.asset import ScanRun
from app.models.org import Org
from app.tasks.discovery import run_discovery_chain
from app.tasks.enrichment import run_enrichment_chain

router = APIRouter(prefix="/api/v1/orgs/{org_id}/scans", tags=["scans"])


class ScanRequest(BaseModel):
    scan_type: str = "full"  # discovery | enrichment | full
    target_domain: str | None = None


class ScanRunResponse(BaseModel):
    """Full scan run response, used for single-scan detail endpoint."""
    id: uuid.UUID
    org_id: uuid.UUID
    scan_type: str
    target_domain: str | None = None
    status: str
    assets_found: int
    assets_changed: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    current_stage: str | None = None
    stage_index: int = 0
    total_stages: int = 0
    stage_started_at: datetime | None = None
    stage_log: list | None = None

    model_config = {"from_attributes": True}


class ScanRunListItem(BaseModel):
    """Lightweight list-row projection of ScanRun.

    Deliberately excludes `stage_log` — it's ~700 bytes per row on a typical
    completed scan, and history lists render 10-20 rows. Sending stage_log
    across the wire for the list view made the history endpoint respond with
    ~14 KB for 20 rows with no benefit (the list UI doesn't render per-stage
    timings — only the detail view does, which hits GET /{scan_id}).
    """
    id: uuid.UUID
    org_id: uuid.UUID
    scan_type: str
    target_domain: str | None = None
    status: str
    assets_found: int
    assets_changed: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    current_stage: str | None = None
    stage_index: int = 0
    total_stages: int = 0
    stage_started_at: datetime | None = None

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

    scan_run = ScanRun(org_id=org_id, scan_type=body.scan_type, target_domain=body.target_domain, status="queued")
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
            link=run_enrichment_chain.si(org_str, run_str),
        )

    return scan_run


@router.get("", response_model=list[ScanRunListItem])
async def list_scans(
    org_id: uuid.UUID,
    limit: int = 20,
    domain: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List recent scan runs for an org, newest first.

    Ordering: queued rows (no `started_at`) float to the top since they were
    just enqueued; otherwise order by `started_at` descending. Previously
    ordered by `ScanRun.id DESC`, but ScanRun.id is UUIDv4 which is random,
    not chronological — it produced a nonsensical "most recent" ordering
    where failed/cancelled scans from yesterday appeared above today's
    successful runs.

    Projection: only the fields the history UI actually renders. stage_log
    is excluded here — a completed scan's stage_log is several hundred bytes
    of JSON that the list view never shows, but used to balloon the response
    payload on orgs with lots of scans. Clients that need per-stage timings
    should hit GET /{scan_id}.
    """
    cols = [
        ScanRun.id,
        ScanRun.org_id,
        ScanRun.scan_type,
        ScanRun.target_domain,
        ScanRun.status,
        ScanRun.assets_found,
        ScanRun.assets_changed,
        ScanRun.started_at,
        ScanRun.finished_at,
        ScanRun.error,
        ScanRun.current_stage,
        ScanRun.stage_index,
        ScanRun.total_stages,
        ScanRun.stage_started_at,
    ]
    stmt = select(*cols).where(ScanRun.org_id == org_id)
    if domain:
        stmt = stmt.where(ScanRun.target_domain == domain)

    # Queued rows (started_at IS NULL) sort first; others newest-first.
    stmt = stmt.order_by(
        func.coalesce(ScanRun.started_at, func.now()).desc(),
        ScanRun.id.desc(),  # tiebreaker for deterministic paging
    ).limit(limit)

    result = await db.execute(stmt)
    return [dict(row._mapping) for row in result.all()]


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
