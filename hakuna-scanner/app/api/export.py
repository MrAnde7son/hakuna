"""Export endpoints for downstream Nuclei/Nessus correlation."""

import csv
import io
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.asset import Asset, AssetEvent

router = APIRouter(prefix="/api/v1/orgs/{org_id}", tags=["export"])


class EventResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    asset_id: uuid.UUID
    event_type: str
    payload: dict | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class NessusLinkRequest(BaseModel):
    nessus_asset_id: str


@router.get("/assets/export")
async def export_assets(
    org_id: uuid.UUID,
    format: str = Query("jsonl", enum=["jsonl", "csv"]),
    ports_only: bool = Query(False, description="Only include assets with open ports"),
    https_only: bool = Query(False, description="Only include assets with HTTPS (443)"),
    tech: str | None = Query(None, description="Filter by tech stack keyword"),
    db: AsyncSession = Depends(get_db),
):
    q = select(Asset).where(Asset.org_id == org_id)

    if ports_only:
        q = q.where(Asset.open_ports != None, func.array_length(Asset.open_ports, 1) > 0)  # noqa: E711
    if https_only:
        q = q.where(Asset.open_ports.any(443))
    if tech:
        q = q.where(Asset.tech_stack.cast(str).ilike(f"%{tech}%"))

    result = await db.execute(q.order_by(Asset.hostname))
    assets = result.scalars().all()

    if format == "csv":
        return _export_csv(assets)
    else:
        return _export_jsonl(assets)


def _export_jsonl(assets: list[Asset]) -> StreamingResponse:
    import json

    def generate():
        for a in assets:
            row = {
                "hostname": a.hostname,
                "ip": str(a.ip) if a.ip else None,
                "open_ports": a.open_ports,
                "services": a.services,
                "http_url": a.http_url,
                "http_status": a.http_status,
                "tech_stack": a.tech_stack,
                "cdn_provider": a.cdn_provider,
                "waf": a.waf,
                "tags": a.tags,
                "nessus_asset_id": a.nessus_asset_id,
            }
            yield json.dumps(row) + "\n"

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=assets.jsonl"},
    )


def _export_csv(assets: list[Asset]) -> StreamingResponse:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "hostname", "ip", "open_ports", "http_url", "http_status",
        "tech_stack", "cdn_provider", "waf", "tags", "nessus_asset_id",
    ])
    writer.writeheader()
    for a in assets:
        writer.writerow({
            "hostname": a.hostname,
            "ip": str(a.ip) if a.ip else "",
            "open_ports": ",".join(map(str, a.open_ports or [])),
            "http_url": a.http_url or "",
            "http_status": a.http_status or "",
            "tech_stack": str(a.tech_stack) if a.tech_stack else "",
            "cdn_provider": a.cdn_provider or "",
            "waf": a.waf or "",
            "tags": ",".join(a.tags or []),
            "nessus_asset_id": a.nessus_asset_id or "",
        })

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=assets.csv"},
    )


@router.get("/events", response_model=list[EventResponse])
async def list_events(
    org_id: uuid.UUID,
    event_type: str | None = Query(None),
    since: datetime | None = Query(None),
    limit: int = Query(100, le=1000),
    db: AsyncSession = Depends(get_db),
):
    q = select(AssetEvent).where(AssetEvent.org_id == org_id)

    if event_type:
        q = q.where(AssetEvent.event_type == event_type)
    if since:
        q = q.where(AssetEvent.created_at >= since)

    q = q.order_by(AssetEvent.created_at.desc()).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/assets/{asset_id}/nessus", status_code=200)
async def link_nessus_asset(
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    body: NessusLinkRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(404, "Asset not found")

    asset.nessus_asset_id = body.nessus_asset_id
    await db.commit()
    return {"status": "linked", "asset_id": str(asset_id), "nessus_asset_id": body.nessus_asset_id}
