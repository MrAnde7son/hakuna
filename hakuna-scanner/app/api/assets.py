"""Asset inventory query endpoints."""

import uuid
from datetime import datetime

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.asset import Asset

router = APIRouter(prefix="/api/v1/orgs/{org_id}/assets", tags=["assets"])


class AssetResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    hostname: str
    ip: str | None = None
    asn: str | None = None

    @field_validator("ip", mode="before")
    @classmethod
    def coerce_ip(cls, v: Any) -> str | None:
        return str(v) if v is not None else None
    asn_org: str | None = None
    open_ports: list[int] | None = None
    http_status: int | None = None
    http_title: str | None = None
    http_url: str | None = None
    tech_stack: dict | list | None = None
    cdn_provider: str | None = None
    waf: str | None = None
    tls_cert: dict | None = None
    dns_records: dict | None = None
    tags: list[str] | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    last_enriched: datetime | None = None
    source: str | None = None
    nessus_asset_id: str | None = None

    model_config = {"from_attributes": True}


class AssetStats(BaseModel):
    total: int
    with_open_ports: int
    with_http: int
    with_cdn: int
    with_expired_cert: int


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    org_id: uuid.UUID,
    tag: str | None = Query(None, description="Filter by tag"),
    tech: str | None = Query(None, description="Filter by tech stack keyword"),
    has_ports: bool | None = Query(None, description="Only assets with open ports"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    q = select(Asset).where(Asset.org_id == org_id)

    if tag:
        q = q.where(Asset.tags.any(tag))
    if tech:
        q = q.where(Asset.tech_stack.cast(str).ilike(f"%{tech}%"))
    if has_ports is True:
        q = q.where(Asset.open_ports != None, func.array_length(Asset.open_ports, 1) > 0)  # noqa: E711

    q = q.order_by(Asset.last_seen.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/stats", response_model=AssetStats)
async def asset_stats(org_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    base = select(Asset).where(Asset.org_id == org_id)

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0

    ports_q = base.where(Asset.open_ports != None, func.array_length(Asset.open_ports, 1) > 0)  # noqa: E711
    with_ports = (await db.execute(select(func.count()).select_from(ports_q.subquery()))).scalar() or 0

    http_q = base.where(Asset.http_status != None)  # noqa: E711
    with_http = (await db.execute(select(func.count()).select_from(http_q.subquery()))).scalar() or 0

    cdn_q = base.where(Asset.cdn_provider != None)  # noqa: E711
    with_cdn = (await db.execute(select(func.count()).select_from(cdn_q.subquery()))).scalar() or 0

    cert_q = base.where(Asset.tags.any("expired-cert"))
    with_expired = (await db.execute(select(func.count()).select_from(cert_q.subquery()))).scalar() or 0

    return AssetStats(
        total=total,
        with_open_ports=with_ports,
        with_http=with_http,
        with_cdn=with_cdn,
        with_expired_cert=with_expired,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(org_id: uuid.UUID, asset_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    from fastapi import HTTPException

    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset
