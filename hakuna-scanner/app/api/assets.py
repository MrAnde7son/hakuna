"""Asset inventory query endpoints."""

import os
import uuid
from datetime import datetime
from pathlib import Path

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database import get_db
from app.ingest.cpe_infer import filter_cpe_list
from app.models.asset import Asset, AssetEndpoint, AssetPort

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
    services: dict | None = None
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
    liveness_state: str = "unconfirmed"
    # CVE-matchable CPEs only (excludes CDNs, WAFs, analytics, policies).
    cpe_list: list[str] | None = None
    # All detected technologies including non-software (for UI display).
    detected_technologies: list[str] | None = None

    model_config = {"from_attributes": True}


class AssetStats(BaseModel):
    total: int
    with_open_ports: int
    with_http: int
    with_cdn: int
    with_expired_cert: int


class EndpointResponse(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    asset_hostname: str | None = None
    url: str
    path: str | None = None
    method: str
    source: str
    status_code: int | None = None
    auth_required: bool | None = None
    content_type: str | None = None
    is_auth_page: bool = False
    parameters: dict | list | None = None
    discovered_at: datetime | None = None

    model_config = {"from_attributes": True}


class EndpointListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    endpoints: list[EndpointResponse]


def _asset_to_response(asset: Asset) -> AssetResponse:
    """Build an AssetResponse including CPEs aggregated across asset_ports.

    Assumes ``asset.ports`` has been eager-loaded via ``selectinload`` — if it
    hasn't, the attribute access triggers a lazy load which is fine for single-
    asset endpoints but catastrophic for list endpoints (N+1).
    """
    raw_cpes: set[str] = set()
    for port in (asset.ports or []):
        if port.cpe_list:
            # cpe_list is a JSONB list[str]; tolerate bad data
            if isinstance(port.cpe_list, list):
                raw_cpes.update(str(c) for c in port.cpe_list if c)

    # Filter out non-software CPEs (CDNs, WAFs, analytics, HTTP policies)
    # at read time so stale data written before the filtering logic is cleaned.
    filtered = filter_cpe_list(sorted(raw_cpes)) if raw_cpes else None

    return AssetResponse.model_validate(
        {
            "id": asset.id,
            "org_id": asset.org_id,
            "hostname": asset.hostname,
            "ip": asset.ip,
            "asn": asset.asn,
            "asn_org": asset.asn_org,
            "open_ports": asset.open_ports,
            "services": asset.services,
            "http_status": asset.http_status,
            "http_title": asset.http_title,
            "http_url": asset.http_url,
            "tech_stack": asset.tech_stack,
            "cdn_provider": asset.cdn_provider,
            "waf": asset.waf,
            "tls_cert": asset.tls_cert,
            "dns_records": asset.dns_records,
            "tags": asset.tags,
            "first_seen": asset.first_seen,
            "last_seen": asset.last_seen,
            "last_enriched": asset.last_enriched,
            "source": asset.source,
            "nessus_asset_id": asset.nessus_asset_id,
            "liveness_state": asset.liveness_state,
            "cpe_list": filtered.cpe_list if filtered else None,
            "detected_technologies": filtered.detected_technologies if filtered else None,
        }
    )


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    org_id: uuid.UUID,
    tag: str | None = Query(None, description="Filter by tag"),
    tech: str | None = Query(None, description="Filter by tech stack keyword"),
    has_ports: bool | None = Query(None, description="Only assets with open ports"),
    updated_since: datetime | None = Query(
        None,
        description="Only assets with last_seen >= this timestamp (ISO-8601). "
                    "Used by the backend to pull incremental changes mid-scan.",
    ),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    # Eager-load ports so _asset_to_response can aggregate cpe_list without N+1.
    q = (
        select(Asset)
        .where(Asset.org_id == org_id)
        .options(selectinload(Asset.ports))
    )

    if tag:
        q = q.where(Asset.tags.any(tag))
    if tech:
        q = q.where(Asset.tech_stack.cast(str).ilike(f"%{tech}%"))
    if has_ports is True:
        q = q.where(Asset.open_ports != None, func.array_length(Asset.open_ports, 1) > 0)  # noqa: E711
    if updated_since is not None:
        q = q.where(Asset.last_seen >= updated_since)

    q = q.order_by(Asset.last_seen.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    return [_asset_to_response(a) for a in result.scalars().all()]


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


@router.get("/endpoints", response_model=EndpointListResponse)
async def list_endpoints(
    org_id: uuid.UUID,
    asset_id: uuid.UUID | None = Query(None, description="Filter to a single asset"),
    source: str | None = Query(None, description="Filter by discovery source (katana|kiterunner|openapi|graphql|llm_js|sourcemap|wordlist)"),
    method: str | None = Query(None, description="Filter by HTTP method"),
    auth_required: bool | None = Query(None, description="Filter by auth_required flag"),
    search: str | None = Query(None, description="Substring match on path or url"),
    sort_by: str = Query("discovered_at", description="Sort column: discovered_at | status_code | path | method | source"),
    order: str = Query("desc", description="asc or desc"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List discovered API/web endpoints for an org.

    Joins asset_endpoints with assets so we can filter by org_id (endpoints
    don't carry org_id directly) and return the parent hostname without a
    second round-trip.
    """
    base = (
        select(AssetEndpoint, Asset.hostname)
        .join(Asset, AssetEndpoint.asset_id == Asset.id)
        .where(Asset.org_id == org_id)
    )
    if asset_id is not None:
        base = base.where(AssetEndpoint.asset_id == asset_id)
    if source:
        base = base.where(AssetEndpoint.source == source)
    if method:
        base = base.where(AssetEndpoint.method == method.upper())
    if auth_required is not None:
        base = base.where(AssetEndpoint.auth_required == auth_required)
    if search:
        pattern = f"%{search}%"
        base = base.where(AssetEndpoint.url.ilike(pattern) | AssetEndpoint.path.ilike(pattern))

    # Total count — wrap the filtered join as a subquery so the count
    # reflects the endpoint rows, not the asset rows (which a naive count
    # over the join would double up).
    total = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar() or 0

    sort_col = {
        "discovered_at": AssetEndpoint.discovered_at,
        "status_code": AssetEndpoint.status_code,
        "path": AssetEndpoint.path,
        "method": AssetEndpoint.method,
        "source": AssetEndpoint.source,
    }.get(sort_by, AssetEndpoint.discovered_at)
    base = base.order_by(sort_col.asc() if order == "asc" else sort_col.desc())

    rows = (await db.execute(base.limit(limit).offset(offset))).all()
    endpoints = [
        EndpointResponse.model_validate({
            "id": ep.id,
            "asset_id": ep.asset_id,
            "asset_hostname": hostname,
            "url": ep.url,
            "path": ep.path,
            "method": ep.method,
            "source": ep.source,
            "status_code": ep.status_code,
            "auth_required": ep.auth_required,
            "content_type": ep.content_type,
            "is_auth_page": ep.is_auth_page,
            "parameters": ep.parameters,
            "discovered_at": ep.discovered_at,
        })
        for ep, hostname in rows
    ]
    return EndpointListResponse(total=total, limit=limit, offset=offset, endpoints=endpoints)


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(org_id: uuid.UUID, asset_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Asset)
        .where(Asset.id == asset_id, Asset.org_id == org_id)
        .options(selectinload(Asset.ports))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(404, "Asset not found")
    return _asset_to_response(asset)


@router.get("/{asset_id}/screenshot")
async def get_asset_screenshot(
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Serve the most recent screenshot for an asset."""
    result = await db.execute(
        text("""
            SELECT screenshot_path FROM asset_enrichments
            WHERE asset_id = :asset_id AND screenshot_path IS NOT NULL
            ORDER BY created_at DESC LIMIT 1
        """),
        {"asset_id": asset_id},
    )
    row = result.fetchone()
    if not row or not row.screenshot_path:
        raise HTTPException(404, "No screenshot available for this asset")

    ss_path = row.screenshot_path
    # Security: ensure path is within the screenshot directory
    real_path = os.path.realpath(ss_path)
    real_base = os.path.realpath(settings.screenshot_dir)
    if not real_path.startswith(real_base):
        raise HTTPException(403, "Invalid screenshot path")

    if not os.path.isfile(real_path):
        raise HTTPException(404, "Screenshot file not found")

    return FileResponse(real_path, media_type="image/png")
