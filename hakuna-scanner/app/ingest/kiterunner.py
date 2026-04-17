"""Kiterunner result parsing and endpoint storage.

Parses kiterunner JSON output and stores discovered API endpoints
as AssetEndpoint records alongside katana-discovered endpoints.
"""

import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def store_kiterunner_results(
    db: AsyncSession,
    org_id: uuid.UUID,
    results: list[dict],
    target_asset_map: dict[str, uuid.UUID],
) -> dict:
    """Parse kiterunner output and store discovered endpoints.

    Kiterunner JSON output format (per line):
    {
        "input": "https://example.com",
        "results": [
            {"route": "/api/v1/users", "method": "GET", "status": 200, "length": 1234}
        ]
    }
    OR flat format:
    {"host": "https://example.com", "path": "/api/v1/users", "method": "GET",
     "status_code": 200, "length": 1234}

    Returns {"endpoints_stored": int, "hosts_with_results": int}.
    """
    now = datetime.now(timezone.utc)
    stored = 0
    hosts_with_results = set()

    for entry in results:
        # Handle nested results format
        if "results" in entry and "input" in entry:
            host_url = entry["input"]
            for route in entry["results"]:
                stored += await _store_endpoint(
                    db, org_id, host_url, route, target_asset_map, now,
                )
                try:
                    hosts_with_results.add(urlparse(host_url).hostname)
                except Exception:
                    pass
        # Handle flat format
        elif "host" in entry or "path" in entry:
            host_url = entry.get("host", "")
            stored += await _store_endpoint(
                db, org_id, host_url, entry, target_asset_map, now,
            )
            try:
                hosts_with_results.add(urlparse(host_url).hostname)
            except Exception:
                pass

    await db.commit()
    logger.info(
        "org=%s kiterunner: endpoints=%d hosts=%d",
        org_id, stored, len(hosts_with_results),
    )
    return {"endpoints_stored": stored, "hosts_with_results": len(hosts_with_results)}


async def _store_endpoint(
    db: AsyncSession,
    org_id: uuid.UUID,
    host_url: str,
    route: dict,
    target_asset_map: dict[str, uuid.UUID],
    now: datetime,
) -> int:
    """Store a single kiterunner-discovered endpoint. Returns 1 if stored, 0 if skipped."""
    try:
        parsed = urlparse(host_url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return 0

    asset_id = target_asset_map.get(hostname)
    if not asset_id:
        return 0

    path = route.get("route") or route.get("path") or "/"
    method = route.get("method", "GET").upper()
    status = route.get("status") or route.get("status_code")

    # Skip error responses that leaked through
    if status and status >= 500:
        return 0

    # Build full URL
    scheme = parsed.scheme or "https"
    url = f"{scheme}://{hostname}{path}"

    endpoint_id = uuid.uuid4()
    # status_code is the most useful ranking signal kiterunner gives us
    # (200 OK is a higher-value scan target than 401 / 302). source is set
    # explicitly so the planner can rank kiterunner-discovered endpoints
    # against other sources (openapi/graphql/katana/llm_js).
    await db.execute(
        text("""
            INSERT INTO asset_endpoints (
                id, asset_id, url, path, method,
                source, status_code, discovered_at, is_auth_page
            )
            VALUES (
                :id, :asset_id, :url, :path, :method,
                'kiterunner', :status_code, :now, false
            )
            ON CONFLICT (asset_id, url, method, source) DO NOTHING
        """),
        {
            "id": endpoint_id,
            "asset_id": asset_id,
            "url": url,
            "path": path,
            "method": method,
            "status_code": int(status) if status else None,
            "now": now,
        },
    )
    return 1
