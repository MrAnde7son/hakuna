"""OpenAPI / Swagger spec discovery.

Probes a curated list of well-known paths against each web-facing asset.
When a JSON spec is found, parses ``paths`` × ``methods`` and stores each
operation as an AssetEndpoint with source="openapi" plus parameter/auth
metadata so the adaptive scan planner can drive precise per-endpoint
fuzzing instead of relying on host-level template selection.

Why this matters: an OpenAPI-known endpoint is the highest-signal scan
target we can have — method, parameters, auth requirement, and content
type are all explicit. Compared to a katana-discovered URL (just a path),
the planner can decide to run injection-style nuclei templates with the
right parameter names rather than fuzzing blind.

Design choices:
  - No external OpenAPI parser (e.g. ``prance``) — both Swagger 2 and
    OpenAPI 3 expose enough surface in plain JSON for what we need
    (paths, methods, parameters, security). Skipping the dependency keeps
    the scanner image lean and avoids fighting spec validators on
    non-canonical specs (which we encounter often in real-world targets).
  - We deliberately don't follow ``$ref``s. They mostly point at schema
    definitions we don't need for endpoint enumeration, and following
    them turns into a recursion / loop risk that's not worth it for an
    enumeration tool.
  - Specs that are larger than ``openapi_discovery_max_spec_bytes`` are
    rejected outright — a 50MB spec from a misconfigured target shouldn't
    be allowed to consume scanner memory.
  - Discovering a spec is itself finding-worthy in some cases (exposed
    Swagger UI on prod). That secondary signal is recorded in the
    endpoint's ``evidence`` JSON (operation_id + spec_url) but not
    surfaced as a separate Finding — the backend can derive it from the
    endpoint records.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# Ordered most-likely → least-likely. We stop at the first hit per asset
# (most stacks expose only one spec path) so ordering matters for latency.
WELL_KNOWN_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/openapi.yaml",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/.well-known/openapi.json",
)


async def discover_openapi_specs(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_targets: list[dict],
    concurrency: int = 10,
    timeout: int = 8,
    max_spec_bytes: int = 5_000_000,
    max_endpoints_per_asset: int = 1000,
) -> dict:
    """Probe each asset's well-known OpenAPI paths and persist endpoints.

    asset_targets: list of ``{"asset_id": uuid, "base_url": str}`` — the
    base URL is what the scanner already considers "the asset" (typically
    the http_url from httpx enrichment). One asset → at most one spec.

    Returns ``{specs_found, endpoints_stored, assets_probed}``.
    """
    if not asset_targets:
        return {"specs_found": 0, "endpoints_stored": 0, "assets_probed": 0}

    sem = asyncio.Semaphore(concurrency)
    now = datetime.now(timezone.utc)
    specs_found = 0
    endpoints_stored = 0

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,  # discovery probes hit prod — self-signed certs are common
        headers={"User-Agent": "hakuna-scanner/openapi-discovery"},
    ) as client:
        tasks = [
            _discover_one(
                client, sem, db, org_id, target, now,
                max_spec_bytes=max_spec_bytes,
                max_endpoints=max_endpoints_per_asset,
            )
            for target in asset_targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            logger.debug("openapi_discoverer: asset task failed: %s", r)
            continue
        if r is None:
            continue
        specs_found += 1
        endpoints_stored += r

    await db.commit()
    logger.info(
        "openapi_discoverer org=%s probed=%d specs=%d endpoints=%d",
        org_id, len(asset_targets), specs_found, endpoints_stored,
    )
    return {
        "specs_found": specs_found,
        "endpoints_stored": endpoints_stored,
        "assets_probed": len(asset_targets),
    }


async def _discover_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    db: AsyncSession,
    org_id: uuid.UUID,
    target: dict,
    now: datetime,
    max_spec_bytes: int,
    max_endpoints: int,
) -> int | None:
    """Probe one asset; return endpoint count stored or None when no spec."""
    base_url = target.get("base_url") or ""
    asset_id = target.get("asset_id")
    if not base_url or not asset_id:
        return None

    async with sem:
        for path in WELL_KNOWN_PATHS:
            url = urljoin(base_url, path)
            spec = await _fetch_spec(client, url, max_spec_bytes)
            if not spec:
                continue
            endpoints = parse_openapi_spec(spec, base_url)
            if not endpoints:
                continue
            stored = await _store_endpoints(
                db, asset_id, endpoints[:max_endpoints], spec_url=url, now=now,
            )
            return stored
    return None


async def _fetch_spec(client: httpx.AsyncClient, url: str, max_bytes: int) -> dict | None:
    """GET ``url``; return parsed JSON dict if it's a plausible OpenAPI spec.

    Validates by checking for either the OpenAPI 3 ``openapi`` version field
    or the Swagger 2 ``swagger`` field. Anything else (HTML 404 pages,
    arbitrary JSON) gets dropped silently.
    """
    try:
        resp = await client.get(url)
    except Exception:
        return None
    if resp.status_code != 200:
        return None

    # Refuse oversized specs — read content_length first when available.
    cl = resp.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > max_bytes:
        return None

    body = resp.content
    if len(body) > max_bytes:
        return None

    try:
        spec = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # YAML support intentionally omitted — see module docstring; YAML
        # specs are rare in the field and require a full YAML parser to
        # disambiguate from arbitrary YAML responses.
        return None

    if not isinstance(spec, dict):
        return None
    if not (spec.get("openapi") or spec.get("swagger")):
        return None
    if not isinstance(spec.get("paths"), dict):
        return None
    return spec


def parse_openapi_spec(spec: dict, base_url: str) -> list[dict]:
    """Walk ``paths`` × HTTP methods and return endpoint records.

    Each record:
        {
            "url": "https://host/api/v1/users",
            "path": "/api/v1/users",
            "method": "GET",
            "auth_required": bool,
            "content_type": str | None,
            "parameters": [{"name", "in", "required"}],
            "operation_id": str | None,
        }

    auth_required logic: an operation is considered auth-required if its
    own ``security`` block is present and non-empty, OR a top-level
    ``security`` block is present and the operation doesn't override it
    with an empty list. This mirrors the OpenAPI spec's resolution rules.
    """
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return []

    global_security = spec.get("security")  # may be None / [] / list
    has_global_security = isinstance(global_security, list) and len(global_security) > 0

    methods = ("get", "post", "put", "patch", "delete", "options", "head")
    out: list[dict] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict) or not isinstance(path, str):
            continue
        # Path-level parameters apply to every operation under this path.
        path_level_params = _normalize_parameters(path_item.get("parameters"))

        for method in methods:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue

            # Operation-level security overrides global. Empty list ([])
            # is OpenAPI's way of saying "explicitly no auth here".
            op_security = op.get("security")
            if isinstance(op_security, list):
                auth_required = len(op_security) > 0
            else:
                auth_required = has_global_security

            params = list(path_level_params) + _normalize_parameters(op.get("parameters"))

            # OpenAPI 3 request body content types — flatten to the first.
            content_type = None
            req_body = op.get("requestBody")
            if isinstance(req_body, dict):
                content = req_body.get("content")
                if isinstance(content, dict) and content:
                    content_type = next(iter(content.keys()), None)

            out.append({
                "url": urljoin(base_url, path),
                "path": path,
                "method": method.upper(),
                "auth_required": auth_required,
                "content_type": content_type,
                "parameters": params,
                "operation_id": op.get("operationId"),
            })

    return out


def _normalize_parameters(params) -> list[dict]:
    """Reduce OpenAPI ``parameters`` arrays to a fuzzing-friendly minimum.

    Drops $ref-only parameters since we don't follow refs (see module
    docstring). The shape is what DAST templates actually consume.
    """
    if not isinstance(params, list):
        return []
    out: list[dict] = []
    for p in params:
        if not isinstance(p, dict):
            continue
        if "$ref" in p:
            continue
        out.append({
            "name": p.get("name"),
            "in": p.get("in"),
            "required": bool(p.get("required")),
        })
    return out


async def _store_endpoints(
    db: AsyncSession,
    asset_id: uuid.UUID,
    endpoints: list[dict],
    spec_url: str,
    now: datetime,
) -> int:
    """Insert endpoints with source='openapi'; ON CONFLICT do nothing.

    The conflict target is (asset_id, url, method, source) — see
    alembic/versions/010_api_discovery_extensions.py.
    """
    stored = 0
    for ep in endpoints:
        try:
            await db.execute(
                text("""
                    INSERT INTO asset_endpoints (
                        id, asset_id, url, path, method,
                        source, auth_required, content_type, parameters,
                        evidence, discovered_at, is_auth_page
                    )
                    VALUES (
                        :id, :asset_id, :url, :path, :method,
                        'openapi', :auth_required, :content_type, :parameters,
                        :evidence, :now, false
                    )
                    ON CONFLICT (asset_id, url, method, source) DO NOTHING
                """),
                {
                    "id": uuid.uuid4(),
                    "asset_id": asset_id,
                    "url": ep["url"],
                    "path": ep["path"],
                    "method": ep["method"],
                    "auth_required": ep["auth_required"],
                    "content_type": ep["content_type"],
                    "parameters": json.dumps(ep["parameters"]),
                    "evidence": json.dumps({
                        "spec_url": spec_url,
                        "operation_id": ep.get("operation_id"),
                    }),
                    "now": now,
                },
            )
            stored += 1
        except Exception as e:
            logger.debug("openapi: failed to insert endpoint %s: %s", ep.get("url"), e)
    return stored
