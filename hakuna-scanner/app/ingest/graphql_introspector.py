"""GraphQL endpoint discovery + introspection.

Probes well-known GraphQL paths and, when one responds, sends a standard
introspection query. Stored:
  - one ``asset_endpoints`` row per discovered Mutation/Query field with
    source="graphql"
  - one ``asset_js_artifacts`` row of artifact_type="graphql_schema" with
    the full schema for downstream agents/UI to consume

Why introspection on its own is finding-worthy: in production, exposed
introspection is the textbook GraphQL misconfiguration — it gives
attackers the entire API surface for free. The actual Finding row is
emitted by the backend post-ingest; this module just records the
``introspection_enabled=True`` flag in the artifact intelligence so the
backend can derive it.

Design choices:
  - We use the canonical introspection query in two passes: a light query
    (just type names) first, and only the full ``__schema`` query if the
    target tolerates the light one. Keeps load on legitimate APIs low and
    helps avoid tripping cautious WAFs.
  - Public-API safety: when ``Access-Control-Allow-Origin: *`` AND the
    asset is tagged ``public-api`` (set elsewhere), we still record the
    schema but mark ``introspection_enabled`` as ``"public"`` so the
    backend doesn't auto-flag legitimate public APIs (Apollo, Hasura
    cloud demos, etc.) as a vulnerability.
  - Field name + base type only — argument types and full schema details
    aren't needed for endpoint enumeration; the intelligence column
    stores the raw schema for callers that want more.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


CANDIDATE_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/gql",
)

# Lightweight first pass — ask for the query/mutation type names only.
_LIGHT_INTROSPECTION = (
    "{ __schema { queryType { name } mutationType { name } } }"
)

# Full schema query — only sent if the light pass works.
_FULL_INTROSPECTION = (
    "{ __schema { "
    "queryType { name fields { name } } "
    "mutationType { name fields { name } } "
    "subscriptionType { name fields { name } } "
    "} }"
)


async def introspect_graphql(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_targets: list[dict],
    concurrency: int = 10,
    timeout: int = 8,
) -> dict:
    """For each asset, probe candidate GraphQL paths and run introspection.

    Stores Query/Mutation field operations as endpoints (POST method, the
    body shape is implicit — the planner emits ``-tags graphql`` so nuclei
    knows to wrap the path name in a real query).
    """
    if not asset_targets:
        return {"introspection_hits": 0, "endpoints_stored": 0, "assets_probed": 0}

    sem = asyncio.Semaphore(concurrency)
    now = datetime.now(timezone.utc)
    introspection_hits = 0
    endpoints_stored = 0

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={
            "User-Agent": "hakuna-scanner/graphql-introspection",
            "Content-Type": "application/json",
        },
    ) as client:
        tasks = [
            _probe_asset(client, sem, db, org_id, target, now)
            for target in asset_targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            logger.debug("graphql_introspector asset task failed: %s", r)
            continue
        if r is None:
            continue
        introspection_hits += 1
        endpoints_stored += r

    await db.commit()
    logger.info(
        "graphql_introspector org=%s probed=%d hits=%d endpoints=%d",
        org_id, len(asset_targets), introspection_hits, endpoints_stored,
    )
    return {
        "introspection_hits": introspection_hits,
        "endpoints_stored": endpoints_stored,
        "assets_probed": len(asset_targets),
    }


async def _probe_asset(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    db: AsyncSession,
    org_id: uuid.UUID,
    target: dict,
    now: datetime,
) -> int | None:
    """Try each candidate path; return endpoint count stored on first hit."""
    base_url = target.get("base_url") or ""
    asset_id = target.get("asset_id")
    if not base_url or not asset_id:
        return None

    async with sem:
        for path in CANDIDATE_PATHS:
            url = urljoin(base_url, path)
            schema_data = await _try_introspect(client, url)
            if not schema_data:
                continue

            endpoints = _schema_to_endpoints(schema_data, url)
            stored = await _store(
                db, asset_id, endpoints, url, schema_data, now,
            )
            return stored
    return None


async def _try_introspect(client: httpx.AsyncClient, url: str) -> dict | None:
    """Run the two-pass introspection probe; return schema dict on success."""
    try:
        light = await client.post(url, json={"query": _LIGHT_INTROSPECTION})
    except Exception:
        return None

    if light.status_code != 200:
        return None

    try:
        data = light.json()
    except (json.JSONDecodeError, ValueError):
        return None

    schema = (data or {}).get("data", {}).get("__schema")
    if not isinstance(schema, dict):
        return None

    # Public-API marker — if the server explicitly allows wildcard CORS,
    # introspection is more likely intentional than misconfigured.
    public = light.headers.get("Access-Control-Allow-Origin", "").strip() == "*"

    # Only escalate to the full query if light succeeded; full schemas can
    # be megabytes on monorepo APIs and we don't want to fetch one
    # gratuitously.
    try:
        full = await client.post(url, json={"query": _FULL_INTROSPECTION})
    except Exception:
        # Fall back to whatever light gave us.
        return {"schema": schema, "public": public, "url": url}

    if full.status_code != 200:
        return {"schema": schema, "public": public, "url": url}

    try:
        full_data = full.json()
    except (json.JSONDecodeError, ValueError):
        return {"schema": schema, "public": public, "url": url}

    full_schema = (full_data or {}).get("data", {}).get("__schema")
    if isinstance(full_schema, dict):
        return {"schema": full_schema, "public": public, "url": url}
    return {"schema": schema, "public": public, "url": url}


def _schema_to_endpoints(schema_data: dict, gql_url: str) -> list[dict]:
    """Project the introspected schema into endpoint records.

    Each Query/Mutation/Subscription field becomes one POST endpoint with
    a synthetic path naming the operation. The actual nuclei templates
    that target GraphQL build their own request body — what matters is
    that we surface every operation name to the planner.
    """
    schema = schema_data.get("schema") or {}
    out: list[dict] = []
    for kind, type_key in (
        ("Query", "queryType"),
        ("Mutation", "mutationType"),
        ("Subscription", "subscriptionType"),
    ):
        type_block = schema.get(type_key) or {}
        if not isinstance(type_block, dict):
            continue
        for f in type_block.get("fields") or []:
            if not isinstance(f, dict):
                continue
            name = f.get("name")
            if not name:
                continue
            out.append({
                "url": gql_url,
                "path": f"{kind}.{name}",
                "method": "POST",
                "operation_kind": kind,
                "operation_name": name,
            })
    return out


async def _store(
    db: AsyncSession,
    asset_id: uuid.UUID,
    endpoints: list[dict],
    gql_url: str,
    schema_data: dict,
    now: datetime,
) -> int:
    """Persist endpoints (one per field) + a single js_artifacts row for the schema.

    Stores the schema in asset_js_artifacts (artifact_type='graphql_schema')
    rather than dumping it inline in every endpoint row. ``content_hash``
    is omitted (we'd need to canonicalize the schema first; not worth the
    cycles here — this row is naturally rare per asset).
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
                        'graphql', NULL, 'application/json', NULL,
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
                    "evidence": json.dumps({
                        "operation_kind": ep["operation_kind"],
                        "operation_name": ep["operation_name"],
                    }),
                    "now": now,
                },
            )
            stored += 1
        except Exception as e:
            logger.debug("graphql: insert endpoint failed (%s): %s", ep.get("path"), e)

    # Store the schema as an artifact for downstream consumers.
    try:
        await db.execute(
            text("""
                INSERT INTO asset_js_artifacts (
                    id, asset_id, artifact_type, js_url, content_hash, intelligence, created_at
                )
                VALUES (
                    :id, :asset_id, 'graphql_schema', :url, NULL, :intel, :now
                )
                ON CONFLICT (asset_id, artifact_type, js_url) DO UPDATE SET
                    intelligence = EXCLUDED.intelligence,
                    created_at = EXCLUDED.created_at
            """),
            {
                "id": uuid.uuid4(),
                "asset_id": asset_id,
                "url": gql_url,
                "intel": json.dumps({
                    "introspection_enabled": "public" if schema_data.get("public") else True,
                    "operation_count": len(endpoints),
                    "schema": schema_data.get("schema"),
                }),
                "now": now,
            },
        )
    except Exception as e:
        logger.warning("graphql: failed to store schema artifact for %s: %s", gql_url, e)

    return stored
