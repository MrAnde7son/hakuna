"""``get_asset_profile`` — read enriched asset context from the shared DB.

Port of ``backend/agents/agent_tools.py::get_asset_profile``. The
backend version uses SQLAlchemy ORM models (``Asset``, ``Finding``,
``InventoryService``, ``InventoryLoggedOn``, ``InventorySecurityControl``,
``InventorySoftware``); the OSS port issues raw asyncpg queries so the
audit-scanner stays free of model-class coupling.

Reads from the same tables the backend writes — schema drift between
this query and the backend's models manifests as a missing column at
fetch time, surfaced as a structured tool error rather than a crash.

Skips queries gracefully when the table doesn't exist — the OSS
scanner can still run against a Postgres that doesn't have the
inventory tables (e.g. a fresh hakuna-vm-scanner schema). Each
optional section returns ``[]`` and the LLM gets enough context from
the asset row alone.
"""

from __future__ import annotations

import logging

import asyncpg

from scanner.audit.agent_context import AuditContext
from scanner.audit.audit_engine import agent_tool

logger = logging.getLogger(__name__)


_ASSET_QUERY = """
    SELECT
        id, ip, hostname, fqdn, os, criticality, risk_score,
        environment_tag, is_internet_facing,
        inferred_primary_user, inferred_team
    FROM assets
    WHERE id = $1
"""

_SEVERITY_COUNTS = """
    SELECT severity, COUNT(*)::int AS n
    FROM findings
    WHERE asset_id = $1
    GROUP BY severity
"""

_TOP_FINDINGS = """
    SELECT id, plugin_name, severity, priority_score, cves, solution
    FROM findings
    WHERE asset_id = $1 AND severity >= 3
    ORDER BY priority_score DESC NULLS LAST
    LIMIT 10
"""

_SERVICES = """
    SELECT service_name, is_running
    FROM inventory_services
    WHERE asset_id = $1
    LIMIT 30
"""

_LOGGED_ON = """
    SELECT username, domain
    FROM inventory_logged_on
    WHERE asset_id = $1
"""

_CONTROLS = """
    SELECT control_type, product_name, is_enabled, is_up_to_date
    FROM inventory_security_controls
    WHERE asset_id = $1
"""

_SOFTWARE_COUNT = """
    SELECT COUNT(*)::int AS n
    FROM inventory_software
    WHERE asset_id = $1
"""


@agent_tool(
    "get_asset_profile",
    "Get a full profile of an asset: vulns, installed software, services, "
    "logged-on users, security controls. Useful for understanding what's "
    "running on a host before/after running protocol-specific tools.",
    {
        "asset_id": {
            "type": ["string", "integer"],
            "description": "Asset id (uuid string or integer; default: the run's asset)",
        },
    },
)
async def get_asset_profile(ctx: AuditContext, params: dict) -> dict:
    aid = params.get("asset_id")
    if aid is None and ctx.asset:
        aid = ctx.asset.get("id")
    if aid is None:
        return {"error": "asset_id is required"}

    if ctx.db_pool is None:
        # Fallback: return what we already know from ctx.asset. OSS
        # standalone runs without a DB get this.
        if ctx.asset:
            return {"asset": _project_asset_from_ctx(ctx.asset), "note": "no db pool — limited profile"}
        return {"error": "no db pool configured and no asset on context"}

    async with ctx.db_pool.acquire() as conn:
        try:
            asset_row = await conn.fetchrow(_ASSET_QUERY, _coerce(aid))
        except asyncpg.PostgresError as e:
            return {"error": f"asset query failed: {e}"}
        if asset_row is None:
            return {"error": f"asset {aid} not found"}

        sev = await _safe_fetch(conn, _SEVERITY_COUNTS, _coerce(aid))
        top = await _safe_fetch(conn, _TOP_FINDINGS, _coerce(aid))
        services = await _safe_fetch(conn, _SERVICES, _coerce(aid))
        logged_on = await _safe_fetch(conn, _LOGGED_ON, _coerce(aid))
        controls = await _safe_fetch(conn, _CONTROLS, _coerce(aid))
        software_count_row = await _safe_fetchrow(conn, _SOFTWARE_COUNT, _coerce(aid))

    return {
        "asset": dict(asset_row),
        "severity_counts": {row["severity"]: row["n"] for row in sev},
        "top_findings": [
            {
                "id": row["id"],
                "plugin_name": row["plugin_name"],
                "severity": row["severity"],
                "priority_score": row["priority_score"],
                "cves": row["cves"],
                "solution": (row["solution"] or "")[:200],
            }
            for row in top
        ],
        "services": [
            {"name": row["service_name"], "running": row["is_running"]}
            for row in services
        ],
        "logged_on_users": [
            {"username": row["username"], "domain": row["domain"]}
            for row in logged_on
        ],
        "security_controls": [
            {
                "type": row["control_type"],
                "product": row["product_name"],
                "enabled": row["is_enabled"],
                "up_to_date": row["is_up_to_date"],
            }
            for row in controls
        ],
        "installed_software_count": (software_count_row or {}).get("n", 0),
    }


# ── Helpers ───────────────────────────────────────────────────────


async def _safe_fetch(conn, query: str, *args):
    """Return [] if the table is missing — keeps the tool runnable on
    Postgres instances that don't have the full Hakuna inventory schema."""
    try:
        return await conn.fetch(query, *args)
    except asyncpg.PostgresError as e:
        logger.warning("get_asset_profile: query failed (%s) — returning empty", e)
        return []


async def _safe_fetchrow(conn, query: str, *args):
    try:
        return await conn.fetchrow(query, *args)
    except asyncpg.PostgresError:
        return None


def _coerce(value):
    """assets.id is uuid in canonical schema; accept str or int."""
    import uuid as _uuid
    if isinstance(value, _uuid.UUID):
        return value
    if isinstance(value, str):
        try:
            return _uuid.UUID(value)
        except ValueError:
            return value
    return value


def _project_asset_from_ctx(asset: dict) -> dict:
    keep = {"id", "ip", "hostname", "fqdn", "os", "criticality", "risk_score",
            "environment_tag", "is_internet_facing",
            "inferred_primary_user", "inferred_team"}
    return {k: v for k, v in asset.items() if k in keep}
