"""Shared helpers for scoping scan queries to a target domain and/or
filtering by asset freshness.

Two complementary filters are used throughout the discovery and enrichment
pipelines:

1. **Target scope** — when a user triggers "scan hakunahq.com", only that
   domain's assets should be touched (not all 22k assets across every
   historical target in the org). The `target_domain` column on `scan_runs`
   carries this selection from the API to the Celery task; this module
   turns it into a SQL predicate.

2. **Staleness filter** — during the nightly full scan (which has no target
   scope), we don't want to re-resolve every asset that was already
   processed in the last 24h. `last_enriched` is our staleness signal:
   assets with a fresh `last_enriched` are skipped by the discovery
   re-processing stages (dnsx/naabu/liveness).

Both filters are additive — callers pass them into a query builder that
returns the `WHERE` fragment and the parameter dict to merge into the
main query. `None` means "do not apply this filter".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# Default staleness window (hours). Assets whose `last_enriched` is newer
# than this are considered "fresh" and skipped by re-processing stages.
DEFAULT_STALE_HOURS = 24


def _normalize_target_domains(target_domains: str | list[str] | None) -> list[str]:
    """Accept a single string, a list, or None; return a clean list."""
    if target_domains is None:
        return []
    if isinstance(target_domains, str):
        return [target_domains.strip().lower()] if target_domains.strip() else []
    return [d.strip().lower() for d in target_domains if d and d.strip()]


def build_target_scope(
    target_domains: str | list[str] | None,
    column: str = "hostname",
    param_prefix: str = "td",
) -> tuple[str, dict]:
    """Build a SQL fragment that restricts `column` to the given target domains.

    Matches both the apex (`hostname = 'hakunahq.com'`) and subdomains
    (`hostname LIKE '%.hakunahq.com'`). Multiple targets are OR-joined.

    Returns a tuple of (sql_fragment, params). sql_fragment is either:
        - empty string (no scoping applied), or
        - a parenthesized predicate like "(hostname = :td_0 OR hostname LIKE :td_0_pat OR ...)"

    Callers splice the fragment into their own query with " AND " and merge
    `params` into their bind dict.
    """
    domains = _normalize_target_domains(target_domains)
    if not domains:
        return "", {}

    clauses: list[str] = []
    params: dict[str, str] = {}
    for i, d in enumerate(domains):
        key = f"{param_prefix}_{i}"
        pat_key = f"{key}_pat"
        clauses.append(f"({column} = :{key} OR {column} LIKE :{pat_key})")
        params[key] = d
        params[pat_key] = f"%.{d}"

    return "(" + " OR ".join(clauses) + ")", params


def build_stale_clause(
    enabled: bool = True,
    stale_hours: int = DEFAULT_STALE_HOURS,
    column: str = "last_enriched",
) -> str:
    """Build a SQL fragment that excludes assets processed within the last N hours.

    When enabled, returns a fragment like:
        "(last_enriched IS NULL OR last_enriched < NOW() - INTERVAL '24 hours')"

    When disabled or stale_hours <= 0, returns an empty string so the caller
    can splice it unconditionally.

    `stale_hours` is interpolated directly as an integer literal (never a
    user-provided value) — INTERVAL with bind parameters is awkward across
    drivers, and the column name is also trusted code.
    """
    if not enabled or stale_hours <= 0:
        return ""
    hours = int(stale_hours)
    return f"({column} IS NULL OR {column} < NOW() - INTERVAL '{hours} hours')"


def compose_where(*fragments: str) -> str:
    """Join non-empty WHERE fragments with ' AND ', prefixing with 'AND '.

    Returns an empty string if all fragments are empty so the caller can
    safely concatenate it onto a query that already has a WHERE clause.

    Example:
        base = "SELECT ... WHERE org_id = :org_id"
        extra = compose_where(scope_sql, stale_sql)
        # extra == " AND (hostname = :td_0 OR ...) AND (last_enriched IS NULL OR ...)"
        query = base + extra
    """
    parts = [f for f in fragments if f]
    if not parts:
        return ""
    return " AND " + " AND ".join(parts)


async def load_scan_run_scope(
    db: "AsyncSession",
    scan_run_id: str | None,
) -> str | None:
    """Read the `target_domain` column of a scan_runs row.

    Returns None if scan_run_id is None, the row doesn't exist, or the
    column is NULL (nightly full-org scan).

    Currently unused inside the chain tasks (they read target_domain inline
    together with scan_type / stage_index), but exposed for the standalone
    per-stage Celery tasks and future callers.
    """
    if not scan_run_id:
        return None
    # Lazy import so the module is importable in test environments that
    # don't have sqlalchemy on the path.
    from sqlalchemy import text
    row = await db.execute(
        text("SELECT target_domain FROM scan_runs WHERE id = :id"),
        {"id": scan_run_id},
    )
    r = row.fetchone()
    if not r:
        return None
    return r.target_domain


async def count_assets_in_scan_scope(
    db: "AsyncSession",
    scan_run_id: str,
) -> int | None:
    """Count assets visible to a scan_run's (org_id, target_domain) scope.

    Used by `_mark_failed` so a scan that times out mid-pipeline still
    reports partial-progress `assets_found` instead of 0 — the upstream
    discovery stages may have already populated the assets table before
    the timeout fired.

    Returns None when the scan_run row doesn't exist.
    """
    from sqlalchemy import text
    row = await db.execute(
        text("SELECT org_id, target_domain FROM scan_runs WHERE id = :id"),
        {"id": scan_run_id},
    )
    r = row.fetchone()
    if not r:
        return None
    scope_sql, scope_params = build_target_scope(r.target_domain)
    extra = compose_where(scope_sql)
    params = {"org_id": str(r.org_id), **scope_params}
    result = await db.execute(
        text(f"SELECT COUNT(*) AS n FROM assets WHERE org_id = :org_id{extra}"),
        params,
    )
    n_row = result.fetchone()
    return int(n_row.n) if n_row else 0
