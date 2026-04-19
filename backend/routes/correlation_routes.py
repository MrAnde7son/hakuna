"""API routes for cross-finding correlation and attack paths."""

import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from core.database import get_db, DATABASE_URL
from core.auth import get_current_user, get_accessible_org_ids
from services.finding_correlator import correlate_findings


def _iso(value):
    """Serialize a TIMESTAMP column value to ISO-8601.

    Raw text() queries return strings on SQLite and datetime on Postgres —
    normalize so the response is consistent and never blows up on either.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _jsonify(value):
    """Normalize a JSON column value to a python object.

    Raw text() queries return JSON columns as strings on SQLite (the driver
    has no type awareness without the ORM) and as dicts/lists on Postgres.
    Return a python object either way so the frontend always receives
    parsed JSON, not a string it has to re-parse.
    """
    if value is None or isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value
    return value

_SQLITE = DATABASE_URL.startswith("sqlite")

router = APIRouter(prefix="/api/correlations", tags=["Correlations"])


def _scope_clause(
    org_ids: Optional[List[int]], alias: str = "ap"
) -> tuple[str, dict, list]:
    """Build an org-scope fragment for raw-SQL queries.

    Returns (clause, params, bindparams). `org_ids is None` means superadmin
    with no org context — we don't filter by org.
    """
    if org_ids is None:
        return f"{alias}.org_id IS NOT NULL", {}, []
    return (
        f"{alias}.org_id IN :org_ids",
        {"org_ids": list(org_ids)},
        [bindparam("org_ids", expanding=True)],
    )


@router.post("/run", status_code=202)
async def run_correlation(
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Dispatch cross-finding correlation as a background job.

    Returns immediately with a job_id the client can poll at
    `GET /api/jobs/{job_id}/status`. The server keeps running even if the
    client navigates away; UI polling can resume on return.

    Superadmins must pin an org via the X-Org-Context header; MSSP parents
    are scoped to whichever linked org they're currently viewing.
    """
    if org_ids is None or len(org_ids) != 1:
        raise HTTPException(
            status_code=400,
            detail="Correlation requires a single org context (set X-Org-Context).",
        )

    from services.job_manager import dispatch
    from core.database import SessionLocal

    org_id = org_ids[0]

    def _run_correlation():
        # Dedicated session — the request-scoped one closes as soon as we
        # return the 202. Correlation + narration can run for tens of
        # seconds and must not share a session with the HTTP handler.
        db = SessionLocal()
        try:
            return correlate_findings(db, org_id)
        finally:
            db.close()

    # 15 minute cap — narration with 20 LLM calls typically finishes well
    # under a minute, but slow providers / rate limits can stretch it.
    job = dispatch(f"correlation_run_org{org_id}", _run_correlation, timeout=900)
    return {
        "job_id": job.id,
        "status": job.status.value,
        "poll_url": f"/api/jobs/{job.id}/status",
    }


_SORT_COLUMNS = {
    # alias → safe ORDER BY expression
    "score": "COALESCE(ap.score, 0)",
    "severity": (
        "CASE ap.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 "
        "WHEN 'Medium' THEN 3 ELSE 4 END"
    ),
    "chain_length": "ap.chain_length",
    "created_at": "ap.created_at",
}


@router.get("/attack-paths")
async def list_attack_paths(
    severity: str = Query(None, description="Critical, High, Medium"),
    search: str = Query(None, description="Substring match on title / entry / target hostname"),
    entry_reason: str = Query(None, description="Substring match on entry_reason code"),
    target_reason: str = Query(None, description="Substring match on target_reason code"),
    min_score: float = Query(None, ge=0, le=100, description="Only paths scored ≥ this"),
    narrated: Optional[bool] = Query(None, description="Only paths with an LLM narrative"),
    sort_by: str = Query("score", description="score | severity | chain_length | created_at"),
    order: str = Query("desc", description="asc | desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """List attack paths visible to the caller (MSSP parents see linked orgs).

    All filters are combined with AND. `search` looks across title plus the
    joined entry/target hostnames. Sort is whitelisted so user input can't
    inject SQL.
    """
    if org_ids is not None and not org_ids:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    scope_clause, params, binds = _scope_clause(org_ids, alias="ap")
    where_parts = [scope_clause]

    if severity:
        where_parts.append("ap.severity = :severity")
        params["severity"] = severity

    if search:
        # Join-aware search — title covers the step chain already, plus we
        # still match the joined hostnames for direct "find by host" use.
        where_parts.append(
            "(LOWER(ap.title) LIKE :q "
            "OR LOWER(COALESCE(entry_a.hostname, '')) LIKE :q "
            "OR LOWER(COALESCE(target_a.hostname, '')) LIKE :q)"
        )
        params["q"] = f"%{search.lower()}%"

    if entry_reason:
        where_parts.append("LOWER(COALESCE(ap.entry_reason, '')) LIKE :entry_reason")
        params["entry_reason"] = f"%{entry_reason.lower()}%"

    if target_reason:
        where_parts.append("LOWER(COALESCE(ap.target_reason, '')) LIKE :target_reason")
        params["target_reason"] = f"%{target_reason.lower()}%"

    if min_score is not None:
        where_parts.append("COALESCE(ap.score, 0) >= :min_score")
        params["min_score"] = min_score

    if narrated is True:
        where_parts.append("ap.narrative IS NOT NULL AND ap.narrative != ''")
    elif narrated is False:
        where_parts.append("(ap.narrative IS NULL OR ap.narrative = '')")

    where = "WHERE " + " AND ".join(where_parts)

    # Resolve sort column (whitelist) + direction. Secondary sort by id keeps
    # pagination stable when primary keys tie.
    sort_expr = _SORT_COLUMNS.get(sort_by, _SORT_COLUMNS["score"])
    direction = "ASC" if str(order).lower() == "asc" else "DESC"
    order_by = f"{sort_expr} {direction}, ap.id DESC"

    # Count needs to see the same JOINs since `search` references them.
    count_stmt = text(
        f"""
            SELECT COUNT(*) FROM attack_paths ap
            LEFT JOIN assets entry_a ON entry_a.id = ap.entry_asset_id
            LEFT JOIN assets target_a ON target_a.id = ap.target_asset_id
            {where}
        """
    )
    if binds:
        count_stmt = count_stmt.bindparams(*binds)
    total = db.execute(count_stmt, params).scalar() or 0

    offset = (page - 1) * page_size
    list_stmt = text(
        f"""
            SELECT ap.id, ap.title, ap.severity, ap.steps, ap.chain_length, ap.created_at,
                   ap.narrative, ap.recommended_mitigations,
                   ap.entry_reason, ap.target_reason, ap.score, ap.score_breakdown,
                   entry_a.hostname as entry_hostname, target_a.hostname as target_hostname
            FROM attack_paths ap
            LEFT JOIN assets entry_a ON entry_a.id = ap.entry_asset_id
            LEFT JOIN assets target_a ON target_a.id = ap.target_asset_id
            {where}
            ORDER BY {order_by}
            LIMIT :limit OFFSET :offset
        """
    )
    if binds:
        list_stmt = list_stmt.bindparams(*binds)

    result = db.execute(list_stmt, {**params, "limit": page_size, "offset": offset})

    paths = [
        {
            "id": row.id,
            "title": row.title,
            "severity": row.severity,
            "steps": _jsonify(row.steps) or [],
            "chain_length": row.chain_length,
            "entry_hostname": row.entry_hostname,
            "target_hostname": row.target_hostname,
            "entry_reason": row.entry_reason,
            "target_reason": row.target_reason,
            "score": row.score,
            "score_breakdown": _jsonify(row.score_breakdown),
            "narrative": row.narrative,
            "recommended_mitigations": _jsonify(row.recommended_mitigations),
            "created_at": _iso(row.created_at),
        }
        for row in result.fetchall()
    ]

    return {"items": paths, "total": total, "page": page, "page_size": page_size}


@router.get("/attack-paths/{path_id}")
async def get_attack_path(
    path_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Get a single attack path with full details."""
    if org_ids is not None and not org_ids:
        raise HTTPException(status_code=404, detail="Attack path not found")

    scope_clause, params, binds = _scope_clause(org_ids, alias="ap")
    stmt = text(
        f"""
            SELECT ap.*, entry_a.hostname as entry_hostname, target_a.hostname as target_hostname
            FROM attack_paths ap
            LEFT JOIN assets entry_a ON entry_a.id = ap.entry_asset_id
            LEFT JOIN assets target_a ON target_a.id = ap.target_asset_id
            WHERE ap.id = :id AND {scope_clause}
        """
    )
    if binds:
        stmt = stmt.bindparams(*binds)

    row = db.execute(stmt, {**params, "id": path_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Attack path not found")

    return {
        "id": row.id,
        "title": row.title,
        "severity": row.severity,
        "steps": _jsonify(row.steps) or [],
        "chain_length": row.chain_length,
        "entry_asset_id": row.entry_asset_id,
        "target_asset_id": row.target_asset_id,
        "entry_hostname": row.entry_hostname,
        "target_hostname": row.target_hostname,
        "entry_reason": row.entry_reason,
        "target_reason": row.target_reason,
        "score": row.score,
        "score_breakdown": _jsonify(row.score_breakdown),
        "narrative": row.narrative,
        "recommended_mitigations": _jsonify(row.recommended_mitigations),
        "created_at": _iso(row.created_at),
    }


@router.get("/corroborated")
async def list_corroborated_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """List findings corroborated by multiple scanners."""
    if org_ids is not None and not org_ids:
        return {"items": [], "page": page, "page_size": page_size}

    scope_clause, params, binds = _scope_clause(org_ids, alias="sc")

    offset = (page - 1) * page_size

    if _SQLITE:
        corr_filter = "json_extract(f.custom_fields, '$.corroboration.corroborated') = 1"
    else:
        corr_filter = (
            "f.custom_fields::jsonb ? 'corroboration' "
            "AND (f.custom_fields->'corroboration'->>'corroborated')::boolean = true"
        )

    stmt = text(
        f"""
            SELECT f.id, f.plugin_name, f.severity, f.severity_label, f.cves,
                   f.source_systems, f.custom_fields,
                   a.hostname, a.ip
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            JOIN scans sc ON sc.id = f.scan_id
            WHERE {scope_clause}
              AND {corr_filter}
            ORDER BY f.severity DESC, f.priority_score DESC NULLS LAST
            LIMIT :limit OFFSET :offset
        """
    )
    if binds:
        stmt = stmt.bindparams(*binds)

    result = db.execute(stmt, {**params, "limit": page_size, "offset": offset})

    findings = [
        {
            "id": row.id,
            "plugin_name": row.plugin_name,
            "severity": row.severity,
            "severity_label": row.severity_label,
            "cves": row.cves,
            "source_systems": row.source_systems,
            "corroboration": (json.loads(row.custom_fields) if isinstance(row.custom_fields, str) else row.custom_fields or {}).get("corroboration", {}),
            "hostname": row.hostname,
            "ip": str(row.ip) if row.ip else None,
        }
        for row in result.fetchall()
    ]

    return {"items": findings, "page": page, "page_size": page_size}
