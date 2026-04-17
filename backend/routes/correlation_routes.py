"""API routes for cross-finding correlation and attack paths."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from services.finding_correlator import correlate_findings

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


@router.post("/run")
async def run_correlation(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Trigger cross-finding correlation for the caller's active org.

    Superadmins must pin an org via the X-Org-Context header; MSSP parents
    are scoped to whichever linked org they're currently viewing.
    """
    if org_ids is None or len(org_ids) != 1:
        raise HTTPException(
            status_code=400,
            detail="Correlation requires a single org context (set X-Org-Context).",
        )

    return correlate_findings(db, org_ids[0])


@router.get("/attack-paths")
async def list_attack_paths(
    severity: str = Query(None, description="Filter by severity: Critical, High, Medium"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """List attack paths visible to the caller (MSSP parents see linked orgs)."""
    if org_ids is not None and not org_ids:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    scope_clause, params, binds = _scope_clause(org_ids, alias="ap")
    where = f"WHERE {scope_clause}"

    if severity:
        where += " AND ap.severity = :severity"
        params["severity"] = severity

    count_stmt = text(f"SELECT COUNT(*) FROM attack_paths ap {where}")
    if binds:
        count_stmt = count_stmt.bindparams(*binds)
    total = db.execute(count_stmt, params).scalar()

    offset = (page - 1) * page_size
    list_stmt = text(
        f"""
            SELECT ap.id, ap.title, ap.severity, ap.steps, ap.chain_length, ap.created_at,
                   ap.narrative, ap.recommended_mitigations,
                   entry_a.hostname as entry_hostname, target_a.hostname as target_hostname
            FROM attack_paths ap
            LEFT JOIN assets entry_a ON entry_a.id = ap.entry_asset_id
            LEFT JOIN assets target_a ON target_a.id = ap.target_asset_id
            {where}
            ORDER BY
                CASE ap.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
                ap.chain_length DESC
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
            "steps": row.steps,
            "chain_length": row.chain_length,
            "entry_hostname": row.entry_hostname,
            "target_hostname": row.target_hostname,
            "narrative": row.narrative,
            "recommended_mitigations": row.recommended_mitigations,
            "created_at": row.created_at.isoformat() if row.created_at else None,
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
        "steps": row.steps,
        "chain_length": row.chain_length,
        "entry_asset_id": row.entry_asset_id,
        "target_asset_id": row.target_asset_id,
        "entry_hostname": row.entry_hostname,
        "target_hostname": row.target_hostname,
        "narrative": row.narrative,
        "recommended_mitigations": row.recommended_mitigations,
        "created_at": row.created_at.isoformat() if row.created_at else None,
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

    scope_clause, params, binds = _scope_clause(org_ids, alias="a")

    offset = (page - 1) * page_size
    stmt = text(
        f"""
            SELECT f.id, f.plugin_name, f.severity, f.severity_label, f.cves,
                   f.source_systems, f.custom_fields,
                   a.hostname, a.ip
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE {scope_clause}
              AND f.custom_fields::jsonb ? 'corroboration'
              AND (f.custom_fields->'corroboration'->>'corroborated')::boolean = true
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
            "corroboration": (row.custom_fields or {}).get("corroboration", {}),
            "hostname": row.hostname,
            "ip": str(row.ip) if row.ip else None,
        }
        for row in result.fetchall()
    ]

    return {"items": findings, "page": page, "page_size": page_size}
