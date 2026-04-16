"""API routes for cross-finding correlation and attack paths."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from services.finding_correlator import correlate_findings

router = APIRouter(prefix="/api/correlations", tags=["Correlations"])


@router.post("/run")
async def run_correlation(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Trigger cross-finding correlation for the current org."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No org context")

    result = correlate_findings(db, org_id)
    return result


@router.get("/attack-paths")
async def list_attack_paths(
    severity: str = Query(None, description="Filter by severity: Critical, High, Medium"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """List attack paths for the current org."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No org context")

    where = "WHERE ap.org_id = :org_id"
    params = {"org_id": org_id}

    if severity:
        where += " AND ap.severity = :severity"
        params["severity"] = severity

    # Count
    count_result = db.execute(
        text(f"SELECT COUNT(*) FROM attack_paths ap {where}"),
        params,
    )
    total = count_result.scalar()

    # Fetch page
    offset = (page - 1) * page_size
    result = db.execute(
        text(f"""
            SELECT ap.id, ap.title, ap.severity, ap.steps, ap.chain_length, ap.created_at,
                   entry_a.hostname as entry_hostname, target_a.hostname as target_hostname
            FROM attack_paths ap
            LEFT JOIN assets entry_a ON entry_a.id = ap.entry_asset_id
            LEFT JOIN assets target_a ON target_a.id = ap.target_asset_id
            {where}
            ORDER BY
                CASE ap.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
                ap.chain_length DESC
            LIMIT :limit OFFSET :offset
        """),
        {**params, "limit": page_size, "offset": offset},
    )

    paths = [
        {
            "id": row.id,
            "title": row.title,
            "severity": row.severity,
            "steps": row.steps,
            "chain_length": row.chain_length,
            "entry_hostname": row.entry_hostname,
            "target_hostname": row.target_hostname,
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
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Get a single attack path with full details."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No org context")

    result = db.execute(
        text("""
            SELECT ap.*, entry_a.hostname as entry_hostname, target_a.hostname as target_hostname
            FROM attack_paths ap
            LEFT JOIN assets entry_a ON entry_a.id = ap.entry_asset_id
            LEFT JOIN assets target_a ON target_a.id = ap.target_asset_id
            WHERE ap.id = :id AND ap.org_id = :org_id
        """),
        {"id": path_id, "org_id": org_id},
    )
    row = result.fetchone()
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
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/corroborated")
async def list_corroborated_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """List findings corroborated by multiple scanners."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No org context")

    offset = (page - 1) * page_size
    result = db.execute(
        text("""
            SELECT f.id, f.plugin_name, f.severity, f.severity_label, f.cves,
                   f.source_systems, f.custom_fields,
                   a.hostname, a.ip
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE a.org_id = :org_id
              AND f.custom_fields::jsonb ? 'corroboration'
              AND (f.custom_fields->'corroboration'->>'corroborated')::boolean = true
            ORDER BY f.severity DESC, f.priority_score DESC NULLS LAST
            LIMIT :limit OFFSET :offset
        """),
        {"org_id": org_id, "limit": page_size, "offset": offset},
    )

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
