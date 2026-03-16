"""
SBOM — FastAPI routes
Prefix: /api/sbom
"""
import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, asc, or_

from core.database import get_db
from core.auth import get_accessible_org_ids, apply_scan_org_filter
from models.models import (
    SBOMComponent, SBOMVulnerability,
    Asset, Scan, Finding,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/sbom", tags=["sbom"])


# ── helpers ──────────────────────────────────────────────

def _asset_lookup(db, asset_ids):
    if not asset_ids:
        return {}
    rows = db.query(Asset).filter(Asset.id.in_(list(asset_ids))).all()
    return {a.id: a for a in rows}


def _asset_label(asset):
    if not asset:
        return "—"
    return asset.hostname or asset.ip or "—"


def _apply_sort(q, model, sort_by, order, default_col):
    col = getattr(model, sort_by, None) or default_col
    return q.order_by(desc(col) if order == "desc" else asc(col))


# ── GET /api/sbom/components ─────────────────────────────

@router.get("/components")
def list_sbom_components(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    component_type: Optional[str] = None,
    has_cves: Optional[bool] = None,
    has_eol: Optional[bool] = None,
    is_running: Optional[bool] = None,
    priority_tier: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "priority_tier",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(SBOMComponent).join(Scan, SBOMComponent.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)

    if scan_id:
        q = q.filter(SBOMComponent.scan_id == scan_id)
    if asset_id:
        q = q.filter(SBOMComponent.asset_id == asset_id)
    if component_type:
        q = q.filter(SBOMComponent.component_type == component_type)
    if has_cves is True:
        q = q.filter(SBOMComponent.cve_count > 0)
    elif has_cves is False:
        q = q.filter(SBOMComponent.cve_count == 0)
    if has_eol is True:
        q = q.filter(SBOMComponent.eol_status.in_(["eol", "approaching_eol"]))
    elif has_eol is False:
        q = q.filter(SBOMComponent.eol_status.notin_(["eol", "approaching_eol"]))
    if is_running is not None:
        q = q.filter(SBOMComponent.is_running == is_running)
    if priority_tier:
        q = q.filter(SBOMComponent.priority_tier == priority_tier)
    if search:
        s = f"%{search}%"
        q = q.filter(or_(
            SBOMComponent.name.ilike(s),
            SBOMComponent.vendor.ilike(s),
            SBOMComponent.cpe.ilike(s),
        ))

    q = _apply_sort(q, SBOMComponent, sort_by, order, SBOMComponent.name)
    total = q.count()

    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()

    assets = _asset_lookup(db, {r.asset_id for r in rows})

    return {
        "total": total,
        "page": 1 if page_size == 0 else page,
        "page_size": page_size,
        "components": [_serialize_component(c, assets) for c in rows],
    }


def _serialize_component(c, assets=None):
    asset = (assets or {}).get(c.asset_id)
    return {
        "id": c.id,
        "scan_id": c.scan_id,
        "asset_id": c.asset_id,
        "asset_label": _asset_label(asset),
        "asset_ip": asset.ip if asset else None,
        "asset_hostname": asset.hostname if asset else None,
        "software_id": c.software_id,
        "name": c.name,
        "version": c.version,
        "vendor": c.vendor,
        "cpe": c.cpe,
        "purl": c.purl,
        "component_type": c.component_type,
        "parent_component_id": c.parent_component_id,
        "is_running": c.is_running,
        "eol_date": c.eol_date,
        "eol_status": c.eol_status,
        "cve_count": c.cve_count,
        "max_severity": c.max_severity,
        "max_cvss": c.max_cvss,
        "priority_tier": c.priority_tier,
        "source_plugin": c.source_plugin,
    }


# ── GET /api/sbom/components/{id}/vulnerabilities ────────

@router.get("/components/{component_id}/vulnerabilities")
def get_component_vulnerabilities(
    component_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    comp = db.query(SBOMComponent).filter(SBOMComponent.id == component_id).first()
    if not comp:
        return {"vulnerabilities": []}

    vulns = db.query(SBOMVulnerability).filter(
        SBOMVulnerability.component_id == component_id
    ).order_by(desc(SBOMVulnerability.severity), desc(SBOMVulnerability.cvss_score)).all()

    return {
        "component": _serialize_component(comp),
        "vulnerabilities": [{
            "id": v.id,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "epss_score": v.epss_score,
            "in_kev": v.in_kev,
            "remediation_note": v.remediation_note,
            "priority_tier": v.priority_tier,
            "finding_id": v.finding_id,
        } for v in vulns],
    }


# ── GET /api/sbom/blast-radius ───────────────────────────

@router.get("/blast-radius")
def get_blast_radius(
    cve_id: Optional[str] = None,
    library_name: Optional[str] = None,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Find all assets affected by a CVE or library across the SBOM."""
    if not cve_id and not library_name:
        return {"error": "Provide cve_id or library_name", "affected_assets": []}

    if cve_id:
        # Find all components that have this CVE
        vuln_q = db.query(SBOMVulnerability).join(
            SBOMComponent, SBOMVulnerability.component_id == SBOMComponent.id
        ).join(Scan, SBOMComponent.scan_id == Scan.id)
        vuln_q = apply_scan_org_filter(vuln_q, org_ids)
        vuln_q = vuln_q.filter(SBOMVulnerability.cve_id == cve_id)
        if scan_id:
            vuln_q = vuln_q.filter(SBOMComponent.scan_id == scan_id)

        vulns = vuln_q.all()
        comp_ids = list({v.component_id for v in vulns})
        comps = db.query(SBOMComponent).filter(SBOMComponent.id.in_(comp_ids)).all() if comp_ids else []
    else:
        # Find all components matching library name
        comp_q = db.query(SBOMComponent).join(Scan, SBOMComponent.scan_id == Scan.id)
        comp_q = apply_scan_org_filter(comp_q, org_ids)
        comp_q = comp_q.filter(SBOMComponent.name.ilike(f"%{library_name}%"))
        if scan_id:
            comp_q = comp_q.filter(SBOMComponent.scan_id == scan_id)
        comps = comp_q.all()

    asset_ids = list({c.asset_id for c in comps})
    assets = _asset_lookup(db, set(asset_ids))

    # Build per-asset result
    affected = []
    for comp in comps:
        asset = assets.get(comp.asset_id)
        # Find parent application if this is a bundled library
        parent_name = None
        if comp.parent_component_id:
            parent = db.query(SBOMComponent).filter(
                SBOMComponent.id == comp.parent_component_id
            ).first()
            if parent:
                parent_name = f"{parent.name} {parent.version or ''}".strip()

        affected.append({
            "asset_id": comp.asset_id,
            "asset_label": _asset_label(asset),
            "asset_ip": asset.ip if asset else None,
            "asset_hostname": asset.hostname if asset else None,
            "asset_os": asset.os if asset else None,
            "component_id": comp.id,
            "component_name": comp.name,
            "component_version": comp.version,
            "component_type": comp.component_type,
            "parent_application": parent_name,
            "is_running": comp.is_running,
            "eol_status": comp.eol_status,
            "eol_date": comp.eol_date,
            "priority_tier": comp.priority_tier,
            "cve_count": comp.cve_count,
        })

    return {
        "query": {"cve_id": cve_id, "library_name": library_name, "scan_id": scan_id},
        "total_assets": len(asset_ids),
        "total_components": len(comps),
        "affected": affected,
    }


# ── GET /api/sbom/asset-summary ──────────────────────────

@router.get("/asset-summary")
def get_sbom_asset_summary(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """SBOM risk summary for an asset or scan."""
    q = db.query(SBOMComponent).join(Scan, SBOMComponent.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(SBOMComponent.scan_id == scan_id)
    if asset_id:
        q = q.filter(SBOMComponent.asset_id == asset_id)

    comps = q.all()

    by_type = {}
    by_priority = {}
    eol_components = []
    running_vulnerable = []
    total_cves = 0
    sev_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}

    for c in comps:
        by_type[c.component_type or "unknown"] = by_type.get(c.component_type or "unknown", 0) + 1
        if c.priority_tier:
            by_priority[c.priority_tier] = by_priority.get(c.priority_tier, 0) + 1
        if c.eol_status in ("eol", "approaching_eol"):
            eol_components.append({
                "id": c.id, "name": c.name, "version": c.version,
                "eol_status": c.eol_status, "eol_date": c.eol_date,
            })
        if c.is_running and c.cve_count > 0:
            running_vulnerable.append({
                "id": c.id, "name": c.name, "version": c.version,
                "cve_count": c.cve_count, "max_severity": c.max_severity,
                "priority_tier": c.priority_tier,
            })
        total_cves += c.cve_count or 0
        if c.max_severity:
            sev_counts[c.max_severity] = sev_counts.get(c.max_severity, 0) + 1

    return {
        "total_components": len(comps),
        "total_cves": total_cves,
        "by_type": by_type,
        "by_priority": by_priority,
        "severity_distribution": sev_counts,
        "eol_components": eol_components,
        "running_vulnerable": running_vulnerable,
    }
