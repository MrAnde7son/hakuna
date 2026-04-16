"""
Report routes — summary, trending, risk-grade, delta comparison,
temporal analytics, owner risk, funnel, and NLP query endpoints.
"""
import time as _time
from typing import Optional, List
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, desc, or_, cast, Text

from core.database import get_db
from core.query_guards import set_statement_timeout
from core.auth import get_accessible_org_ids, apply_org_filter, apply_scan_org_filter
from models.models import (
    Scan, Asset, Finding, ScanComparison, SLAConfig, FindingException,
    AggregatedSolution, Tag, TagAssignment,
    FindingOwnership, AssetOwnership,
    InventoryService, InventoryUser, InventoryLoggedOn,
    InventoryShare, InventorySecurityControl,
)
import services.tags as tag_engine
from services.nlp_search import parse_nlp_query
from services.nlp_filters import (
    apply_asset_nlp_filters,
    apply_finding_nlp_filters,
    severity_breakdown_grouped,
)

router = APIRouter()


# ─── Simple TTL cache (local copy to avoid circular import from app) ───

_endpoint_cache: dict[str, tuple[float, any]] = {}
_CACHE_TTL = 30  # seconds


def _cache_get(key: str):
    """Return cached value if still valid, else None."""
    entry = _endpoint_cache.get(key)
    if entry and (_time.monotonic() - entry[0]) < _CACHE_TTL:
        return entry[1]
    return None


def _cache_set(key: str, value):
    """Store value in cache with current timestamp."""
    _endpoint_cache[key] = (_time.monotonic(), value)


# ─────────────────────────────────────────────
# Reports & Summary
# ─────────────────────────────────────────────

@router.get("/api/reports/summary")
def get_summary(scan_id: Optional[int] = None, tags: Optional[str] = None, tag_logic: str = "AND", db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return summary statistics for the dashboard."""
    _ck = f"summary:{scan_id}:{tags}:{tag_logic}:{sorted(org_ids or [])}"
    cached = _cache_get(_ck)
    if cached is not None:
        return cached
    set_statement_timeout(db)
    asset_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    finding_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    asset_q = apply_scan_org_filter(asset_q, org_ids)
    finding_q = apply_scan_org_filter(finding_q, org_ids)

    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
        finding_q = finding_q.filter(Finding.scan_id == scan_id)

    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, False, db)
        asset_q = tag_engine.apply_asset_tag_filter(asset_q, id_sets, tag_logic, db)
        finding_q = tag_engine.apply_finding_tag_filter(finding_q, id_sets, tag_logic, db)

    total_assets = asset_q.count()
    total_findings = finding_q.count()

    # Exclude findings with active exceptions that have exclude_from_reports=True
    excluded_exception_ids = [
        e.id for e in db.query(FindingException.id).filter(
            FindingException.is_active == True,
            FindingException.exclude_from_reports == True,
        ).all()
    ]
    report_q = finding_q
    if excluded_exception_ids:
        report_q = finding_q.filter(
            or_(Finding.exception_id.is_(None), ~Finding.exception_id.in_(excluded_exception_ids))
        )

    # Severity breakdown (excludes report-excluded exceptions)
    severity_counts = {}
    for sev in range(5):
        severity_counts[sev] = report_q.filter(Finding.severity == sev).count()

    # Top plugin families — derived from report_q (already tag/scan/org/exception filtered)
    filtered_ids_subq = report_q.filter(Finding.severity >= 1).with_entities(Finding.id).subquery()
    family_counts = (
        db.query(Finding.plugin_family, func.count(Finding.id).label("count"))
        .filter(Finding.id.in_(filtered_ids_subq))
        .group_by(Finding.plugin_family)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    # Severity breakdown per family — for heatmap widgets
    top_family_names = [row[0] for row in family_counts]
    family_severity_rows = []
    if top_family_names:
        family_severity_rows = (
            db.query(
                Finding.plugin_family,
                Finding.severity,
                func.count(Finding.id).label("count"),
            )
            .filter(Finding.id.in_(filtered_ids_subq))
            .filter(Finding.plugin_family.in_(top_family_names))
            .group_by(Finding.plugin_family, Finding.severity)
            .all()
        )
    severity_by_family: dict[str, dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    _sev_label = {4: "critical", 3: "high", 2: "medium", 1: "low"}
    for fam, sev, cnt in family_severity_rows:
        key = _sev_label.get(sev)
        if key:
            severity_by_family[fam or "Unknown"][key] = cnt

    # Top risky assets
    top_assets = asset_q.order_by(desc(Asset.risk_score)).limit(5).all()

    # Effort breakdown
    effort_counts = {}
    for effort in ("quick_win", "medium", "complex"):
        effort_counts[effort] = report_q.filter(Finding.effort_level == effort, Finding.severity >= 1).count()

    # Owner breakdown — derived from report_q
    owner_counts = (
        db.query(Finding.owner_suggestion, func.count(Finding.id).label("count"))
        .filter(Finding.id.in_(filtered_ids_subq))
        .group_by(Finding.owner_suggestion)
        .order_by(desc("count"))
        .all()
    )

    # Severity breakdown per owner — for heatmap widgets
    top_owner_names = [row[0] for row in owner_counts[:10]]
    owner_severity_rows = []
    if top_owner_names:
        owner_severity_rows = (
            db.query(
                Finding.owner_suggestion,
                Finding.severity,
                func.count(Finding.id).label("count"),
            )
            .filter(Finding.id.in_(filtered_ids_subq))
            .filter(Finding.owner_suggestion.in_(top_owner_names))
            .group_by(Finding.owner_suggestion, Finding.severity)
            .all()
        )
    severity_by_owner: dict[str, dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    for own, sev, cnt in owner_severity_rows:
        key = _sev_label.get(sev)
        if key:
            severity_by_owner[own or "Unknown"][key] = cnt

    # Exploit availability
    exploit_count = report_q.filter(Finding.exploit_available == True).count()
    high_priority_count = report_q.filter(Finding.priority_score >= 7.0).count()

    excepted_count = total_findings - report_q.count() if excluded_exception_ids else 0

    # Quick wins: top 5 critical/high findings with quick_win effort, ordered by priority
    quick_wins_q = (
        report_q.filter(
            Finding.severity >= 3,
            Finding.effort_level == "quick_win",
        )
        .order_by(desc(Finding.priority_score))
        .limit(5)
        .all()
    )
    # Batch load assets for quick wins
    qw_asset_ids = {f.asset_id for f in quick_wins_q if f.asset_id}
    qw_assets = {}
    if qw_asset_ids:
        qw_assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(qw_asset_ids)).all()}

    quick_wins = []
    for f in quick_wins_q:
        asset = qw_assets.get(f.asset_id)
        quick_wins.append({
            "id": f.id,
            "plugin_name": f.plugin_name,
            "severity": f.severity,
            "priority_score": f.priority_score,
            "solution": (f.solution or "")[:200],
            "host": asset.hostname or asset.ip if asset else "—",
            "asset_id": f.asset_id,
            "plugin_family": f.plugin_family,
        })

    # Coverage / Assessment maturity
    credentialed_count = asset_q.filter(Asset.is_credentialed == True).count()
    with_auth_run = asset_q.filter(Asset.last_auth_run.isnot(None)).count()
    coverage_pct = round((credentialed_count / total_assets) * 100) if total_assets > 0 else 0

    result = {
        "total_assets": total_assets,
        "total_findings": total_findings,
        "excepted_findings": excepted_count,
        "coverage": {
            "credentialed_count": credentialed_count,
            "uncredentialed_count": total_assets - credentialed_count,
            "with_auth_run": with_auth_run,
            "coverage_pct": coverage_pct,
        },
        "severity_breakdown": {
            "critical": severity_counts.get(4, 0),
            "high": severity_counts.get(3, 0),
            "medium": severity_counts.get(2, 0),
            "low": severity_counts.get(1, 0),
            "info": severity_counts.get(0, 0),
        },
        "top_plugin_families": [
            {
                "family": row[0] or "Unknown",
                "count": row[1],
                **severity_by_family.get(row[0] or "Unknown", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
            }
            for row in family_counts
        ],
        "top_risky_assets": [_asset_to_dict(a) for a in top_assets],
        "effort_breakdown": effort_counts,
        "owner_breakdown": [
            {
                "owner": row[0] or "Unknown",
                "count": row[1],
                **severity_by_owner.get(row[0] or "Unknown", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
            }
            for row in owner_counts
        ],
        "exploit_count": exploit_count,
        "high_priority_count": high_priority_count,
        "quick_wins": quick_wins,
    }
    _cache_set(_ck, result)
    return result


# ─────────────────────────────────────────────
# Dynamic heatmap pivot
# ─────────────────────────────────────────────

_SEV_LABEL = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
_SEV_KEYS_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _age_bucket(first_seen, now):
    if not first_seen:
        return "Unknown"
    days = (now - first_seen).days
    if days < 30:
        return "0-30d"
    if days < 90:
        return "30-90d"
    if days < 180:
        return "90-180d"
    return "180d+"


_AGE_BUCKET_ORDER = ["0-30d", "30-90d", "90-180d", "180d+", "Unknown"]


def _priority_bucket(p):
    if p is None:
        return "Unknown"
    if p >= 7:
        return "Critical (7-10)"
    if p >= 5:
        return "High (5-7)"
    if p >= 3:
        return "Medium (3-5)"
    return "Low (0-3)"


_PRIORITY_BUCKET_ORDER = ["Critical (7-10)", "High (5-7)", "Medium (3-5)", "Low (0-3)", "Unknown"]


_CRITICALITY_LABEL = {
    1: "Very Low", 2: "Low", 3: "Low-Med", 4: "Medium", 5: "Medium",
    6: "Med-High", 7: "High", 8: "High", 9: "Very High", 10: "Critical",
}


HEATMAP_ROW_DIMS = {
    "family":       {"label": "Family"},
    "owner":        {"label": "Owner"},
    "asset":        {"label": "Asset"},
    "os":           {"label": "OS"},
    "environment":  {"label": "Environment"},
    "criticality":  {"label": "Asset Criticality"},
    "effort":       {"label": "Effort"},
}

HEATMAP_COL_DIMS = {
    "severity":      {"label": "Severity"},
    "effort":        {"label": "Effort"},
    "exploit":       {"label": "Exploit Available"},
    "kev":           {"label": "CISA KEV"},
    "sla_status":    {"label": "SLA Status"},
    "age_bucket":    {"label": "Age"},
    "priority_bucket": {"label": "Priority"},
}


@router.get("/api/reports/heatmap")
def get_heatmap(
    rows: str = "family",
    cols: str = "severity",
    scan_id: Optional[int] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    limit: int = 15,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return a dynamic row × column matrix of finding counts.

    `rows` picks the row dimension (family, owner, asset, os, environment,
    criticality, effort) and `cols` picks the column dimension (severity,
    effort, exploit, kev, sla_status, age_bucket, priority_bucket).
    """
    if rows not in HEATMAP_ROW_DIMS:
        raise HTTPException(status_code=400, detail=f"unknown row dim: {rows}")
    if cols not in HEATMAP_COL_DIMS:
        raise HTTPException(status_code=400, detail=f"unknown col dim: {cols}")

    _ck = f"heatmap:{rows}:{cols}:{scan_id}:{tags}:{tag_logic}:{limit}:{sorted(org_ids or [])}"
    cached = _cache_get(_ck)
    if cached is not None:
        return cached
    set_statement_timeout(db)

    # Join findings -> assets so asset-level row dims work; exclude info severity (0)
    q = (
        db.query(Finding, Asset)
        .join(Scan, Finding.scan_id == Scan.id)
        .outerjoin(Asset, Finding.asset_id == Asset.id)
    )
    q = apply_scan_org_filter(q, org_ids)
    q = q.filter(Finding.severity >= 1)

    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, False, db)
        q = tag_engine.apply_finding_tag_filter(q, id_sets, tag_logic, db)

    # Exclude report-excluded exceptions
    excluded_exception_ids = [
        e.id for e in db.query(FindingException.id).filter(
            FindingException.is_active == True,
            FindingException.exclude_from_reports == True,
        ).all()
    ]
    if excluded_exception_ids:
        q = q.filter(
            or_(Finding.exception_id.is_(None), ~Finding.exception_id.in_(excluded_exception_ids))
        )

    now = datetime.utcnow()

    def row_key(finding: Finding, asset: Optional[Asset]) -> str:
        if rows == "family":
            return finding.plugin_family or "Unknown"
        if rows == "owner":
            return finding.owner_suggestion or "Unassigned"
        if rows == "asset":
            if not asset:
                return "Unknown"
            return asset.hostname or asset.ip or f"asset#{asset.id}"
        if rows == "os":
            return (asset.os if asset else None) or "Unknown"
        if rows == "environment":
            return (asset.environment_tag if asset else None) or "Unknown"
        if rows == "criticality":
            c = asset.criticality if asset else None
            return _CRITICALITY_LABEL.get(c, "Unknown")
        if rows == "effort":
            return (finding.effort_level or "unknown").replace("_", " ").title()
        return "Unknown"

    def col_key(finding: Finding) -> Optional[str]:
        if cols == "severity":
            lbl = _SEV_LABEL.get(finding.severity)
            return lbl if lbl and lbl != "Info" else None
        if cols == "effort":
            return (finding.effort_level or "unknown").replace("_", " ").title()
        if cols == "exploit":
            return "Exploit Available" if finding.exploit_available else "No Exploit"
        if cols == "kev":
            return "In KEV" if finding.is_kev else "Not in KEV"
        if cols == "sla_status":
            return (finding.sla_status or "n/a").replace("_", " ").title()
        if cols == "age_bucket":
            return _age_bucket(finding.first_seen, now)
        if cols == "priority_bucket":
            return _priority_bucket(finding.priority_score)
        return None

    # Aggregate in Python — the per-row result counts are already bounded by `limit`
    # and heatmaps are capped at low hundreds of cells; a full scan of the filtered
    # query is fine and keeps the SQL simple across dim combinations.
    row_totals: dict[str, int] = defaultdict(int)
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    col_order: list[str] = []
    col_seen: set[str] = set()

    for finding, asset in q.all():
        rk = row_key(finding, asset)
        ck = col_key(finding)
        if ck is None:
            continue
        matrix[rk][ck] += 1
        row_totals[rk] += 1
        if ck not in col_seen:
            col_seen.add(ck)
            col_order.append(ck)

    # Order columns with a stable preferred order for known dims
    if cols == "severity":
        col_order = [c for c in _SEV_KEYS_ORDER if c in col_seen]
    elif cols == "age_bucket":
        col_order = [c for c in _AGE_BUCKET_ORDER if c in col_seen]
    elif cols == "priority_bucket":
        col_order = [c for c in _PRIORITY_BUCKET_ORDER if c in col_seen]
    elif cols == "effort":
        preferred = ["Quick Win", "Medium", "Complex", "Unknown"]
        col_order = [c for c in preferred if c in col_seen] + [c for c in col_order if c not in preferred]
    elif cols == "sla_status":
        preferred = ["Breached", "At Risk", "On Track", "Resolved", "N/A"]
        col_order = [c for c in preferred if c in col_seen] + [c for c in col_order if c not in preferred]
    elif cols == "exploit":
        col_order = [c for c in ["Exploit Available", "No Exploit"] if c in col_seen]
    elif cols == "kev":
        col_order = [c for c in ["In KEV", "Not in KEV"] if c in col_seen]

    # Top N rows by total count
    top_rows = sorted(row_totals.items(), key=lambda kv: kv[1], reverse=True)[: max(1, limit)]
    rows_out = [
        {
            "key": rk,
            "label": rk,
            "total": total,
            "cells": {ck: matrix[rk].get(ck, 0) for ck in col_order},
        }
        for rk, total in top_rows
    ]

    result = {
        "row_dim": rows,
        "col_dim": cols,
        "row_label": HEATMAP_ROW_DIMS[rows]["label"],
        "col_label": HEATMAP_COL_DIMS[cols]["label"],
        "cols": [{"key": c, "label": c} for c in col_order],
        "rows": rows_out,
    }
    _cache_set(_ck, result)
    return result


@router.get("/api/reports/risk-grade")
def get_risk_grade(
    scan_id: Optional[int] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Compute a composite organisation risk grade (0-100 score -> A-F letter)."""
    from services.sla_engine import ensure_sla_defaults as _ensure_sla_defaults

    # ── Gather summary data ──
    asset_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    finding_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    asset_q = apply_scan_org_filter(asset_q, org_ids)
    finding_q = apply_scan_org_filter(finding_q, org_ids)
    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
        finding_q = finding_q.filter(Finding.scan_id == scan_id)
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, False, db)
        asset_q = tag_engine.apply_asset_tag_filter(asset_q, id_sets, tag_logic, db)
        finding_q = tag_engine.apply_finding_tag_filter(finding_q, id_sets, tag_logic, db)

    total_assets = asset_q.count()
    total_findings = finding_q.count()

    # No data → no meaningful grade
    if total_assets == 0 and total_findings == 0:
        return {
            "score": None,
            "grade": None,
            "grade_color": "#94a3b8",
            "components": {
                "severity_mix": None,
                "sla_compliance": None,
                "remediation_velocity": None,
                "assessment_coverage": None,
                "exploit_exposure": None,
            },
            "weights": {
                "severity_mix": 0.25,
                "sla_compliance": 0.25,
                "remediation_velocity": 0.20,
                "assessment_coverage": 0.15,
                "exploit_exposure": 0.15,
            },
            "total_assets": 0,
            "total_findings": 0,
        }

    sev_counts = {}
    for sev in range(5):
        sev_counts[sev] = finding_q.filter(Finding.severity == sev).count()
    non_info = max(total_findings - sev_counts.get(0, 0), 1)
    critical = sev_counts.get(4, 0)
    high = sev_counts.get(3, 0)
    exploit_count = finding_q.filter(Finding.exploit_available == True).count()

    credentialed = asset_q.filter(Asset.is_credentialed == True).count()
    coverage_pct = (credentialed / total_assets * 100) if total_assets > 0 else 0

    # ── Gather SLA data ──
    _ensure_sla_defaults(db)
    sla_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    sla_q = apply_scan_org_filter(sla_q, org_ids)
    if scan_id:
        sla_q = sla_q.filter(Finding.scan_id == scan_id)
    enabled_sevs = [c.severity for c in db.query(SLAConfig).filter(SLAConfig.is_enabled == True).all()]
    sla_q = sla_q.filter(Finding.severity.in_(enabled_sevs))
    sla_findings = sla_q.all()

    sla_counts = {"on_track": 0, "at_risk": 0, "breached": 0, "resolved": 0, "n/a": 0}
    cfg_map = {c.severity: c for c in db.query(SLAConfig).all()}
    mttr_vals = []
    for f in sla_findings:
        status = f.sla_status or "n/a"
        sla_counts[status] = sla_counts.get(status, 0) + 1
        if f.resolved_at and f.sla_due_date:
            cfg = cfg_map.get(f.severity)
            if cfg:
                obs_date = f.sla_due_date - timedelta(days=cfg.days_to_remediate)
                days = (f.resolved_at - obs_date).total_seconds() / 86400
                if days >= 0:
                    mttr_vals.append(days)

    total_sla = sum(sla_counts[k] for k in ("on_track", "at_risk", "breached", "resolved"))
    compliance_pct = ((sla_counts["on_track"] + sla_counts["resolved"]) / total_sla * 100) if total_sla else 100
    avg_mttr = (sum(mttr_vals) / len(mttr_vals)) if mttr_vals else 0

    # ── Score components (each 0-100, higher = better) ──
    # 1. Severity mix: penalise critical/high ratio
    crit_high_ratio = (critical + high) / non_info if non_info else 0
    severity_score = max(0, 100 - crit_high_ratio * 200)  # 50% crit+high → 0

    # 2. SLA compliance (already 0-100)
    sla_score = compliance_pct

    # 3. Remediation velocity: MTTR < 7d = 100, >90d = 0
    if not mttr_vals:
        velocity_score = 50  # no remediation data yet — neutral score
    elif avg_mttr <= 0:
        velocity_score = 100  # instant remediation
    else:
        velocity_score = max(0, min(100, 100 - (avg_mttr - 7) * (100 / 83)))

    # 4. Assessment coverage (already 0-100)
    coverage_score = coverage_pct

    # 5. Exploit exposure: % of non-info findings that are exploitable
    exploit_ratio = exploit_count / non_info if non_info else 0
    exploit_score = max(0, 100 - exploit_ratio * 300)  # 33% exploitable → 0

    # ── Weighted composite ──
    composite = (
        severity_score * 0.25 +
        sla_score * 0.25 +
        velocity_score * 0.20 +
        coverage_score * 0.15 +
        exploit_score * 0.15
    )
    composite = max(0, min(100, round(composite, 1)))

    # ── Letter grade ──
    if composite >= 90:
        grade, grade_color = "A", "#16a34a"
    elif composite >= 80:
        grade, grade_color = "B", "#65a30d"
    elif composite >= 70:
        grade, grade_color = "C", "#d97706"
    elif composite >= 60:
        grade, grade_color = "D", "#ea580c"
    else:
        grade, grade_color = "F", "#dc2626"

    # ── Top solutions per component (for actionable tips) ──
    top_solutions_by_component = {}
    try:
        sol_q = db.query(AggregatedSolution).join(Scan, AggregatedSolution.scan_id == Scan.id)
        sol_q = apply_scan_org_filter(sol_q, org_ids)
        if scan_id:
            sol_q = sol_q.filter(AggregatedSolution.scan_id == scan_id)
        sol_q = sol_q.order_by(desc(AggregatedSolution.risk_reduction))
        all_solutions = sol_q.limit(50).all()

        # Map solutions to the risk component they most improve
        for sol in all_solutions:
            mapped_components = []
            rc = sol.root_cause_type or ""
            at = sol.action_type or ""
            # Severity mix: any fix that resolves critical/high findings
            if (sol.severity_max or 0) >= 3:
                mapped_components.append("severity_mix")
            # Exploit exposure: fixes that resolve exploitable findings
            if sol.finding_ids:
                exploit_findings = db.query(func.count(Finding.id)).filter(
                    Finding.id.in_(sol.finding_ids),
                    Finding.exploit_available == True,
                ).scalar() or 0
                if exploit_findings > 0:
                    mapped_components.append("exploit_exposure")
            # Remediation velocity: quick wins that speed up MTTR
            if sol.effort_level in ("low", "quick_win"):
                mapped_components.append("remediation_velocity")
            # SLA compliance: any fix for SLA-breached findings
            if sol.finding_ids:
                breached = db.query(func.count(Finding.id)).filter(
                    Finding.id.in_(sol.finding_ids),
                    Finding.sla_status == "breached",
                ).scalar() or 0
                if breached > 0:
                    mapped_components.append("sla_compliance")
            # Fallback: high risk-reduction solutions help severity mix
            if not mapped_components and (sol.risk_reduction or 0) > 1:
                mapped_components.append("severity_mix")

            for comp in mapped_components:
                if comp not in top_solutions_by_component:
                    top_solutions_by_component[comp] = []
                if len(top_solutions_by_component[comp]) < 2:
                    top_solutions_by_component[comp].append({
                        "id": sol.id,
                        "title": sol.title,
                        "affected_component": sol.affected_component,
                        "risk_reduction": round(sol.risk_reduction or 0, 1),
                        "finding_count": sol.finding_count or 0,
                        "asset_count": sol.asset_count or 0,
                        "effort_level": sol.effort_level,
                        "action_type": sol.action_type,
                        "finding_ids": sol.finding_ids or [],
                        "owner_suggestion": sol.owner_suggestion,
                    })
    except Exception:
        pass  # Graceful degradation — tips still work without solutions

    return {
        "score": composite,
        "grade": grade,
        "grade_color": grade_color,
        "components": {
            "severity_mix": round(severity_score, 1),
            "sla_compliance": round(sla_score, 1),
            "remediation_velocity": round(velocity_score, 1),
            "assessment_coverage": round(coverage_score, 1),
            "exploit_exposure": round(exploit_score, 1),
        },
        "weights": {
            "severity_mix": 0.25,
            "sla_compliance": 0.25,
            "remediation_velocity": 0.20,
            "assessment_coverage": 0.15,
            "exploit_exposure": 0.15,
        },
        "context": {
            "critical_count": critical,
            "high_count": high,
            "total_non_info": non_info,
            "exploit_count": exploit_count,
            "credentialed_assets": credentialed,
            "total_assets": total_assets,
            "coverage_pct": round(coverage_pct, 1),
            "sla_breached": sla_counts.get("breached", 0),
            "sla_at_risk": sla_counts.get("at_risk", 0),
            "avg_mttr_days": round(avg_mttr, 1) if mttr_vals else None,
        },
        "top_solutions": top_solutions_by_component,
    }


@router.get("/api/reports/plugin-families")
def get_plugin_families(scan_id: Optional[int] = None, tags: Optional[str] = None, tag_logic: str = "AND", db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return all unique plugin families for filter dropdowns."""
    q = db.query(Finding.plugin_family).join(Scan, Finding.scan_id == Scan.id).distinct()
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, False, db)
        q = tag_engine.apply_finding_tag_filter(q, id_sets, tag_logic, db)
    families = [row[0] for row in q.all() if row[0]]
    return sorted(families)


@router.get("/api/reports/trending")
def get_trending(
    mode: str = "per_scan",
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return severity counts over time for trend view.

    mode=per_scan   — counts per individual scan (default)
    mode=cumulative — total open (unresolved) findings as of each scan date
    """
    _ck = f"trending:{mode}:{sorted(org_ids or [])}"
    cached = _cache_get(_ck)
    if cached is not None:
        return cached
    from sqlalchemy import case as sa_case
    scans = apply_org_filter(db.query(Scan), Scan, org_ids).order_by(Scan.created_at).all()
    scan_ids = [s.id for s in scans]

    if mode == "cumulative":
        # For each scan date, count all findings that were open at that point:
        # first_seen <= scan_date AND (resolved_at IS NULL OR resolved_at > scan_date)
        base_q = apply_org_filter(db.query(Finding), Finding, org_ids).filter(
            Finding.first_seen != None
        )
        all_findings = base_q.with_entities(
            Finding.severity, Finding.first_seen, Finding.resolved_at
        ).all()

        result = []
        for s in scans:
            scan_dt = s.scan_date or s.created_at.isoformat()
            # Parse scan date to compare
            if isinstance(scan_dt, str):
                try:
                    cutoff = datetime.fromisoformat(scan_dt.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    cutoff = s.created_at
            else:
                cutoff = scan_dt

            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            sev_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
            for sev, first_seen, resolved_at in all_findings:
                if first_seen and first_seen <= cutoff:
                    if resolved_at is None or resolved_at > cutoff:
                        key = sev_map.get(sev)
                        if key:
                            counts[key] += 1

            result.append({
                "scan_id": s.id,
                "scan_name": s.scan_name,
                "scan_date": scan_dt if isinstance(scan_dt, str) else scan_dt.isoformat(),
                **counts,
            })
    else:
        # per_scan: counts per individual scan
        rows = db.query(
            Finding.scan_id,
            func.count(sa_case((Finding.severity == 4, 1))).label("critical"),
            func.count(sa_case((Finding.severity == 3, 1))).label("high"),
            func.count(sa_case((Finding.severity == 2, 1))).label("medium"),
            func.count(sa_case((Finding.severity == 1, 1))).label("low"),
            func.count(sa_case((Finding.severity == 0, 1))).label("info_count"),
        ).filter(Finding.scan_id.in_(scan_ids)).group_by(Finding.scan_id).all()

        counts_map = {r.scan_id: r for r in rows}

        result = []
        for s in scans:
            c = counts_map.get(s.id)
            result.append({
                "scan_id": s.id,
                "scan_name": s.scan_name,
                "scan_date": s.scan_date or s.created_at.isoformat(),
                "critical": c.critical if c else 0,
                "high": c.high if c else 0,
                "medium": c.medium if c else 0,
                "low": c.low if c else 0,
                "info": c.info_count if c else 0,
            })
    _cache_set(_ck, result)
    return result


@router.get("/api/reports/metrics-timeline")
def get_metrics_timeline(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return per-scan metrics for a configurable timeline widget.
    Each scan gets a snapshot of: severity counts, total findings/assets,
    exploit counts, SLA stats, workflow status breakdown, MTTR, and risk scores."""
    _ck = f"metrics_timeline:{sorted(org_ids or [])}"
    cached = _cache_get(_ck)
    if cached is not None:
        return cached
    set_statement_timeout(db)
    from sqlalchemy import case as sa_case
    scans = apply_org_filter(db.query(Scan), Scan, org_ids).order_by(Scan.created_at).all()
    if not scans:
        return []

    scan_ids = [s.id for s in scans]

    # --- 1) Finding aggregation: severity, exploit, SLA, workflow counts in ONE query ---
    sev_agg_rows = db.query(
        Finding.scan_id,
        func.count(Finding.id).label("total"),
        func.count(sa_case((Finding.severity == 4, 1))).label("critical"),
        func.count(sa_case((Finding.severity == 3, 1))).label("high"),
        func.count(sa_case((Finding.severity == 2, 1))).label("medium"),
        func.count(sa_case((Finding.severity == 1, 1))).label("low"),
        func.count(sa_case((Finding.severity == 0, 1))).label("info_count"),
        func.count(sa_case((Finding.exploit_available == True, 1))).label("exploit_count"),
        # SLA
        func.count(sa_case((Finding.sla_status == "on_track", 1))).label("sla_on_track"),
        func.count(sa_case((Finding.sla_status == "at_risk", 1))).label("sla_at_risk"),
        func.count(sa_case((Finding.sla_status == "breached", 1))).label("sla_breached"),
        func.count(sa_case((Finding.sla_status == "resolved", 1))).label("sla_resolved"),
        # Workflow
        func.count(sa_case((or_(Finding.workflow_status == "open", Finding.workflow_status == None), 1))).label("ws_open"),
        func.count(sa_case((Finding.workflow_status == "in_progress", 1))).label("ws_in_progress"),
        func.count(sa_case((Finding.workflow_status == "resolved", 1))).label("ws_resolved"),
        func.count(sa_case((Finding.workflow_status.in_(["accepted_risk", "false_positive", "compensating_control"]), 1))).label("ws_excepted"),
        func.count(sa_case((Finding.workflow_status == "technical_debt", 1))).label("ws_tech_debt"),
    ).filter(Finding.scan_id.in_(scan_ids)).group_by(Finding.scan_id).all()

    finding_stats = {row.scan_id: row for row in sev_agg_rows}

    # --- 2) Asset aggregation: count, avg/max risk_score in ONE query ---
    asset_agg_rows = db.query(
        Asset.scan_id,
        func.count(Asset.id).label("total_assets"),
        func.avg(sa_case((Asset.risk_score > 0, Asset.risk_score))).label("avg_risk"),
        func.max(sa_case((Asset.risk_score > 0, Asset.risk_score))).label("max_risk"),
    ).filter(Asset.scan_id.in_(scan_ids)).group_by(Asset.scan_id).all()

    asset_stats = {row.scan_id: row for row in asset_agg_rows}

    # --- 3) MTTR: join Finding with Scan to avoid N+1 ---
    mttr_rows = db.query(
        Finding.scan_id, Finding.resolved_at, Scan.created_at
    ).join(Scan, Finding.scan_id == Scan.id).filter(
        Finding.resolved_at != None,
        Finding.sla_due_date != None,
        Finding.scan_id.in_(scan_ids),
    ).all()

    mttr_by_scan: dict = {}
    for scan_id_val, resolved_at, created_at in mttr_rows:
        if resolved_at and created_at:
            days = (resolved_at - created_at).total_seconds() / 86400
            if days >= 0:
                mttr_by_scan.setdefault(scan_id_val, []).append(days)

    # --- 4) Build result from pre-computed maps ---
    result = []
    for s in scans:
        fs = finding_stats.get(s.id)
        ast = asset_stats.get(s.id)

        total = fs.total if fs else 0
        critical = fs.critical if fs else 0
        high = fs.high if fs else 0
        medium = fs.medium if fs else 0
        low = fs.low if fs else 0
        info = fs.info_count if fs else 0
        exploit_count = fs.exploit_count if fs else 0

        sla_on_track = fs.sla_on_track if fs else 0
        sla_at_risk = fs.sla_at_risk if fs else 0
        sla_breached = fs.sla_breached if fs else 0
        sla_resolved = fs.sla_resolved if fs else 0
        total_with_sla = sla_on_track + sla_at_risk + sla_breached + sla_resolved
        sla_compliance = round(((sla_on_track + sla_resolved) / total_with_sla * 100) if total_with_sla else 0, 1)

        ws_open = fs.ws_open if fs else 0
        ws_in_progress = fs.ws_in_progress if fs else 0
        ws_resolved = fs.ws_resolved if fs else 0
        ws_excepted = fs.ws_excepted if fs else 0
        ws_tech_debt = fs.ws_tech_debt if fs else 0

        total_assets = ast.total_assets if ast else 0
        avg_risk = round(ast.avg_risk, 2) if ast and ast.avg_risk else 0
        max_risk = round(ast.max_risk, 2) if ast and ast.max_risk else 0

        mttrs = mttr_by_scan.get(s.id)
        avg_mttr = round(sum(mttrs) / len(mttrs), 1) if mttrs else None

        result.append({
            "scan_id": s.id,
            "scan_name": s.scan_name or s.filename,
            "scan_date": s.scan_date or (s.created_at.isoformat() if s.created_at else None),
            # Severity
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            # Totals
            "total_findings": total,
            "actionable_findings": total - info,
            "total_assets": total_assets,
            "exploit_count": exploit_count,
            # SLA
            "sla_on_track": sla_on_track,
            "sla_at_risk": sla_at_risk,
            "sla_breached": sla_breached,
            "sla_resolved": sla_resolved,
            "sla_compliance_pct": sla_compliance,
            # Workflow
            "workflow_open": ws_open,
            "workflow_in_progress": ws_in_progress,
            "workflow_resolved": ws_resolved,
            "workflow_excepted": ws_excepted,
            "workflow_technical_debt": ws_tech_debt,
            # Risk
            "avg_risk_score": avg_risk,
            "max_risk_score": max_risk,
            # MTTR
            "avg_mttr_days": avg_mttr,
        })
    _cache_set(_ck, result)
    return result


# ─────────────────────────────────────────────
# Cross-Scan Delta Comparison
# ─────────────────────────────────────────────

@router.get("/api/scans/compare")
def compare_scans(
    base_scan_id: int,
    compare_scan_id: int,
    db: Session = Depends(get_db),
):
    """Compare two scans and return new/fixed/recurring findings."""
    # Check if we have a cached comparison
    cached = db.query(ScanComparison).filter(
        ScanComparison.base_scan_id == base_scan_id,
        ScanComparison.compare_scan_id == compare_scan_id,
    ).first()
    if cached:
        return _format_comparison(cached, db)

    # Compute delta
    base_scan = db.query(Scan).filter(Scan.id == base_scan_id).first()
    compare_scan = db.query(Scan).filter(Scan.id == compare_scan_id).first()
    if not base_scan or not compare_scan:
        raise HTTPException(404, "Scan not found")

    result = _compute_scan_delta(db, base_scan_id, compare_scan_id)

    # Cache it
    comp = ScanComparison(
        base_scan_id=base_scan_id,
        compare_scan_id=compare_scan_id,
        new_count=result["new_count"],
        fixed_count=result["fixed_count"],
        recurring_count=result["recurring_count"],
        new_findings=result["new_findings"][:500],  # cap for storage
        fixed_findings=result["fixed_findings"][:500],
        new_by_severity=result["new_by_severity"],
        fixed_by_severity=result["fixed_by_severity"],
    )
    db.add(comp)
    db.commit()
    return _format_comparison(comp, db)


@router.get("/api/scans/delta-timeline")
def scan_delta_timeline(db: Session = Depends(get_db)):
    """Return a timeline of scan-over-scan deltas (each scan compared to previous)."""
    scans = db.query(Scan).order_by(Scan.created_at).all()
    if len(scans) < 2:
        return []

    timeline = []
    for i in range(1, len(scans)):
        base = scans[i - 1]
        current = scans[i]
        # Check cache
        cached = db.query(ScanComparison).filter(
            ScanComparison.base_scan_id == base.id,
            ScanComparison.compare_scan_id == current.id,
        ).first()
        if cached:
            delta = {
                "new_count": cached.new_count,
                "fixed_count": cached.fixed_count,
                "recurring_count": cached.recurring_count,
                "new_by_severity": cached.new_by_severity or {},
                "fixed_by_severity": cached.fixed_by_severity or {},
            }
        else:
            delta = _compute_scan_delta(db, base.id, current.id)
            # Cache
            comp = ScanComparison(
                base_scan_id=base.id, compare_scan_id=current.id,
                new_count=delta["new_count"], fixed_count=delta["fixed_count"],
                recurring_count=delta["recurring_count"],
                new_findings=delta["new_findings"][:500],
                fixed_findings=delta["fixed_findings"][:500],
                new_by_severity=delta["new_by_severity"],
                fixed_by_severity=delta["fixed_by_severity"],
            )
            db.add(comp)

        timeline.append({
            "scan_id": current.id,
            "scan_name": current.scan_name or current.filename,
            "scan_date": current.scan_date or (current.created_at.isoformat() if current.created_at else None),
            "base_scan_id": base.id,
            "base_scan_name": base.scan_name or base.filename,
            "new_count": delta["new_count"],
            "fixed_count": delta["fixed_count"],
            "recurring_count": delta["recurring_count"],
            "new_by_severity": delta.get("new_by_severity", {}),
            "fixed_by_severity": delta.get("fixed_by_severity", {}),
            "net_change": delta["new_count"] - delta["fixed_count"],
        })
    db.commit()
    return timeline


def _compute_scan_delta(db: Session, base_scan_id: int, compare_scan_id: int) -> dict:
    """Compute the set-difference between two scans' findings.
    A finding is identified by (plugin_id, asset_ip)."""
    # Build sets: {(plugin_id, asset_ip): finding_info}
    def _build_finding_set(scan_id):
        findings = db.query(Finding, Asset.ip).join(Asset, Finding.asset_id == Asset.id).filter(
            Finding.scan_id == scan_id
        ).all()
        result = {}
        for f, ip in findings:
            key = (f.plugin_id, ip or "")
            result[key] = {
                "plugin_id": f.plugin_id, "plugin_name": f.plugin_name,
                "severity": f.severity, "severity_label": f.severity_label,
                "asset_ip": ip, "cvss3_score": f.cvss3_score,
                "priority_score": f.priority_score,
            }
        return result

    base_set = _build_finding_set(base_scan_id)
    compare_set = _build_finding_set(compare_scan_id)

    base_keys = set(base_set.keys())
    compare_keys = set(compare_set.keys())

    new_keys = compare_keys - base_keys
    fixed_keys = base_keys - compare_keys
    recurring_keys = base_keys & compare_keys

    new_findings = [compare_set[k] for k in new_keys]
    fixed_findings = [base_set[k] for k in fixed_keys]

    # Severity breakdown
    new_by_sev = {}
    for f in new_findings:
        s = f.get("severity", 0)
        new_by_sev[s] = new_by_sev.get(s, 0) + 1
    fixed_by_sev = {}
    for f in fixed_findings:
        s = f.get("severity", 0)
        fixed_by_sev[s] = fixed_by_sev.get(s, 0) + 1

    # Sort by severity desc then priority
    new_findings.sort(key=lambda x: (-(x.get("severity") or 0), -(x.get("priority_score") or 0)))
    fixed_findings.sort(key=lambda x: (-(x.get("severity") or 0), -(x.get("priority_score") or 0)))

    return {
        "new_count": len(new_keys),
        "fixed_count": len(fixed_keys),
        "recurring_count": len(recurring_keys),
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "new_by_severity": new_by_sev,
        "fixed_by_severity": fixed_by_sev,
    }


def _format_comparison(comp: ScanComparison, db: Session) -> dict:
    """Format a cached ScanComparison for API response."""
    sev_labels = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    base = db.query(Scan).filter(Scan.id == comp.base_scan_id).first()
    compare = db.query(Scan).filter(Scan.id == comp.compare_scan_id).first()
    return {
        "base_scan": {"id": comp.base_scan_id, "name": base.scan_name if base else None,
                       "date": base.scan_date if base else None},
        "compare_scan": {"id": comp.compare_scan_id, "name": compare.scan_name if compare else None,
                          "date": compare.scan_date if compare else None},
        "new_count": comp.new_count,
        "fixed_count": comp.fixed_count,
        "recurring_count": comp.recurring_count,
        "net_change": comp.new_count - comp.fixed_count,
        "new_findings": comp.new_findings or [],
        "fixed_findings": comp.fixed_findings or [],
        "new_by_severity": {sev_labels.get(int(k), k): v for k, v in (comp.new_by_severity or {}).items()},
        "fixed_by_severity": {sev_labels.get(int(k), k): v for k, v in (comp.fixed_by_severity or {}).items()},
    }


# ─────────────────────────────────────────────
# Temporal Analytics & Remediation Velocity
# ─────────────────────────────────────────────

@router.get("/api/reports/regressions")
def get_regressions(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Return findings that are regressions (were resolved, then reappeared)."""
    q = db.query(Finding).filter(Finding.is_regression == True)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    q = q.order_by(desc(Finding.severity), desc(Finding.priority_score))
    findings = q.limit(200).all()

    result = []
    for f in findings:
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        result.append({
            "id": f.id,
            "plugin_id": f.plugin_id,
            "plugin_name": f.plugin_name,
            "severity": f.severity,
            "severity_label": f.severity_label,
            "asset_ip": asset.ip if asset else None,
            "asset_hostname": asset.hostname if asset else None,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "times_seen": f.times_seen,
            "priority_score": f.priority_score,
            "scan_id": f.scan_id,
        })
    return {
        "total": len(result),
        "regressions": result,
    }


@router.get("/api/reports/temporal-summary")
def get_temporal_summary(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Return temporal health summary: zombie vulns, regression count, age distribution."""
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)

    findings = q.filter(Finding.severity > 0).all()  # Exclude Info
    now = datetime.utcnow()

    regression_count = 0
    age_buckets = {"under_30d": 0, "30_90d": 0, "90_180d": 0, "over_180d": 0}
    zombie_count = 0  # Open > 180 days
    total_with_temporal = 0

    for f in findings:
        if f.is_regression:
            regression_count += 1
        if f.first_seen:
            total_with_temporal += 1
            age_days = (now - f.first_seen).days
            if age_days < 30:
                age_buckets["under_30d"] += 1
            elif age_days < 90:
                age_buckets["30_90d"] += 1
            elif age_days < 180:
                age_buckets["90_180d"] += 1
            else:
                age_buckets["over_180d"] += 1
                if f.workflow_status in ("open", None):
                    zombie_count += 1

    return {
        "total_findings": len(findings),
        "total_with_temporal": total_with_temporal,
        "regression_count": regression_count,
        "zombie_count": zombie_count,
        "age_distribution": age_buckets,
    }


@router.get("/api/reports/remediation-velocity")
def get_remediation_velocity(
    period: str = "month",
    db: Session = Depends(get_db),
):
    """Return remediation velocity: findings resolved per time period.
    period: 'week' or 'month'"""

    resolved = db.query(Finding).filter(Finding.resolved_at != None).all()
    if not resolved:
        return {"period": period, "buckets": [], "total_resolved": 0, "avg_per_period": 0}

    # Group by period
    buckets = defaultdict(lambda: {"resolved": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
    for f in resolved:
        dt = f.resolved_at
        if period == "week":
            # ISO week: Monday-start
            key = f"{dt.isocalendar()[0]}-W{dt.isocalendar()[1]:02d}"
        else:
            key = f"{dt.year}-{dt.month:02d}"
        buckets[key]["resolved"] += 1
        sev_map = {4: "critical", 3: "high", 2: "medium", 1: "low"}
        sev_key = sev_map.get(f.severity, "low")
        buckets[key][sev_key] += 1

    sorted_keys = sorted(buckets.keys())
    result_buckets = []
    for k in sorted_keys:
        entry = buckets[k]
        entry["period_label"] = k
        result_buckets.append(entry)

    total = len(resolved)
    avg = round(total / max(len(sorted_keys), 1), 1)

    # Compute velocity trend (last 3 periods vs prior 3)
    trend = None
    if len(sorted_keys) >= 6:
        recent = sum(buckets[k]["resolved"] for k in sorted_keys[-3:])
        prior = sum(buckets[k]["resolved"] for k in sorted_keys[-6:-3])
        if prior > 0:
            trend = round((recent - prior) / prior * 100, 1)

    return {
        "period": period,
        "buckets": result_buckets,
        "total_resolved": total,
        "avg_per_period": avg,
        "velocity_trend_pct": trend,
    }


@router.post("/api/scans/{scan_id}/backfill-temporal")
def backfill_temporal(scan_id: int, db: Session = Depends(get_db)):
    """Backfill temporal fields for an existing scan (for scans uploaded before this feature)."""
    from app import _populate_temporal_fields
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    _populate_temporal_fields(db, scan)
    db.commit()
    regressions = db.query(func.count(Finding.id)).filter(
        Finding.scan_id == scan_id, Finding.is_regression == True
    ).scalar()
    return {
        "ok": True,
        "scan_id": scan_id,
        "regressions_detected": regressions,
    }


@router.post("/api/scans/backfill-temporal-all")
def backfill_temporal_all(db: Session = Depends(get_db)):
    """Backfill temporal fields for ALL scans in chronological order."""
    from app import _populate_temporal_fields
    scans = db.query(Scan).order_by(Scan.created_at).all()
    results = []
    for scan in scans:
        _populate_temporal_fields(db, scan)
        db.flush()
        regressions = db.query(func.count(Finding.id)).filter(
            Finding.scan_id == scan.id, Finding.is_regression == True
        ).scalar()
        results.append({"scan_id": scan.id, "scan_name": scan.scan_name, "regressions": regressions})
    db.commit()
    return {"ok": True, "scans_processed": len(results), "details": results}


# ── Tag-based Risk Report ─────────────────────────────────────────────────────


@router.get("/api/reports/risk-by-tags")
def get_risk_by_tags(
    category: Optional[str] = None,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Risk breakdown grouped by tag category (business unit, environment, etc.).
    Returns severity counts, avg risk score, finding density, grade, and SLA per group."""

    # Get all tags, optionally filtered by category
    tag_q = apply_org_filter(db.query(Tag), Tag, org_ids)
    if category:
        tag_q = tag_q.filter(func.lower(Tag.category) == category.lower())
    tags = tag_q.all()

    # Available categories for the picker
    cat_q = apply_org_filter(db.query(Tag.category).distinct(), Tag, org_ids)
    available_categories = sorted([r[0] for r in cat_q.all() if r[0]])

    if not tags:
        return {"category": category, "groups": [], "org_avg_risk": 0, "available_categories": available_categories}

    # Get all tag assignments for assets
    ta_q = db.query(TagAssignment).filter(
        TagAssignment.tag_id.in_([t.id for t in tags]),
        TagAssignment.asset_id.isnot(None),
    )
    assignments = ta_q.all()

    # Map asset_ids per tag
    tag_assets = defaultdict(set)
    for ta in assignments:
        tag_assets[ta.tag_id].add(ta.asset_id)

    # Build scoped asset/finding queries
    asset_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    asset_q = apply_scan_org_filter(asset_q, org_ids)
    finding_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    finding_q = apply_scan_org_filter(finding_q, org_ids)
    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
        finding_q = finding_q.filter(Finding.scan_id == scan_id)

    # Pre-validate asset IDs in scope
    all_asset_ids = set()
    for ids in tag_assets.values():
        all_asset_ids.update(ids)
    if scan_id and all_asset_ids:
        valid_asset_ids = {a.id for a in asset_q.filter(Asset.id.in_(all_asset_ids)).all()}
    else:
        valid_asset_ids = all_asset_ids

    groups = []
    for tag in tags:
        asset_ids = tag_assets.get(tag.id, set()) & valid_asset_ids
        if not asset_ids:
            continue

        tag_findings_q = finding_q.filter(Finding.asset_id.in_(asset_ids))
        sev_counts = {}
        for sev, label in [(4, "critical"), (3, "high"), (2, "medium"), (1, "low"), (0, "info")]:
            sev_counts[label] = tag_findings_q.filter(Finding.severity == sev).count()

        total_findings = sum(sev_counts.values())
        exploit_count = tag_findings_q.filter(Finding.exploit_available == True).count()

        # SLA compliance
        sla_on = tag_findings_q.filter(Finding.sla_status == "on_track").count()
        sla_resolved = tag_findings_q.filter(Finding.sla_status == "resolved").count()
        sla_breached = tag_findings_q.filter(Finding.sla_status == "breached").count()
        sla_at_risk = tag_findings_q.filter(Finding.sla_status == "at_risk").count()
        sla_total = sla_on + sla_resolved + sla_breached + sla_at_risk
        sla_compliance = round((sla_on + sla_resolved) / sla_total * 100, 1) if sla_total else None

        # Risk scores
        risk_scores = [a.risk_score for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
                       if a.risk_score and a.risk_score > 0]
        avg_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0

        # Grade
        grade = "A" if avg_risk <= 2 else "B" if avg_risk <= 4 else "C" if avg_risk <= 6 else "D" if avg_risk <= 8 else "F"

        groups.append({
            "tag_id": tag.id,
            "category": tag.category,
            "value": tag.value,
            "color": tag.color,
            "asset_count": len(asset_ids),
            "finding_count": total_findings,
            "finding_density": round(total_findings / len(asset_ids), 1),
            "severity": sev_counts,
            "avg_risk_score": avg_risk,
            "sla_compliance": sla_compliance,
            "exploit_count": exploit_count,
            "grade": grade,
        })

    # Sort by risk desc, assign rank
    groups.sort(key=lambda g: g["avg_risk_score"], reverse=True)
    for i, g in enumerate(groups):
        g["rank"] = i + 1

    # Org-wide average for benchmark comparison
    all_risk = [a.risk_score for a in asset_q.all() if a.risk_score and a.risk_score > 0]
    org_avg = round(sum(all_risk) / len(all_risk), 2) if all_risk else 0

    return {
        "category": category,
        "groups": groups,
        "org_avg_risk": org_avg,
        "available_categories": available_categories,
    }


# ─────────────────────────────────────────────────────────
# Owner Risk Summary (Hall of Shame)
# ─────────────────────────────────────────────────────────

@router.get("/api/reports/owner-risk-summary")
def get_owner_risk_summary(
    scan_id: Optional[int] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Per-owner risk breakdown with RAG (red/amber/green) scoring.

    Resolution order for owner identity:
      1. FindingOwnership.owner_name / owner_role
      2. AssetOwnership.owner_name / owner_role
      3. Asset.inferred_team
      4. Finding.owner_suggestion (see core.ownership_teams.OWNERSHIP_ROLES)
      5. 'Unassigned' fallback
    """

    finding_q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
    )
    finding_q = apply_scan_org_filter(finding_q, org_ids)
    if scan_id:
        finding_q = finding_q.filter(Finding.scan_id == scan_id)
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, False, db)
        finding_q = tag_engine.apply_finding_tag_filter(finding_q, id_sets, tag_logic, db)

    findings = (
        finding_q
        .options(
            joinedload(Finding.ownership),
            joinedload(Finding.asset).joinedload(Asset.ownership),
        )
        .all()
    )

    # Bucket findings by resolved owner label
    buckets: dict = defaultdict(lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "total": 0, "exploit": 0,
        "sla_on": 0, "sla_resolved": 0, "sla_breached": 0, "sla_at_risk": 0,
        "priority_sum": 0.0, "priority_count": 0,
        "quick_wins": 0,
        "owner_role": None,
    })

    for f in findings:
        asset = f.asset
        owner_label = "Unassigned"
        owner_role = None

        if f.ownership:
            own = f.ownership[0]
            if own.owner_name or own.owner_role:
                owner_label = own.owner_name or own.owner_role
                owner_role = own.owner_role or own.owner_name
        elif asset and asset.ownership:
            own = asset.ownership[0]
            if own.owner_name or own.owner_role:
                owner_label = own.owner_name or own.owner_role
                owner_role = own.owner_role or own.owner_name
        elif asset and asset.inferred_team:
            owner_label = asset.inferred_team
            owner_role = asset.inferred_team
        elif f.owner_suggestion:
            owner_label = f.owner_suggestion
            owner_role = f.owner_suggestion

        b = buckets[owner_label]
        if b["owner_role"] is None:
            b["owner_role"] = owner_role or owner_label

        sev_key = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}.get(f.severity, "info")
        b[sev_key] += 1
        b["total"] += 1
        if f.exploit_available:
            b["exploit"] += 1
        if f.sla_status == "on_track":
            b["sla_on"] += 1
        elif f.sla_status == "resolved":
            b["sla_resolved"] += 1
        elif f.sla_status == "breached":
            b["sla_breached"] += 1
        elif f.sla_status == "at_risk":
            b["sla_at_risk"] += 1
        if f.priority_score is not None:
            b["priority_sum"] += f.priority_score
            b["priority_count"] += 1
        if f.effort_level == "quick_win" and f.severity >= 2:
            b["quick_wins"] += 1

    owners = []
    for label, b in buckets.items():
        avg_priority = round(b["priority_sum"] / b["priority_count"], 2) if b["priority_count"] else 0
        sla_total = b["sla_on"] + b["sla_resolved"] + b["sla_breached"] + b["sla_at_risk"]
        sla_compliance = round((b["sla_on"] + b["sla_resolved"]) / sla_total * 100, 1) if sla_total else None

        # RAG: Red = critical > 0 OR avg_priority > 7 OR SLA < 40
        #      Amber = avg_priority > 4 OR SLA < 70 OR has exploitable findings
        #      Green = otherwise
        if b["critical"] > 0 or avg_priority > 7 or (sla_compliance is not None and sla_compliance < 40):
            rag = "red"
        elif avg_priority > 4 or (sla_compliance is not None and sla_compliance < 70) or b["exploit"] > 0:
            rag = "amber"
        else:
            rag = "green"

        owners.append({
            "owner": label,
            "owner_role": b["owner_role"] or label,
            "rag": rag,
            "total": b["total"],
            "critical": b["critical"],
            "high": b["high"],
            "medium": b["medium"],
            "low": b["low"],
            "exploit_count": b["exploit"],
            "quick_wins": b["quick_wins"],
            "avg_priority_score": avg_priority,
            "sla_compliance": sla_compliance,
            "sla_breached": b["sla_breached"],
        })

    rag_order = {"red": 0, "amber": 1, "green": 2}
    owners.sort(key=lambda o: (rag_order[o["rag"]], -o["critical"], -o["avg_priority_score"]))
    for i, o in enumerate(owners):
        o["rank"] = i + 1

    return {
        "owners": owners,
        "total_findings": sum(o["total"] for o in owners),
        "owner_count": len(owners),
    }


# ─────────────────────────────────────────────────────────
# Funnel Widget
# ─────────────────────────────────────────────────────────

class FunnelStep(BaseModel):
    label: str
    filters: dict = {}

class FunnelRequest(BaseModel):
    base_entity: str = "findings"  # "findings" or "assets"
    scan_id: Optional[int] = None
    steps: List[FunnelStep] = []

@router.post("/api/reports/funnel")
def compute_funnel(
    body: FunnelRequest,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Compute counts for a multi-step funnel.
    Each step progressively narrows results by applying cumulative filters.
    Supports both findings-based and assets-based funnels."""
    results = []

    if body.base_entity == "findings":
        base_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
        base_q = apply_scan_org_filter(base_q, org_ids)
        if body.scan_id:
            base_q = base_q.filter(Finding.scan_id == body.scan_id)

        q = base_q
        for step in body.steps:
            f = step.filters
            _is_true = lambda v: v == True or v == "true"
            # Severity
            if f.get("severity") is not None and f["severity"] != "":
                q = q.filter(Finding.severity == int(f["severity"]))
            if f.get("min_severity") is not None and f["min_severity"] != "":
                q = q.filter(Finding.severity >= int(f["min_severity"]))
            # Scoring
            if f.get("min_cvss3"):
                q = q.filter(Finding.cvss3_score >= float(f["min_cvss3"]))
            if f.get("min_cvss4"):
                q = q.filter(Finding.cvss4_score >= float(f["min_cvss4"]))
            if f.get("min_vpr"):
                q = q.filter(Finding.vpr_score >= float(f["min_vpr"]))
            if f.get("min_epss"):
                q = q.filter(Finding.epss_score >= float(f["min_epss"]))
            # Threat intel
            if _is_true(f.get("is_kev")):
                q = q.filter(Finding.is_kev == True)
            if _is_true(f.get("has_exploit")):
                q = q.filter(Finding.exploit_available == True)
            if _is_true(f.get("ransomware_linked")):
                q = q.filter(Finding.ransomware_linked == True)
            if _is_true(f.get("trending_in_news")):
                q = q.filter(Finding.trending_in_news == True)
            if _is_true(f.get("zero_day")):
                q = q.filter(Finding.zero_day == True)
            if f.get("exploit_maturity"):
                q = q.filter(Finding.exploit_maturity == f["exploit_maturity"])
            # ATT&CK (matched_ttps is JSON — cast to Text for string comparisons)
            if _is_true(f.get("has_ttps")):
                q = q.filter(Finding.matched_ttps.isnot(None), cast(Finding.matched_ttps, Text) != "[]")
            if f.get("tactic"):
                q = q.filter(cast(Finding.matched_ttps, Text).ilike(f'%"tactic": "{f["tactic"]}"%'))
            if f.get("technique_id"):
                q = q.filter(cast(Finding.matched_ttps, Text).ilike(f'%"technique_id": "{f["technique_id"]}%'))
            # Workflow & state
            if f.get("workflow_status"):
                q = q.filter(Finding.workflow_status == f["workflow_status"])
            if f.get("vulnerability_state"):
                q = q.filter(Finding.vulnerability_state == f["vulnerability_state"])
            if f.get("sla_status"):
                q = q.filter(Finding.sla_status == f["sla_status"])
            if _is_true(f.get("is_regression")):
                q = q.filter(Finding.is_regression == True)
            if _is_true(f.get("has_exception")):
                q = q.filter(Finding.exception_id.isnot(None))
            # Effort & ownership
            if f.get("effort_level"):
                q = q.filter(Finding.effort_level == f["effort_level"])
            if f.get("owner_suggestion"):
                q = q.filter(Finding.owner_suggestion == f["owner_suggestion"])
            # Plugin details
            if f.get("plugin_family"):
                q = q.filter(Finding.plugin_family.ilike(f"%{f['plugin_family']}%"))
            if f.get("plugin_name"):
                q = q.filter(Finding.plugin_name.ilike(f"%{f['plugin_name']}%"))
            if f.get("port"):
                q = q.filter(Finding.port == int(f["port"]))
            if f.get("protocol"):
                q = q.filter(Finding.protocol == f["protocol"])
            if f.get("cve"):
                q = q.filter(Finding.cves.ilike(f"%{f['cve']}%"))
            if f.get("risk_factor"):
                q = q.filter(Finding.risk_factor == f["risk_factor"])
            # Search text
            if f.get("search"):
                q = q.filter(
                    Finding.plugin_name.ilike(f"%{f['search']}%") |
                    Finding.synopsis.ilike(f"%{f['search']}%")
                )
            # Asset-level joins for findings funnel
            need_asset_join = any(f.get(k) for k in ("on_critical_assets", "on_internet_facing", "asset_min_risk"))
            if need_asset_join:
                q = q.join(Asset, Finding.asset_id == Asset.id)
            if _is_true(f.get("on_critical_assets")):
                q = q.filter(Asset.criticality >= 8)
            if _is_true(f.get("on_internet_facing")):
                q = q.filter(Asset.is_internet_facing == True)
            if f.get("asset_min_risk"):
                q = q.filter(Asset.risk_score >= float(f["asset_min_risk"]))

            count = q.count()
            results.append({"label": step.label, "count": count})

    elif body.base_entity == "assets":
        base_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
        base_q = apply_scan_org_filter(base_q, org_ids)
        if body.scan_id:
            base_q = base_q.filter(Asset.scan_id == body.scan_id)

        q = base_q
        # Track asset IDs for subquery-based filters
        need_asset_ids = False
        asset_ids_filter = None

        for step in body.steps:
            f = step.filters
            _is_true = lambda v: v == True or v == "true"
            # Asset properties
            if f.get("criticality") is not None and f["criticality"] != "":
                q = q.filter(Asset.criticality >= int(f["criticality"]))
            if f.get("min_risk"):
                q = q.filter(Asset.risk_score >= float(f["min_risk"]))
            if f.get("os"):
                q = q.filter(Asset.os.ilike(f"%{f['os']}%"))
            if f.get("environment"):
                q = q.filter(Asset.environment_tag == f["environment"])
            # Exposure & role
            if _is_true(f.get("is_internet_facing")):
                q = q.filter(Asset.is_internet_facing == True)
            if _is_true(f.get("is_domain_controller")):
                q = q.filter(Asset.is_domain_controller == True)
            # Service-based role detection
            _svc_role_map = {
                "is_database_server": ["mssql", "sqlserver", "mysql", "mysqld", "postgres",
                                       "postgresql", "oracle", "mongodb", "mariadb", "redis", "db2"],
                "is_web_server":  ["iis", "w3svc", "apache", "httpd", "nginx", "tomcat", "kestrel"],
                "is_dns_server":  ["dns", "named", "bind", "dnsmasq", "unbound"],
                "is_mail_server": ["exchange", "smtp", "imap", "pop3", "postfix", "sendmail", "exim"],
            }
            for role_key, patterns in _svc_role_map.items():
                if _is_true(f.get(role_key)):
                    svc_conditions = [InventoryService.service_name.ilike(f"%{p}%") for p in patterns]
                    role_ids = db.query(InventoryService.asset_id).filter(or_(*svc_conditions)).distinct().subquery()
                    q = q.filter(Asset.id.in_(db.query(role_ids)))
            # Severity counts
            if f.get("min_critical") is not None and f["min_critical"] != "":
                q = q.filter(Asset.critical_count >= int(f["min_critical"]))
            if f.get("min_high") is not None and f["min_high"] != "":
                q = q.filter(Asset.high_count >= int(f["min_high"]))
            if f.get("min_medium") is not None and f["min_medium"] != "":
                q = q.filter(Asset.medium_count >= int(f["min_medium"]))
            if _is_true(f.get("has_findings")):
                q = q.filter((Asset.critical_count + Asset.high_count + Asset.medium_count + Asset.low_count) > 0)
            # Finding-based subquery filters
            if _is_true(f.get("has_critical_cves")):
                crit_asset_ids = db.query(Finding.asset_id).filter(Finding.severity == 4).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(crit_asset_ids)))
            if _is_true(f.get("has_kev_findings")):
                kev_asset_ids = db.query(Finding.asset_id).filter(Finding.is_kev == True).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(kev_asset_ids)))
            if _is_true(f.get("has_exploitable")):
                exp_asset_ids = db.query(Finding.asset_id).filter(Finding.exploit_available == True).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(exp_asset_ids)))
            if _is_true(f.get("has_ransomware_findings")):
                rw_asset_ids = db.query(Finding.asset_id).filter(Finding.ransomware_linked == True).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(rw_asset_ids)))
            # Identity & access (inventory-based)
            if _is_true(f.get("has_domain_admin_logged_on")):
                da_usernames = db.query(InventoryUser.username).filter(
                    InventoryUser.is_domain_admin == True
                ).distinct().subquery()
                da_asset_ids = db.query(InventoryLoggedOn.asset_id).filter(
                    InventoryLoggedOn.username.in_(db.query(da_usernames))
                ).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(da_asset_ids)))
            if _is_true(f.get("has_privileged_user")):
                priv_usernames = db.query(InventoryUser.username).filter(
                    InventoryUser.is_privileged == True
                ).distinct().subquery()
                priv_asset_ids = db.query(InventoryLoggedOn.asset_id).filter(
                    InventoryLoggedOn.username.in_(db.query(priv_usernames))
                ).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(priv_asset_ids)))
            if _is_true(f.get("has_kerberoastable")):
                kerb_asset_ids = db.query(InventoryUser.asset_id).filter(
                    InventoryUser.spns.isnot(None), InventoryUser.spns != "[]"
                ).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(kerb_asset_ids)))
            if _is_true(f.get("has_writeable_share")):
                share_asset_ids = db.query(InventoryShare.asset_id).filter(
                    InventoryShare.is_writeable == True
                ).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(share_asset_ids)))
            # Security controls
            if _is_true(f.get("lacks_security_controls")):
                has_ctrl_ids = db.query(InventorySecurityControl.asset_id).distinct().subquery()
                q = q.filter(~Asset.id.in_(db.query(has_ctrl_ids)))
            if _is_true(f.get("lacks_av")):
                has_av_ids = db.query(InventorySecurityControl.asset_id).filter(
                    InventorySecurityControl.control_type == "antivirus"
                ).distinct().subquery()
                q = q.filter(~Asset.id.in_(db.query(has_av_ids)))
            if _is_true(f.get("lacks_edr")):
                has_edr_ids = db.query(InventorySecurityControl.asset_id).filter(
                    InventorySecurityControl.control_type == "edr"
                ).distinct().subquery()
                q = q.filter(~Asset.id.in_(db.query(has_edr_ids)))
            if _is_true(f.get("lacks_firewall")):
                has_fw_ids = db.query(InventorySecurityControl.asset_id).filter(
                    InventorySecurityControl.control_type == "firewall"
                ).distinct().subquery()
                q = q.filter(~Asset.id.in_(db.query(has_fw_ids)))
            # Search
            if f.get("search"):
                pattern = f"%{f['search']}%"
                q = q.filter(or_(
                    Asset.hostname.ilike(pattern),
                    Asset.ip.ilike(pattern),
                    Asset.fqdn.ilike(pattern),
                ))

            count = q.count()
            results.append({"label": step.label, "count": count})
    else:
        raise HTTPException(400, "base_entity must be 'findings' or 'assets'")

    return {"base_entity": body.base_entity, "steps": results}


# ─────────────────────────────────────────────────────────
# NLP Report Query
# ─────────────────────────────────────────────────────────

class NLPReportQueryRequest(BaseModel):
    query: str
    scan_id: Optional[int] = None

@router.post("/api/reports/nlp-query")
def nlp_report_query(
    body: NLPReportQueryRequest,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Parse a natural language query and return matching findings + assets as a structured report."""
    parsed = parse_nlp_query(body.query)
    af = parsed["asset_filters"]
    ff = parsed["finding_filters"]
    scan_id = body.scan_id

    # ── Assets ────────────────────────────────────────────
    aq = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    aq = apply_scan_org_filter(aq, org_ids)
    if scan_id:
        aq = aq.filter(Asset.scan_id == scan_id)
    aq = apply_asset_nlp_filters(aq, af, db)
    aq = aq.order_by(desc(Asset.risk_score))
    total_assets = aq.count()
    assets = aq.limit(20).all()

    # ── Findings ──────────────────────────────────────────
    fq = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    fq = apply_scan_org_filter(fq, org_ids)
    if scan_id:
        fq = fq.filter(Finding.scan_id == scan_id)
    fq = apply_finding_nlp_filters(fq, ff, db)
    # If asset filters produced an asset set, scope findings to those assets
    if af and total_assets > 0:
        asset_id_subq = aq.with_entities(Asset.id).subquery()
        fq = fq.filter(Finding.asset_id.in_(asset_id_subq))

    sort_col = Finding.priority_score
    if parsed.get("sort"):
        sort_field = parsed["sort"].get("sort_by", "priority_score")
        sort_col = getattr(Finding, sort_field, Finding.priority_score)
        if parsed["sort"].get("order", "desc") == "asc":
            fq = fq.order_by(sort_col)
        else:
            fq = fq.order_by(desc(sort_col))
    else:
        fq = fq.order_by(desc(sort_col))

    total_findings = fq.count()
    findings = fq.limit(50).all()

    # ── Severity breakdown (single GROUP BY) ───────────────
    sev_breakdown = severity_breakdown_grouped(fq)

    # ── Serialise ──────────────────────────────────────────
    def _finding(f):
        return {
            "id": f.id,
            "plugin_id": f.plugin_id,
            "plugin_name": f.plugin_name,
            "plugin_family": f.plugin_family,
            "severity": f.severity,
            "severity_label": f.severity_label or ["Info","Low","Medium","High","Critical"][f.severity],
            "cvss3_score": f.cvss3_score,
            "vpr_score": f.vpr_score,
            "epss_score": f.epss_score,
            "priority_score": f.priority_score,
            "effort_level": f.effort_level,
            "exploit_available": f.exploit_available,
            "is_kev": f.is_kev,
            "ransomware_linked": f.ransomware_linked,
            "trending_in_news": f.trending_in_news,
            "zero_day": f.zero_day,
            "is_regression": f.is_regression,
            "synopsis": f.synopsis,
            "solution": f.solution,
            "asset_id": f.asset_id,
            "port": f.port,
            "cves": f.cves or [],
            "sla_status": f.sla_status,
            "workflow_status": f.workflow_status,
            "matched_ttps": f.matched_ttps,
        }

    def _asset(a):
        return {
            "id": a.id,
            "ip": a.ip,
            "hostname": a.hostname,
            "fqdn": a.fqdn,
            "os": a.os,
            "risk_score": a.risk_score,
            "criticality": a.criticality,
            "environment_tag": a.environment_tag,
            "critical_count": a.critical_count,
            "high_count": a.high_count,
            "medium_count": a.medium_count,
            "low_count": a.low_count,
        }

    return {
        "original_query": body.query,
        "explanation": parsed["explanation"],
        "parsed_filters": {
            "asset_filters": af,
            "finding_filters": ff,
            "sort": parsed.get("sort"),
        },
        "summary": {
            "total_findings": total_findings,
            "total_assets": total_assets,
            "by_severity": sev_breakdown,
        },
        "findings": [_finding(f) for f in findings],
        "assets": [_asset(a) for a in assets],
    }


def _asset_to_dict(a: Asset) -> dict:
    """Delegates to the canonical version in asset_routes."""
    from routes.asset_routes import _asset_to_dict as _full_asset_to_dict
    return _full_asset_to_dict(a)
