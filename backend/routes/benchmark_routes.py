"""
Benchmark routes — compare org metrics against industry & platform peers.
Prefix: /api/benchmarks

Two benchmark sources:
  1. Industry — static reference data seeded from published reports (Qualys, DBIR, etc.)
  2. Platform — live cross-tenant aggregation from all orgs on the platform
"""
import logging
import statistics
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case

from core.database import get_db
from models.models import (
    Organization, Scan, Asset, Finding, SLAConfig, BenchmarkReference,
)
from core.auth import (
    get_current_user, get_accessible_org_ids,
    apply_org_filter, apply_scan_org_filter,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/benchmarks", tags=["benchmarks"])


# ─────────────────────────────────────────────
# Industry benchmark seed data
# ─────────────────────────────────────────────

INDUSTRY_BENCHMARKS = [
    # Risk grade (0-100 score, higher = better)
    {"metric": "risk_grade", "industry": "all", "org_size": "all",
     "p25": 35, "p50": 52, "p75": 72, "p90": 85,
     "unit": "score", "higher_is_better": True,
     "source": "Aggregated Industry Data", "source_year": 2024},
    {"metric": "risk_grade", "industry": "financial", "org_size": "all",
     "p25": 45, "p50": 62, "p75": 78, "p90": 88,
     "unit": "score", "higher_is_better": True,
     "source": "Financial Services ISACs", "source_year": 2024},
    {"metric": "risk_grade", "industry": "healthcare", "org_size": "all",
     "p25": 28, "p50": 45, "p75": 65, "p90": 80,
     "unit": "score", "higher_is_better": True,
     "source": "H-ISAC Benchmarks", "source_year": 2024},
    {"metric": "risk_grade", "industry": "technology", "org_size": "all",
     "p25": 40, "p50": 58, "p75": 75, "p90": 90,
     "unit": "score", "higher_is_better": True,
     "source": "Industry Benchmarks", "source_year": 2024},
    {"metric": "risk_grade", "industry": "government", "org_size": "all",
     "p25": 30, "p50": 48, "p75": 68, "p90": 82,
     "unit": "score", "higher_is_better": True,
     "source": "CISA Federal Benchmarks", "source_year": 2024},

    # MTTR Critical (days, lower = better)
    {"metric": "mttr_critical", "industry": "all", "org_size": "all",
     "p25": 21, "p50": 7, "p75": 3, "p90": 1,
     "unit": "days", "higher_is_better": False,
     "source": "Qualys TruRisk Report", "source_year": 2024},
    {"metric": "mttr_critical", "industry": "financial", "org_size": "all",
     "p25": 14, "p50": 5, "p75": 2, "p90": 1,
     "unit": "days", "higher_is_better": False,
     "source": "Financial Services ISACs", "source_year": 2024},
    {"metric": "mttr_critical", "industry": "healthcare", "org_size": "all",
     "p25": 30, "p50": 12, "p75": 5, "p90": 2,
     "unit": "days", "higher_is_better": False,
     "source": "H-ISAC Benchmarks", "source_year": 2024},

    # MTTR High (days, lower = better)
    {"metric": "mttr_high", "industry": "all", "org_size": "all",
     "p25": 45, "p50": 21, "p75": 10, "p90": 5,
     "unit": "days", "higher_is_better": False,
     "source": "Qualys TruRisk Report", "source_year": 2024},

    # MTTR Medium (days, lower = better)
    {"metric": "mttr_medium", "industry": "all", "org_size": "all",
     "p25": 90, "p50": 45, "p75": 21, "p90": 10,
     "unit": "days", "higher_is_better": False,
     "source": "Industry Benchmarks", "source_year": 2024},

    # SLA Compliance (%, higher = better)
    {"metric": "sla_compliance", "industry": "all", "org_size": "all",
     "p25": 45, "p50": 65, "p75": 82, "p90": 93,
     "unit": "percent", "higher_is_better": True,
     "source": "Aggregated Industry Data", "source_year": 2024},
    {"metric": "sla_compliance", "industry": "financial", "org_size": "all",
     "p25": 55, "p50": 72, "p75": 88, "p90": 95,
     "unit": "percent", "higher_is_better": True,
     "source": "Financial Services ISACs", "source_year": 2024},

    # Critical finding density (per 100 assets, lower = better)
    {"metric": "critical_density", "industry": "all", "org_size": "all",
     "p25": 25, "p50": 12, "p75": 5, "p90": 2,
     "unit": "per_100_assets", "higher_is_better": False,
     "source": "Qualys TruRisk Report", "source_year": 2024},

    # Exploit exposure % (lower = better)
    {"metric": "exploit_exposure", "industry": "all", "org_size": "all",
     "p25": 35, "p50": 18, "p75": 8, "p90": 3,
     "unit": "percent", "higher_is_better": False,
     "source": "Mandiant M-Trends", "source_year": 2024},

    # Patch coverage % (higher = better)
    {"metric": "patch_coverage", "industry": "all", "org_size": "all",
     "p25": 55, "p50": 72, "p75": 88, "p90": 95,
     "unit": "percent", "higher_is_better": True,
     "source": "Verizon DBIR", "source_year": 2024},

    # Assessment coverage % (higher = better)
    {"metric": "assessment_coverage", "industry": "all", "org_size": "all",
     "p25": 40, "p50": 62, "p75": 80, "p90": 92,
     "unit": "percent", "higher_is_better": True,
     "source": "Industry Benchmarks", "source_year": 2024},

    # Remediation velocity (findings/month, higher = better)
    {"metric": "remediation_velocity", "industry": "all", "org_size": "all",
     "p25": 8, "p50": 25, "p75": 60, "p90": 120,
     "unit": "findings_per_month", "higher_is_better": True,
     "source": "Aggregated Industry Data", "source_year": 2024},

    # Average risk score (0-10, lower = better)
    {"metric": "avg_risk_score", "industry": "all", "org_size": "all",
     "p25": 7.2, "p50": 5.0, "p75": 3.2, "p90": 1.8,
     "unit": "score", "higher_is_better": False,
     "source": "Aggregated Industry Data", "source_year": 2024},
]

# Metric metadata — used for both industry and platform benchmarks
METRIC_META = {
    "risk_grade":           {"label": "Risk Grade",              "unit": "score",            "higher_is_better": True},
    "sla_compliance":       {"label": "SLA Compliance",          "unit": "percent",          "higher_is_better": True},
    "mttr_critical":        {"label": "MTTR (Critical)",         "unit": "days",             "higher_is_better": False},
    "mttr_high":            {"label": "MTTR (High)",             "unit": "days",             "higher_is_better": False},
    "mttr_medium":          {"label": "MTTR (Medium)",           "unit": "days",             "higher_is_better": False},
    "critical_density":     {"label": "Critical Finding Density","unit": "per_100_assets",   "higher_is_better": False},
    "exploit_exposure":     {"label": "Exploit Exposure",        "unit": "percent",          "higher_is_better": False},
    "assessment_coverage":  {"label": "Assessment Coverage",     "unit": "percent",          "higher_is_better": True},
    "avg_risk_score":       {"label": "Avg Risk Score",          "unit": "score",            "higher_is_better": False},
    "remediation_velocity": {"label": "Remediation Velocity",    "unit": "findings_per_month","higher_is_better": True},
    "patch_coverage":       {"label": "Patch Coverage",          "unit": "percent",          "higher_is_better": True},
}


def _ensure_benchmark_seed(db: Session):
    """Seed default industry benchmarks if the table is empty."""
    count = db.query(BenchmarkReference).count()
    if count > 0:
        return
    for b in INDUSTRY_BENCHMARKS:
        db.add(BenchmarkReference(**b))
    db.commit()


# ─────────────────────────────────────────────
# Per-org metric computation
# ─────────────────────────────────────────────

def _compute_org_metrics(db: Session, org_ids: Optional[List[int]], scan_id: Optional[int] = None) -> dict:
    """Compute all benchmark-relevant metrics for the given org scope."""
    asset_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    finding_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    asset_q = apply_scan_org_filter(asset_q, org_ids)
    finding_q = apply_scan_org_filter(finding_q, org_ids)

    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
        finding_q = finding_q.filter(Finding.scan_id == scan_id)

    # Single aggregation query replaces 9 separate count() calls
    asset_agg = asset_q.with_entities(
        func.count().label("total"),
        func.sum(case((Asset.is_credentialed == True, 1), else_=0)).label("credentialed"),
        func.avg(Asset.risk_score).label("avg_risk"),
    ).one()
    total_assets = asset_agg.total or 0
    credentialed = int(asset_agg.credentialed or 0)
    avg_risk_score = round(float(asset_agg.avg_risk), 2) if asset_agg.avg_risk else 0
    coverage_pct = (credentialed / total_assets * 100) if total_assets > 0 else 0

    finding_agg_rows = finding_q.with_entities(
        Finding.severity,
        func.count().label("cnt"),
        func.sum(case((Finding.exploit_available == True, 1), else_=0)).label("exploit_cnt"),
    ).group_by(Finding.severity).all()

    sev_counts = {}
    exploit_count = 0
    total_findings = 0
    for row in finding_agg_rows:
        sev_counts[row.severity] = row.cnt
        total_findings += row.cnt
        exploit_count += int(row.exploit_cnt or 0)

    if total_assets == 0 and total_findings == 0:
        return {}

    non_info = max(total_findings - sev_counts.get(0, 0), 1)
    critical = sev_counts.get(4, 0)
    high = sev_counts.get(3, 0)

    # SLA & MTTR — load SLAConfig once
    all_sla_configs = db.query(SLAConfig).all()
    cfg_map = {c.severity: c for c in all_sla_configs}
    enabled_sevs = [c.severity for c in all_sla_configs if c.is_enabled]

    sla_q = finding_q.filter(Finding.severity.in_(enabled_sevs)) if enabled_sevs else finding_q.filter(False)
    sla_findings = sla_q.all()

    sla_counts = {"on_track": 0, "at_risk": 0, "breached": 0, "resolved": 0, "n/a": 0}
    mttr_by_sev = {4: [], 3: [], 2: [], 1: [], 0: []}

    for f in sla_findings:
        status = f.sla_status or "n/a"
        sla_counts[status] = sla_counts.get(status, 0) + 1
        if f.resolved_at and f.sla_due_date:
            cfg = cfg_map.get(f.severity)
            if cfg:
                obs_date = f.sla_due_date - timedelta(days=cfg.days_to_remediate)
                days = (f.resolved_at - obs_date).total_seconds() / 86400
                if days >= 0:
                    mttr_by_sev[f.severity].append(days)

    total_sla = sum(sla_counts[k] for k in ("on_track", "at_risk", "breached", "resolved"))
    compliance_pct = ((sla_counts["on_track"] + sla_counts["resolved"]) / total_sla * 100) if total_sla else 100

    sev_labels = {4: "critical", 3: "high", 2: "medium", 1: "low"}
    avg_mttr = {}
    for sev, vals in mttr_by_sev.items():
        label = sev_labels.get(sev)
        if label and vals:
            avg_mttr[label] = round(sum(vals) / len(vals), 1)

    # Risk grade
    crit_high_ratio = (critical + high) / non_info if non_info else 0
    severity_score = max(0, 100 - crit_high_ratio * 200)
    sla_score = compliance_pct
    all_mttr = [v for vals in mttr_by_sev.values() for v in vals]
    avg_mttr_all = (sum(all_mttr) / len(all_mttr)) if all_mttr else 0
    if not all_mttr:
        velocity_score = 100 if (critical + high == 0) else 50
    elif avg_mttr_all <= 0:
        velocity_score = 100
    else:
        velocity_score = max(0, min(100, 100 - (avg_mttr_all - 7) * (100 / 83)))
    coverage_score = coverage_pct
    exploit_ratio = exploit_count / non_info if non_info else 0
    exploit_score = max(0, 100 - exploit_ratio * 300)
    risk_grade_score = round(
        severity_score * 0.25 + sla_score * 0.25 +
        velocity_score * 0.20 + coverage_score * 0.15 + exploit_score * 0.15, 1
    )
    risk_grade_score = max(0, min(100, risk_grade_score))

    critical_density = (critical / total_assets * 100) if total_assets else 0
    exploit_exposure = (exploit_count / non_info * 100) if non_info else 0

    # avg_risk_score already computed in the asset aggregation query above

    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    resolved_last_30 = finding_q.filter(
        Finding.resolved_at.isnot(None),
        Finding.resolved_at >= thirty_days_ago,
    ).count()

    return {
        "risk_grade": risk_grade_score,
        "sla_compliance": round(compliance_pct, 1),
        "mttr_critical": avg_mttr.get("critical"),
        "mttr_high": avg_mttr.get("high"),
        "mttr_medium": avg_mttr.get("medium"),
        "critical_density": round(critical_density, 1),
        "exploit_exposure": round(exploit_exposure, 1),
        "assessment_coverage": round(coverage_pct, 1),
        "avg_risk_score": avg_risk_score,
        "remediation_velocity": resolved_last_30,
        "patch_coverage": round(coverage_pct, 1),
        "total_assets": total_assets,
        "total_findings": total_findings,
    }


# ─────────────────────────────────────────────
# Cross-tenant platform aggregation
# ─────────────────────────────────────────────

def _compute_platform_benchmarks(db: Session, exclude_org_ids: Optional[List[int]] = None) -> dict:
    """
    Compute benchmark percentiles from ALL orgs on the platform.

    Iterates every org that has at least one scan, computes their metrics,
    then derives real P25/P50/P75/P90 from the population.

    Returns: {metric_key: {p25, p50, p75, p90, population_size}} or empty
    if fewer than 2 orgs have data.
    """
    # Find all orgs that have at least one scan
    org_rows = (
        db.query(Scan.org_id)
        .filter(Scan.org_id.isnot(None))
        .distinct()
        .all()
    )
    all_org_ids = [r[0] for r in org_rows]

    # Also include orgs with no org_id (legacy / dev mode scans) as a single "null" org
    null_scan_count = db.query(Scan).filter(Scan.org_id.is_(None)).count()
    has_null_org = null_scan_count > 0

    if len(all_org_ids) + (1 if has_null_org else 0) < 2:
        # Not enough orgs for meaningful benchmarks
        return {}

    # Compute metrics per org
    per_org_metrics: list[dict] = []

    for oid in all_org_ids:
        try:
            metrics = _compute_org_metrics(db, org_ids=[oid])
            if metrics:
                metrics["_org_id"] = oid
                per_org_metrics.append(metrics)
        except Exception:
            logger.debug(f"Skipping org {oid} in platform benchmarks (error)")
            continue

    # Include null-org scans as a virtual org
    if has_null_org:
        try:
            metrics = _compute_org_metrics(db, org_ids=None)
            if metrics:
                metrics["_org_id"] = None
                per_org_metrics.append(metrics)
        except Exception:
            pass

    if len(per_org_metrics) < 2:
        return {}

    # Compute percentiles per metric
    result = {}
    metric_keys = [k for k in METRIC_META.keys()]

    for mk in metric_keys:
        values = [m[mk] for m in per_org_metrics if m.get(mk) is not None]
        if len(values) < 2:
            continue

        sorted_vals = sorted(values)
        n = len(sorted_vals)

        result[mk] = {
            "p25": round(_percentile(sorted_vals, 25), 2),
            "p50": round(_percentile(sorted_vals, 50), 2),
            "p75": round(_percentile(sorted_vals, 75), 2),
            "p90": round(_percentile(sorted_vals, 90), 2),
            "population_size": n,
        }

    return result


def _percentile(sorted_data: list, pct: float) -> float:
    """Compute the pct-th percentile from pre-sorted data using linear interpolation."""
    if not sorted_data:
        return 0
    n = len(sorted_data)
    if n == 1:
        return sorted_data[0]
    # Use the same method as numpy's linear interpolation
    k = (pct / 100) * (n - 1)
    f = int(k)
    c = f + 1
    if c >= n:
        return sorted_data[-1]
    d = k - f
    return sorted_data[f] + d * (sorted_data[c] - sorted_data[f])


def _compute_platform_percentile_rank(value: float, sorted_population: list) -> int:
    """Compute exact percentile rank: % of population values that are <= this value."""
    if not sorted_population:
        return 50
    count_below = sum(1 for v in sorted_population if v <= value)
    return int(round(count_below / len(sorted_population) * 100))


def _compute_percentile_rank(value: float, p25: float, p50: float, p75: float, p90: float = None, higher_is_better: bool = True) -> int:
    """Estimate the org's percentile rank (0-100) given benchmark quartiles."""
    if higher_is_better:
        if value <= p25:
            return int(25 * value / p25) if p25 > 0 else 0
        elif value <= p50:
            return int(25 + 25 * (value - p25) / (p50 - p25)) if (p50 - p25) > 0 else 25
        elif value <= p75:
            return int(50 + 25 * (value - p50) / (p75 - p50)) if (p75 - p50) > 0 else 50
        elif p90 and value <= p90:
            return int(75 + 15 * (value - p75) / (p90 - p75)) if (p90 - p75) > 0 else 75
        else:
            return min(99, 90 if not p90 else int(90 + 10 * min(1, (value - (p90 or p75)) / max(1, (p90 or p75) * 0.2))))
    else:
        if value >= p25:
            return int(25 * (1 - min(1, (value - p25) / max(1, p25)))) if p25 > 0 else 0
        elif value >= p50:
            return int(25 + 25 * (p25 - value) / (p25 - p50)) if (p25 - p50) > 0 else 25
        elif value >= p75:
            return int(50 + 25 * (p50 - value) / (p50 - p75)) if (p50 - p75) > 0 else 50
        elif p90 and value >= p90:
            return int(75 + 15 * (p75 - value) / (p75 - p90)) if (p75 - p90) > 0 else 75
        else:
            return min(99, 90)


def _rating_from_percentile(prank: int) -> str:
    if prank >= 75:
        return "excellent"
    elif prank >= 50:
        return "good"
    elif prank >= 25:
        return "fair"
    return "poor"


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@router.get("")
def get_benchmarks(
    scan_id: Optional[int] = None,
    industry: str = "all",
    org_size: str = "all",
    source: str = "auto",  # "industry", "platform", or "auto" (platform if enough orgs, else industry)
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """
    Return org metrics benchmarked against industry references and/or platform peers.

    source=auto (default): returns platform benchmarks if ≥3 orgs exist, else industry.
    source=platform: cross-tenant only.
    source=industry: static reference data only.

    Each metric includes: org_value, benchmark (industry + platform), percentile_rank, rating.
    """
    _ensure_benchmark_seed(db)

    # Compute current org metrics
    org_metrics = _compute_org_metrics(db, org_ids, scan_id)
    if not org_metrics:
        return {"metrics": [], "industry": industry, "org_size": org_size,
                "source": source, "has_data": False}

    # ── Industry benchmarks ──
    industry_ref_map = {}
    if source in ("industry", "auto"):
        bench_q = db.query(BenchmarkReference)
        if industry != "all":
            bench_q_specific = bench_q.filter(
                BenchmarkReference.industry == industry,
                BenchmarkReference.org_size == org_size,
            )
            bench_q_fallback = bench_q.filter(
                BenchmarkReference.industry == "all",
                BenchmarkReference.org_size == org_size,
            )
        else:
            bench_q_specific = bench_q.filter(
                BenchmarkReference.industry == "all",
                BenchmarkReference.org_size == org_size,
            )
            bench_q_fallback = None

        for r in bench_q_specific.all():
            industry_ref_map[r.metric] = r
        if bench_q_fallback:
            for r in bench_q_fallback.all():
                if r.metric not in industry_ref_map:
                    industry_ref_map[r.metric] = r

    # ── Platform benchmarks (cross-tenant) ──
    platform_benchmarks = {}
    if source in ("platform", "auto"):
        platform_benchmarks = _compute_platform_benchmarks(db, exclude_org_ids=None)

    # Determine effective source
    effective_source = source
    if source == "auto":
        # Prefer platform if we have enough data (≥3 orgs with metrics)
        any_pop = next(iter(platform_benchmarks.values()), None)
        if any_pop and any_pop.get("population_size", 0) >= 3:
            effective_source = "platform"
        else:
            effective_source = "industry"

    # ── Build response ──
    results = []
    for metric_key, meta in METRIC_META.items():
        org_val = org_metrics.get(metric_key)
        if org_val is None:
            continue

        label = meta["label"]
        unit = meta["unit"]
        higher_is_better = meta["higher_is_better"]

        # Industry benchmark data
        ind_ref = industry_ref_map.get(metric_key)
        industry_bm = None
        if ind_ref:
            industry_bm = {
                "p25": ind_ref.p25, "p50": ind_ref.p50,
                "p75": ind_ref.p75, "p90": ind_ref.p90,
                "source": ind_ref.source,
                "source_year": ind_ref.source_year,
                "industry": ind_ref.industry,
            }

        # Platform benchmark data
        plat_data = platform_benchmarks.get(metric_key)
        platform_bm = None
        if plat_data:
            platform_bm = {
                "p25": plat_data["p25"], "p50": plat_data["p50"],
                "p75": plat_data["p75"], "p90": plat_data["p90"],
                "population_size": plat_data["population_size"],
                "source": "Platform",
            }

        # Pick the active benchmark based on effective source
        if effective_source == "platform" and platform_bm:
            active_bm = platform_bm
        elif industry_bm:
            active_bm = industry_bm
        else:
            active_bm = platform_bm  # fallback

        if active_bm:
            prank = _compute_percentile_rank(
                org_val, active_bm["p25"], active_bm["p50"],
                active_bm["p75"], active_bm.get("p90"),
                higher_is_better,
            )
            rating = _rating_from_percentile(prank)
        else:
            prank = None
            rating = None

        results.append({
            "metric": metric_key,
            "label": label,
            "org_value": org_val,
            "unit": unit,
            "higher_is_better": higher_is_better,
            "benchmark": active_bm,
            "industry_benchmark": industry_bm,
            "platform_benchmark": platform_bm,
            "percentile_rank": prank,
            "rating": rating,
            "effective_source": effective_source if active_bm else None,
        })

    # Available filter options
    industries = [r[0] for r in db.query(BenchmarkReference.industry).distinct().all()]
    sizes = [r[0] for r in db.query(BenchmarkReference.org_size).distinct().all()]

    # Platform population info
    any_plat = next(iter(platform_benchmarks.values()), None)
    platform_population = any_plat["population_size"] if any_plat else 0

    return {
        "metrics": results,
        "industry": industry,
        "org_size": org_size,
        "source": effective_source,
        "has_data": True,
        "platform_population": platform_population,
        "available_industries": sorted(industries),
        "available_sizes": sorted(sizes),
        "available_sources": _available_sources(platform_population),
        "total_assets": org_metrics.get("total_assets", 0),
        "total_findings": org_metrics.get("total_findings", 0),
    }


def _available_sources(platform_population: int) -> list:
    """Return which benchmark sources are available."""
    sources = ["industry"]
    if platform_population >= 3:
        sources.append("platform")
    return sources


@router.get("/platform-summary")
def get_platform_summary(
    db: Session = Depends(get_db),
):
    """
    Return aggregated platform benchmark percentiles (anonymized).
    No org-specific data is exposed — only population-level statistics.
    """
    platform_bm = _compute_platform_benchmarks(db)
    if not platform_bm:
        return {"has_data": False, "metrics": {}, "population_size": 0}

    any_pop = next(iter(platform_bm.values()), None)
    pop_size = any_pop["population_size"] if any_pop else 0

    metrics = {}
    for mk, data in platform_bm.items():
        meta = METRIC_META.get(mk, {})
        metrics[mk] = {
            "label": meta.get("label", mk),
            "unit": meta.get("unit", ""),
            "higher_is_better": meta.get("higher_is_better", True),
            **data,
        }

    return {
        "has_data": True,
        "metrics": metrics,
        "population_size": pop_size,
    }


# ─────────────────────────────────────────────
# Reference CRUD (unchanged)
# ─────────────────────────────────────────────

@router.get("/references")
def list_benchmark_references(
    industry: Optional[str] = None,
    metric: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all stored industry benchmark reference values."""
    _ensure_benchmark_seed(db)
    q = db.query(BenchmarkReference)
    if industry:
        q = q.filter(BenchmarkReference.industry == industry)
    if metric:
        q = q.filter(BenchmarkReference.metric == metric)
    rows = q.order_by(BenchmarkReference.metric, BenchmarkReference.industry).all()
    return [
        {
            "id": r.id, "metric": r.metric, "industry": r.industry,
            "org_size": r.org_size,
            "p25": r.p25, "p50": r.p50, "p75": r.p75, "p90": r.p90,
            "unit": r.unit, "higher_is_better": r.higher_is_better,
            "source": r.source, "source_year": r.source_year,
        }
        for r in rows
    ]


class BenchmarkRefUpdate(BaseModel):
    metric: Optional[str] = None
    industry: Optional[str] = None
    org_size: Optional[str] = None
    p25: Optional[float] = None
    p50: Optional[float] = None
    p75: Optional[float] = None
    p90: Optional[float] = None
    unit: Optional[str] = None
    higher_is_better: Optional[bool] = None
    source: Optional[str] = None
    source_year: Optional[int] = None


@router.put("/references/{ref_id}")
def update_benchmark_reference(
    ref_id: int,
    body: BenchmarkRefUpdate,
    db: Session = Depends(get_db),
):
    """Update an industry benchmark reference value."""
    ref = db.query(BenchmarkReference).filter(BenchmarkReference.id == ref_id).first()
    if not ref:
        raise HTTPException(404, "Benchmark reference not found")
    for field in ("metric", "industry", "org_size", "p25", "p50", "p75", "p90",
                  "unit", "higher_is_better", "source", "source_year"):
        val = getattr(body, field, None)
        if val is not None:
            setattr(ref, field, val)
    db.commit()
    return {"ok": True, "id": ref.id}


class BenchmarkRefCreate(BaseModel):
    metric: str
    industry: str = "all"
    org_size: str = "all"
    p25: float
    p50: float
    p75: float
    p90: Optional[float] = None
    unit: str = ""
    higher_is_better: bool = True
    source: Optional[str] = None
    source_year: Optional[int] = None


@router.post("/references")
def create_benchmark_reference(
    body: BenchmarkRefCreate,
    db: Session = Depends(get_db),
):
    """Create a new industry benchmark reference."""
    existing = db.query(BenchmarkReference).filter(
        BenchmarkReference.metric == body.metric,
        BenchmarkReference.industry == body.industry,
        BenchmarkReference.org_size == body.org_size,
    ).first()
    if existing:
        raise HTTPException(409, "Benchmark reference already exists for this metric/industry/size combination")
    ref = BenchmarkReference(**body.dict())
    db.add(ref)
    db.commit()
    db.refresh(ref)
    return {"ok": True, "id": ref.id}


@router.delete("/references/{ref_id}")
def delete_benchmark_reference(
    ref_id: int,
    db: Session = Depends(get_db),
):
    """Delete an industry benchmark reference."""
    ref = db.query(BenchmarkReference).filter(BenchmarkReference.id == ref_id).first()
    if not ref:
        raise HTTPException(404, "Benchmark reference not found")
    db.delete(ref)
    db.commit()
    return {"ok": True}
