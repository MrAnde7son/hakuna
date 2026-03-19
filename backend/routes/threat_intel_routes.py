"""
Threat Intelligence Center — FastAPI routes
Prefix: /api/threat-intel
"""
import logging
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, BackgroundTasks, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, asc, or_, text, case

from core.database import get_db, SessionLocal
from models.models import Finding, Asset, Scan
from models.threat_intel_models import (
    ThreatGroup, TTP, ThreatGroupTTP,
    ThreatCVE, ThreatCampaign, IntelRemediationCampaign, CisaAdvisory,
    ProductLifecycle, CWEEntry, ExploitReference, SSVCDecision,
    MSRCPatch,
)
import threat_intel.threat_intel_sync as sync_engine
import threat_intel.ttp_matcher as ttp_matcher

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


def _run_with_fresh_db(sync_fn, *args, **kwargs):
    """Run a sync function with a fresh DB session.

    Background tasks share the request's DB session, which may become stale
    after a long-running sync (SSVC takes 10+ min). Each slow sync gets its
    own connection so they don't depend on the original request session.
    """
    db = SessionLocal()
    try:
        sync_fn(db, *args, **kwargs)
    except Exception as exc:
        logger.warning("Sync %s failed: %s", getattr(sync_fn, "__name__", str(sync_fn)), exc)
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()


# ─────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────

class ImpactSearchRequest(BaseModel):
    cve_ids: List[str] = []
    ttp_ids: List[str] = []
    scan_id: Optional[int] = None


class CreateRemediationCampaignRequest(BaseModel):
    name: str
    description: Optional[str] = None
    threat_campaign_id: Optional[int] = None
    cve_ids: List[str] = []
    ttp_ids: List[str] = []


class UpdateRemediationCampaignRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    affected_asset_ids: Optional[List[int]] = None
    affected_finding_ids: Optional[List[int]] = None


# ─────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Aggregated stats for the TI Center header."""
    total_cves = db.query(func.count(ThreatCVE.id)).scalar() or 0
    kev_count = db.query(func.count(ThreatCVE.id)).filter(ThreatCVE.in_kev == True).scalar() or 0
    high_epss_count = db.query(func.count(ThreatCVE.id)).filter(ThreatCVE.epss_score >= 0.5).scalar() or 0
    remediation_campaigns = db.query(func.count(IntelRemediationCampaign.id)).scalar() or 0

    # Affected assets: count unique assets that have findings matching tracked intel CVEs
    tracked_cve_ids = {r[0] for r in db.query(ThreatCVE.cve_id).all()}
    affected_asset_set = set()
    if tracked_cve_ids:
        for (asset_id, cves) in db.query(Finding.asset_id, Finding.cves).filter(Finding.cves.isnot(None)).all():
            if cves and any(c in tracked_cve_ids for c in cves):
                affected_asset_set.add(asset_id)
    affected_assets = len(affected_asset_set)

    avg_epss_row = db.query(func.avg(ThreatCVE.epss_score)).filter(ThreatCVE.epss_score.isnot(None)).scalar()
    avg_epss = round(float(avg_epss_row), 4) if avg_epss_row else 0.0

    # Exposed groups: threat groups with ≥50% TTP overlap in any uploaded scan
    all_matched_ttps: set = set()
    for (mtps,) in db.query(Finding.matched_ttps).filter(Finding.matched_ttps.isnot(None)).all():
        if mtps:
            for t in mtps:
                tid = t.get("technique_id") if isinstance(t, dict) else None
                if tid:
                    all_matched_ttps.add(tid)

    exposed_groups = 0
    if all_matched_ttps:
        group_tech_rows = (
            db.query(ThreatGroupTTP.group_id, TTP.technique_id)
            .join(TTP, TTP.id == ThreatGroupTTP.ttp_id)
            .all()
        )
        group_tech_map: dict = {}
        for gid, tid in group_tech_rows:
            group_tech_map.setdefault(gid, set()).add(tid)
        for gid, tech_set in group_tech_map.items():
            matched = len(tech_set & all_matched_ttps)
            min_match = max(3, round(len(tech_set) * 0.5))
            if matched >= min_match:
                exposed_groups += 1

    # Product lifecycle counts
    total_products = db.query(func.count(func.distinct(ProductLifecycle.slug))).scalar() or 0
    eol_products = (
        db.query(func.count(func.distinct(ProductLifecycle.slug)))
        .filter(ProductLifecycle.is_eol == True)
        .scalar() or 0
    )

    # New intel source counts
    exploit_ref_count = db.query(func.count(func.distinct(ExploitReference.cve_id))).scalar() or 0
    ssvc_count = db.query(func.count(SSVCDecision.id)).scalar() or 0
    ssvc_act_count = db.query(func.count(SSVCDecision.id)).filter(SSVCDecision.decision == "Act").scalar() or 0
    cwe_count = db.query(func.count(CWEEntry.id)).scalar() or 0
    msrc_patch_count = db.query(func.count(func.distinct(MSRCPatch.cve_id))).scalar() or 0

    return {
        "total_cves": total_cves,
        "kev_count": kev_count,
        "high_epss_count": high_epss_count,
        "exposed_groups": exposed_groups,
        "remediation_campaigns": remediation_campaigns,
        "affected_assets": affected_assets,
        "avg_epss": avg_epss,
        "total_products": total_products,
        "eol_products": eol_products,
        # New intel sources
        "exploit_ref_cves": exploit_ref_count,
        "ssvc_decisions": ssvc_count,
        "ssvc_act_count": ssvc_act_count,
        "cwe_entries": cwe_count,
        "msrc_patched_cves": msrc_patch_count,
    }


# ─────────────────────────────────────────────
# Threat Campaign Feed (Newsroom)
# ─────────────────────────────────────────────

@router.get("/feed")
def get_feed(
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    active_only: bool = True,
    db: Session = Depends(get_db),
):
    q = db.query(ThreatCampaign)
    if active_only:
        q = q.filter(ThreatCampaign.is_active == True)
    if severity:
        q = q.filter(ThreatCampaign.severity == severity)
    campaigns = q.order_by(desc(ThreatCampaign.created_at)).limit(limit).all()

    result = []
    for c in campaigns:
        group_name = None
        if c.threat_group_id:
            g = db.query(ThreatGroup.name).filter(ThreatGroup.id == c.threat_group_id).first()
            group_name = g[0] if g else None
        result.append({
            "id": c.id,
            "name": c.name,
            "aliases": c.aliases or [],
            "description": c.description or "",
            "threat_group_name": group_name,
            "severity": c.severity,
            "first_seen": c.first_seen,
            "last_seen": c.last_seen,
            "target_sectors": c.target_sectors or [],
            "target_countries": c.target_countries or [],
            "malware_used": c.malware_used or [],
            "cve_ids": c.cve_ids or [],
            "ttp_ids": c.ttp_ids or [],
            "is_active": c.is_active,
            "source": c.source,
            "source_url": c.source_url,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        })
    return result


# ─────────────────────────────────────────────
# CVE Intel
# ─────────────────────────────────────────────

@router.get("/cves")
def get_cves(
    search: Optional[str] = None,
    kev_only: bool = False,
    min_epss: Optional[float] = None,
    min_cvss: Optional[float] = None,
    in_scan: Optional[str] = None,   # scan_id or "all" — only CVEs found in findings
    has_exploit: bool = False,       # Only CVEs with public exploits
    ssvc_act: bool = False,          # Only CVEs with SSVC decision "Act"
    sort_by: Optional[str] = Query(None, regex="^(cve_id|cvss3_score|epss_score|in_kev|published_date|kev_date_added|in_scan_count)$"),
    sort_dir: Optional[str] = Query("desc", regex="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(ThreatCVE)

    if search:
        q = q.filter(ThreatCVE.cve_id.ilike(f"%{search}%"))
    if kev_only:
        q = q.filter(ThreatCVE.in_kev == True)
    if min_epss is not None:
        q = q.filter(ThreatCVE.epss_score >= min_epss)
    if min_cvss is not None:
        q = q.filter(ThreatCVE.cvss3_score >= min_cvss)
    if has_exploit:
        q = q.filter(ThreatCVE.has_public_exploit == True)
    if ssvc_act:
        q = q.filter(ThreatCVE.ssvc_decision == "Act")

    # Collect CVE IDs found in findings for a given scan (or all scans)
    scan_cve_ids: set = set()
    if in_scan:
        fq = db.query(Finding.cves).filter(Finding.cves.isnot(None))
        if in_scan != "all":
            fq = fq.filter(Finding.scan_id == int(in_scan))
        for (cves,) in fq.all():
            if cves:
                scan_cve_ids.update(c.strip() for c in cves if c)
        if scan_cve_ids:
            # Use a temp table to avoid SQLite's variable limit with large IN clauses
            db.execute(text("CREATE TEMP TABLE IF NOT EXISTS _scan_cves (cve_id TEXT PRIMARY KEY)"))
            db.execute(text("DELETE FROM _scan_cves"))
            BATCH = 500
            cve_list = list(scan_cve_ids)
            for i in range(0, len(cve_list), BATCH):
                batch = cve_list[i:i+BATCH]
                db.execute(text("INSERT OR IGNORE INTO _scan_cves (cve_id) VALUES " +
                    ",".join(["(:v%d)" % j for j in range(len(batch))])),
                    {"v%d" % j: v for j, v in enumerate(batch)})
            q = q.filter(ThreatCVE.cve_id.in_(text("SELECT cve_id FROM _scan_cves")))
        else:
            return {"items": [], "total": 0}

    total = q.count()

    # Build full in_scan_counts lookup (needed for sort or display)
    def _build_scan_counts(cve_id_set=None) -> dict:
        counts: dict = {}
        all_findings_with_cves = db.query(Finding.cves).filter(Finding.cves.isnot(None)).all()
        for (cves,) in all_findings_with_cves:
            if not cves:
                continue
            for cve in cves:
                if cve_id_set is None or cve in cve_id_set:
                    counts[cve] = counts.get(cve, 0) + 1
        return counts

    # Sorting
    SORT_COLS = {
        'cve_id': ThreatCVE.cve_id,
        'cvss3_score': ThreatCVE.cvss3_score,
        'epss_score': ThreatCVE.epss_score,
        'in_kev': ThreatCVE.in_kev,
        'published_date': ThreatCVE.published_date,
        'kev_date_added': ThreatCVE.kev_date_added,
    }

    if sort_by == 'in_scan_count':
        # Compute counts for ALL matching CVEs, sort in Python, then paginate
        all_records = q.all()
        all_ids = {r.cve_id for r in all_records}
        in_scan_counts = _build_scan_counts(all_ids)
        reverse = sort_dir == 'desc'
        all_records.sort(key=lambda r: in_scan_counts.get(r.cve_id, 0), reverse=reverse)
        records = all_records[offset: offset + limit]
    elif sort_by and sort_by in SORT_COLS:
        col = SORT_COLS[sort_by]
        order = asc(col) if sort_dir == 'asc' else desc(col)
        records = q.order_by(order).offset(offset).limit(limit).all()
        cve_ids_page = {r.cve_id for r in records}
        in_scan_counts = _build_scan_counts(cve_ids_page)
    else:
        records = q.order_by(desc(ThreatCVE.kev_date_added), desc(ThreatCVE.epss_score), desc(ThreatCVE.cvss3_score)).offset(offset).limit(limit).all()
        cve_ids_page = {r.cve_id for r in records}
        in_scan_counts = _build_scan_counts(cve_ids_page)

    result = []
    for r in records:
        result.append({
            "cve_id": r.cve_id,
            "description": r.description or "",
            "cvss2_score": r.cvss2_score,
            "cvss3_score": r.cvss3_score,
            "cvss3_vector": r.cvss3_vector,
            "cvss4_score": r.cvss4_score,
            "cvss4_vector": r.cvss4_vector,
            "epss_score": r.epss_score,
            "epss_percentile": r.epss_percentile,
            "in_kev": r.in_kev,
            "kev_date_added": r.kev_date_added,
            "kev_due_date": r.kev_due_date,
            "kev_ransomware_use": r.kev_ransomware_use,
            "kev_notes": r.kev_notes,
            "has_public_exploit": r.has_public_exploit,
            "exploit_references": r.exploit_references or [],
            "affected_products": (r.affected_products or [])[:10],
            "cwe_ids": r.cwe_ids or [],
            "nvd_url": r.nvd_url,
            "patch_urls": r.patch_urls or [],
            "published_date": r.published_date,
            "trending_in_news": r.trending_in_news or False,
            "in_scan_count": in_scan_counts.get(r.cve_id, 0),
            # New intel source fields
            "exploit_count": r.exploit_count or 0,
            "exploit_sources": r.exploit_sources or [],
            "exploit_maturity_level": r.exploit_maturity_level,
            "ssvc_decision": r.ssvc_decision,
            "ssvc_exploitation": r.ssvc_exploitation,
            "cwe_names": r.cwe_names or [],
            "cwe_categories": r.cwe_categories or [],
            "msrc_kb_ids": r.msrc_kb_ids or [],
        })

    return {"total": total, "offset": offset, "limit": limit, "items": result}


@router.patch("/cves/{cve_id}/trending")
def toggle_trending(cve_id: str, trending: bool = True, db: Session = Depends(get_db)):
    """Mark or unmark a CVE as trending in the news."""
    record = db.query(ThreatCVE).filter(ThreatCVE.cve_id == cve_id.upper()).first()
    if not record:
        raise HTTPException(404, f"CVE {cve_id} not found in threat intel")
    record.trending_in_news = trending
    record.updated_at = datetime.utcnow()
    db.commit()
    # Propagate to findings
    try:
        sync_engine.enrich_findings_from_threat_intel(db)
    except Exception:
        pass
    return {"cve_id": record.cve_id, "trending_in_news": record.trending_in_news}


# ─────────────────────────────────────────────
# KEV feed (latest entries, for newsroom sidebar)
# ─────────────────────────────────────────────

@router.get("/kev-recent")
def get_kev_recent(limit: int = Query(10, ge=1, le=50), db: Session = Depends(get_db)):
    records = (
        db.query(ThreatCVE)
        .filter(ThreatCVE.in_kev == True)
        .order_by(desc(ThreatCVE.kev_date_added))
        .limit(limit)
        .all()
    )
    return [
        {
            "cve_id": r.cve_id,
            "description": r.description or "",
            "kev_date_added": r.kev_date_added,
            "kev_due_date": r.kev_due_date,
            "kev_ransomware_use": r.kev_ransomware_use,
            "kev_notes": r.kev_notes,
            "cvss3_score": r.cvss3_score,
            "epss_score": r.epss_score,
        }
        for r in records
    ]


# ─────────────────────────────────────────────
# Threat Groups
# ─────────────────────────────────────────────

@router.get("/groups")
def get_groups(
    search: Optional[str] = None,
    motivation: Optional[str] = None,
    is_ransomware: Optional[bool] = None,
    in_scan: Optional[int] = None,  # scan_id — filter groups relevant to this scan's CVEs
    db: Session = Depends(get_db),
):
    q = db.query(ThreatGroup)
    if search:
        q = q.filter(
            or_(
                ThreatGroup.name.ilike(f"%{search}%"),
                ThreatGroup.description.ilike(f"%{search}%"),
            )
        )
    if motivation:
        q = q.filter(ThreatGroup.motivation == motivation)
    if is_ransomware is not None:
        q = q.filter(ThreatGroup.is_ransomware == is_ransomware)

    if in_scan is not None:
        # Collect CVE IDs from this scan's findings
        rows = db.query(Finding.cves).filter(Finding.scan_id == in_scan).all()
        scan_cve_ids: set = set()
        for (cves,) in rows:
            if cves:
                scan_cve_ids.update(c.strip() for c in cves if c)
        if scan_cve_ids:
            # If scan has KEV CVEs with ransomware use → show ransomware groups
            has_ransomware_kev = db.query(ThreatCVE.id).filter(
                ThreatCVE.cve_id.in_(list(scan_cve_ids)),
                ThreatCVE.in_kev == True,
                ThreatCVE.kev_ransomware_use.isnot(None),
                ThreatCVE.kev_ransomware_use != 'Unknown',
            ).first() is not None
            if has_ransomware_kev:
                q = q.filter(ThreatGroup.is_ransomware == True)
            else:
                # Fallback: show nation-state and ransomware groups (broad relevance)
                q = q.filter(or_(ThreatGroup.is_nation_state == True, ThreatGroup.is_ransomware == True))
        else:
            return []

    groups = q.order_by(ThreatGroup.name).all()

    # Count TTPs per group
    group_ids = [g.id for g in groups]
    ttp_counts: dict = {}
    if group_ids:
        rows = (
            db.query(ThreatGroupTTP.group_id, func.count(ThreatGroupTTP.ttp_id))
            .filter(ThreatGroupTTP.group_id.in_(group_ids))
            .group_by(ThreatGroupTTP.group_id)
            .all()
        )
        ttp_counts = {gid: cnt for gid, cnt in rows}

    return [
        {
            "id": g.id,
            "mitre_id": g.mitre_id,
            "name": g.name,
            "aliases": g.aliases or [],
            "country": g.country,
            "motivation": g.motivation,
            "description": g.description or "",
            "first_seen": g.first_seen,
            "last_seen": g.last_seen,
            "is_ransomware": g.is_ransomware,
            "is_nation_state": g.is_nation_state,
            "target_sectors": g.target_sectors or [],
            "target_countries": g.target_countries or [],
            "source": g.source,
            "source_url": g.source_url,
            "ttp_count": ttp_counts.get(g.id, 0),
        }
        for g in groups
    ]


# ─────────────────────────────────────────────
# TTPs
# ─────────────────────────────────────────────

@router.get("/ttps")
def get_ttps(
    search: Optional[str] = None,
    tactic: Optional[str] = None,
    group_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    q = db.query(TTP)
    if search:
        q = q.filter(
            or_(
                TTP.technique_id.ilike(f"%{search}%"),
                TTP.name.ilike(f"%{search}%"),
            )
        )
    if tactic:
        q = q.filter(TTP.tactic == tactic)
    if group_id:
        ttp_ids = [
            row[0]
            for row in db.query(ThreatGroupTTP.ttp_id)
            .filter(ThreatGroupTTP.group_id == group_id)
            .all()
        ]
        q = q.filter(TTP.id.in_(ttp_ids))

    ttps = q.order_by(TTP.tactic, TTP.technique_id).all()

    # Count groups per TTP
    ttp_ids_page = [t.id for t in ttps]
    group_counts: dict = {}
    if ttp_ids_page:
        rows = (
            db.query(ThreatGroupTTP.ttp_id, func.count(ThreatGroupTTP.group_id))
            .filter(ThreatGroupTTP.ttp_id.in_(ttp_ids_page))
            .group_by(ThreatGroupTTP.ttp_id)
            .all()
        )
        group_counts = {tid: cnt for tid, cnt in rows}

    return [
        {
            "id": t.id,
            "technique_id": t.technique_id,
            "name": t.name,
            "tactic": t.tactic,
            "description": t.description or "",
            "platforms": t.platforms or [],
            "detection": t.detection or "",
            "data_sources": t.data_sources or [],
            "mitre_url": t.mitre_url,
            "is_subtechnique": t.is_subtechnique,
            "parent_technique_id": t.parent_technique_id,
            "group_count": group_counts.get(t.id, 0),
        }
        for t in ttps
    ]


# ─────────────────────────────────────────────
# Impact Analysis
# ─────────────────────────────────────────────

@router.post("/impact-search")
def impact_search(req: ImpactSearchRequest, db: Session = Depends(get_db)):
    """
    Cross-reference CVE IDs / TTP IDs against internal findings and assets.
    Returns matched assets and findings.
    """
    cve_ids = [c.strip().upper() for c in req.cve_ids if c.strip()]
    # TTP IDs don't directly map to findings, but we can surface related CVEs from threat campaigns
    ttp_ids = [t.strip() for t in req.ttp_ids if t.strip()]

    # Also pull in CVEs from threat campaigns that use these TTPs
    if ttp_ids:
        campaigns_with_ttp = (
            db.query(ThreatCampaign.cve_ids)
            .filter(ThreatCampaign.is_active == True)
            .all()
        )
        for (campaign_cves,) in campaigns_with_ttp:
            if campaign_cves:
                cve_ids.extend(campaign_cves)
    cve_ids = list(set(cve_ids))

    if not cve_ids:
        return {
            "matched_assets": [],
            "matched_findings": [],
            "total_assets": 0,
            "total_findings": 0,
            "cve_ids_searched": [],
        }

    # Find findings that contain any of the searched CVE IDs
    findings_q = db.query(Finding)
    if req.scan_id:
        findings_q = findings_q.filter(Finding.scan_id == req.scan_id)
    all_findings = findings_q.filter(Finding.cves.isnot(None)).all()

    matched_findings = []
    matched_asset_ids: set = set()

    for f in all_findings:
        if not f.cves:
            continue
        finding_cves = set(c.upper() for c in f.cves if c)
        common = finding_cves & set(cve_ids)
        if common:
            matched_findings.append({
                "id": f.id,
                "plugin_id": f.plugin_id,
                "plugin_name": f.plugin_name,
                "severity": f.severity,
                "severity_label": f.severity_label,
                "cvss3_score": f.cvss3_score,
                "asset_id": f.asset_id,
                "cves": list(common),
                "cve_match_count": len(common),
                "priority_score": f.priority_score,
            })
            matched_asset_ids.add(f.asset_id)

    # Fetch matched assets with basic info
    matched_assets = []
    if matched_asset_ids:
        assets = db.query(Asset).filter(Asset.id.in_(list(matched_asset_ids))).all()
        # Build per-asset finding count
        asset_finding_counts = {
            a_id: sum(1 for mf in matched_findings if mf["asset_id"] == a_id)
            for a_id in matched_asset_ids
        }
        for a in assets:
            # Collect which CVEs matched on this asset
            asset_cves = set()
            for mf in matched_findings:
                if mf["asset_id"] == a.id:
                    asset_cves.update(mf["cves"])
            matched_assets.append({
                "id": a.id,
                "ip": a.ip,
                "hostname": a.hostname,
                "fqdn": a.fqdn,
                "os": a.os,
                "criticality": a.criticality,
                "risk_score": a.risk_score,
                "finding_count": asset_finding_counts.get(a.id, 0),
                "cve_matches": list(asset_cves),
            })

    # Sort findings by priority (severity desc, then cvss3 desc)
    matched_findings.sort(key=lambda x: (-(x["severity"] or 0), -(x["cvss3_score"] or 0)))
    matched_assets.sort(key=lambda x: -(x["risk_score"] or 0))

    # Resolve asset IP for each finding
    asset_ip_map = {a["id"]: a["ip"] for a in matched_assets}
    for mf in matched_findings:
        mf["asset_ip"] = asset_ip_map.get(mf["asset_id"], "")

    return {
        "matched_assets": matched_assets[:100],
        "matched_findings": matched_findings[:200],
        "total_assets": len(matched_asset_ids),
        "total_findings": len(matched_findings),
        "cve_ids_searched": cve_ids,
    }


# ─────────────────────────────────────────────
# Scan Exposure (group/TTP correlation with findings)
# ─────────────────────────────────────────────

@router.get("/scan-exposure")
def scan_exposure(scan_id: Optional[int] = Query(None), db: Session = Depends(get_db)):
    """
    For each threat group, count matched findings via two signals:
      1. TTP overlap: group's known techniques vs finding.matched_ttps (primary — always populated)
      2. CVE overlap: campaign CVE IDs vs finding CVEs (fallback — sparse in MITRE data)
    Returns only groups with at least one matched finding, sorted by impact.
    """
    # ── Signal 1: TTP-based matching (group → technique_ids → matched_ttps on findings) ──
    # Build group_id → set of technique_ids
    group_ttp_rows = (
        db.query(ThreatGroupTTP.group_id, TTP.technique_id)
        .join(TTP, TTP.id == ThreatGroupTTP.ttp_id)
        .all()
    )
    group_techniques: dict = {}
    for group_id, tech_id in group_ttp_rows:
        group_techniques.setdefault(group_id, set()).add(tech_id)

    # Load findings with matched_ttps (and optionally CVEs) scoped to scan
    fq = db.query(
        Finding.id, Finding.asset_id, Finding.severity,
        Finding.plugin_name, Finding.cvss3_score,
        Finding.matched_ttps, Finding.cves,
    )
    if scan_id is not None:
        fq = fq.filter(Finding.scan_id == scan_id)
    all_findings = fq.all()

    if not all_findings and not group_techniques:
        return []

    # Pre-index findings: technique_id → [(fid, asset_id, severity)]
    tech_to_findings: dict = {}
    finding_cves: dict = {}  # fid → set of CVE strings (for signal 2)
    for fid, asset_id, severity, plugin_name, cvss3, matched_ttps, cves in all_findings:
        if matched_ttps:
            for ttp in matched_ttps:
                tid = ttp.get("technique_id")
                if tid:
                    tech_to_findings.setdefault(tid, []).append((fid, asset_id, severity))
        if cves:
            finding_cves[fid] = {c.upper().strip() for c in cves if c}

    # For each group, aggregate TTP-matched findings
    results: dict = {}
    for group_id, tech_set in group_techniques.items():
        matched_finding_ids = set()
        matched_assets = set()
        matched_techs = set()
        for tech_id in tech_set:
            for fid, asset_id, severity in tech_to_findings.get(tech_id, []):
                matched_finding_ids.add(fid)
                matched_assets.add(asset_id)
                matched_techs.add(tech_id)

        if matched_techs:
            coverage_pct = round(len(matched_techs) / len(tech_set) * 100, 1) if tech_set else 0.0
            # ≥50% overlap (floor of 3) = "In My Environment" quality signal
            min_match = max(3, round(len(tech_set) * 0.50))
            meets_threshold = len(matched_techs) >= min_match
            results[group_id] = {
                "group_id": group_id,
                "matched_findings": len(matched_finding_ids),
                "matched_assets": len(matched_assets),
                "matched_ttps": sorted(matched_techs),
                "total_group_ttps": len(tech_set),
                "coverage_pct": coverage_pct,
                "meets_threshold": meets_threshold,
                "matched_cves": [],
                "match_method": "ttp",
            }

    # ── Signal 2: CVE-based matching (from campaigns) — adds CVE context if available ──
    campaigns = (
        db.query(ThreatCampaign.threat_group_id, ThreatCampaign.cve_ids)
        .filter(
            ThreatCampaign.threat_group_id.isnot(None),
            ThreatCampaign.cve_ids.isnot(None),
        )
        .all()
    )
    group_cves: dict = {}
    for group_id, cve_ids in campaigns:
        if cve_ids and group_id:
            group_cves.setdefault(group_id, set()).update(c.upper().strip() for c in cve_ids if c)

    for group_id, cve_set in group_cves.items():
        matched_finding_ids = set()
        matched_assets = set()
        matched_cves_found = set()
        for fid, cve_set_f in finding_cves.items():
            common = cve_set_f & cve_set
            if common:
                matched_finding_ids.add(fid)
                matched_cves_found.update(common)
        if matched_finding_ids:
            if group_id in results:
                # Merge CVE data into existing TTP-based result
                results[group_id]["matched_cves"] = sorted(matched_cves_found)[:20]
            else:
                results[group_id] = {
                    "group_id": group_id,
                    "matched_findings": len(matched_finding_ids),
                    "matched_assets": len(matched_assets),
                    "matched_ttps": [],
                    "total_group_ttps": len(group_techniques.get(group_id, set())),
                    "coverage_pct": 0.0,
                    "meets_threshold": False,  # CVE-only matches don't qualify without TTP overlap
                    "matched_cves": sorted(matched_cves_found)[:20],
                    "match_method": "cve",
                }

    if not results:
        return []

    # Enrich with group metadata
    group_ids = list(results.keys())
    groups = {g.id: g for g in db.query(ThreatGroup).filter(ThreatGroup.id.in_(group_ids)).all()}
    enriched = []
    for r in results.values():
        g = groups.get(r["group_id"])
        if g:
            enriched.append({
                **r,
                "group_name": g.name,
                "group_mitre_id": g.mitre_id,
                "motivation": g.motivation,
                "is_ransomware": g.is_ransomware,
                "is_nation_state": g.is_nation_state,
                "country": g.country,
            })

    enriched.sort(key=lambda x: (-x["matched_findings"], -x["matched_assets"]))
    return enriched


@router.get("/groups/{group_id}/exposure")
def get_group_exposure(
    group_id: int,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """
    Detailed exposure for a single threat group against a scan (or all scans).
    Returns matched findings + assets.
    """
    group = db.query(ThreatGroup).filter(ThreatGroup.id == group_id).first()
    if not group:
        raise HTTPException(404, "Threat group not found")

    # Collect CVE IDs from all campaigns linked to this group
    campaigns = db.query(ThreatCampaign).filter(
        ThreatCampaign.threat_group_id == group_id,
        ThreatCampaign.cve_ids.isnot(None),
    ).all()

    cve_ids: set = set()
    for c in campaigns:
        if c.cve_ids:
            cve_ids.update(cv.upper().strip() for cv in c.cve_ids if cv)

    if not cve_ids:
        return {
            "group_id": group_id,
            "group_name": group.name,
            "cve_ids_from_campaigns": [],
            "matched_findings": 0,
            "matched_assets": 0,
            "top_findings": [],
            "affected_assets": [],
        }

    # Reuse impact_search logic
    result = impact_search(
        ImpactSearchRequest(cve_ids=list(cve_ids), scan_id=scan_id),
        db=db,
    )

    return {
        "group_id": group_id,
        "group_name": group.name,
        "cve_ids_from_campaigns": sorted(cve_ids),
        "matched_findings": result["total_findings"],
        "matched_assets": result["total_assets"],
        "top_findings": result["matched_findings"][:15],
        "affected_assets": result["matched_assets"][:20],
    }


# ─────────────────────────────────────────────
# TTP Coverage (non-CVE ATT&CK matching)
# ─────────────────────────────────────────────

@router.get("/ttp-coverage")
def get_ttp_coverage(
    scan_id: Optional[int] = Query(None),
    tactic: Optional[str] = Query(None),
    min_findings: int = Query(1, ge=1),
    db: Session = Depends(get_db),
):
    """
    Aggregate findings by matched ATT&CK technique.
    Returns each technique with finding count, asset count, severity breakdown.
    """
    fq = db.query(Finding.id, Finding.matched_ttps, Finding.asset_id, Finding.severity, Finding.plugin_name, Finding.plugin_id)
    fq = fq.filter(Finding.matched_ttps.isnot(None))
    if scan_id is not None:
        fq = fq.filter(Finding.scan_id == scan_id)
    rows = fq.all()

    # Aggregate by technique_id
    technique_map: dict = {}
    for fid, ttps, asset_id, severity, plugin_name, plugin_id in rows:
        if not ttps:
            continue
        for ttp in ttps:
            tid = ttp.get("technique_id")
            if not tid:
                continue
            if tactic and ttp.get("tactic") != tactic:
                continue
            if tid not in technique_map:
                technique_map[tid] = {
                    "technique_id": tid,
                    "name": ttp.get("name", ""),
                    "tactic": ttp.get("tactic", ""),
                    "mitre_url": ttp.get("mitre_url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
                    "finding_ids": [],
                    "asset_ids": set(),
                    "severity_counts": {0: 0, 1: 0, 2: 0, 3: 0, 4: 0},
                    "example_plugins": [],
                    "confidence_counts": {"high": 0, "medium": 0, "low": 0},
                }
            entry = technique_map[tid]
            entry["finding_ids"].append(fid)
            entry["asset_ids"].add(asset_id)
            sev = severity if severity is not None else 0
            entry["severity_counts"][sev] = entry["severity_counts"].get(sev, 0) + 1
            if plugin_name and plugin_name not in entry["example_plugins"]:
                entry["example_plugins"].append(plugin_name)
            conf = ttp.get("confidence", "medium")
            entry["confidence_counts"][conf] = entry["confidence_counts"].get(conf, 0) + 1

    # Serialize + filter
    result = []
    for entry in technique_map.values():
        fc = len(entry["finding_ids"])
        if fc < min_findings:
            continue
        result.append({
            "technique_id": entry["technique_id"],
            "name": entry["name"],
            "tactic": entry["tactic"],
            "mitre_url": entry["mitre_url"],
            "finding_count": fc,
            "asset_count": len(entry["asset_ids"]),
            "severity_counts": entry["severity_counts"],
            "example_plugins": entry["example_plugins"][:5],
            "confidence_counts": entry["confidence_counts"],
            "top_severity": max(entry["severity_counts"], key=lambda k: entry["severity_counts"][k]),
        })

    # Sort by finding_count desc
    result.sort(key=lambda x: (-x["finding_count"], -x["asset_count"]))
    return result


@router.post("/match-ttps")
def trigger_ttp_matching(
    background_tasks: BackgroundTasks,
    scan_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Trigger ATT&CK TTP matching on findings (keyword + plugin ID + plugin family).
    Runs synchronously for a specific scan, in background for all scans.
    """
    if scan_id is not None:
        result = ttp_matcher.match_findings_to_ttps(db, scan_id=scan_id)
        return {"status": "ok", **result}
    else:
        background_tasks.add_task(ttp_matcher.match_findings_to_ttps, db, None)
        return {"status": "ok", "message": "TTP matching running in background"}


# ─────────────────────────────────────────────
# CISA Advisories
# ─────────────────────────────────────────────

@router.get("/advisories")
def get_advisories(
    search: Optional[str] = None,
    advisory_type: Optional[str] = None,   # "advisory" | "alert" | "ics" | "ics_medical" | "malware"
    ics_only: bool = False,
    exclude_ics: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(CisaAdvisory)
    if search:
        q = q.filter(
            or_(
                CisaAdvisory.title.ilike(f"%{search}%"),
                CisaAdvisory.summary.ilike(f"%{search}%"),
                CisaAdvisory.advisory_id.ilike(f"%{search}%"),
            )
        )
    if advisory_type:
        q = q.filter(CisaAdvisory.advisory_type == advisory_type)
    if ics_only:
        q = q.filter(CisaAdvisory.is_ics == True)
    if exclude_ics:
        q = q.filter(CisaAdvisory.is_ics == False)

    total = q.count()
    records = q.order_by(desc(CisaAdvisory.pub_date), desc(CisaAdvisory.created_at)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": r.id,
                "advisory_id": r.advisory_id,
                "title": r.title,
                "advisory_type": r.advisory_type,
                "pub_date": r.pub_date,
                "summary": r.summary,
                "url": r.url,
                "co_sealers": r.co_sealers or [],
                "sectors": r.sectors or [],
                "cve_ids": r.cve_ids or [],
                "cve_count": len(r.cve_ids or []),
                "threat_group_ids": r.threat_group_ids or [],
                "threat_group_names": r.threat_group_names or [],
                "is_ics": r.is_ics,
            }
            for r in records
        ],
    }


# ─────────────────────────────────────────────
# Sync
# ─────────────────────────────────────────────

def _run_sync_in_background(db: Session):
    """Run the full sync pipeline. Called in a background task."""
    try:
        sync_engine.sync_kev_to_db(db)
    except Exception as exc:
        logger.warning("Background KEV sync failed: %s", exc)
    try:
        sync_engine.sync_epss_for_scan_cves(db)
    except Exception as exc:
        logger.warning("Background EPSS sync failed: %s", exc)
    try:
        sync_engine.sync_nvd_scores(db)
    except Exception as exc:
        logger.warning("Background NVD CVSS sync failed: %s", exc)
    try:
        sync_engine.sync_mitre_groups_to_db(db)
    except Exception as exc:
        logger.warning("Background MITRE sync failed: %s", exc)
    # Enrich all findings with the freshly synced intel data
    try:
        sync_engine.enrich_findings_from_threat_intel(db)
    except Exception as exc:
        logger.warning("Background finding enrichment failed: %s", exc)
    # Match findings to ATT&CK TTPs
    try:
        ttp_matcher.match_findings_to_ttps(db)
    except Exception as exc:
        logger.warning("Background TTP matching failed: %s", exc)
    # Sync CISA advisories
    advisory_sync_fn = getattr(sync_engine, 'sync_cisa_advisories_to_db', None)
    if advisory_sync_fn:
        try:
            advisory_sync_fn(db)
        except Exception as exc:
            logger.warning("Background CISA advisory sync failed: %s", exc)
    # New intel sources
    try:
        sync_engine.sync_ssvc_decisions_to_db(db)
    except Exception as exc:
        logger.warning("Background SSVC sync failed: %s", exc)
    try:
        sync_engine.sync_cwe_catalog_to_db(db)
    except Exception as exc:
        logger.warning("Background CWE sync failed: %s", exc)
    try:
        sync_engine.sync_metasploit_modules_to_db(db)
    except Exception as exc:
        logger.warning("Background Metasploit sync failed: %s", exc)
    try:
        sync_engine.sync_exploitdb_to_db(db)
    except Exception as exc:
        logger.warning("Background ExploitDB sync failed: %s", exc)
    try:
        sync_engine.sync_msrc_patches_to_db(db)
    except Exception as exc:
        logger.warning("Background MSRC sync failed: %s", exc)
    try:
        sync_engine.enrich_findings_extended(db)
    except Exception as exc:
        logger.warning("Background extended enrichment failed: %s", exc)
    logger.info("Background intel sync complete")


@router.post("/sync")
def sync_intel(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Kick off a background sync from CISA KEV, EPSS, and MITRE ATT&CK.
    Returns immediately; check /stats for updated counts after ~30–60s.
    KEV + EPSS complete in seconds; MITRE bundle (~30 MB) takes longer.
    """
    # Run KEV and EPSS synchronously (fast, <5s each) so we can return partial counts
    try:
        kev_result = sync_engine.sync_kev_to_db(db)
    except Exception as exc:
        logger.warning("KEV sync failed: %s", exc)
        kev_result = {"added": 0, "updated": 0, "total": 0}

    try:
        epss_result = sync_engine.sync_epss_for_scan_cves(db)
    except Exception as exc:
        logger.warning("EPSS sync failed: %s", exc)
        epss_result = {"updated": 0}

    # Enrich findings with freshly synced KEV + EPSS data
    try:
        enrich_result = sync_engine.enrich_findings_from_threat_intel(db)
    except Exception as exc:
        logger.warning("Finding enrichment failed: %s", exc)
        enrich_result = {"enriched": 0}

    # NVD CVSS backfill — moderate speed (~3 req/s), run in background
    background_tasks.add_task(sync_engine.sync_nvd_scores, db)

    # MITRE is slow (~30 MB download) — run in background
    background_tasks.add_task(sync_engine.sync_mitre_groups_to_db, db)

    # CISA advisories — fast RSS fetch, run in background so main sync stays quick
    advisory_sync_fn = getattr(sync_engine, 'sync_cisa_advisories_to_db', None)
    if advisory_sync_fn:
        background_tasks.add_task(advisory_sync_fn, db)

    # endoflife.date product lifecycles — background
    eol_sync_fn = getattr(sync_engine, 'sync_product_lifecycles', None)
    if eol_sync_fn:
        background_tasks.add_task(eol_sync_fn, db)

    # New intel sources — each gets its own fresh DB session so a stale connection
    # from a previous long-running sync (e.g. SSVC) doesn't block the rest.
    background_tasks.add_task(_run_with_fresh_db, sync_engine.sync_ssvc_decisions_to_db)
    background_tasks.add_task(_run_with_fresh_db, sync_engine.sync_cwe_catalog_to_db)
    background_tasks.add_task(_run_with_fresh_db, sync_engine.sync_metasploit_modules_to_db)
    background_tasks.add_task(_run_with_fresh_db, sync_engine.sync_exploitdb_to_db)
    background_tasks.add_task(_run_with_fresh_db, sync_engine.sync_msrc_patches_to_db)
    # Extended enrichment (runs after the new sources are synced)
    background_tasks.add_task(_run_with_fresh_db, sync_engine.enrich_findings_extended)

    return {
        "status": "ok",
        "kev_added": kev_result.get("added", 0),
        "kev_updated": kev_result.get("updated", 0),
        "kev_total": kev_result.get("total", 0),
        "epss_updated": epss_result.get("updated", 0),
        "findings_enriched": enrich_result.get("enriched", 0),
        "message": (
            f"KEV: +{kev_result.get('added', 0)} new, {kev_result.get('updated', 0)} updated. "
            f"EPSS: {epss_result.get('updated', 0)} refreshed. "
            f"Findings enriched: {enrich_result.get('enriched', 0)}. "
            f"NVD CVSS + MITRE ATT&CK + CISA advisories + endoflife.date + "
            f"SSVC + CWE + ExploitDB + Metasploit + MSRC"
            f": syncing in background."
        ),
    }


# ─────────────────────────────────────────────
# Intel Remediation Campaigns
# ─────────────────────────────────────────────

@router.get("/remediation-campaigns")
def list_remediation_campaigns(db: Session = Depends(get_db)):
    campaigns = db.query(IntelRemediationCampaign).order_by(desc(IntelRemediationCampaign.created_at)).all()
    return [_serialize_remediation_campaign(c) for c in campaigns]


@router.post("/remediation-campaigns")
def create_remediation_campaign(req: CreateRemediationCampaignRequest, db: Session = Depends(get_db)):
    # Run impact search to populate affected assets/findings
    impact = impact_search(
        ImpactSearchRequest(cve_ids=req.cve_ids, ttp_ids=req.ttp_ids),
        db=db,
    )

    campaign = IntelRemediationCampaign(
        name=req.name,
        description=req.description,
        threat_campaign_id=req.threat_campaign_id,
        cve_ids=req.cve_ids,
        ttp_ids=req.ttp_ids,
        status="draft",
        affected_asset_ids=[a["id"] for a in impact["matched_assets"]],
        affected_finding_ids=[f["id"] for f in impact["matched_findings"]],
        affected_asset_count=impact["total_assets"],
        suggested_sigma_rules=[],
        suggested_patches=[],
        priority_score=_compute_campaign_priority(req.cve_ids, db),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    return _serialize_remediation_campaign(campaign)


@router.patch("/remediation-campaigns/{campaign_id}")
def update_remediation_campaign(
    campaign_id: int,
    req: UpdateRemediationCampaignRequest,
    db: Session = Depends(get_db),
):
    campaign = db.query(IntelRemediationCampaign).filter(IntelRemediationCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    if req.name is not None:
        campaign.name = req.name
    if req.description is not None:
        campaign.description = req.description
    if req.status is not None:
        campaign.status = req.status
    if req.affected_asset_ids is not None:
        campaign.affected_asset_ids = req.affected_asset_ids
        campaign.affected_asset_count = len(req.affected_asset_ids)
    if req.affected_finding_ids is not None:
        campaign.affected_finding_ids = req.affected_finding_ids
    campaign.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(campaign)
    return _serialize_remediation_campaign(campaign)


@router.delete("/remediation-campaigns/{campaign_id}")
def delete_remediation_campaign(campaign_id: int, db: Session = Depends(get_db)):
    campaign = db.query(IntelRemediationCampaign).filter(IntelRemediationCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    db.delete(campaign)
    db.commit()
    return {"deleted": True}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _serialize_remediation_campaign(c: IntelRemediationCampaign) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "description": c.description,
        "threat_campaign_id": c.threat_campaign_id,
        "cve_ids": c.cve_ids or [],
        "ttp_ids": c.ttp_ids or [],
        "status": c.status,
        "affected_asset_count": c.affected_asset_count or 0,
        "affected_asset_ids": c.affected_asset_ids or [],
        "affected_finding_ids": c.affected_finding_ids or [],
        "suggested_sigma_rules": c.suggested_sigma_rules or [],
        "suggested_patches": c.suggested_patches or [],
        "priority_score": c.priority_score,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _compute_campaign_priority(cve_ids: list, db: Session) -> float:
    """
    Priority score based on:
    - KEV presence (+ 4.0 max)
    - Max EPSS * 3.0
    - Max CVSS / 10 * 3.0
    Capped at 10.0
    """
    if not cve_ids:
        return 0.0
    records = db.query(ThreatCVE).filter(ThreatCVE.cve_id.in_(cve_ids)).all()
    if not records:
        return 0.0

    has_kev = any(r.in_kev for r in records)
    max_epss = max((r.epss_score or 0.0) for r in records)
    max_cvss = max((r.cvss3_score or 0.0) for r in records)

    score = (4.0 if has_kev else 0.0) + (max_epss * 3.0) + (max_cvss / 10.0 * 3.0)
    return min(round(score, 2), 10.0)


# ─────────────────────────────────────────────
# Product Lifecycle (endoflife.date)
# ─────────────────────────────────────────────

@router.get("/products")
def list_products(
    search: Optional[str] = None,
    is_eol: Optional[bool] = None,
    in_scan: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    """List products with their lifecycle data, grouped by product slug."""
    from models.models import AggregatedSolution

    q = db.query(ProductLifecycle)
    if search:
        q = q.filter(or_(
            ProductLifecycle.product_name.ilike(f"%{search}%"),
            ProductLifecycle.slug.ilike(f"%{search}%"),
        ))

    # Get all scan component slugs for in_scan marking/filtering
    scan_slugs = set()
    components = [r[0] for r in db.query(AggregatedSolution.affected_component).distinct().all() if r[0]]
    for comp in components:
        slug = sync_engine._resolve_slug(comp)
        if slug:
            scan_slugs.add(slug)

    rows = q.order_by(ProductLifecycle.slug, desc(ProductLifecycle.is_eol), ProductLifecycle.cycle).all()

    # Group by slug
    products = {}
    for r in rows:
        if r.slug not in products:
            products[r.slug] = {
                "slug": r.slug,
                "product_name": r.product_name,
                "in_scan": r.slug in scan_slugs,
                "cycles": [],
            }
        products[r.slug]["cycles"].append({
            "cycle": r.cycle,
            "latest_version": r.latest_version,
            "release_date": r.release_date,
            "eol": r.eol,
            "is_eol": r.is_eol,
            "lts": r.lts,
            "support_end": r.support_end,
            "latest_release_date": r.latest_release_date,
            "link": r.link,
        })

    result = list(products.values())

    # Apply filters that work on grouped data
    if is_eol is not None:
        if is_eol:
            result = [p for p in result if any(c["is_eol"] for c in p["cycles"])]
        else:
            result = [p for p in result if any(not c["is_eol"] for c in p["cycles"])]
    if in_scan is True:
        result = [p for p in result if p["in_scan"]]
    elif in_scan is False:
        result = [p for p in result if not p["in_scan"]]

    return result


@router.get("/products/{slug}")
def get_product(slug: str, db: Session = Depends(get_db)):
    """Get all lifecycle cycles for a specific product."""
    rows = (
        db.query(ProductLifecycle)
        .filter(ProductLifecycle.slug == slug)
        .order_by(ProductLifecycle.cycle)
        .all()
    )
    if not rows:
        raise HTTPException(404, f"Product '{slug}' not found")
    return {
        "slug": slug,
        "product_name": rows[0].product_name,
        "cycles": [
            {
                "cycle": r.cycle,
                "latest_version": r.latest_version,
                "release_date": r.release_date,
                "eol": r.eol,
                "is_eol": r.is_eol,
                "lts": r.lts,
                "support_end": r.support_end,
                "latest_release_date": r.latest_release_date,
                "link": r.link,
            }
            for r in rows
        ],
    }


# ─────────────────────────────────────────────
# CWE Weakness Catalog
# ─────────────────────────────────────────────

@router.get("/cwes")
def get_cwes(
    search: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List CWE entries with optional search and category filtering."""
    q = db.query(CWEEntry)
    if search:
        q = q.filter(
            or_(
                CWEEntry.cwe_id.ilike(f"%{search}%"),
                CWEEntry.name.ilike(f"%{search}%"),
            )
        )
    if category:
        q = q.filter(CWEEntry.category == category)

    total = q.count()
    records = q.order_by(CWEEntry.cwe_id).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "cwe_id": r.cwe_id,
                "name": r.name,
                "description": (r.description or "")[:300],
                "weakness_type": r.weakness_type,
                "category": r.category,
                "parent_cwe_ids": r.parent_cwe_ids or [],
                "mitigations_count": len(r.mitigations or []),
                "url": r.url,
            }
            for r in records
        ],
    }


@router.get("/cwes/{cwe_id}")
def get_cwe_detail(cwe_id: str, db: Session = Depends(get_db)):
    """Detailed CWE entry with mitigations, consequences, and detection methods."""
    record = db.query(CWEEntry).filter(CWEEntry.cwe_id == cwe_id.upper()).first()
    if not record:
        raise HTTPException(404, f"CWE {cwe_id} not found")

    # Count CVEs in our intel that reference this CWE
    cve_count = 0
    for (cwe_ids,) in db.query(ThreatCVE.cwe_ids).filter(ThreatCVE.cwe_ids.isnot(None)).all():
        if cwe_ids and cwe_id.upper() in cwe_ids:
            cve_count += 1

    return {
        "cwe_id": record.cwe_id,
        "name": record.name,
        "description": record.description or "",
        "extended_description": record.extended_description or "",
        "weakness_type": record.weakness_type,
        "status": record.status,
        "category": record.category,
        "parent_cwe_ids": record.parent_cwe_ids or [],
        "child_cwe_ids": record.child_cwe_ids or [],
        "related_attack_patterns": record.related_attack_patterns or [],
        "applicable_platforms": record.applicable_platforms or [],
        "common_consequences": record.common_consequences or [],
        "detection_methods": record.detection_methods or [],
        "mitigations": record.mitigations or [],
        "owasp_top_ten": record.owasp_top_ten or [],
        "url": record.url,
        "cve_count": cve_count,
    }


# ─────────────────────────────────────────────
# Exploit References (ExploitDB, Metasploit, Nuclei)
# ─────────────────────────────────────────────

@router.get("/exploits")
def get_exploits(
    cve_id: Optional[str] = None,
    source: Optional[str] = Query(None, regex="^(exploitdb|metasploit|nuclei)$"),
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List public exploit references."""
    q = db.query(ExploitReference)
    if cve_id:
        q = q.filter(ExploitReference.cve_id == cve_id.upper())
    if source:
        q = q.filter(ExploitReference.source == source)
    if search:
        q = q.filter(
            or_(
                ExploitReference.cve_id.ilike(f"%{search}%"),
                ExploitReference.title.ilike(f"%{search}%"),
            )
        )

    total = q.count()
    records = q.order_by(desc(ExploitReference.created_at)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": r.id,
                "cve_id": r.cve_id,
                "source": r.source,
                "source_id": r.source_id,
                "title": r.title or "",
                "url": r.url,
                "exploit_type": r.exploit_type,
                "platform": r.platform,
                "verified": r.verified,
                "maturity": r.maturity,
                "published_date": r.published_date,
            }
            for r in records
        ],
    }


@router.get("/exploits/summary")
def get_exploit_summary(db: Session = Depends(get_db)):
    """Summary counts of public exploits by source and maturity."""
    by_source = (
        db.query(ExploitReference.source, func.count(ExploitReference.id))
        .group_by(ExploitReference.source)
        .all()
    )
    by_maturity = (
        db.query(ExploitReference.maturity, func.count(ExploitReference.id))
        .group_by(ExploitReference.maturity)
        .all()
    )
    total_cves = db.query(func.count(func.distinct(ExploitReference.cve_id))).scalar() or 0

    return {
        "total_exploits": sum(c for _, c in by_source),
        "total_cves_with_exploits": total_cves,
        "by_source": {s: c for s, c in by_source},
        "by_maturity": {m or "unknown": c for m, c in by_maturity},
    }


# ─────────────────────────────────────────────
# SSVC Decisions
# ─────────────────────────────────────────────

@router.get("/ssvc")
def get_ssvc_decisions(
    decision: Optional[str] = Query(None, regex="^(Track|Track\\*|Attend|Act)$"),
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List CISA SSVC vulnerability categorization decisions."""
    q = db.query(SSVCDecision)
    if decision:
        q = q.filter(SSVCDecision.decision == decision)
    if search:
        q = q.filter(SSVCDecision.cve_id.ilike(f"%{search}%"))

    total = q.count()

    # Sort by severity of decision: Act > Attend > Track* > Track
    records = q.order_by(
        desc(
            case(
                (SSVCDecision.decision == "Act", 4),
                (SSVCDecision.decision == "Attend", 3),
                (SSVCDecision.decision == "Track*", 2),
                else_=1,
            )
        )
    ).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "cve_id": r.cve_id,
                "decision": r.decision,
                "exploitation": r.exploitation,
                "automatable": r.automatable,
                "technical_impact": r.technical_impact,
                "provider": r.provider,
                "timestamp": r.timestamp,
            }
            for r in records
        ],
    }


@router.get("/ssvc/summary")
def get_ssvc_summary(db: Session = Depends(get_db)):
    """SSVC decision distribution."""
    by_decision = (
        db.query(SSVCDecision.decision, func.count(SSVCDecision.id))
        .group_by(SSVCDecision.decision)
        .all()
    )
    return {
        "total": sum(c for _, c in by_decision),
        "by_decision": {d: c for d, c in by_decision},
    }


# ─────────────────────────────────────────────
# MSRC Patches
# ─────────────────────────────────────────────

@router.get("/msrc-patches")
def get_msrc_patches(
    cve_id: Optional[str] = None,
    kb_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List MSRC Patch Tuesday entries."""
    q = db.query(MSRCPatch)
    if cve_id:
        q = q.filter(MSRCPatch.cve_id == cve_id.upper())
    if kb_id:
        q = q.filter(MSRCPatch.kb_id.ilike(f"%{kb_id}%"))
    if search:
        q = q.filter(
            or_(
                MSRCPatch.cve_id.ilike(f"%{search}%"),
                MSRCPatch.kb_id.ilike(f"%{search}%"),
                MSRCPatch.product_name.ilike(f"%{search}%"),
            )
        )

    total = q.count()
    records = q.order_by(desc(MSRCPatch.release_date)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": r.id,
                "cve_id": r.cve_id,
                "kb_id": r.kb_id,
                "product_name": r.product_name,
                "article_url": r.article_url,
                "severity": r.severity,
                "impact": r.impact,
                "supercedence": r.supercedence,
                "restart_required": r.restart_required,
                "release_date": r.release_date,
            }
            for r in records
        ],
    }


# ─────────────────────────────────────────────
# Individual source sync triggers
# ─────────────────────────────────────────────

@router.post("/sync-exploits")
def sync_exploits(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Sync ExploitDB + Metasploit module data."""
    background_tasks.add_task(sync_engine.sync_metasploit_modules_to_db, db)
    background_tasks.add_task(sync_engine.sync_exploitdb_to_db, db)
    return {"status": "ok", "message": "ExploitDB + Metasploit sync started in background"}


@router.post("/sync-ssvc")
def sync_ssvc(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Sync CISA SSVC vulnrichment decisions."""
    background_tasks.add_task(sync_engine.sync_ssvc_decisions_to_db, db)
    return {"status": "ok", "message": "SSVC sync started in background"}


@router.post("/sync-cwe")
def sync_cwe(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Sync CWE full catalog from MITRE."""
    background_tasks.add_task(sync_engine.sync_cwe_catalog_to_db, db)
    return {"status": "ok", "message": "CWE catalog sync started in background"}


@router.post("/sync-msrc")
def sync_msrc(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Sync MSRC Patch Tuesday data."""
    background_tasks.add_task(sync_engine.sync_msrc_patches_to_db, db)
    return {"status": "ok", "message": "MSRC Patch Tuesday sync started in background"}
