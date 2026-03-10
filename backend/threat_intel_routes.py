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
from sqlalchemy import func, desc, asc, or_, text

from database import get_db
from models import Finding, Asset, Scan
from threat_intel_models import (
    ThreatGroup, TTP, ThreatGroupTTP,
    ThreatCVE, ThreatCampaign, IntelRemediationCampaign,
)
import threat_intel_sync as sync_engine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


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
    active_campaigns = db.query(func.count(ThreatCampaign.id)).filter(ThreatCampaign.is_active == True).scalar() or 0
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

    return {
        "total_cves": total_cves,
        "kev_count": kev_count,
        "high_epss_count": high_epss_count,
        "active_campaigns": active_campaigns,
        "remediation_campaigns": remediation_campaigns,
        "affected_assets": affected_assets,
        "avg_epss": avg_epss,
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
    sort_by: Optional[str] = Query(None, regex="^(cve_id|cvss3_score|epss_score|in_kev|published_date|kev_date_added)$"),
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

    # Sorting
    SORT_COLS = {
        'cve_id': ThreatCVE.cve_id,
        'cvss3_score': ThreatCVE.cvss3_score,
        'epss_score': ThreatCVE.epss_score,
        'in_kev': ThreatCVE.in_kev,
        'published_date': ThreatCVE.published_date,
        'kev_date_added': ThreatCVE.kev_date_added,
    }
    if sort_by and sort_by in SORT_COLS:
        col = SORT_COLS[sort_by]
        order = asc(col) if sort_dir == 'asc' else desc(col)
        records = q.order_by(order).offset(offset).limit(limit).all()
    else:
        records = q.order_by(desc(ThreatCVE.kev_date_added), desc(ThreatCVE.epss_score), desc(ThreatCVE.cvss3_score)).offset(offset).limit(limit).all()

    # Build a lookup: how many findings across all scans reference each CVE
    cve_ids_page = [r.cve_id for r in records]
    in_scan_counts: dict = {}
    if cve_ids_page:
        all_findings_with_cves = db.query(Finding.cves).filter(Finding.cves.isnot(None)).all()
        for (cves,) in all_findings_with_cves:
            if not cves:
                continue
            for cve in cves:
                if cve in cve_ids_page:
                    in_scan_counts[cve] = in_scan_counts.get(cve, 0) + 1

    result = []
    for r in records:
        result.append({
            "cve_id": r.cve_id,
            "description": r.description or "",
            "cvss3_score": r.cvss3_score,
            "cvss3_vector": r.cvss3_vector,
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
            "in_scan_count": in_scan_counts.get(r.cve_id, 0),
        })

    return {"total": total, "offset": offset, "limit": limit, "items": result}


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

    # NVD CVSS backfill — moderate speed (~3 req/s), run in background
    background_tasks.add_task(sync_engine.sync_nvd_scores, db)

    # MITRE is slow (~30 MB download) — run in background
    background_tasks.add_task(sync_engine.sync_mitre_groups_to_db, db)
    return {
        "status": "ok",
        "kev_added": kev_result.get("added", 0),
        "kev_updated": kev_result.get("updated", 0),
        "kev_total": kev_result.get("total", 0),
        "epss_updated": epss_result.get("updated", 0),
        "message": (
            f"KEV: +{kev_result.get('added', 0)} new, {kev_result.get('updated', 0)} updated. "
            f"EPSS: {epss_result.get('updated', 0)} refreshed. "
            f"NVD CVSS + MITRE ATT&CK: syncing in background."
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
