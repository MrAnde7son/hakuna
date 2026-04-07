"""
Scan management, NLP search, Data Sources, Remediation Queue, Automate Click tracking,
Health checks, and Background job status endpoints.
Extracted from app.py.
"""
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, distinct, or_

from core.database import get_db
from core.auth import (
    get_current_user, get_accessible_org_ids,
    apply_org_filter, apply_scan_org_filter,
)
from models.models import (
    Scan, Asset, Finding, AutomateClick,
)
from parsers.registry import list_parsers
from services.nlp_search import parse_nlp_query
from services.nlp_filters import apply_asset_nlp_filters, apply_finding_nlp_filters
from routes.finding_routes import _finding_to_dict

router = APIRouter()


# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────

@router.get("/api/health")
def health_check():
    return {"status": "ok"}


@router.get("/api/health/db")
def health_db():
    """DB connectivity check with connection pool metrics."""
    from core.database import check_db_health
    result = check_db_health()
    status_code = 200 if result["status"] == "ok" else 503
    return JSONResponse(content=result, status_code=status_code)


# ─────────────────────────────────────────────
# Background job status tracking
# ─────────────────────────────────────────────

@router.get("/api/jobs/{job_id}/status")
def get_job_status(job_id: str):
    """Return status of a background job."""
    from services.job_manager import get_job
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job.to_dict()


@router.get("/api/jobs")
def list_jobs(limit: int = 50):
    """List recent background jobs."""
    from services.job_manager import list_jobs as _list_jobs
    return _list_jobs(limit=limit)


# ─────────────────────────────────────────────
# Sources (parser registry)
# ─────────────────────────────────────────────

@router.get("/api/sources")
def get_sources():
    """Return all registered scanner source types and their supported file extensions."""
    return list_parsers()


# ─────────────────────────────────────────────
# Scans
# ─────────────────────────────────────────────

@router.get("/api/scans")
def list_scans(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = apply_org_filter(db.query(Scan), Scan, org_ids)
    scans = q.order_by(desc(Scan.created_at)).all()
    result = []
    for s in scans:
        finding_count = db.query(func.count(Finding.id)).filter(Finding.scan_id == s.id).scalar()
        # VM scans may link findings to existing assets (different scan_id), so union both
        if s.source_type == "vm_scanner":
            asset_count = db.query(func.count(distinct(Asset.id))).filter(
                or_(Asset.scan_id == s.id,
                    Asset.id.in_(db.query(Finding.asset_id).filter(Finding.scan_id == s.id)))
            ).scalar()
        else:
            asset_count = db.query(func.count(Asset.id)).filter(Asset.scan_id == s.id).scalar()
        result.append({
            "id": s.id,
            "filename": s.filename,
            "scan_name": s.scan_name,
            "scan_date": s.scan_date,
            "scan_type": s.scan_type,
            "nessus_version": s.nessus_version,
            "source_type": s.source_type or "nessus",
            "source_version": s.source_version,
            "raw_metadata": s.raw_metadata,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "asset_count": asset_count,
            "finding_count": finding_count,
            "schedule": s.schedule,
            "status": s.status or "completed",
            "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
            "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
            "run_count": s.run_count or 0,
        })
    return result


@router.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = apply_org_filter(db.query(Scan), Scan, org_ids)
    scan = q.filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    finding_count = db.query(func.count(Finding.id)).filter(Finding.scan_id == scan_id).scalar()
    asset_count = db.query(func.count(Asset.id)).filter(Asset.scan_id == scan_id).scalar()
    return {
        "id": scan.id,
        "status": scan.status or "completed",
        "scan_name": scan.scan_name,
        "filename": scan.filename,
        "scan_date": scan.scan_date,
        "source_type": scan.source_type or "nessus",
        "asset_count": asset_count,
        "finding_count": finding_count,
    }


@router.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    # Import these from app to avoid duplicating cascade logic
    import app as _app
    q = apply_org_filter(db.query(Scan), Scan, org_ids)
    scan = q.filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    _scan_name = scan.scan_name or scan.filename
    _scan_org = scan.org_id
    from core.audit import log_audit
    _app._delete_scan_cascade(db, scan)
    log_audit(db, "delete", "scan", scan_id, entity_name=_scan_name, org_id=_scan_org)
    db.commit()
    _app._endpoint_cache.clear()
    return {"message": "Scan deleted"}


@router.patch("/api/scans/{scan_id}/schedule")
def update_scan_schedule(
    scan_id: int,
    body: dict,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Update the schedule (cron expression) for a scan."""
    q = apply_org_filter(db.query(Scan), Scan, org_ids)
    scan = q.filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    schedule = body.get("schedule")  # None or "" to remove, cron string to set

    # Validate cron expression if provided
    if schedule:
        try:
            from apscheduler.triggers.cron import CronTrigger
            trigger = CronTrigger.from_crontab(schedule)
            scan.schedule = schedule
            scan.next_run_at = trigger.get_next_fire_time(None, __import__("datetime").datetime.utcnow())
        except Exception:
            raise HTTPException(400, f"Invalid cron expression: {schedule}")
    else:
        scan.schedule = None
        scan.next_run_at = None

    db.commit()

    # Update the EASM scheduler
    if scan.source_type == "easm":
        from services.easm_scheduler import register_scan, deregister_scan
        if schedule:
            register_scan(scan.id, schedule)
        else:
            deregister_scan(scan.id)

    return {
        "id": scan.id,
        "schedule": scan.schedule,
        "next_run_at": scan.next_run_at.isoformat() if scan.next_run_at else None,
    }


# ─────────────────────────────────────────────
# NLP Search
# ─────────────────────────────────────────────

@router.get("/api/search/nlp")
def nlp_search(
    q: str,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Parse a natural language query and return matching asset/finding counts + filter params."""
    parsed = parse_nlp_query(q)

    af = dict(parsed["asset_filters"])
    ff = dict(parsed["finding_filters"])

    # ── Count matching assets ──────────────────────────────────────────────────
    aq = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    aq = apply_scan_org_filter(aq, org_ids)
    if scan_id:
        target_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if target_scan and target_scan.source_type == "vm_scanner":
            _vm_asset_ids = [
                r[0] for r in db.query(Finding.asset_id)
                .filter(Finding.scan_id == scan_id).distinct().all()
            ]
            aq = aq.filter(or_(Asset.scan_id == scan_id, Asset.id.in_(_vm_asset_ids)))
        else:
            aq = aq.filter(Asset.scan_id == scan_id)
    aq = apply_asset_nlp_filters(aq, af, db)
    asset_count = aq.count()

    # ── Count matching findings ────────────────────────────────────────────────
    fq = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    fq = apply_scan_org_filter(fq, org_ids)
    if scan_id:
        fq = fq.filter(Finding.scan_id == scan_id)
    fq = apply_finding_nlp_filters(fq, ff, db)
    finding_count = fq.count()

    return {
        **parsed,
        "asset_count": asset_count,
        "finding_count": finding_count,
    }


# ─────────────────────────────────────────────
# Data Sources
# ─────────────────────────────────────────────

@router.get("/api/sources", include_in_schema=False)
def list_sources(
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return distinct source types present in the current org's scans."""
    q = db.query(Scan.source_type).distinct()
    q = apply_scan_org_filter(q, org_ids)
    rows = q.all()
    sources = sorted(set(r[0] for r in rows if r[0]))
    return {"sources": sources}


# ─────────────────────────────────────────────
# Remediation Queue
# ─────────────────────────────────────────────

@router.get("/api/remediation-queue")
def get_remediation_queue(
    scan_id: Optional[int] = None,
    effort: Optional[str] = None,
    owner: Optional[str] = None,
    min_severity: int = 2,
    limit: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return prioritized remediation queue (non-info findings, sorted by priority)."""
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Finding.severity >= min_severity)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if effort:
        q = q.filter(Finding.effort_level == effort)
    if owner:
        q = q.filter(Finding.owner_suggestion == owner)
    q = q.order_by(desc(Finding.priority_score))

    findings = q.limit(limit).all()
    return [_finding_to_dict(f, db) for f in findings]


# ─────────────────────────────────────────────
# Automate Click Tracking
# ─────────────────────────────────────────────

@router.post("/api/automate-click")
def log_automate_click(
    finding_id: int,
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()

    click = AutomateClick(
        finding_id=finding_id,
        plugin_id=finding.plugin_id,
        plugin_name=finding.plugin_name,
        asset_ip=asset.ip if asset else None,
    )
    db.add(click)
    db.commit()
    return {"message": "Click logged", "finding_id": finding_id}


@router.get("/api/automate-clicks")
def get_automate_clicks(db: Session = Depends(get_db)):
    """Return top requested automations."""
    results = (
        db.query(
            AutomateClick.plugin_id,
            AutomateClick.plugin_name,
            func.count(AutomateClick.id).label("click_count"),
        )
        .group_by(AutomateClick.plugin_id, AutomateClick.plugin_name)
        .order_by(desc("click_count"))
        .limit(20)
        .all()
    )
    return [
        {"plugin_id": r[0], "plugin_name": r[1], "click_count": r[2]}
        for r in results
    ]
