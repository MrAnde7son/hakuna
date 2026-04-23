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
from core.time_utils import iso_utc
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
    # Order by most recent activity: last_run_at if present, else created_at
    scans = q.order_by(desc(func.coalesce(Scan.last_run_at, Scan.created_at))).all()

    scan_ids = [s.id for s in scans]
    if not scan_ids:
        return []

    # Map scan_id → current run_id so we can filter rows of active VM rescans
    # (old-run rows coexist with new-run rows until finalize). Non-VM scans
    # and scans without a run_id show up with run_id=None and match all rows.
    current_run_by_scan = {
        s.id: (s.raw_metadata or {}).get("current_run_id") for s in scans
    }
    current_run_ids = [rid for rid in current_run_by_scan.values() if rid]

    # Batch finding counts in one query
    finding_counts = dict(
        db.query(Finding.scan_id, func.count(Finding.id))
        .filter(Finding.scan_id.in_(scan_ids))
        .filter(or_(
            Finding.scan_run_id.is_(None),
            Finding.scan_run_id.in_(current_run_ids),
        ))
        .group_by(Finding.scan_id)
        .all()
    )

    # Batch asset counts: direct scan_id linkage
    direct_asset_counts = dict(
        db.query(Asset.scan_id, func.count(Asset.id))
        .filter(Asset.scan_id.in_(scan_ids))
        .filter(or_(
            Asset.scan_run_id.is_(None),
            Asset.scan_run_id.in_(current_run_ids),
        ))
        .group_by(Asset.scan_id)
        .all()
    )

    # VM scans may link findings to assets from other scans — get those extra asset IDs
    vm_scan_ids = [s.id for s in scans if s.source_type == "vm_scanner"]
    vm_extra_asset_counts = {}
    if vm_scan_ids:
        # Count distinct assets linked via findings (including cross-scan assets)
        vm_asset_counts = dict(
            db.query(Finding.scan_id, func.count(distinct(Finding.asset_id)))
            .filter(Finding.scan_id.in_(vm_scan_ids), Finding.asset_id.isnot(None))
            .filter(or_(
                Finding.scan_run_id.is_(None),
                Finding.scan_run_id.in_(current_run_ids),
            ))
            .group_by(Finding.scan_id)
            .all()
        )
        # For VM scans, use the larger of direct assets or finding-linked assets
        for sid in vm_scan_ids:
            direct = direct_asset_counts.get(sid, 0)
            via_findings = vm_asset_counts.get(sid, 0)
            vm_extra_asset_counts[sid] = max(direct, via_findings)

    result = []
    for s in scans:
        if s.source_type == "vm_scanner":
            asset_count = vm_extra_asset_counts.get(s.id, 0)
        else:
            asset_count = direct_asset_counts.get(s.id, 0)
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
            "created_at": iso_utc(s.created_at),
            "asset_count": asset_count,
            "finding_count": finding_counts.get(s.id, 0),
            "schedule": s.schedule,
            "status": s.status or "completed",
            "last_run_at": iso_utc(s.last_run_at),
            "next_run_at": iso_utc(s.next_run_at),
            "run_count": s.run_count or 0,
        })
    return result


@router.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = apply_org_filter(db.query(Scan), Scan, org_ids)
    scan = q.filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    current_run_id = (scan.raw_metadata or {}).get("current_run_id")
    run_scope_f = or_(Finding.scan_run_id.is_(None), Finding.scan_run_id == current_run_id) if current_run_id else True
    run_scope_a = or_(Asset.scan_run_id.is_(None), Asset.scan_run_id == current_run_id) if current_run_id else True
    finding_count = db.query(func.count(Finding.id)).filter(Finding.scan_id == scan_id).filter(run_scope_f).scalar()
    asset_count = db.query(func.count(Asset.id)).filter(Asset.scan_id == scan_id).filter(run_scope_a).scalar()

    # Surface streaming-progress state so the UI can render per-target / per-stage
    # detail while the scan is still running, instead of just a spinner on the
    # aggregate count. Shape varies by source_type:
    #   vm_scanner: job_statuses keyed by job_id → {target, status, findings_count, ...}
    #   easm: current_stage / stage_index / total_stages / stage_log from the scanner
    # Everything lives in raw_metadata already; we just project a stable envelope.
    meta = scan.raw_metadata or {}
    progress: dict = {}
    if scan.source_type == "vm_scanner":
        job_statuses = meta.get("job_statuses") or {}
        # List form is friendlier to render, and the scanner doesn't rely on
        # job_id as a stable key beyond the raw_metadata bookkeeping.
        targets = [
            {
                "job_id": job_id,
                "target": (info or {}).get("target"),
                "status": (info or {}).get("status"),
                "findings_count": (info or {}).get("findings_count"),
                "duration_seconds": (info or {}).get("duration_seconds"),
                "error": (info or {}).get("error"),
            }
            for job_id, info in job_statuses.items()
        ]
        progress = {
            "completed_jobs": meta.get("completed_jobs", 0),
            "total_jobs": meta.get("total_jobs", 0),
            "completed_targets": meta.get("completed_targets", 0),
            "total_targets": meta.get("total_targets", len(meta.get("targets") or [])),
            "targets": targets,
        }
    elif scan.source_type == "easm":
        progress = {
            "current_stage": meta.get("current_stage"),
            "stage_index": meta.get("stage_index", 0),
            "total_stages": meta.get("total_stages", 0),
            "stage_started_at": meta.get("stage_started_at"),
            "stage_log": meta.get("stage_log") or [],
            "incremental_asset_count": meta.get("incremental_asset_count", 0),
            "incremental_finding_count": meta.get("incremental_finding_count", 0),
        }

    # Prefer the scanner-owned status (raw_metadata.status) when present — it
    # tracks the live streaming lifecycle ("running"/"completed_with_errors"/…)
    # more granularly than the terminal Scan.status column.
    status = meta.get("status") or scan.status or "completed"

    return {
        "id": scan.id,
        "status": status,
        "scan_name": scan.scan_name,
        "filename": scan.filename,
        "scan_date": scan.scan_date,
        "source_type": scan.source_type or "nessus",
        "asset_count": asset_count,
        "finding_count": finding_count,
        "progress": progress,
        "error": meta.get("error"),
    }


@router.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Stop an in-flight VM or EASM scan.

    - VM: revokes Celery task ids on the VM scanner (best-effort) and flips
      ``raw_metadata.status`` to ``"cancelled"`` so the UI and reaper stop
      tracking it.
    - EASM: asks hakuna-scanner to mark the ScanRun cancelled. Celery chain
      keeps draining to completion on the scanner side (the per-stage DB
      writes don't hold a cancellation check), but the UI stops polling and
      the local Scan row reflects the cancelled state.
    - Uploaded scans (nessus, qualys, …) are ingest-only — returns 400.
    """
    q = apply_org_filter(db.query(Scan), Scan, org_ids)
    scan = q.filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    meta = scan.raw_metadata or {}
    # Audit scans mirror status to both scan.status and raw_metadata.status
    # (audit_worker._finalize_scan_if_complete writes both). VM + EASM live
    # on raw_metadata only. Fall back to the column so audits still read
    # during the window between insert and first worker commit.
    status = meta.get("status") or scan.status
    if status not in ("running", "queued"):
        raise HTTPException(409, f"Scan is not running (status={status or 'completed'})")

    from core.audit import log_audit
    scan_name = scan.scan_name or scan.filename

    if (scan.scan_type or "").endswith("_audit"):
        from services.audit_runner import revoke_audit_tasks
        from models.models import AgentRun
        task_ids_by_agent = meta.get("task_ids") or {}
        task_ids = list(task_ids_by_agent.values()) if isinstance(task_ids_by_agent, dict) else []
        revoke_result = revoke_audit_tasks(task_ids)
        # Mark any still-running/pending AgentRuns as cancelled so the scan UI
        # reflects the real state. Don't touch already-terminal rows — SIGTERM
        # on a worker may arrive after the run has already committed `done`.
        scratch_agent_ids = meta.get("scratch_agent_ids") or []
        if scratch_agent_ids:
            from datetime import datetime as _dt
            now = _dt.utcnow()
            affected = (
                db.query(AgentRun)
                .filter(
                    AgentRun.agent_id.in_(scratch_agent_ids),
                    AgentRun.status.in_(("pending", "running")),
                )
                .all()
            )
            for r in affected:
                r.status = "cancelled"
                r.error = "Cancelled by user"
                r.finished_at = now
        scan.status = "cancelled"
        scan.raw_metadata = {
            **meta,
            "status": "cancelled",
            "error": "Cancelled by user",
        }
        log_audit(db, "cancel", "scan", scan_id, entity_name=scan_name, org_id=scan.org_id)
        db.commit()
        return {
            "message": "Audit cancelled",
            "revoked_tasks": revoke_result.get("revoked", []),
            "revoke_errors": revoke_result.get("errors", {}),
            "total_tasks": len(task_ids),
        }

    if scan.source_type == "vm_scanner":
        from services.vm_scanner import _revoke_vm_jobs_sync, _rollback_failed_run
        job_ids = meta.get("job_ids") or []
        revoked = _revoke_vm_jobs_sync(job_ids)
        _rollback_failed_run(db, scan)
        rolled = dict(scan.raw_metadata or {})
        scan.raw_metadata = {
            **rolled,
            "status": "cancelled",
            "error": "Cancelled by user",
        }
        log_audit(db, "cancel", "scan", scan_id, entity_name=scan_name, org_id=scan.org_id)
        db.commit()
        return {"message": "Scan cancelled", "revoked_jobs": revoked, "total_jobs": len(job_ids)}

    if scan.source_type == "easm":
        from services.easm import cancel_easm_scan
        hakuna_org_id = meta.get("hakuna_org_id")
        run_id = meta.get("run_id")
        remote_ok, remote_err = (False, None)
        if hakuna_org_id and run_id:
            remote_ok, remote_err = await cancel_easm_scan(hakuna_org_id, run_id)
        scan.raw_metadata = {
            **meta,
            "status": "cancelled",
            "error": "Cancelled by user" + (f" (scanner: {remote_err})" if remote_err and not remote_ok else ""),
        }
        log_audit(db, "cancel", "scan", scan_id, entity_name=scan_name, org_id=scan.org_id)
        db.commit()
        return {"message": "Scan cancelled", "scanner_cancelled": remote_ok}

    raise HTTPException(400, f"Scans of type '{scan.source_type}' cannot be cancelled")


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

    # Same hook for Protocol Audit scans (snmp_audit, ldap_audit, ssh_audit, ...).
    # Without this the UI saves the cron string but nothing ever fires.
    if (scan.scan_type or "").endswith("_audit"):
        from services.audit_scheduler import (
            register_scan as register_audit_scan,
            deregister_scan as deregister_audit_scan,
        )
        if schedule:
            register_audit_scan(scan.id, schedule)
        else:
            deregister_audit_scan(scan.id)

    return {
        "id": scan.id,
        "schedule": scan.schedule,
        "next_run_at": iso_utc(scan.next_run_at),
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
