"""Protocol Audit scheduler — fires cron-scheduled audit runs.

Mirror of ``services/easm_scheduler.py`` for ``*_audit`` scans. When the user
sets a cron on an audit scan via ``PATCH /api/scans/{id}/schedule``, the
scan_routes handler calls ``register_scan`` here so the cron actually fires.
At fire time, we read the original scan's ``raw_metadata`` (protocol,
mission, credential, relay, targets/assets) and call ``dispatch_audit_run``.

Kept separate from EASM/VM schedulers so a misbehaving audit job can't
disrupt EASM/VM scheduling and vice versa.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from core.database import SessionLocal
from models.models import Scan, Organization

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
    return _scheduler


def start_scheduler():
    """Load every scheduled audit scan on boot and register cron jobs."""
    scheduler = get_scheduler()
    db = SessionLocal()
    try:
        scans = db.query(Scan).filter(
            Scan.scan_type.like("%_audit"),
            Scan.schedule != None,
            Scan.schedule != "",
        ).all()
        for scan in scans:
            _register_job(scheduler, scan.id, scan.schedule)
        logger.info("Registered %d audit scan schedules", len(scans))
    except Exception as e:
        logger.error("Failed to load audit scan schedules: %s", e)
    finally:
        db.close()

    if not scheduler.running:
        scheduler.start()
        logger.info("Audit scan scheduler started")


def register_scan(scan_id: int, schedule: str):
    """Register or update the cron job for an audit scan."""
    scheduler = get_scheduler()
    _deregister_job(scheduler, scan_id)
    if schedule:
        _register_job(scheduler, scan_id, schedule)


def deregister_scan(scan_id: int):
    scheduler = get_scheduler()
    _deregister_job(scheduler, scan_id)


def _job_id(scan_id: int) -> str:
    return f"audit_scan_{scan_id}"


def _register_job(scheduler: BackgroundScheduler, scan_id: int, schedule: str):
    job_id = _job_id(scan_id)
    try:
        trigger = CronTrigger.from_crontab(schedule)
        scheduler.add_job(
            _run_audit_scan_job,
            trigger=trigger,
            id=job_id,
            args=[scan_id],
            replace_existing=True,
            # Grace time matches EASM — if the scheduler was down for <5min,
            # still fire. Beyond that, assume the miss is intentional.
            misfire_grace_time=300,
        )
        logger.info("Registered audit schedule for scan %s: %s", scan_id, schedule)
    except Exception as e:
        logger.error("Failed to register audit schedule for scan %s: %s", scan_id, e)


def _deregister_job(scheduler: BackgroundScheduler, scan_id: int):
    job_id = _job_id(scan_id)
    try:
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
            logger.info("Deregistered audit schedule for scan %s", scan_id)
    except Exception:
        pass


_thread_local = threading.local()


def _get_or_create_loop() -> asyncio.AbstractEventLoop:
    """Reusable event loop for this scheduler thread.

    ``dispatch_audit_run`` is synchronous, but it calls ``load_credentials``
    down the stack which is async, so keep a loop handy even though we only
    need it for the occasional coroutine.
    """
    if not hasattr(_thread_local, "loop") or _thread_local.loop.is_closed():
        _thread_local.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_thread_local.loop)
    return _thread_local.loop


def _run_audit_scan_job(scan_id: int):
    """Fire one scheduled audit.

    Reads the parent scan's ``raw_metadata`` and calls ``dispatch_audit_run``
    with the same params. Each fire creates a *new* Scan row (matches the
    rescan endpoint) so history is preserved.
    """
    logger.info("Scheduled audit triggered for scan %s", scan_id)

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.scan_type.like("%_audit"),
        ).first()
        if not scan or not scan.schedule:
            logger.warning("Scheduled audit %s not found or unscheduled, skipping", scan_id)
            return

        org = db.query(Organization).filter(Organization.id == scan.org_id).first()
        if not org:
            logger.warning("Org not found for scheduled audit scan %s", scan_id)
            return

        md = scan.raw_metadata or {}
        protocol = md.get("protocol")
        mission = md.get("mission")
        credential_id = md.get("credential_id")
        relay_agent_id = md.get("relay_agent_id")
        if not all([protocol, mission, credential_id, relay_agent_id]):
            logger.warning(
                "Scheduled audit %s missing required metadata (protocol/mission/cred/relay); skipping",
                scan_id,
            )
            return

        # Prefer original targets if the original was ad-hoc; else reuse asset_ids.
        targets = md.get("ad_hoc_targets") or None
        asset_ids = md.get("asset_ids") if not targets else None

        from services.audit_runner import AuditDispatchError, dispatch_audit_run
        try:
            result = dispatch_audit_run(
                db=db, org=org,
                protocol=protocol, mission=mission,
                asset_ids=list(asset_ids) if asset_ids else None,
                targets=list(targets) if targets else None,
                relay_agent_id=relay_agent_id,
                credential_id=credential_id,
                max_steps=md.get("max_steps"),
                wallclock_s=md.get("wallclock_s"),
                model=md.get("model"),
            )
        except AuditDispatchError as e:
            logger.error("Scheduled audit %s dispatch failed: %s", scan_id, e)
            return

        # Link the new scan back to its parent schedule owner.
        new_scan = db.query(Scan).filter(Scan.id == result["scan_id"]).first()
        if new_scan:
            nmd = dict(new_scan.raw_metadata or {})
            nmd["parent_scan_id"] = scan_id
            nmd["scheduled"] = True
            new_scan.raw_metadata = nmd

        # Bump the parent's run counters so the UI can show "3 runs".
        pmd = dict(scan.raw_metadata or {})
        pmd["last_scheduled_run_at"] = datetime.utcnow().isoformat()
        pmd["run_count"] = int(pmd.get("run_count") or 0) + 1
        scan.raw_metadata = pmd
        scan.last_run_at = datetime.utcnow()
        db.commit()

        logger.info(
            "Scheduled audit dispatched: parent_scan=%s new_scan=%s runs=%d",
            scan_id, result["scan_id"], len(result.get("runs") or []),
        )
    except Exception as e:
        logger.exception("Scheduled audit failed for scan %s: %s", scan_id, e)
    finally:
        db.close()
