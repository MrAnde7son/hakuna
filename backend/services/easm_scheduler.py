"""EASM scan scheduler — runs scheduled EASM scans based on cron expressions on Scan records."""

import asyncio
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from core.database import SessionLocal
from models.models import Scan, Organization

logger = logging.getLogger(__name__)

_scheduler = None


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
    return _scheduler


def start_scheduler():
    """Load all EASM scans with schedules and register cron jobs."""
    scheduler = get_scheduler()

    db = SessionLocal()
    try:
        scans = db.query(Scan).filter(
            Scan.source_type == "easm",
            Scan.schedule != None,
            Scan.schedule != "",
        ).all()

        for scan in scans:
            _register_job(scheduler, scan.id, scan.schedule)

        logger.info("Registered %d EASM scan schedules", len(scans))
    except Exception as e:
        logger.error("Failed to load EASM scan schedules: %s", e)
    finally:
        db.close()

    if not scheduler.running:
        scheduler.start()
        logger.info("EASM scan scheduler started")


def register_scan(scan_id: int, schedule: str):
    """Register or update a cron job for an EASM scan."""
    scheduler = get_scheduler()
    _deregister_job(scheduler, scan_id)
    if schedule:
        _register_job(scheduler, scan_id, schedule)


def deregister_scan(scan_id: int):
    """Remove a cron job for an EASM scan."""
    scheduler = get_scheduler()
    _deregister_job(scheduler, scan_id)


def _job_id(scan_id: int) -> str:
    return f"easm_scan_{scan_id}"


def _register_job(scheduler: BackgroundScheduler, scan_id: int, schedule: str):
    """Add a cron job to the scheduler."""
    job_id = _job_id(scan_id)
    try:
        trigger = CronTrigger.from_crontab(schedule)
        scheduler.add_job(
            _run_easm_scan_job,
            trigger=trigger,
            id=job_id,
            args=[scan_id],
            replace_existing=True,
            misfire_grace_time=300,
        )
        logger.info("Registered EASM schedule for scan %s: %s", scan_id, schedule)
    except Exception as e:
        logger.error("Failed to register EASM schedule for scan %s: %s", scan_id, e)


def _deregister_job(scheduler: BackgroundScheduler, scan_id: int):
    """Remove a cron job from the scheduler."""
    job_id = _job_id(scan_id)
    try:
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
            logger.info("Deregistered EASM schedule for scan %s", scan_id)
    except Exception:
        pass


_thread_local = __import__("threading").local()


def _get_or_create_loop() -> asyncio.AbstractEventLoop:
    """Return a reusable event loop for this scheduler thread."""
    if not hasattr(_thread_local, "loop") or _thread_local.loop.is_closed():
        _thread_local.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_thread_local.loop)
    return _thread_local.loop


def _run_easm_scan_job(scan_id: int):
    """Execute an EASM scan from a scheduled job.

    Uses short-lived sessions: one to load scan metadata (and release
    the connection), a second for the actual scan execution.
    """
    logger.info("Scheduled EASM scan triggered for scan %s", scan_id)

    # 1. Load metadata with a short-lived session.
    check_db = SessionLocal()
    try:
        scan = check_db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.source_type == "easm",
        ).first()

        if not scan or not scan.schedule:
            logger.warning("Scheduled EASM scan %s not found or unscheduled, skipping", scan_id)
            return

        org = check_db.query(Organization).filter(Organization.id == scan.org_id).first()
        if not org or not org.easm_org_id:
            logger.warning("Org not found or EASM not configured for scan %s", scan_id)
            return

        domain = (scan.raw_metadata or {}).get("domain")
        if not domain:
            logger.warning("No domain in scan %s metadata", scan_id)
            return

        scan_type = (scan.raw_metadata or {}).get("scan_type", "full")
        # Snapshot org fields needed by scan_domain before closing session
        org_id = org.id
        easm_org_id = org.easm_org_id
    except Exception as e:
        logger.exception("Scheduled EASM scan failed loading metadata for scan %s: %s", scan_id, e)
        return
    finally:
        check_db.close()

    # 2. Execute the scan with its own session.
    run_db = SessionLocal()
    try:
        from services.easm import scan_domain
        # Re-load org inside the new session to avoid detached instance
        org = run_db.query(Organization).filter(Organization.id == org_id).first()
        loop = _get_or_create_loop()
        result = loop.run_until_complete(scan_domain(run_db, org, domain, scan_type))
        logger.info("Scheduled EASM scan completed: scan=%s result=%s", scan_id, result)
    except Exception as e:
        logger.exception("Scheduled EASM scan failed for scan %s: %s", scan_id, e)
    finally:
        run_db.close()
