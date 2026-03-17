"""Schedule runner — registers cron jobs for enabled integrations with schedules."""

import asyncio
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from core.database import SessionLocal
from models.models import Integration

logger = logging.getLogger(__name__)

_scheduler = None


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
    return _scheduler


def start_scheduler():
    """Load all enabled integrations with schedules and register cron jobs."""
    scheduler = get_scheduler()

    db = SessionLocal()
    try:
        integrations = db.query(Integration).filter(
            Integration.enabled == True,
            Integration.schedule != None,
            Integration.schedule != "",
        ).all()

        for integration in integrations:
            _register_job(scheduler, integration.id, integration.schedule)

        logger.info("Registered %d integration schedules", len(integrations))
    except Exception as e:
        logger.error("Failed to load integration schedules: %s", e)
    finally:
        db.close()

    if not scheduler.running:
        scheduler.start()
        logger.info("Integration scheduler started")


def register_integration(integration_id: str, schedule: str):
    """Register or update a cron job for an integration."""
    scheduler = get_scheduler()
    _deregister_job(scheduler, integration_id)
    if schedule:
        _register_job(scheduler, integration_id, schedule)


def deregister_integration(integration_id: str):
    """Remove a cron job for an integration."""
    scheduler = get_scheduler()
    _deregister_job(scheduler, integration_id)


def _job_id(integration_id: str) -> str:
    return f"integration_{integration_id}"


def _register_job(scheduler: BackgroundScheduler, integration_id: str, schedule: str):
    """Add a cron job to the scheduler."""
    job_id = _job_id(integration_id)
    try:
        trigger = CronTrigger.from_crontab(schedule)
        scheduler.add_job(
            _run_integration_job,
            trigger=trigger,
            id=job_id,
            args=[integration_id],
            replace_existing=True,
            misfire_grace_time=300,  # 5 minutes grace
        )
        logger.info("Registered schedule for integration %s: %s", integration_id, schedule)
    except Exception as e:
        logger.error("Failed to register schedule for %s: %s", integration_id, e)


def _deregister_job(scheduler: BackgroundScheduler, integration_id: str):
    """Remove a cron job from the scheduler."""
    job_id = _job_id(integration_id)
    try:
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
            logger.info("Deregistered schedule for integration %s", integration_id)
    except Exception:
        pass


def _run_integration_job(integration_id: str):
    """Execute an integration run from a scheduled job."""
    logger.info("Scheduled run triggered for integration %s", integration_id)

    db = SessionLocal()
    try:
        # Verify integration still exists and is enabled
        integration = db.query(Integration).filter(
            Integration.id == integration_id,
            Integration.enabled == True,
        ).first()

        if not integration:
            logger.warning("Scheduled integration %s not found or disabled, skipping", integration_id)
            return

        # Run in event loop
        from services.run_engine import execute
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            run_id = loop.run_until_complete(execute(db, integration_id, triggered_by="schedule"))
            logger.info("Scheduled run completed: integration=%s run=%s", integration_id, run_id)
        finally:
            loop.close()
    except Exception as e:
        logger.exception("Scheduled run failed for integration %s: %s", integration_id, e)
    finally:
        db.close()
