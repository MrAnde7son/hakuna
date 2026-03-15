"""Celery Beat schedule: daily discovery + enrichment for all active orgs."""

import asyncio
import logging

from sqlalchemy import text

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session
from app.tasks.discovery import run_discovery_chain
from app.tasks.enrichment import run_enrichment_chain

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _get_active_org_ids() -> list[str]:
    sf = get_task_session()
    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT DISTINCT o.id::text FROM orgs o
                JOIN target_domains td ON td.org_id = o.id
                WHERE td.active = true
            """)
        )
        return [row[0] for row in result.fetchall()]


@celery.task(name="scheduler.trigger_all_discovery")
def trigger_all_discovery():
    """Trigger discovery chains for all active orgs with staggering."""
    org_ids = _run_async(_get_active_org_ids())
    stagger = settings.org_scan_stagger_seconds

    for i, org_id in enumerate(org_ids):
        run_discovery_chain.apply_async(
            args=[org_id],
            countdown=i * stagger,
        )
        logger.info("Scheduled discovery for org %s with %ds delay", org_id, i * stagger)

    return {"orgs_scheduled": len(org_ids)}


@celery.task(name="scheduler.trigger_all_enrichment")
def trigger_all_enrichment():
    """Trigger enrichment chains for all active orgs with staggering."""
    org_ids = _run_async(_get_active_org_ids())
    stagger = settings.org_scan_stagger_seconds

    for i, org_id in enumerate(org_ids):
        run_enrichment_chain.apply_async(
            args=[org_id],
            countdown=i * stagger,
        )
        logger.info("Scheduled enrichment for org %s with %ds delay", org_id, i * stagger)

    return {"orgs_scheduled": len(org_ids)}


from celery.schedules import crontab

celery.conf.beat_schedule = {
    "daily-discovery-2am": {
        "task": "scheduler.trigger_all_discovery",
        "schedule": crontab(hour=2, minute=0),
    },
    "daily-enrichment-4am": {
        "task": "scheduler.trigger_all_enrichment",
        "schedule": crontab(hour=4, minute=0),
    },
}
