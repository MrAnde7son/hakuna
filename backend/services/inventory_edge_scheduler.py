"""Periodic rebuild of inventory-derived unified edges.

Phase 2 of the Cross-Scan Chain Coordinator. The post-ingest hook
materializes edges scan-scoped on every upload — fine for the active
scan, but it leaves cross-scan signals stale (a host scanned in scan-A
yesterday now shares a privileged session with a host scanned today in
scan-B; the per-scan pass on B would not see the A-side session).

This scheduler runs the materializer org-wide on an interval so the
unified edge graph stays current without requiring a fresh upload per
org.

Cadence: every 30 minutes. Cheap — the materializer is upsert-only and
caps every signal that could explode.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_scheduler = None


def _rebuild_all_orgs():
    """Run the materializer for every active org. Called by APScheduler."""
    from core.database import SessionLocal
    from models.models import Organization
    from services.inventory_edge_materializer import materialize_inventory_edges

    db = SessionLocal()
    try:
        org_ids = [
            row.id for row in db.query(Organization.id)
            .filter(Organization.is_active.is_(True))
            .all()
        ]
        for org_id in org_ids:
            try:
                stats = materialize_inventory_edges(db, org_id=org_id)
                if any(stats.values()):
                    logger.info(
                        "[inventory_edges] org=%d periodic rebuild: %s",
                        org_id, stats,
                    )
                db.commit()
            except Exception as exc:
                db.rollback()
                logger.warning(
                    "[inventory_edges] org=%d periodic rebuild failed: %s",
                    org_id, exc,
                )
    finally:
        db.close()


def start_scheduler():
    """Register the inventory-edge rebuild job with APScheduler."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    interval_minutes = int(os.environ.get("INVENTORY_EDGE_REBUILD_MINUTES", "30"))

    sched = BackgroundScheduler()
    sched.add_job(
        _rebuild_all_orgs,
        IntervalTrigger(minutes=interval_minutes),
        id="inventory_edge_rebuild",
        replace_existing=True,
        misfire_grace_time=300,
    )
    sched.start()
    _scheduler = sched
    logger.info(
        "Inventory edge rebuild scheduler started (every %d min)",
        interval_minutes,
    )
    return sched
