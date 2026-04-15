"""Drain hot-tier SIEM events to the Iceberg lake.

Runs every 15 minutes via APScheduler. Selects events older than 1 hour,
writes them as Parquet to the lake, then deletes from Postgres.
Idempotent: uses dedup_hash to avoid duplicates in the lake.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

DRAIN_AGE_HOURS = 1       # Events older than this are eligible for draining
DRAIN_BATCH_SIZE = 50_000  # Max events per drain cycle


def drain_hot_to_lake(db: Session = None) -> dict:
    """Move aged-out events from hot tier (Postgres) to Iceberg lake.

    Returns dict with counts: {drained, deleted, skipped, error}.
    """
    from core.database import SessionLocal
    from models.models import SIEMEvent
    from services.event_store.lake_iceberg import LakeIcebergStore
    from services.event_store.base import EventRecord

    own_session = db is None
    if own_session:
        db = SessionLocal()

    result = {"drained": 0, "deleted": 0, "skipped": 0, "error": None}

    try:
        lake = LakeIcebergStore()
        if not lake.available:
            result["error"] = "Lake tier unavailable"
            logger.warning("Event drain skipped — lake tier unavailable")
            return result

        cutoff = datetime.utcnow() - timedelta(hours=DRAIN_AGE_HOURS)

        # Fetch events to drain
        events = (
            db.query(SIEMEvent)
            .filter(SIEMEvent.ingested_at < cutoff)
            .order_by(SIEMEvent.event_time.asc())
            .limit(DRAIN_BATCH_SIZE)
            .all()
        )

        if not events:
            logger.info("Event drain: no events to drain (cutoff=%s)", cutoff.isoformat())
            return result

        # Convert to EventRecord for lake write
        records = []
        for ev in events:
            records.append(EventRecord(
                id=ev.id,
                org_id=ev.org_id,
                event_time=ev.event_time,
                ingested_at=ev.ingested_at,
                source_system=ev.source_system,
                source_id=ev.source_id,
                event_type=ev.event_type,
                event_category=ev.event_category,
                severity=ev.severity,
                action=ev.action,
                outcome=ev.outcome,
                asset_id=ev.asset_id,
                user_name=ev.user_name,
                source_ip=ev.source_ip,
                dest_ip=ev.dest_ip,
                host_name=ev.host_name,
                message=ev.message,
                raw=ev.raw,
                normalized=ev.normalized,
                dedup_hash=ev.dedup_hash,
                integration_id=ev.integration_id,
            ))

        # Write to lake
        written = lake.write_batch(records)
        result["drained"] = written

        # Delete from hot tier (only the events we successfully wrote)
        event_ids = [ev.id for ev in events]
        for batch_start in range(0, len(event_ids), 500):
            batch = event_ids[batch_start:batch_start + 500]
            db.query(SIEMEvent).filter(SIEMEvent.id.in_(batch)).delete(synchronize_session=False)
        db.commit()
        result["deleted"] = len(event_ids)

        logger.info("Event drain: drained %d events to lake, deleted %d from hot tier",
                     result["drained"], result["deleted"])

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("Event drain failed: %s", exc)
        db.rollback()
    finally:
        if own_session:
            db.close()

    return result


def start_drain_scheduler():
    """Register the drain job with APScheduler (called from app.py startup)."""
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    lake_enabled = os.environ.get("SIEM_LAKE_ENABLED", "false").lower() == "true"
    if not lake_enabled:
        logger.info("SIEM lake tier disabled — drain scheduler not started")
        return

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        drain_hot_to_lake,
        IntervalTrigger(minutes=15),
        id="siem_event_drain",
        replace_existing=True,
        misfire_grace_time=300,
        coalesce=True,
    )
    scheduler.start()
    logger.info("SIEM event drain scheduler started (every 15 minutes)")
