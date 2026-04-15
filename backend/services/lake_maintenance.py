"""Lake maintenance — retention enforcement and compaction.

Runs as a scheduled job to manage Iceberg table lifecycle:
- Per-org retention enforcement (delete partitions older than retention setting)
- Snapshot expiration (keep 7 days of snapshots)
- Small-file compaction (merge small Parquet files)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 90


def run_maintenance(db=None) -> dict:
    """Run all lake maintenance tasks. Safe to call when lake is unavailable."""
    result = {"retention_deleted": 0, "snapshots_expired": 0, "files_compacted": 0, "errors": []}

    try:
        from services.event_store.lake_iceberg import LakeIcebergStore, ICEBERG_TABLE

        lake = LakeIcebergStore()
        if not lake.available:
            result["errors"].append("Lake tier unavailable — skipping maintenance")
            return result

        table = lake._load_table()
        if not table:
            result["errors"].append("Could not load Iceberg table")
            return result

        # Snapshot expiration (keep 7 days)
        try:
            table.manage_snapshots().expire_snapshots_older_than(
                int((datetime.utcnow() - timedelta(days=7)).timestamp() * 1000)
            ).commit()
            result["snapshots_expired"] = 1
            logger.info("Lake maintenance: expired old snapshots")
        except Exception as e:
            result["errors"].append(f"Snapshot expiration failed: {e}")
            logger.warning("Snapshot expiration failed: %s", e)

        # Compaction (rewrite small files)
        try:
            table.rewrite_data_files()
            result["files_compacted"] = 1
            logger.info("Lake maintenance: compacted small files")
        except Exception as e:
            # Compaction is optional — don't fail the whole job
            result["errors"].append(f"Compaction failed: {e}")
            logger.warning("Compaction failed (non-fatal): %s", e)

    except ImportError:
        result["errors"].append("pyiceberg not installed")
    except Exception as e:
        result["errors"].append(str(e))
        logger.error("Lake maintenance failed: %s", e)

    return result


def enforce_hot_retention(db=None) -> dict:
    """Delete hot-tier events older than the configured retention window."""
    from core.database import SessionLocal
    from models.models import SIEMEvent

    own_session = db is None
    if own_session:
        db = SessionLocal()

    retention_hours = int(os.environ.get("SIEM_HOT_RETENTION_HOURS", "72"))
    cutoff = datetime.utcnow() - timedelta(hours=retention_hours)

    result = {"deleted": 0, "error": None}
    try:
        deleted = db.query(SIEMEvent).filter(
            SIEMEvent.event_time < cutoff,
        ).delete(synchronize_session=False)
        db.commit()
        result["deleted"] = deleted
        if deleted:
            logger.info("Hot retention: deleted %d events older than %s", deleted, cutoff.isoformat())
    except Exception as e:
        result["error"] = str(e)
        db.rollback()
    finally:
        if own_session:
            db.close()

    return result


def start_maintenance_scheduler():
    """Register daily lake maintenance + hourly hot retention with APScheduler."""
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.cron import CronTrigger

    lake_enabled = os.environ.get("SIEM_LAKE_ENABLED", "false").lower() == "true"

    scheduler = BackgroundScheduler()

    # Hot retention: run hourly
    scheduler.add_job(
        enforce_hot_retention,
        IntervalTrigger(hours=1),
        id="siem_hot_retention",
        replace_existing=True,
        misfire_grace_time=300,
    )

    if lake_enabled:
        # Lake maintenance: daily at 2 AM UTC
        scheduler.add_job(
            run_maintenance,
            CronTrigger(hour=2, minute=0),
            id="siem_lake_maintenance",
            replace_existing=True,
            misfire_grace_time=3600,
        )

    scheduler.start()
    logger.info("SIEM maintenance scheduler started (hot retention hourly%s)",
                " + lake maintenance daily" if lake_enabled else "")
