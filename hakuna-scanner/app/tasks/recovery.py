"""Orphan scan recovery: detect and re-dispatch stuck scan runs.

When the Celery worker restarts (crash, OOM, deploy), in-flight scan tasks
are lost. The scan_runs table is left with status='running' but no Celery
task is processing them. This module detects those orphans and re-dispatches
the appropriate chain.

Safety: the staleness-based skipping in each pipeline stage means
re-dispatching a scan is safe -- completed stages will be skipped
automatically. The recovery_attempts counter prevents infinite loops.

Two entry points:
  1. ``recover_orphaned_scans`` -- periodic Celery beat task (every 5 min)
  2. ``_on_worker_ready_recovery`` -- worker_ready signal (runs once at boot)
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from celery.signals import worker_ready
from sqlalchemy import text

from app.celery_app import celery
from app.database import get_task_session
from app.tasks.discovery import run_discovery_chain
from app.tasks.enrichment import run_enrichment_chain

logger = logging.getLogger(__name__)

# A scan stuck for longer than this is considered orphaned.
ORPHAN_THRESHOLD_MINUTES = 15

# Maximum times a single scan run will be re-dispatched before being marked
# failed. Prevents infinite recovery loops if a scan is genuinely broken.
MAX_RECOVERY_ATTEMPTS = 3

# Discovery stages occupy indices 0..6 in the chain (subfinder through
# liveness_gate). Enrichment stages come after.
DISCOVERY_MAX_STAGE_INDEX = 6


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _find_and_recover_orphans() -> dict:
    """Core logic: find orphaned scan runs and re-dispatch them.

    Returns a summary dict for logging/monitoring.
    """
    sf = get_task_session()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=ORPHAN_THRESHOLD_MINUTES)

    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT id, org_id, scan_type, stage_index, recovery_attempts
                FROM scan_runs
                WHERE status = 'running'
                  AND stage_started_at < :cutoff
                  AND recovery_attempts < :max_attempts
            """),
            {"cutoff": cutoff, "max_attempts": MAX_RECOVERY_ATTEMPTS},
        )
        orphans = result.fetchall()

    if not orphans:
        return {"orphans_found": 0}

    recovered = 0
    exhausted = 0

    for row in orphans:
        scan_run_id = str(row.id)
        org_id = str(row.org_id)
        scan_type = row.scan_type
        stage_index = row.stage_index
        attempts = row.recovery_attempts + 1

        logger.warning(
            "Recovering orphaned scan run %s (org=%s, type=%s, stage_index=%d, attempt=%d/%d)",
            scan_run_id, org_id, scan_type, stage_index, attempts, MAX_RECOVERY_ATTEMPTS,
        )

        # Bump recovery_attempts and reset stage_started_at so we don't
        # immediately re-detect this scan as orphaned.
        async with sf() as db:
            await db.execute(
                text("""
                    UPDATE scan_runs SET
                        recovery_attempts = :attempts,
                        stage_started_at = :now
                    WHERE id = :id
                """),
                {"attempts": attempts, "id": scan_run_id, "now": now},
            )
            await db.commit()

        # Decide which chain to re-dispatch based on where the scan was stuck.
        # Discovery phase: stage_index <= DISCOVERY_MAX_STAGE_INDEX
        # Enrichment phase: stage_index > DISCOVERY_MAX_STAGE_INDEX
        if stage_index <= DISCOVERY_MAX_STAGE_INDEX:
            # Re-dispatch discovery chain. For full scans, run_discovery_chain
            # will link to run_enrichment_chain automatically via the
            # apply_async(link=...) pattern in the API layer -- but since the
            # chain task itself checks scan_type and the enrichment chain is
            # called inline, we just re-dispatch discovery which will cascade.
            if scan_type == "full":
                run_discovery_chain.apply_async(
                    args=[org_id, scan_run_id],
                    link=run_enrichment_chain.si(org_id, scan_run_id),
                )
            else:
                run_discovery_chain.apply_async(args=[org_id, scan_run_id])
        else:
            # Discovery was done but enrichment stalled -- only re-dispatch
            # the enrichment chain.
            run_enrichment_chain.apply_async(args=[org_id, scan_run_id])

        recovered += 1

    # Mark scans that have exhausted recovery attempts as failed.
    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT id FROM scan_runs
                WHERE status = 'running'
                  AND stage_started_at < :cutoff
                  AND recovery_attempts >= :max_attempts
            """),
            {"cutoff": cutoff, "max_attempts": MAX_RECOVERY_ATTEMPTS},
        )
        exhausted_rows = result.fetchall()

        for row in exhausted_rows:
            await db.execute(
                text("""
                    UPDATE scan_runs SET
                        status = 'failed',
                        finished_at = :now,
                        error = :err
                    WHERE id = :id
                """),
                {
                    "id": str(row.id),
                    "now": now,
                    "err": f"Scan orphaned and recovery exhausted after {MAX_RECOVERY_ATTEMPTS} attempts",
                },
            )
            exhausted += 1

        if exhausted_rows:
            await db.commit()

    if exhausted:
        logger.error(
            "Marked %d orphaned scan(s) as failed after exhausting %d recovery attempts",
            exhausted, MAX_RECOVERY_ATTEMPTS,
        )

    return {"orphans_found": len(orphans) + exhausted, "recovered": recovered, "exhausted": exhausted}


@celery.task(name="recovery.recover_orphaned_scans")
def recover_orphaned_scans() -> dict:
    """Periodic beat task: detect and re-dispatch orphaned scans."""
    return _run_async(_find_and_recover_orphans())


@worker_ready.connect
def _on_worker_ready_recovery(sender=None, **_kwargs) -> None:
    """On worker startup, immediately check for orphaned scans.

    The most common cause of orphaned scans is the worker restarting, so
    checking at boot catches them without waiting for the next beat tick.
    """
    logger.info("Worker starting: checking for orphaned scan runs")
    try:
        summary = _run_async(_find_and_recover_orphans())
        if summary["orphans_found"]:
            logger.warning("Worker startup recovery: %s", summary)
        else:
            logger.info("Worker startup recovery: no orphaned scans found")
    except Exception:
        logger.exception("Worker startup orphan recovery failed (non-fatal)")
