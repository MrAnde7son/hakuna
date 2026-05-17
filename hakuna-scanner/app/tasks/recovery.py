"""Orphan scan recovery: detect and re-dispatch stuck scan runs.

When the Celery worker restarts (crash, OOM, deploy), in-flight scan tasks
are lost. The scan_runs table is left with status='running' but no Celery
task is processing them. This module detects those orphans and re-dispatches
the appropriate chain.

Safety: the staleness-based skipping in each pipeline stage means
re-dispatching a scan is safe -- completed stages will be skipped
automatically. The recovery_attempts counter prevents infinite loops.

Three entry points:
  1. ``recover_orphaned_scans`` -- periodic Celery beat task (every 5 min)
  2. ``_on_worker_ready_recovery`` -- worker_ready signal (runs once at boot)
  3. ``reap_zombie_tasks`` -- periodic beat task (every 30 min) that clears
     orphaned ``unacked`` entries left by dead worker containers. Without
     this, stale claims pin worker slots forever and ``recover_orphaned_scans``
     itself starves in the queue.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta

import redis
from celery.exceptions import WorkerLostError
from celery.signals import worker_ready
from sqlalchemy import text

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session
from app.tasks.discovery import run_discovery_chain
from app.tasks.enrichment import run_enrichment_chain

logger = logging.getLogger(__name__)

# Visibility timeout is 14700s (~4h, see celery_app.py). Anything still in
# `unacked` past that boundary plus a 1h grace was claimed by a worker that's
# no longer acking — kombu only restores entries claimed by the *current*
# client_id, so entries orphaned by a container restart never come back
# without help. Observed in production 2026-05-06: 4 unacked entries from a
# previous worker generation re-delivered to the live worker, pinning all 4
# slots with redelivered ghosts (3 of which were duplicates of the same
# scan_run) and starving the recovery beat task itself.
ZOMBIE_TASK_THRESHOLD_SECONDS = 5 * 3600

# A scan stuck in 'running' for longer than this is considered orphaned.
ORPHAN_THRESHOLD_MINUTES = 15

# A scan stuck in 'queued' (never picked up by Celery) for longer than this
# is considered lost and will be re-dispatched.
QUEUED_THRESHOLD_MINUTES = 10

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

    Recovers two categories:
      1. 'running' scans whose stage_started_at is stale (worker crashed mid-scan)
      2. 'queued' scans that were never picked up (Celery message lost on restart)

    Returns a summary dict for logging/monitoring.
    """
    sf = get_task_session()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=ORPHAN_THRESHOLD_MINUTES)
    queued_cutoff = now - timedelta(minutes=QUEUED_THRESHOLD_MINUTES)

    # Atomic claim: a single UPDATE … RETURNING bumps recovery_attempts and
    # resets stage_started_at for every eligible orphan in one shot. With
    # FOR UPDATE SKIP LOCKED, concurrent recovery passes (periodic beat,
    # worker_ready signal on each worker boot) cannot both claim the same
    # scan_run — the loser sees an empty result set and re-dispatches nothing.
    async with sf() as db:
        result = await db.execute(
            text("""
                UPDATE scan_runs SET
                    recovery_attempts = recovery_attempts + 1,
                    stage_started_at = :now
                WHERE id IN (
                    SELECT id FROM scan_runs
                    WHERE (
                        (status = 'running' AND stage_started_at < :cutoff)
                        OR (status = 'queued' AND created_at < :queued_cutoff)
                    )
                    AND recovery_attempts < :max_attempts
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, org_id, scan_type,
                          COALESCE(stage_index, 0) AS stage_index,
                          recovery_attempts, status
            """),
            {
                "cutoff": cutoff,
                "queued_cutoff": queued_cutoff,
                "max_attempts": MAX_RECOVERY_ATTEMPTS,
                "now": now,
            },
        )
        orphans = list(result.fetchall())
        await db.commit()

    if not orphans:
        return {"orphans_found": 0}

    # Split: rows whose bumped counter equals MAX are exhausted — mark them
    # failed and DO NOT dispatch. Previously we dispatched everything and
    # then marked the exhausted ones failed in a separate UPDATE, which
    # raced with discovery's bootstrap clobbering status back to 'running'.
    to_dispatch = [r for r in orphans if r.recovery_attempts < MAX_RECOVERY_ATTEMPTS]
    to_fail = [r for r in orphans if r.recovery_attempts >= MAX_RECOVERY_ATTEMPTS]

    recovered = 0
    exhausted = 0

    if to_fail:
        async with sf() as db:
            await db.execute(
                text("""
                    UPDATE scan_runs SET
                        status = 'failed',
                        finished_at = :now,
                        error = :err
                    WHERE id = ANY(:ids)
                """),
                {
                    "ids": [str(r.id) for r in to_fail],
                    "now": now,
                    "err": f"Scan orphaned and recovery exhausted after {MAX_RECOVERY_ATTEMPTS} attempts",
                },
            )
            await db.commit()
        exhausted = len(to_fail)
        logger.error(
            "Marked %d orphaned scan(s) as failed after exhausting %d recovery attempts",
            exhausted, MAX_RECOVERY_ATTEMPTS,
        )

    for row in to_dispatch:
        scan_run_id = str(row.id)
        org_id = str(row.org_id)
        scan_type = row.scan_type
        # 'queued' rows haven't started any stage yet — treat them as
        # stage 0 so we re-dispatch the full discovery chain.
        stage_index = row.stage_index if row.status == "running" else 0
        attempts = row.recovery_attempts

        logger.warning(
            "Recovering orphaned scan run %s (org=%s, type=%s, stage_index=%d, attempt=%d/%d)",
            scan_run_id, org_id, scan_type, stage_index, attempts, MAX_RECOVERY_ATTEMPTS,
        )

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

    return {"orphans_found": len(orphans), "recovered": recovered, "exhausted": exhausted}


@celery.task(name="recovery.recover_orphaned_scans")
def recover_orphaned_scans() -> dict:
    """Periodic beat task: detect and re-dispatch orphaned scans."""
    return _run_async(_find_and_recover_orphans())


@worker_ready.connect
def _on_worker_ready_recovery(sender=None, **_kwargs) -> None:
    """On worker startup, reap unacked ghosts then check for orphaned scans.

    The most common cause of orphaned scans is the worker restarting, so
    checking at boot catches them without waiting for the next beat tick.

    Ghost reap runs first: if the previous container generation left
    redelivered ``unacked`` entries, they'll re-pin every slot the moment
    this worker connects to the broker. Clearing them before recovery
    re-dispatches anything ensures the new tasks can actually be picked up.
    """
    logger.info("Worker starting: reaping zombie unacked entries")
    try:
        reap_summary = _reap_zombie_tasks_impl()
        if reap_summary.get("reaped"):
            logger.warning("Worker startup zombie reap: %s", reap_summary)
    except Exception:
        logger.exception("Worker startup zombie reap failed (non-fatal)")

    logger.info("Worker starting: checking for orphaned scan runs")
    try:
        summary = _run_async(_find_and_recover_orphans())
        if summary["orphans_found"]:
            logger.warning("Worker startup recovery: %s", summary)
        else:
            logger.info("Worker startup recovery: no orphaned scans found")
    except Exception:
        logger.exception("Worker startup orphan recovery failed (non-fatal)")


@celery.task(name="recovery.reap_zombie_tasks")
def reap_zombie_tasks() -> dict:
    """Fail tasks orphaned in Celery's redis ``unacked`` set.

    When an easm-worker container is killed mid-scan, its ``unacked`` entries
    are left behind: kombu's visibility_timeout-based restore only acts on
    entries claimed by the *current* client_id, so entries from a dead
    container never recover. With ``task_acks_late=True`` and
    ``worker_prefetch_multiplier=1``, those ghost entries pin worker slots
    indefinitely and the periodic ``recover_orphaned_scans`` beat task
    starves in the queue behind them — that's the failure mode observed in
    production 2026-05-06, where 3 of 4 slots were pinned by redelivered
    duplicates of the same scan_run from a previous worker generation.

    Finds delivery tags older than ``ZOMBIE_TASK_THRESHOLD_SECONDS``, marks
    each task FAILURE in the result backend so any caller polling on it
    sees a terminal state, and removes the unacked bookkeeping.
    """
    return _reap_zombie_tasks_impl()


def _reap_zombie_tasks_impl(now: float | None = None) -> dict:
    cutoff = (now if now is not None else time.time()) - ZOMBIE_TASK_THRESHOLD_SECONDS
    client = redis.from_url(settings.redis_url)

    # `unacked_index` is a ZSET of delivery_tag -> claim timestamp.
    stale_tags = client.zrangebyscore("unacked_index", "-inf", cutoff)
    if not stale_tags:
        return {"status": "ok", "reaped": 0}

    reaped = []
    for delivery_tag in stale_tags:
        body = client.hget("unacked", delivery_tag)
        if not body:
            client.zrem("unacked_index", delivery_tag)
            continue

        try:
            msg = json.loads(body)
            headers = msg[0].get("headers", {})
            task_id = headers.get("id")
            task_name = headers.get("task")
        except Exception:
            logger.warning(
                "zombie reaper: could not parse unacked body for %s; removing anyway",
                delivery_tag,
            )
            client.hdel("unacked", delivery_tag)
            client.zrem("unacked_index", delivery_tag)
            continue

        if task_id:
            exc = WorkerLostError(
                f"Task {task_name} ({task_id}) abandoned by dead worker; "
                f"reaped after {ZOMBIE_TASK_THRESHOLD_SECONDS}s in unacked."
            )
            try:
                celery.backend.mark_as_failure(task_id, exc)
            except Exception:
                logger.exception(
                    "zombie reaper: failed to mark %s as failure", task_id
                )

        client.hdel("unacked", delivery_tag)
        client.zrem("unacked_index", delivery_tag)
        reaped.append({"task_id": task_id, "task_name": task_name})
        logger.warning(
            "zombie reaper: failed task %s (%s) abandoned in unacked",
            task_id, task_name,
        )

    return {"status": "ok", "reaped": len(reaped), "tasks": reaped}
