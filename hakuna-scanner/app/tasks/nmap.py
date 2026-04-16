"""Extension 4: Nmap light fingerprinting tasks.

Runs on confirmed_alive assets in a dedicated 'nmap_queue' with max concurrency 5.
Uses python-libnmap to invoke Nmap and parse results.
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session
from app.ingest.enrichment import store_nmap_results

logger = logging.getLogger(__name__)

NMAP_TIMEOUT_SECONDS = 300  # 5 min hard timeout per host (TCP)
NMAP_UDP_TIMEOUT_SECONDS = 600  # 10 min for UDP (slower scanning)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _run_nmap_scan(target: str, ports: str) -> tuple:
    """Run Nmap via python-libnmap. Returns (NmapHost | None, duration, timed_out)."""
    from libnmap.process import NmapProcess
    from libnmap.parser import NmapParser

    nmap_args = (
        f"-sV --version-intensity 5 -p {ports} "
        f"--script=banner,ssl-cert,http-title,http-server-header "
        f"--max-rate 100 -T3"
    )

    start = time.monotonic()
    proc = NmapProcess(targets=target, options=nmap_args)
    proc.run_background()

    timed_out = False
    while proc.is_running():
        elapsed = time.monotonic() - start
        if elapsed > NMAP_TIMEOUT_SECONDS:
            proc.stop()
            timed_out = True
            logger.warning("nmap timeout for %s after %.0fs", target, elapsed)
            break
        time.sleep(1)

    duration = time.monotonic() - start

    # Parse results (even partial on timeout)
    try:
        report = NmapParser.parse(proc.stdout)
        if report.hosts:
            return report.hosts[0], duration, timed_out
    except Exception as e:
        logger.error("nmap parse error for %s: %s", target, e)

    return None, duration, timed_out


def _run_nmap_udp_scan(target: str, ports: str) -> tuple:
    """Run Nmap UDP scan via python-libnmap. Returns (NmapHost | None, duration, timed_out)."""
    from libnmap.process import NmapProcess
    from libnmap.parser import NmapParser

    timeout = settings.nmap_udp_timeout_seconds or NMAP_UDP_TIMEOUT_SECONDS
    nmap_args = (
        f"-sU -sV --version-intensity 2 -p {ports} "
        f"--max-rate 50 -T3"
    )

    start = time.monotonic()
    proc = NmapProcess(targets=target, options=nmap_args)
    proc.run_background()

    timed_out = False
    while proc.is_running():
        elapsed = time.monotonic() - start
        if elapsed > timeout:
            proc.stop()
            timed_out = True
            logger.warning("nmap UDP timeout for %s after %.0fs", target, elapsed)
            break
        time.sleep(1)

    duration = time.monotonic() - start

    try:
        report = NmapParser.parse(proc.stdout)
        if report.hosts:
            return report.hosts[0], duration, timed_out
    except Exception as e:
        logger.error("nmap UDP parse error for %s: %s", target, e)

    return None, duration, timed_out


@celery.task(
    bind=True,
    name="nmap.nmap_udp_enrich_asset",
    max_retries=2,
    retry_backoff=True,
    autoretry_for=(Exception,),
    queue="nmap_queue",
)
def nmap_udp_enrich_asset(self, asset_id: str) -> dict:
    """Run Nmap UDP scanning on a single asset.

    Scans the configured UDP ports (top ~50) for service detection.
    Enqueued on 'nmap_queue' alongside TCP tasks.
    """

    async def _run():
        sf = get_task_session()
        async with sf() as db:
            row = await db.execute(
                text("""
                    SELECT id, hostname, host(ip) as ip, liveness_state
                    FROM assets WHERE id = :id
                """),
                {"id": asset_id},
            )
            asset = row.fetchone()
            if not asset:
                return {"error": "asset not found", "asset_id": asset_id}

            if asset.liveness_state != "confirmed_alive":
                return {"nmap_udp_status": "skipped", "reason": "not confirmed_alive"}

        target = asset.hostname or str(asset.ip)
        ports_str = settings.nmap_udp_ports

        logger.info("nmap UDP starting: asset=%s target=%s ports=%s", asset_id, target, ports_str)

        nmap_host, duration, timed_out = _run_nmap_udp_scan(target, ports_str)

        sf2 = get_task_session()
        async with sf2() as db:
            if nmap_host:
                result = await store_nmap_results(
                    db, uuid.UUID(asset_id), nmap_host, duration, timed_out,
                )
                result["scan_type"] = "udp"
            else:
                result = {
                    "nmap_udp_status": "timeout" if timed_out else "no_results",
                    "duration": duration,
                    "scan_type": "udp",
                }

            logger.info("nmap UDP complete: asset=%s result=%s", asset_id, result)
            return result

    return _run_async(_run())


@celery.task(
    bind=True,
    name="nmap.nmap_enrich_asset",
    max_retries=3,
    retry_backoff=True,
    autoretry_for=(Exception,),
    queue="nmap_queue",
)
def nmap_enrich_asset(self, asset_id: str) -> dict:
    """Run Nmap light fingerprinting on a single asset.

    Enqueued on 'nmap_queue' with max concurrency 5.
    Only scans confirmed open ports from Naabu output.
    """

    async def _run():
        sf = get_task_session()
        async with sf() as db:
            row = await db.execute(
                text("""
                    SELECT id, hostname, host(ip) as ip, open_ports, liveness_state
                    FROM assets WHERE id = :id
                """),
                {"id": asset_id},
            )
            asset = row.fetchone()
            if not asset:
                return {"error": "asset not found", "asset_id": asset_id}

            if asset.liveness_state != "confirmed_alive":
                await db.execute(
                    text("UPDATE assets SET nmap_status = 'skipped' WHERE id = :id"),
                    {"id": asset_id},
                )
                await db.commit()
                return {"nmap_status": "skipped", "reason": "not confirmed_alive"}

            ports = asset.open_ports or []
            if not ports:
                await db.execute(
                    text("UPDATE assets SET nmap_status = 'skipped' WHERE id = :id"),
                    {"id": asset_id},
                )
                await db.commit()
                return {"nmap_status": "skipped", "reason": "no open ports"}

            # Mark as pending
            await db.execute(
                text("UPDATE assets SET nmap_status = 'pending' WHERE id = :id"),
                {"id": asset_id},
            )
            await db.commit()

        # Use hostname if available, fall back to IP
        target = asset.hostname or str(asset.ip)
        ports_str = ",".join(str(p) for p in ports)

        logger.info("nmap starting: asset=%s target=%s ports=%s", asset_id, target, ports_str)

        # Run nmap synchronously (it's a subprocess)
        nmap_host, duration, timed_out = _run_nmap_scan(target, ports_str)

        sf2 = get_task_session()
        async with sf2() as db:
            if nmap_host:
                result = await store_nmap_results(
                    db, uuid.UUID(asset_id), nmap_host, duration, timed_out,
                )
            else:
                # No results — mark as timeout or error
                await db.execute(
                    text("UPDATE assets SET nmap_status = :status, nmap_last_run = :now WHERE id = :id"),
                    {
                        "status": "timeout" if timed_out else "pending",
                        "now": datetime.now(timezone.utc),
                        "id": asset_id,
                    },
                )
                await db.commit()
                result = {
                    "nmap_status": "timeout" if timed_out else "error",
                    "duration": duration,
                }

            logger.info("nmap complete: asset=%s result=%s", asset_id, result)
            return result

    return _run_async(_run())
