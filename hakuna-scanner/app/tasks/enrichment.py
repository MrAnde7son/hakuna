"""Celery tasks for the enrichment pipeline."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session
from app.ingest.assets import update_enrichment, update_tls, update_cdn
from app.ingest.delta import detect_cert_expiring, auto_tag_assets, detect_changes
from app.runner.tools import CdncheckRunner, HttpxRunner, TlsxRunner

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _get_asset_hostnames(sf, org_id: str) -> list[str]:
    async with sf() as db:
        result = await db.execute(
            text("SELECT hostname FROM assets WHERE org_id = :org_id"),
            {"org_id": org_id},
        )
        return [row.hostname for row in result.fetchall()]


async def _get_asset_snapshot(sf, org_id: str) -> list[dict]:
    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT id, hostname, host(ip) as ip, open_ports, tech_stack, tls_cert
                FROM assets WHERE org_id = :org_id
            """),
            {"org_id": org_id},
        )
        return [
            {
                "id": row.id,
                "hostname": row.hostname,
                "ip": row.ip,
                "open_ports": row.open_ports,
                "tech_stack": row.tech_stack,
                "tls_cert": row.tls_cert,
            }
            for row in result.fetchall()
        ]


async def _do_httpx(sf, org_id: str) -> dict:
    hostnames = await _get_asset_hostnames(sf, org_id)
    if not hostnames:
        return {"probed": 0}

    runner = HttpxRunner(hostnames)
    result = await runner.run(org_id=org_id)

    async with sf() as db:
        updated = await update_enrichment(db, uuid.UUID(org_id), result.results)

    return {"probed": len(result.results), "updated": updated}


async def _do_tlsx(sf, org_id: str) -> dict:
    hostnames = await _get_asset_hostnames(sf, org_id)
    if not hostnames:
        return {"inspected": 0}

    runner = TlsxRunner(hostnames)
    result = await runner.run(org_id=org_id)

    async with sf() as db:
        updated = await update_tls(db, uuid.UUID(org_id), result.results)

    return {"inspected": len(result.results), "updated": updated}


async def _do_cdncheck(sf, org_id: str) -> dict:
    hostnames = await _get_asset_hostnames(sf, org_id)
    if not hostnames:
        return {"checked": 0}

    runner = CdncheckRunner(hostnames)
    result = await runner.run(org_id=org_id)

    async with sf() as db:
        updated = await update_cdn(db, uuid.UUID(org_id), result.results)

    return {"checked": len(result.results), "updated": updated}


# Individual tasks

@celery.task(bind=True, name="enrichment.run_httpx")
def run_httpx(self, org_id: str) -> dict:
    return _run_async(_do_httpx(get_task_session(), org_id))


@celery.task(bind=True, name="enrichment.run_tlsx")
def run_tlsx(self, org_id: str) -> dict:
    return _run_async(_do_tlsx(get_task_session(), org_id))


@celery.task(bind=True, name="enrichment.run_cdncheck")
def run_cdncheck(self, org_id: str) -> dict:
    return _run_async(_do_cdncheck(get_task_session(), org_id))


@celery.task(bind=True, name="enrichment.run_enrichment_chain")
def run_enrichment_chain(self, org_id: str, scan_run_id: str | None = None) -> dict:
    """Full enrichment chain: httpx → tlsx → cdncheck → auto-tag → delta.

    Calls runners directly (no subtask dispatch) to avoid Celery deadlocks.
    """

    async def _run():
        sf = get_task_session()

        async with sf() as db:
            if scan_run_id:
                await db.execute(
                    text("UPDATE scan_runs SET status = 'running', started_at = :now WHERE id = :id"),
                    {"id": scan_run_id, "now": datetime.now(timezone.utc)},
                )
                await db.commit()

        # Snapshot before enrichment for delta
        snapshot = await _get_asset_snapshot(sf, org_id)

        results = {}
        steps = [
            ("httpx", _do_httpx),
            ("tlsx", _do_tlsx),
            ("cdncheck", _do_cdncheck),
        ]

        for step_name, step_fn in steps:
            try:
                results[step_name] = await step_fn(get_task_session(), org_id)
            except Exception as e:
                logger.error("enrichment step %s failed for org %s: %s", step_name, org_id, e)
                results[step_name] = {"error": str(e)}

        # Post-enrichment: auto-tag + delta detection
        sf2 = get_task_session()
        async with sf2() as db:
            await auto_tag_assets(db, uuid.UUID(org_id))
            cert_events = await detect_cert_expiring(db, uuid.UUID(org_id))
            change_events = await detect_changes(db, uuid.UUID(org_id), snapshot)

            results["cert_expiring_events"] = cert_events
            results["change_events"] = change_events

            if scan_run_id:
                total_updated = sum(r.get("updated", 0) for r in results.values() if isinstance(r, dict))
                await db.execute(
                    text("""
                        UPDATE scan_runs SET
                            status = 'done', finished_at = :now,
                            assets_changed = :changed
                        WHERE id = :id
                    """),
                    {
                        "id": scan_run_id,
                        "now": datetime.now(timezone.utc),
                        "changed": total_updated,
                    },
                )
                await db.commit()

        return results

    try:
        return _run_async(_run())
    except Exception as e:
        if scan_run_id:
            _run_async(_mark_failed(scan_run_id, str(e)))
        raise


async def _mark_failed(scan_run_id: str, error: str):
    sf = get_task_session()
    async with sf() as db:
        await db.execute(
            text("UPDATE scan_runs SET status = 'failed', finished_at = :now, error = :err WHERE id = :id"),
            {"id": scan_run_id, "now": datetime.now(timezone.utc), "err": error},
        )
        await db.commit()
