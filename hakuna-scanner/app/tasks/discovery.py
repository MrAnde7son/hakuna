"""Celery tasks for the discovery pipeline."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session
from app.ingest.assets import upsert_discovered_hosts, update_dns_records, update_ports
from app.ingest.delta import emit_new_asset_events, detect_gone_assets
from app.runner.tools import (
    AsnmapRunner,
    DnsxRunner,
    NaabuRunner,
    SubfinderRunner,
    UncoverRunner,
)

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine from sync Celery task context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _get_target_domains(sf, org_id: str) -> list[str]:
    async with sf() as db:
        result = await db.execute(
            text("SELECT domain FROM target_domains WHERE org_id = :org_id AND active = true"),
            {"org_id": org_id},
        )
        return [row.domain for row in result.fetchall()]


async def _get_org_name(sf, org_id: str) -> str | None:
    async with sf() as db:
        result = await db.execute(text("SELECT name FROM orgs WHERE id = :id"), {"id": org_id})
        row = result.fetchone()
        return row.name if row else None


async def _get_asset_hostnames(sf, org_id: str) -> list[str]:
    async with sf() as db:
        result = await db.execute(
            text("SELECT hostname FROM assets WHERE org_id = :org_id"),
            {"org_id": org_id},
        )
        return [row.hostname for row in result.fetchall()]


async def _do_subfinder(sf, org_id: str) -> dict:
    domains = await _get_target_domains(sf, org_id)
    all_hosts: list[dict] = []
    for domain in domains:
        runner = SubfinderRunner(domain)
        result = await runner.run(org_id=org_id)
        all_hosts.extend(result.results)

    async with sf() as db:
        total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), all_hosts, "subfinder")
        await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)

    return {"hosts_found": len(all_hosts), "upserted": total, "new": len(new_ids)}


async def _do_asnmap(sf, org_id: str) -> dict:
    org_name = await _get_org_name(sf, org_id)
    if not org_name:
        return {"error": "org not found"}

    runner = AsnmapRunner(org_name)
    result = await runner.run(org_id=org_id)
    hosts = [{"host": r.get("ip", r.get("input", "")), "asn": r.get("as_number"), "asn_org": r.get("as_org")} for r in result.results]

    async with sf() as db:
        total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), hosts, "asnmap")
        await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)

    return {"ranges_found": len(result.results), "upserted": total, "new": len(new_ids)}


async def _do_uncover(sf, org_id: str) -> dict:
    domains = await _get_target_domains(sf, org_id)
    all_hosts: list[dict] = []
    for domain in domains:
        runner = UncoverRunner(domain)
        result = await runner.run(org_id=org_id)
        for r in result.results:
            all_hosts.append({"host": r.get("host", r.get("ip", "")), "ip": r.get("ip")})

    async with sf() as db:
        total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), all_hosts, "uncover")
        await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)

    return {"hosts_found": len(all_hosts), "upserted": total, "new": len(new_ids)}


async def _do_dnsx(sf, org_id: str) -> dict:
    hostnames = await _get_asset_hostnames(sf, org_id)
    if not hostnames:
        return {"resolved": 0}

    runner = DnsxRunner(hostnames)
    result = await runner.run(org_id=org_id)

    async with sf() as db:
        updated = await update_dns_records(db, uuid.UUID(org_id), result.results)

    return {"resolved": updated}


async def _do_naabu(sf, org_id: str) -> dict:
    hostnames = await _get_asset_hostnames(sf, org_id)
    if not hostnames:
        return {"scanned": 0}

    runner = NaabuRunner(hostnames)
    result = await runner.run(org_id=org_id)

    async with sf() as db:
        updated = await update_ports(db, uuid.UUID(org_id), result.results)

    return {"ports_found": len(result.results), "hosts_updated": updated}


# Individual tasks (can be called standalone)

@celery.task(bind=True, name="discovery.run_subfinder")
def run_subfinder(self, org_id: str) -> dict:
    return _run_async(_do_subfinder(get_task_session(), org_id))


@celery.task(bind=True, name="discovery.run_asnmap")
def run_asnmap(self, org_id: str) -> dict:
    return _run_async(_do_asnmap(get_task_session(), org_id))


@celery.task(bind=True, name="discovery.run_uncover")
def run_uncover(self, org_id: str) -> dict:
    return _run_async(_do_uncover(get_task_session(), org_id))


@celery.task(bind=True, name="discovery.run_dnsx")
def run_dnsx(self, org_id: str) -> dict:
    return _run_async(_do_dnsx(get_task_session(), org_id))


@celery.task(bind=True, name="discovery.run_naabu")
def run_naabu(self, org_id: str) -> dict:
    return _run_async(_do_naabu(get_task_session(), org_id))


@celery.task(bind=True, name="discovery.run_discovery_chain")
def run_discovery_chain(self, org_id: str, scan_run_id: str | None = None) -> dict:
    """Full discovery chain: subfinder → asnmap → uncover → dnsx → naabu.

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

        results = {}
        steps = [
            ("subfinder", _do_subfinder),
            ("asnmap", _do_asnmap),
            ("uncover", _do_uncover),
            ("dnsx", _do_dnsx),
            ("naabu", _do_naabu),
        ]

        for step_name, step_fn in steps:
            try:
                # Each step gets a fresh session factory
                results[step_name] = await step_fn(get_task_session(), org_id)
            except Exception as e:
                logger.error("discovery step %s failed for org %s: %s", step_name, org_id, e)
                results[step_name] = {"error": str(e)}

        # Post-discovery: detect gone assets
        sf2 = get_task_session()
        async with sf2() as db:
            gone = await detect_gone_assets(db, uuid.UUID(org_id))
            results["gone_assets"] = gone

            if scan_run_id:
                total_found = sum(r.get("upserted", 0) for r in results.values() if isinstance(r, dict))
                total_new = sum(r.get("new", 0) for r in results.values() if isinstance(r, dict))
                await db.execute(
                    text("""
                        UPDATE scan_runs SET
                            status = 'done', finished_at = :now,
                            assets_found = :found, assets_changed = :changed
                        WHERE id = :id
                    """),
                    {
                        "id": scan_run_id,
                        "now": datetime.now(timezone.utc),
                        "found": total_found,
                        "changed": total_new,
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
