"""Celery tasks for the discovery pipeline.

Pipeline A task graph (after extensions):
  subfinder → wildcard_detect → puredns_bruteforce → naabu → liveness_gate
"""

import asyncio
import json
import logging
import shutil
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session
from app.ingest.assets import upsert_discovered_hosts, update_dns_records, update_ports
from app.ingest.delta import emit_new_asset_events, detect_gone_assets
from app.ingest.liveness import (
    check_dns_resolution,
    create_dangling_dns_finding,
    identify_cloud_provider,
    validate_and_update_assets,
)
from app.ingest.wildcard import detect_wildcard, filter_wildcard_results
from app.runner.tools import (
    AsnmapRunner,
    DnsxRunner,
    HttpxRunner,
    NaabuRunner,
    PurednsRunner,
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


async def _get_asset_ids(sf, org_id: str) -> list[uuid.UUID]:
    async with sf() as db:
        result = await db.execute(
            text("SELECT id FROM assets WHERE org_id = :org_id"),
            {"org_id": org_id},
        )
        return [row.id for row in result.fetchall()]


async def _get_assets_with_ports(sf, org_id: str) -> list[dict]:
    """Get assets that have open ports (for liveness HTTP check)."""
    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT id, hostname, host(ip) as ip, open_ports
                FROM assets WHERE org_id = :org_id AND open_ports IS NOT NULL
            """),
            {"org_id": org_id},
        )
        return [
            {"id": row.id, "hostname": row.hostname, "ip": row.ip, "open_ports": row.open_ports}
            for row in result.fetchall()
        ]


# --- Step functions ---


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


async def _do_wildcard_and_bruteforce(sf, org_id: str) -> dict:
    """Extension 1: Detect wildcard DNS and run safe brute force.

    For each target domain:
    1. Detect if wildcard DNS is active
    2. Run puredns (preferred) or skip brute force if unavailable
    3. Filter results matching wildcard fingerprint
    4. Tag wildcard-domain assets
    """
    domains = await _get_target_domains(sf, org_id)
    total_new = 0
    total_bruteforced = 0
    total_filtered = 0
    wildcard_domains = []

    has_puredns = shutil.which("puredns") is not None

    for domain in domains:
        # Step 1: Wildcard detection
        fingerprint = detect_wildcard(domain)

        if fingerprint.is_wildcard:
            wildcard_domains.append(domain)
            logger.info("org=%s domain=%s wildcard detected, IPs=%s", org_id, domain, fingerprint.wildcard_ips)

        # Step 2: Brute force (puredns handles wildcard filtering natively)
        brute_hosts: list[dict] = []
        if has_puredns:
            runner = PurednsRunner(domain)
            result = await runner.run(org_id=org_id)
            brute_hosts = result.results
            total_bruteforced += len(brute_hosts)

            # puredns already filters wildcards, but double-check if needed
            if fingerprint.is_wildcard:
                brute_hosts, removed = filter_wildcard_results(brute_hosts, fingerprint)
                total_filtered += removed
        else:
            logger.info("org=%s puredns not available, skipping brute force for %s", org_id, domain)

        if not brute_hosts:
            continue

        # Step 3: Upsert discovered hosts
        async with sf() as db:
            upserted, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), brute_hosts, "puredns")
            await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)
            total_new += len(new_ids)

    # Step 4: Tag assets on wildcard domains
    if wildcard_domains:
        async with sf() as db:
            for wc_domain in wildcard_domains:
                await db.execute(
                    text("""
                        UPDATE assets SET tags = array_append(
                            array_remove(tags, 'wildcard_domain'), 'wildcard_domain'
                        )
                        WHERE org_id = :org_id AND hostname LIKE :pattern
                    """),
                    {"org_id": org_id, "pattern": f"%.{wc_domain}"},
                )
            await db.commit()

    return {
        "wildcard_domains": wildcard_domains,
        "bruteforced": total_bruteforced,
        "filtered": total_filtered,
        "new": total_new,
    }


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


async def _do_liveness_gate(sf, org_id: str) -> dict:
    """Extension 2: Validate asset liveness after port scanning.

    Runs three checks per asset:
    1. DNS resolution (Python socket)
    2. Port response (Naabu recheck with --timeout 3)
    3. HTTP probe (httpx on 80/443/8080/8443)

    Routes assets to confirmed_alive / unconfirmed / likely_dead.
    Creates findings for dangling DNS.
    """
    asset_ids = await _get_asset_ids(sf, org_id)
    if not asset_ids:
        return {"validated": 0}

    assets_data = await _get_assets_with_ports(sf, org_id)

    # Check 2: Quick Naabu recheck on known ports
    port_check_results: dict[str, bool] = {}
    hosts_with_ports = [a["hostname"] for a in assets_data if a.get("open_ports")]
    if hosts_with_ports:
        # Build port list from known ports
        all_ports = set()
        host_port_map = {}
        for a in assets_data:
            if a.get("open_ports"):
                host_port_map[a["hostname"]] = a["open_ports"]
                for p in a["open_ports"]:
                    all_ports.add(p)

        ports_str = ",".join(str(p) for p in sorted(all_ports))
        runner = NaabuRunner(hosts_with_ports, ports=ports_str, timeout_seconds=3)
        result = await runner.run(org_id=org_id)

        for entry in result.results:
            host = (entry.get("host") or entry.get("ip") or "").strip().lower()
            if host:
                port_check_results[host] = True

    # Check 3: HTTP probe on web ports
    http_check_results: dict[str, bool] = {}
    HTTP_PORTS = {80, 443, 8080, 8443}
    http_hosts = []
    for a in assets_data:
        ports = set(a.get("open_ports") or [])
        if ports & HTTP_PORTS:
            http_hosts.append(a["hostname"])

    if http_hosts:
        runner = HttpxRunner(http_hosts)
        result = await runner.run(org_id=org_id)
        for entry in result.results:
            host = (entry.get("input") or entry.get("host") or "").strip().lower()
            if host and entry.get("status_code") or entry.get("status-code"):
                http_check_results[host] = True

    # Run validation and update states
    async with get_task_session()() as db:
        summary = await validate_and_update_assets(
            db, uuid.UUID(org_id), asset_ids,
            port_check_results, http_check_results,
        )

    # Create findings for dangling DNS assets
    async with get_task_session()() as db:
        rows = await db.execute(
            text("""
                SELECT id, hostname FROM assets
                WHERE org_id = :org_id AND 'dangling_dns' = ANY(tags)
            """),
            {"org_id": org_id},
        )
        for row in rows.fetchall():
            resolved_ips = check_dns_resolution(row.hostname)
            cloud_provider = None
            for ip in resolved_ips:
                cloud_provider = identify_cloud_provider(ip)
                if cloud_provider:
                    break
            await create_dangling_dns_finding(
                db, uuid.UUID(org_id), row.id, row.hostname, resolved_ips, cloud_provider,
            )
        await db.commit()

    return summary


# --- Individual tasks (can be called standalone) ---


@celery.task(bind=True, name="discovery.run_subfinder")
def run_subfinder(self, org_id: str) -> dict:
    return _run_async(_do_subfinder(get_task_session(), org_id))


@celery.task(bind=True, name="discovery.run_wildcard_bruteforce")
def run_wildcard_bruteforce(self, org_id: str) -> dict:
    return _run_async(_do_wildcard_and_bruteforce(get_task_session(), org_id))


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


@celery.task(bind=True, name="discovery.run_liveness_gate")
def run_liveness_gate(self, org_id: str) -> dict:
    return _run_async(_do_liveness_gate(get_task_session(), org_id))


@celery.task(bind=True, name="discovery.run_discovery_chain")
def run_discovery_chain(self, org_id: str, scan_run_id: str | None = None) -> dict:
    """Full discovery chain:
    subfinder → wildcard_bruteforce → asnmap → uncover → dnsx → naabu → liveness_gate.

    Calls runners directly (no subtask dispatch) to avoid Celery deadlocks.
    """

    async def _run():
        sf = get_task_session()

        steps = [
            ("subfinder", _do_subfinder),
            ("wildcard_bruteforce", _do_wildcard_and_bruteforce),
            ("asnmap", _do_asnmap),
            ("uncover", _do_uncover),
            ("dnsx", _do_dnsx),
            ("naabu", _do_naabu),
            ("liveness_gate", _do_liveness_gate),
        ]

        async with sf() as db:
            if scan_run_id:
                await db.execute(
                    text("""
                        UPDATE scan_runs SET
                            status = 'running', started_at = :now,
                            total_stages = :total, stage_index = 0
                        WHERE id = :id
                    """),
                    {"id": scan_run_id, "now": datetime.now(timezone.utc), "total": len(steps)},
                )
                await db.commit()

        results = {}
        stage_log = []

        for i, (step_name, step_fn) in enumerate(steps):
            step_start = datetime.now(timezone.utc)

            # Update current stage
            if scan_run_id:
                async with get_task_session()() as db:
                    await db.execute(
                        text("""
                            UPDATE scan_runs SET
                                current_stage = :stage, stage_index = :idx,
                                stage_started_at = :now
                            WHERE id = :id
                        """),
                        {"id": scan_run_id, "stage": step_name, "idx": i + 1, "now": step_start},
                    )
                    await db.commit()

            try:
                results[step_name] = await step_fn(get_task_session(), org_id)
                duration = (datetime.now(timezone.utc) - step_start).total_seconds()
                stage_log.append({"stage": step_name, "status": "done", "duration_s": round(duration, 1)})
            except Exception as e:
                logger.error("discovery step %s failed for org %s: %s", step_name, org_id, e)
                results[step_name] = {"error": str(e)}
                duration = (datetime.now(timezone.utc) - step_start).total_seconds()
                stage_log.append({"stage": step_name, "status": "error", "duration_s": round(duration, 1), "error": str(e)})

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
                            assets_found = :found, assets_changed = :changed,
                            current_stage = NULL, stage_log = :log
                        WHERE id = :id
                    """),
                    {
                        "id": scan_run_id,
                        "now": datetime.now(timezone.utc),
                        "found": total_found,
                        "changed": total_new,
                        "log": json.dumps(stage_log),
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
