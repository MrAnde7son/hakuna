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

import aiohttp
from sqlalchemy import text

from app.tasks.enrichment import ENRICHMENT_STEP_COUNT

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session
from app.ingest.assets import upsert_discovered_hosts, update_dns_records, update_ports
from app.ingest.delta import (
    apply_shodan_observations,
    decay_unseen_assets,
    detect_gone_assets,
    emit_new_asset_events,
)
from app.ingest.liveness import (
    check_dns_resolution,
    create_dangling_dns_finding,
    identify_cloud_provider,
    probe_dangling_asset,
    validate_and_update_assets,
)
from app.ingest.wildcard import detect_wildcard, filter_wildcard_results
from app.ingest.chaos import query_chaos
from app.ingest.crtsh import query_crtsh
from app.ingest.otx_passive_dns import query_otx_passive_dns
from app.ingest.shodan_discovery import query_shodan
from app.runner.base import BaseRunner, batch_hosts, run_batches_parallel, run_batches_parallel_with_outcomes
from app.tasks.scoping import (
    build_stale_clause,
    build_target_scope,
    compose_where,
    count_assets_in_scan_scope,
    load_scan_run_scope,
)
from app.runner.tools import (
    AsnmapRunner,
    DnsxRunner,
    HttpxRunner,
    NaabuRunner,
    PurednsRunner,
    SubfinderRunner,
    UncoverRunner,
)

# Batch sizes for liveness gate. These are lightweight probes (quick naabu
# recheck + httpx HEAD), so batches can be larger than enrichment.
LIVENESS_NAABU_BATCH_SIZE = 1000
LIVENESS_HTTPX_BATCH_SIZE = 1000

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine from sync Celery task context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _get_target_domains(
    sf,
    org_id: str,
    target_scope: str | None = None,
) -> list[str]:
    """Active target domains for an org.

    When `target_scope` is set (a single domain string from scan_runs.target_domain),
    returns only that domain if it's active — effectively restricting a scan
    to one target even though the org has many.
    """
    async with sf() as db:
        if target_scope:
            result = await db.execute(
                text("""
                    SELECT domain FROM target_domains
                    WHERE org_id = :org_id AND active = true AND domain = :td
                """),
                {"org_id": org_id, "td": target_scope},
            )
        else:
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


async def _get_asset_hostnames(
    sf,
    org_id: str,
    target_scope: str | list[str] | None = None,
    apply_stale: bool = False,
    stale_hours: int = 24,
) -> list[str]:
    """Hostnames to process in discovery stages.

    `target_scope` restricts to assets belonging to the given domain(s) —
    apex + subdomains. `apply_stale=True` additionally excludes assets with
    a recent `last_enriched` (within `stale_hours`), so re-scans skip work
    that was already done.
    """
    scope_sql, scope_params = build_target_scope(target_scope)
    stale_sql = build_stale_clause(enabled=apply_stale, stale_hours=stale_hours)
    extra = compose_where(scope_sql, stale_sql)
    params = {"org_id": org_id, **scope_params}
    async with sf() as db:
        result = await db.execute(
            text(f"SELECT hostname FROM assets WHERE org_id = :org_id{extra}"),
            params,
        )
        return [row.hostname for row in result.fetchall()]


async def _get_asset_ids(
    sf,
    org_id: str,
    target_scope: str | list[str] | None = None,
    apply_stale: bool = False,
    stale_hours: int = 24,
) -> list[uuid.UUID]:
    scope_sql, scope_params = build_target_scope(target_scope)
    stale_sql = build_stale_clause(enabled=apply_stale, stale_hours=stale_hours)
    extra = compose_where(scope_sql, stale_sql)
    params = {"org_id": org_id, **scope_params}
    async with sf() as db:
        result = await db.execute(
            text(f"SELECT id FROM assets WHERE org_id = :org_id{extra}"),
            params,
        )
        return [row.id for row in result.fetchall()]


async def _get_assets_with_ports(
    sf,
    org_id: str,
    target_scope: str | list[str] | None = None,
    apply_stale: bool = False,
    stale_hours: int = 24,
) -> list[dict]:
    """Assets that have open ports (for liveness HTTP check).

    PR #2: each asset dict carries ``port_service_types`` so the
    liveness HTTP gate can prefer service identity over the canonical
    {80, 443, 8080, 8443} port set.
    """
    from app.ingest.service_lookup import attach_port_service_types

    scope_sql, scope_params = build_target_scope(target_scope)
    stale_sql = build_stale_clause(enabled=apply_stale, stale_hours=stale_hours)
    extra = compose_where(scope_sql, stale_sql)
    params = {"org_id": org_id, **scope_params}
    async with sf() as db:
        result = await db.execute(
            text(f"""
                SELECT id, hostname, host(ip) as ip, open_ports
                FROM assets WHERE org_id = :org_id AND open_ports IS NOT NULL{extra}
            """),
            params,
        )
        assets = [
            {"id": row.id, "hostname": row.hostname, "ip": row.ip, "open_ports": row.open_ports}
            for row in result.fetchall()
        ]
        await attach_port_service_types(db, assets)
        return assets


# --- Step functions ---


async def _do_subfinder(sf, org_id: str, target_scope: str | None = None) -> dict:
    domains = await _get_target_domains(sf, org_id, target_scope=target_scope)
    all_hosts: list[dict] = []
    for domain in domains:
        runner = SubfinderRunner(domain)
        result = await runner.run(org_id=org_id)
        all_hosts.extend(result.results)

    async with sf() as db:
        total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), all_hosts, "subfinder")
        await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)

    return {"hosts_found": len(all_hosts), "upserted": total, "new": len(new_ids)}


async def _do_wildcard_and_bruteforce(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Extension 1: Detect wildcard DNS and run safe brute force.

    For each target domain:
    1. Detect if wildcard DNS is active
    2. Run puredns (preferred) or skip brute force if unavailable
    3. Filter results matching wildcard fingerprint
    4. Tag wildcard-domain assets
    """
    domains = await _get_target_domains(sf, org_id, target_scope=target_scope)
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
            # WARNING level — this degrades Pipeline A Stage 1 silently if it
            # fires repeatedly. Surfaces in monitoring/Sentry instead of being
            # buried in worker INFO logs.
            logger.warning(
                "org=%s puredns not in PATH — skipping brute force for %s. "
                "Subdomain discovery is degraded to passive sources only. "
                "Check the worker image build (puredns + massdns + resolvers).",
                org_id, domain,
            )

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


async def _do_asnmap(sf, org_id: str, target_scope: str | None = None) -> dict:
    # target_scope is accepted for signature parity with the other step
    # functions (so the chain's _run_step closure can pass it uniformly),
    # but asnmap scans by org name, not by domain, so it ignores the value.
    _ = target_scope  # intentionally unused
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


async def _do_uncover(sf, org_id: str, target_scope: str | None = None) -> dict:
    domains = await _get_target_domains(sf, org_id, target_scope=target_scope)
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


async def _do_shodan(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Query Shodan for hosts pivoting on the org's seed domains.

    Catches shadow-IT and orphan assets that DNS/CT enumeration miss:
    forgotten dev boxes serving a corp cert, hosts with hostnames Shodan
    resolved that the org never published. Skipped silently when no
    SHODAN_API_KEY is configured.
    """
    api_key = settings.shodan_api_key
    if not api_key:
        logger.info("shodan: SHODAN_API_KEY not set — skipping")
        return {"hosts_found": 0, "upserted": 0, "new": 0, "skipped": True}

    domains = await _get_target_domains(sf, org_id, target_scope=target_scope)
    all_hosts: list[dict] = []
    for domain in domains:
        hosts = await query_shodan(api_key, domain)
        all_hosts.extend(hosts)

    if not all_hosts:
        return {"hosts_found": 0, "upserted": 0, "new": 0}

    async with sf() as db:
        total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), all_hosts, "shodan")
        await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)
        # Merge Shodan port/banner/CVE data and synthesize port_change events
        # for newly-observed ports. Lets the audit auto-trigger fire on
        # Shodan-discovered services (exposed SMB, SNMP, datastore, etc.) the
        # same way it fires on naabu-discovered ports — without waiting for an
        # internal port sweep that may never reach an orphan IP.
        shodan_meta = await apply_shodan_observations(db, uuid.UUID(org_id), all_hosts)

    return {
        "hosts_found": len(all_hosts),
        "upserted": total,
        "new": len(new_ids),
        "shodan_observations": shodan_meta,
    }


async def _do_crtsh(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Query certificate transparency logs (crt.sh) for subdomain discovery."""
    domains = await _get_target_domains(sf, org_id, target_scope=target_scope)
    all_hosts: list[dict] = []
    for domain in domains:
        hostnames = await query_crtsh(domain)
        for h in hostnames:
            all_hosts.append({"host": h})

    if not all_hosts:
        return {"hosts_found": 0, "upserted": 0, "new": 0}

    async with sf() as db:
        total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), all_hosts, "crtsh")
        await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)

    return {"hosts_found": len(all_hosts), "upserted": total, "new": len(new_ids)}


async def _do_otx(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Query AlienVault OTX passive DNS for subdomain discovery.

    Catches subdomains that resolved historically but never appeared in a
    public certificate (so crt.sh missed them). No-op when otx_api_key is
    unset — keeps dev environments quiet.
    """
    if not settings.otx_api_key:
        return {"hosts_found": 0, "upserted": 0, "new": 0, "skipped": "no_api_key"}

    domains = await _get_target_domains(sf, org_id, target_scope=target_scope)
    all_hosts: list[dict] = []
    for domain in domains:
        hostnames = await query_otx_passive_dns(domain, settings.otx_api_key)
        for h in hostnames:
            all_hosts.append({"host": h})

    if not all_hosts:
        return {"hosts_found": 0, "upserted": 0, "new": 0}

    async with sf() as db:
        total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), all_hosts, "otx")
        await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)

    return {"hosts_found": len(all_hosts), "upserted": total, "new": len(new_ids)}


async def _do_chaos(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Query ProjectDiscovery Chaos for curated bug-bounty subdomains.

    Distinct from crt.sh (CT-only) and OTX (resolved-only): Chaos pools
    subdomains seen across years of bug-bounty recon, often catching names
    no other free source surfaces. No-op when chaos_api_key is unset.
    """
    if not settings.chaos_api_key:
        return {"hosts_found": 0, "upserted": 0, "new": 0, "skipped": "no_api_key"}

    domains = await _get_target_domains(sf, org_id, target_scope=target_scope)
    all_hosts: list[dict] = []
    for domain in domains:
        hostnames = await query_chaos(domain, settings.chaos_api_key)
        for h in hostnames:
            all_hosts.append({"host": h})

    if not all_hosts:
        return {"hosts_found": 0, "upserted": 0, "new": 0}

    async with sf() as db:
        total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), all_hosts, "chaos")
        await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)

    return {"hosts_found": len(all_hosts), "upserted": total, "new": len(new_ids)}


async def _do_dnsx(sf, org_id: str, target_scope: str | None = None) -> dict:
    # Staleness filter: skip assets that were already enriched within the last
    # 24h. First-ever discovery still runs because last_enriched is NULL.
    hostnames = await _get_asset_hostnames(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not hostnames:
        logger.info("org=%s dnsx: no fresh assets to resolve (all within staleness window)", org_id)
        return {"resolved": 0, "skipped_fresh": True}

    # dnsx is fast but can still stall on 10k+ hosts; batch defensively and
    # run batches in parallel bounded by discovery_batch_concurrency.
    batches = batch_hosts(hostnames, 2000)
    per_batch_timeout = BaseRunner.timeout_for_host_count(2000, per_host_seconds=0.2)

    def _build(batch):
        r = DnsxRunner(batch)
        r.timeout = per_batch_timeout
        return r

    all_results = await run_batches_parallel(
        build_runner=_build,
        batches=batches,
        org_id=org_id,
        concurrency=settings.discovery_batch_concurrency,
        stage_name="dnsx",
    )

    async with sf() as db:
        total_updated = await update_dns_records(db, uuid.UUID(org_id), all_results)

    return {"resolved": total_updated, "batches": len(batches)}


async def _do_naabu(sf, org_id: str, target_scope: str | None = None) -> dict:
    hostnames = await _get_asset_hostnames(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not hostnames:
        logger.info("org=%s naabu: no fresh assets to port-scan (all within staleness window)", org_id)
        return {"scanned": 0, "skipped_fresh": True}

    batches = batch_hosts(hostnames, 1000)
    per_host_seconds = (
        settings.naabu_per_host_seconds_top1000
        if settings.naabu_use_top1000
        else 0.5
    )
    per_batch_timeout = BaseRunner.timeout_for_host_count(1000, per_host_seconds=per_host_seconds)
    logger.info("org=%s naabu hosts=%d batches=%d concurrency=%d per_batch_timeout=%ds top1000=%s",
                org_id, len(hostnames), len(batches),
                settings.discovery_batch_concurrency, per_batch_timeout,
                settings.naabu_use_top1000)

    outcomes = await run_batches_parallel_with_outcomes(
        build_runner=lambda batch: NaabuRunner(batch, timeout=per_batch_timeout),
        batches=batches,
        org_id=org_id,
        concurrency=settings.discovery_batch_concurrency,
        stage_name="naabu",
    )

    all_results: list[dict] = []
    scanned_hosts: list[str] = []
    failed_hosts: list[str] = []
    for o in outcomes:
        if o.success:
            all_results.extend(o.results)
            scanned_hosts.extend(o.batch_input)
        else:
            failed_hosts.extend(o.batch_input)

    if failed_hosts:
        logger.warning("org=%s naabu: %d hosts in failed/timed-out batches",
                       org_id, len(failed_hosts))

    async with sf() as db:
        updated = await update_ports(
            db, uuid.UUID(org_id), all_results,
            scanned_hosts=scanned_hosts, failed_hosts=failed_hosts,
        )

    return {
        "ports_found": len(all_results),
        "hosts_updated": updated,
        "hosts_scanned": len(scanned_hosts),
        "hosts_failed": len(failed_hosts),
        "batches": len(batches),
    }


async def _do_liveness_gate(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Extension 2: Validate asset liveness after port scanning.

    Runs three checks per asset:
    1. DNS resolution (Python socket)
    2. Port response (Naabu recheck with --timeout 3)
    3. HTTP probe (httpx on 80/443/8080/8443)

    Routes assets to confirmed_alive / unconfirmed / likely_dead.
    Creates findings for dangling DNS.
    """
    asset_ids = await _get_asset_ids(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not asset_ids:
        logger.info("org=%s liveness_gate: no fresh assets to validate", org_id)
        return {"validated": 0, "skipped_fresh": True}

    assets_data = await _get_assets_with_ports(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )

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
        naabu_batches = batch_hosts(hosts_with_ports, LIVENESS_NAABU_BATCH_SIZE)
        naabu_timeout = BaseRunner.timeout_for_host_count(
            LIVENESS_NAABU_BATCH_SIZE, per_host_seconds=0.3
        )
        logger.info(
            "org=%s liveness naabu hosts=%d batches=%d concurrency=%d per_batch_timeout=%ds",
            org_id, len(hosts_with_ports), len(naabu_batches),
            settings.discovery_batch_concurrency, naabu_timeout,
        )
        naabu_results = await run_batches_parallel(
            build_runner=lambda batch: NaabuRunner(
                batch, ports=ports_str, timeout_seconds=3, timeout=naabu_timeout,
            ),
            batches=naabu_batches,
            org_id=org_id,
            concurrency=settings.discovery_batch_concurrency,
            stage_name="liveness.naabu",
        )
        for entry in naabu_results:
            host = (entry.get("host") or entry.get("ip") or "").strip().lower()
            if host:
                port_check_results[host] = True

    # Check 3: HTTP probe on web ports
    # PR #2: service_type-driven gate with legacy port fallback.
    # An asset newly stamped as "http"/"https" on 8081 (post PR #1)
    # gets liveness-probed even though 8081 isn't in the canonical set.
    from app.ingest.service_lookup import asset_has_matching_port
    http_check_results: dict[str, bool] = {}
    _HTTP_SERVICE_TYPES = {"http", "https"}
    _HTTP_LEGACY_PORTS = {80, 443, 8080, 8443}
    http_hosts = []
    for a in assets_data:
        if asset_has_matching_port(
            a,
            service_types=_HTTP_SERVICE_TYPES,
            legacy_ports=_HTTP_LEGACY_PORTS,
        ):
            http_hosts.append(a["hostname"])

    if http_hosts:
        httpx_batches = batch_hosts(http_hosts, LIVENESS_HTTPX_BATCH_SIZE)
        httpx_timeout = BaseRunner.timeout_for_host_count(
            LIVENESS_HTTPX_BATCH_SIZE, per_host_seconds=0.5
        )
        logger.info(
            "org=%s liveness httpx hosts=%d batches=%d concurrency=%d per_batch_timeout=%ds",
            org_id, len(http_hosts), len(httpx_batches),
            settings.discovery_batch_concurrency, httpx_timeout,
        )
        httpx_results = await run_batches_parallel(
            build_runner=lambda batch: HttpxRunner(batch, timeout=httpx_timeout),
            batches=httpx_batches,
            org_id=org_id,
            concurrency=settings.discovery_batch_concurrency,
            stage_name="liveness.httpx",
        )
        for entry in httpx_results:
            host = (entry.get("input") or entry.get("host") or "").strip().lower()
            if host and (entry.get("status_code") or entry.get("status-code")):
                http_check_results[host] = True

    # Run validation and update states
    async with get_task_session()() as db:
        summary = await validate_and_update_assets(
            db, uuid.UUID(org_id), asset_ids,
            port_check_results, http_check_results,
        )

    # Create findings for dangling DNS assets. The CNAME from dns_records
    # short-circuits the takeover fingerprint check on known-vulnerable
    # targets (S3, GitHub Pages, etc.). DNS + HTTP probing is gathered
    # across all dangling hosts so we don't pay 5s × N in serial timeouts;
    # the DB writes are then sequential on the single session.
    async with get_task_session()() as db:
        rows = await db.execute(
            text("""
                SELECT id, hostname, dns_records FROM assets
                WHERE org_id = :org_id AND 'dangling_dns' = ANY(tags)
            """),
            {"org_id": org_id},
        )
        dangling_rows = rows.fetchall()

        if dangling_rows:
            connector = aiohttp.TCPConnector(limit=20, ssl=False)
            async with aiohttp.ClientSession(
                connector=connector,
                headers={"User-Agent": "Mozilla/5.0 (compatible; HakunaScanner/1.0 takeover-probe)"},
            ) as http_session:
                sem = asyncio.Semaphore(20)

                async def _probe(row):
                    async with sem:
                        try:
                            cname_targets: list[str] = []
                            dns_records = row.dns_records
                            if isinstance(dns_records, dict):
                                raw_cnames = (
                                    dns_records.get("CNAME") or dns_records.get("cname") or []
                                )
                                if isinstance(raw_cnames, str):
                                    cname_targets = [raw_cnames]
                                elif isinstance(raw_cnames, list):
                                    cname_targets = [str(c) for c in raw_cnames if c]
                            resolved_ips, cloud_provider, evidence = await probe_dangling_asset(
                                row.hostname, cname_targets, http_session,
                            )
                            return row, cname_targets, resolved_ips, cloud_provider, evidence
                        except Exception:
                            logger.exception(
                                "org=%s dangling_dns probe failed for asset=%s host=%s",
                                org_id, row.id, row.hostname,
                            )
                            return None

                # Hard cap on the dangling-probe phase. Each probe is
                # already bounded internally (DNS 5s, HTTP 5s), but a
                # large dangling set under sem(20) plus retries can still
                # take a long time. ~6s/host with a 60s floor gives slack
                # without leaving the gate hung if something misbehaves.
                probe_timeout = max(60.0, len(dangling_rows) * 6.0)
                try:
                    probe_results = await asyncio.wait_for(
                        asyncio.gather(*[_probe(r) for r in dangling_rows]),
                        timeout=probe_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "org=%s dangling_dns probe timed out after %.0fs (n=%d); "
                        "skipping remaining probes",
                        org_id, probe_timeout, len(dangling_rows),
                    )
                    probe_results = []

            for result in probe_results:
                if result is None:
                    continue
                row, cname_targets, resolved_ips, cloud_provider, evidence = result
                try:
                    await create_dangling_dns_finding(
                        db, uuid.UUID(org_id), row.id, row.hostname,
                        resolved_ips, cloud_provider,
                        cname_targets=cname_targets,
                        takeover_evidence=evidence,
                    )
                except Exception:
                    # Per-asset isolation — one bad insert must not abort the
                    # liveness_gate stage, otherwise the recovery loop would
                    # re-dispatch this stage forever.
                    logger.exception(
                        "org=%s dangling_dns finding failed for asset=%s host=%s",
                        org_id, row.id, row.hostname,
                    )

        await db.commit()

    return summary


# --- Individual tasks (can be called standalone) ---


@celery.task(bind=True, name="discovery.run_subfinder")
def run_subfinder(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_subfinder(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="discovery.run_wildcard_bruteforce")
def run_wildcard_bruteforce(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_wildcard_and_bruteforce(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="discovery.run_asnmap")
def run_asnmap(self, org_id: str) -> dict:
    return _run_async(_do_asnmap(get_task_session(), org_id))


@celery.task(bind=True, name="discovery.run_uncover")
def run_uncover(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_uncover(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="discovery.run_shodan")
def run_shodan(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_shodan(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="discovery.run_chaos")
def run_chaos(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_chaos(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="discovery.run_dnsx")
def run_dnsx(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_dnsx(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="discovery.run_naabu")
def run_naabu(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_naabu(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="discovery.run_liveness_gate")
def run_liveness_gate(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_liveness_gate(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="discovery.run_discovery_chain",
             soft_time_limit=14400, time_limit=14700)  # 4h / 4h5min — large scans (10k+ assets)
def run_discovery_chain(self, org_id: str, scan_run_id: str | None = None) -> dict:
    """Full discovery chain, organized into parallel groups.

    Group 1 (parallel): subfinder, wildcard_bruteforce, uncover, crtsh, otx, chaos, shodan
        All three read target_domains and append to assets via idempotent
        upserts. No inter-step dependency, so they run concurrently.

    Group 2 (parallel): dnsx, naabu
        Both read hostnames from assets. dnsx writes dns_records; naabu writes
        open_ports. Disjoint columns → safe to parallelize.

    Group 3 (sequential): liveness_gate
        Depends on open_ports from naabu, so it runs after Group 2.

    asnmap is deliberately NOT in the chain: the ProjectDiscovery binary
    requires a PDCP API key and hangs on an interactive stdin prompt when
    unset, wasting 90s of every scan for zero data. The standalone
    `discovery.run_asnmap` task is still registered for users who have a
    key configured and want to invoke it manually.
    """

    async def _run():
        sf = get_task_session()

        # Step groups — see the docstring above for the rationale.
        step_groups: list[list[tuple[str, object]]] = [
            [
                ("subfinder", _do_subfinder),
                ("wildcard_bruteforce", _do_wildcard_and_bruteforce),
                ("uncover", _do_uncover),
                ("crtsh", _do_crtsh),
                ("otx", _do_otx),
                ("chaos", _do_chaos),
                ("shodan", _do_shodan),
            ],
            [
                ("dnsx", _do_dnsx),
                ("naabu", _do_naabu),
            ],
            [("liveness_gate", _do_liveness_gate)],
        ]
        # Flat list preserved for step-count bookkeeping.
        steps = [s for group in step_groups for s in group]

        # Read the target_domain scope + scan_type from scan_runs in a single
        # query. target_scope is None for nightly full-org scans (no scoping)
        # and a domain string for user-triggered targeted scans.
        target_scope: str | None = None
        async with sf() as db:
            if scan_run_id:
                row = await db.execute(
                    text("SELECT scan_type, target_domain FROM scan_runs WHERE id = :id"),
                    {"id": scan_run_id},
                )
                scan_type_row = row.fetchone()
                total = len(steps)
                if scan_type_row:
                    if scan_type_row.scan_type == "full":
                        total += ENRICHMENT_STEP_COUNT
                    target_scope = scan_type_row.target_domain

                await db.execute(
                    text("""
                        UPDATE scan_runs SET
                            status = 'running', started_at = :now,
                            total_stages = :total, stage_index = 0
                        WHERE id = :id
                    """),
                    {"id": scan_run_id, "now": datetime.now(timezone.utc), "total": total},
                )
                await db.commit()

        # Seed target domains themselves as assets so the base domain is
        # always present even when subdomain enumeration finds nothing.
        seed_domains = await _get_target_domains(sf, org_id, target_scope=target_scope)
        if seed_domains:
            seed_hosts = [{"host": d} for d in seed_domains]
            async with sf() as db:
                total, new_ids = await upsert_discovered_hosts(db, uuid.UUID(org_id), seed_hosts, "seed")
                await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)
            logger.info("org=%s seeded %d target domain(s) as assets (%d new)", org_id, total, len(new_ids))

        results = {}
        stage_log = []

        async def _run_step(step_name: str, step_fn) -> tuple[str, dict, float, Exception | None]:
            """Run a single discovery step, capturing duration + errors."""
            step_start = datetime.now(timezone.utc)
            try:
                out = await step_fn(get_task_session(), org_id, target_scope=target_scope)
                duration = (datetime.now(timezone.utc) - step_start).total_seconds()
                return step_name, out, duration, None
            except Exception as e:
                duration = (datetime.now(timezone.utc) - step_start).total_seconds()
                logger.error("discovery step %s failed for org %s: %s", step_name, org_id, e)
                return step_name, {"error": str(e)}, duration, e

        step_cursor = 0
        for group in step_groups:
            group_names = [name for name, _ in group]
            first_absolute_idx = step_cursor + 1

            if scan_run_id:
                async with get_task_session()() as db:
                    await db.execute(
                        text("""
                            UPDATE scan_runs SET
                                current_stage = :stage, stage_index = :idx,
                                stage_started_at = :now
                            WHERE id = :id
                        """),
                        {
                            "id": scan_run_id,
                            "stage": (
                                group_names[0] if len(group) == 1
                                else "+".join(group_names)
                            )[:64],
                            "idx": first_absolute_idx,
                            "now": datetime.now(timezone.utc),
                        },
                    )
                    await db.commit()

            logger.info("org=%s discovery group starting: %s", org_id, group_names)
            group_outputs = await asyncio.gather(
                *(_run_step(name, fn) for name, fn in group),
                return_exceptions=False,  # _run_step already traps exceptions
            )

            for step_name, out, duration, _err in group_outputs:
                results[step_name] = out
                stage_log.append({
                    "stage": step_name,
                    "status": "error" if _err else "done",
                    "duration_s": round(duration, 1),
                    **({"error": str(_err)} if _err else {}),
                })

            step_cursor += len(group)

            if scan_run_id:
                async with get_task_session()() as db:
                    await db.execute(
                        text("""
                            UPDATE scan_runs SET
                                stage_log = :log, stage_index = :idx
                            WHERE id = :id
                        """),
                        {
                            "id": scan_run_id,
                            "log": json.dumps(stage_log),
                            "idx": step_cursor,
                        },
                    )
                    await db.commit()

        # Post-discovery: decay assets that weren't validated this cycle,
        # then emit asset_gone events for hosts unseen across multiple
        # scans. The decay must run BEFORE detect_gone_assets so the score
        # reflects this scan's outcome before downstream consumers read it.
        sf2 = get_task_session()
        async with sf2() as db:
            decayed = await decay_unseen_assets(db, uuid.UUID(org_id))
            results["liveness_decayed"] = decayed
            gone = await detect_gone_assets(db, uuid.UUID(org_id))
            results["gone_assets"] = gone

            if scan_run_id:
                total_found = sum(r.get("upserted", 0) for r in results.values() if isinstance(r, dict))
                total_new = sum(r.get("new", 0) for r in results.values() if isinstance(r, dict))

                # Check if enrichment follows (full scan) — don't mark done yet
                row = await db.execute(
                    text("SELECT scan_type FROM scan_runs WHERE id = :id"),
                    {"id": scan_run_id},
                )
                scan_type_row = row.fetchone()
                is_full = scan_type_row and scan_type_row.scan_type == "full"

                if is_full:
                    # Discovery phase done, enrichment will continue
                    await db.execute(
                        text("""
                            UPDATE scan_runs SET
                                assets_found = :found, assets_changed = :changed,
                                stage_log = :log
                            WHERE id = :id
                        """),
                        {
                            "id": scan_run_id,
                            "found": total_found,
                            "changed": total_new,
                            "log": json.dumps(stage_log),
                        },
                    )
                else:
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
        # Best-effort partial-progress count: if upstream stages already
        # populated assets before the failure, surface that on the UI
        # instead of leaving assets_found at the default 0.
        partial = None
        try:
            partial = await count_assets_in_scan_scope(db, scan_run_id)
        except Exception:
            logger.exception("scan_run=%s partial asset count failed", scan_run_id)

        if partial is None:
            await db.execute(
                text("UPDATE scan_runs SET status = 'failed', finished_at = :now, error = :err WHERE id = :id"),
                {"id": scan_run_id, "now": datetime.now(timezone.utc), "err": error},
            )
        else:
            await db.execute(
                text("""
                    UPDATE scan_runs
                    SET status = 'failed', finished_at = :now, error = :err,
                        assets_found = :found
                    WHERE id = :id
                """),
                {
                    "id": scan_run_id,
                    "now": datetime.now(timezone.utc),
                    "err": error,
                    "found": partial,
                },
            )
        await db.commit()
