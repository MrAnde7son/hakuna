"""Celery tasks for the enrichment pipeline.

Pipeline A enrichment (runs on confirmed_alive assets only):
  tlsx (per-port) → httpx (full JSON) → cdncheck → katana → nmap dispatch
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

ENRICHMENT_STEP_COUNT = 6  # tlsx, httpx, cdncheck, js_fingerprint, katana, nmap_dispatch

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session

from app.ingest.assets import update_enrichment, update_tls, update_cdn
from app.ingest.delta import detect_cert_expiring, auto_tag_assets, detect_changes
from app.ingest.enrichment import (
    JS_FINGERPRINT_ENABLED,
    store_httpx_enrichment,
    store_js_fingerprints,
    store_katana_endpoints,
    store_tlsx_per_port,
)
from app.ingest.js_fingerprint import fingerprint_assets
from app.runner.base import BaseRunner, batch_hosts, run_batches_parallel
from app.runner.tools import CdncheckRunner, HttpxRunner, KatanaRunner, TlsxRunner
from app.tasks.scoping import (
    build_stale_clause,
    build_target_scope,
    compose_where,
)

# Batch sizes tuned for 10k+ host scans. Each batch runs as an independent
# subprocess invocation with its own timeout, so a slow host in one batch
# can't stall the others. Multiple batches run in parallel bounded by
# settings.enrichment_batch_concurrency.
TLSX_BATCH_SIZE = 500
HTTPX_BATCH_SIZE = 500
KATANA_BATCH_SIZE = 200
CDNCHECK_BATCH_SIZE = 2000

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _get_confirmed_alive_hostnames(
    sf,
    org_id: str,
    target_scope: str | list[str] | None = None,
    apply_stale: bool = False,
    stale_hours: int = 24,
) -> list[str]:
    """Get hostnames of confirmed_alive or HTTP-responsive unconfirmed assets.

    `target_scope` restricts results to a single target domain (apex +
    subdomains). `apply_stale=True` additionally excludes assets enriched
    within the last `stale_hours` so re-scans skip already-processed hosts.
    """
    scope_sql, scope_params = build_target_scope(target_scope)
    stale_sql = build_stale_clause(enabled=apply_stale, stale_hours=stale_hours)
    extra = compose_where(scope_sql, stale_sql)
    params = {"org_id": org_id, **scope_params}
    async with sf() as db:
        result = await db.execute(
            text(f"""
                SELECT hostname FROM assets
                WHERE org_id = :org_id
                  AND (liveness_state = 'confirmed_alive'
                       OR (liveness_state = 'unconfirmed' AND http_status IS NOT NULL))
                  {extra}
            """),
            params,
        )
        return [row.hostname for row in result.fetchall()]


async def _get_confirmed_alive_assets(
    sf,
    org_id: str,
    target_scope: str | list[str] | None = None,
    apply_stale: bool = False,
    stale_hours: int = 24,
) -> list[dict]:
    """Get confirmed_alive (or HTTP-responsive unconfirmed) assets with ports for enrichment routing."""
    scope_sql, scope_params = build_target_scope(target_scope)
    stale_sql = build_stale_clause(enabled=apply_stale, stale_hours=stale_hours)
    extra = compose_where(scope_sql, stale_sql)
    params = {"org_id": org_id, **scope_params}
    async with sf() as db:
        result = await db.execute(
            text(f"""
                SELECT id, hostname, host(ip) as ip, open_ports, cdn_provider, tags
                FROM assets
                WHERE org_id = :org_id
                  AND (liveness_state = 'confirmed_alive'
                       OR (liveness_state = 'unconfirmed' AND http_status IS NOT NULL))
                  {extra}
            """),
            params,
        )
        return [
            {
                "id": row.id,
                "hostname": row.hostname,
                "ip": row.ip,
                "open_ports": row.open_ports or [],
                "cdn_provider": row.cdn_provider,
                "tags": row.tags or [],
            }
            for row in result.fetchall()
        ]


async def _get_asset_snapshot(
    sf,
    org_id: str,
    target_scope: str | list[str] | None = None,
) -> list[dict]:
    """Snapshot of asset state *before* enrichment so post-run delta detection
    can compute what changed. Scope this to the same target as the scan so
    the delta doesn't report "removed" for every asset of other targets.
    """
    scope_sql, scope_params = build_target_scope(target_scope)
    extra = compose_where(scope_sql)
    params = {"org_id": org_id, **scope_params}
    async with sf() as db:
        result = await db.execute(
            text(f"""
                SELECT id, hostname, host(ip) as ip, open_ports, tech_stack, tls_cert
                FROM assets WHERE org_id = :org_id{extra}
            """),
            params,
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


async def _do_tlsx(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Extension 3: Run tlsx on all open ports (not just 443) for confirmed_alive assets.

    For large scans (10k+ targets), tlsx is invoked in batches of TLSX_BATCH_SIZE
    so a single invocation never hits the per-tool timeout wall.
    """
    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not assets:
        logger.info("org=%s tlsx: no fresh assets to inspect", org_id)
        return {"inspected": 0, "skipped_fresh": True}

    # Build host:port list for all open ports
    tlsx_targets: list[str] = []
    for asset in assets:
        hostname = asset["hostname"]
        ports = asset.get("open_ports", [])
        if ports:
            for port in ports:
                tlsx_targets.append(f"{hostname}:{port}")
        else:
            # Default to 443
            tlsx_targets.append(f"{hostname}:443")

    batches = batch_hosts(tlsx_targets, TLSX_BATCH_SIZE)
    per_batch_timeout = BaseRunner.timeout_for_host_count(TLSX_BATCH_SIZE)
    logger.info("org=%s tlsx targets=%d batches=%d concurrency=%d per_batch_timeout=%ds",
                org_id, len(tlsx_targets), len(batches),
                settings.enrichment_batch_concurrency, per_batch_timeout)

    all_results = await run_batches_parallel(
        build_runner=lambda batch: TlsxRunner(batch, timeout=per_batch_timeout),
        batches=batches,
        org_id=org_id,
        concurrency=settings.enrichment_batch_concurrency,
        stage_name="tlsx",
    )

    # Store per-port TLS data and collect SANs for discovery feedback
    async with sf() as db:
        per_port_result = await store_tlsx_per_port(db, uuid.UUID(org_id), all_results)

    # Also update the legacy tls_cert field on the asset
    async with sf() as db:
        await update_tls(db, uuid.UUID(org_id), all_results)

    return {
        "inspected": len(all_results),
        "per_port_updated": per_port_result["updated"],
        "new_sans_discovered": per_port_result["new_sans"],
        "batches": len(batches),
    }


async def _do_httpx(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Extension 3: Run httpx with full flags + screenshots on confirmed_alive assets.

    For large scans, hostnames are batched into HTTPX_BATCH_SIZE chunks; each batch
    runs in its own subprocess with a scaled timeout, and multiple batches run in
    parallel bounded by settings.enrichment_batch_concurrency.

    Screenshots (headless Chromium) are ~1s/host — disabled on scans above
    settings.screenshot_max_hosts to keep wall time reasonable.
    """
    hostnames = await _get_confirmed_alive_hostnames(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not hostnames:
        logger.info("org=%s httpx: no fresh assets to probe", org_id)
        return {"probed": 0, "skipped_fresh": True}

    ss_dir = os.path.join(settings.screenshot_dir, str(org_id))
    batches = batch_hosts(hostnames, HTTPX_BATCH_SIZE)
    # 2.5s/host per batch accounts for slow CDN redirect chains and the
    # -follow-redirects flag — worker logs showed wordpress.org 500-host
    # batches hitting the previous 600s ceiling mid-chain.
    per_batch_timeout = BaseRunner.timeout_for_host_count(HTTPX_BATCH_SIZE, per_host_seconds=2.5)
    screenshots_enabled = len(hostnames) <= settings.screenshot_max_hosts
    logger.info(
        "org=%s httpx hosts=%d batches=%d concurrency=%d screenshots=%s per_batch_timeout=%ds",
        org_id, len(hostnames), len(batches),
        settings.enrichment_batch_concurrency, screenshots_enabled, per_batch_timeout,
    )

    def _build(batch):
        return HttpxRunner(
            batch,
            screenshots=screenshots_enabled,
            screenshot_dir=ss_dir if screenshots_enabled else None,
            timeout=per_batch_timeout,
        )

    all_results = await run_batches_parallel(
        build_runner=_build,
        batches=batches,
        org_id=org_id,
        concurrency=settings.enrichment_batch_concurrency,
        stage_name="httpx",
    )

    # If we enabled screenshots but got zero results, retry once without
    # screenshots — browser may be missing in this environment.
    if screenshots_enabled and not all_results:
        logger.warning("org=%s httpx produced no results with screenshots; retrying without", org_id)
        all_results = await run_batches_parallel(
            build_runner=lambda batch: HttpxRunner(batch, screenshots=False, timeout=per_batch_timeout),
            batches=batches,
            org_id=org_id,
            concurrency=settings.enrichment_batch_concurrency,
            stage_name="httpx",
        )

    async with sf() as db:
        # Legacy enrichment (http_status, http_title, tech_stack, etc.)
        updated = await update_enrichment(db, uuid.UUID(org_id), all_results)

    # Store full httpx JSON as AssetEnrichment records.
    #
    # The CPE inference layer inside store_httpx_enrichment also wants the TLS
    # cert for the host (subject CN can identify products like Jenkins). tlsx
    # runs before httpx in the chain (see run_enrichment_chain step ordering),
    # so the certs are already in asset_ports.tls_cert. Build a per-asset map
    # once up front to avoid N round-trips inside the loop.
    async with sf() as db:
        for entry in all_results:
            host = (entry.get("input") or entry.get("host") or "").strip().lower()
            if not host:
                continue
            row = await db.execute(
                text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
                {"org_id": org_id, "host": host},
            )
            asset_row = row.fetchone()
            if not asset_row:
                continue

            # Look up the TLS cert for the port this httpx entry hit.
            tls_cert = None
            url = entry.get("url") or ""
            scheme = url.split("://", 1)[0].lower() if "://" in url else ""
            port = entry.get("port") or (443 if scheme == "https" else 80 if scheme == "http" else None)
            if port:
                tls_row = await db.execute(
                    text("SELECT tls_cert FROM asset_ports WHERE asset_id = :aid AND port = :p"),
                    {"aid": asset_row.id, "p": int(port)},
                )
                tr = tls_row.fetchone()
                if tr and tr.tls_cert:
                    tls_cert = tr.tls_cert

            await store_httpx_enrichment(
                db, uuid.UUID(org_id), asset_row.id, entry, tls_cert=tls_cert,
            )
        await db.commit()

    return {"probed": len(all_results), "updated": updated, "batches": len(batches)}


async def _do_js_fingerprint(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Run JS library fingerprinting on confirmed_alive HTTP assets.

    Fetches HTML pages, parses <script> tags, downloads JS files, and matches
    version patterns to detect client-side libraries (jQuery, Moment.js, etc.)
    that httpx's Wappalyzer misses. Results are merged into asset_ports.cpe_list.
    """
    if not JS_FINGERPRINT_ENABLED:
        return {"fingerprinted": 0, "disabled": True}

    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not assets:
        logger.info("org=%s js_fingerprint: no fresh assets to fingerprint", org_id)
        return {"fingerprinted": 0, "skipped_fresh": True}

    # Filter to assets with HTTP ports (CDN assets are fine — we fetch the
    # actual page content, so Cloudflare etc. don't interfere).
    HTTP_PORTS = {80, 443, 8080, 8443}
    http_assets = []
    for asset in assets:
        ports = set(asset.get("open_ports") or [])
        if ports & HTTP_PORTS:
            http_assets.append(asset)

    if not http_assets:
        return {"fingerprinted": 0}

    logger.info("org=%s js_fingerprint: scanning %d assets", org_id, len(http_assets))

    js_results = await fingerprint_assets(
        http_assets,
        concurrency=settings.js_fingerprint_concurrency,
        connect_timeout=settings.js_fingerprint_connect_timeout,
    )

    # Store results — merge into asset_ports.cpe_list.
    async with sf() as db:
        store_result = await store_js_fingerprints(db, uuid.UUID(org_id), js_results)

    total_libs = sum(len(dets) for dets in js_results.values())
    return {
        "fingerprinted": len(http_assets),
        "assets_with_js": len(js_results),
        "total_libs_detected": total_libs,
        **store_result,
    }


async def _do_cdncheck(sf, org_id: str, target_scope: str | None = None) -> dict:
    hostnames = await _get_confirmed_alive_hostnames(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not hostnames:
        logger.info("org=%s cdncheck: no fresh assets to check", org_id)
        return {"checked": 0, "skipped_fresh": True}

    # cdncheck is lightweight (single lookup per host) so the batch can be bigger.
    batches = batch_hosts(hostnames, CDNCHECK_BATCH_SIZE)
    all_results = await run_batches_parallel(
        build_runner=lambda batch: CdncheckRunner(batch),
        batches=batches,
        org_id=org_id,
        concurrency=settings.enrichment_batch_concurrency,
        stage_name="cdncheck",
    )

    async with sf() as db:
        updated = await update_cdn(db, uuid.UUID(org_id), all_results)

    return {"checked": len(all_results), "updated": updated, "batches": len(batches)}


async def _do_katana(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Extension 3: Run katana on confirmed_alive HTTP/HTTPS assets (skip CDN)."""
    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not assets:
        logger.info("org=%s katana: no fresh assets to crawl", org_id)
        return {"crawled": 0, "skipped_fresh": True}

    HTTP_PORTS = {80, 443, 8080, 8443}
    targets: list[str] = []
    target_asset_map: dict[str, uuid.UUID] = {}

    for asset in assets:
        # Skip CDN assets
        if asset.get("cdn_provider") or "cdn" in (asset.get("tags") or []):
            continue

        ports = set(asset.get("open_ports") or [])
        if ports & HTTP_PORTS:
            hostname = asset["hostname"]
            # Prefer HTTPS if 443 is open
            if 443 in ports:
                url = f"https://{hostname}"
            else:
                url = f"http://{hostname}"
            targets.append(url)
            target_asset_map[hostname] = asset["id"]

    if not targets:
        return {"crawled": 0}

    # Katana is the slowest per-host tool — a small batch size keeps each
    # invocation well under the scaled timeout. Batches run in parallel.
    batches = batch_hosts(targets, KATANA_BATCH_SIZE)
    per_batch_timeout = BaseRunner.timeout_for_host_count(KATANA_BATCH_SIZE, per_host_seconds=2.0)
    logger.info("org=%s katana targets=%d batches=%d concurrency=%d per_batch_timeout=%ds",
                org_id, len(targets), len(batches),
                settings.enrichment_batch_concurrency, per_batch_timeout)

    all_katana_results = await run_batches_parallel(
        build_runner=lambda batch: KatanaRunner(batch, timeout=per_batch_timeout),
        batches=batches,
        org_id=org_id,
        concurrency=settings.enrichment_batch_concurrency,
        stage_name="katana",
    )

    # Group results by asset
    asset_results: dict[uuid.UUID, list[dict]] = {}
    for entry in all_katana_results:
        url = entry.get("request", {}).get("endpoint") or entry.get("endpoint") or entry.get("url") or ""
        if not url:
            continue
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
        except Exception:
            continue

        asset_id = target_asset_map.get(hostname)
        if asset_id:
            asset_results.setdefault(asset_id, []).append(entry)

    total_endpoints = 0
    total_auth = 0
    all_new_hostnames: list[str] = []

    for asset_id, entries in asset_results.items():
        async with sf() as db:
            katana_result = await store_katana_endpoints(db, uuid.UUID(org_id), asset_id, entries)
            total_endpoints += katana_result["endpoints_stored"]
            total_auth += katana_result["auth_pages"]
            all_new_hostnames.extend(katana_result["new_hostnames"])

    # Tag assets with auth pages
    if total_auth > 0:
        async with sf() as db:
            await db.execute(
                text("""
                    UPDATE assets SET tags = array_append(
                        array_remove(tags, 'auth_page'), 'auth_page'
                    )
                    WHERE id IN (
                        SELECT DISTINCT asset_id FROM asset_endpoints WHERE is_auth_page = true
                    ) AND org_id = :org_id
                """),
                {"org_id": org_id},
            )
            await db.commit()

    return {
        "crawled": len(targets),
        "endpoints": total_endpoints,
        "auth_pages": total_auth,
        "new_hostnames": all_new_hostnames,
    }


async def _dispatch_nmap(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Extension 4: Dispatch nmap_enrich_asset tasks for confirmed_alive assets.

    Note: apply_stale is NOT set here because nmap_enrich_asset has its own
    idempotency (it checks the asset's nmap-specific freshness inside the
    sub-task). We scope to the target domain but let the sub-task decide
    whether to actually re-scan.
    """
    from app.tasks.nmap import nmap_enrich_asset

    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    dispatched = 0

    for asset in assets:
        if asset.get("open_ports"):
            nmap_enrich_asset.apply_async(
                args=[str(asset["id"])],
                queue="nmap_queue",
            )
            dispatched += 1

    logger.info("org=%s nmap dispatched=%d assets to nmap_queue", org_id, dispatched)
    return {"nmap_dispatched": dispatched}


# --- Individual tasks ---


@celery.task(bind=True, name="enrichment.run_js_fingerprint")
def run_js_fingerprint(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_js_fingerprint(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_httpx")
def run_httpx(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_httpx(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_tlsx")
def run_tlsx(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_tlsx(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_cdncheck")
def run_cdncheck(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_cdncheck(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_katana")
def run_katana(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_katana(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_enrichment_chain",
             soft_time_limit=14400, time_limit=14700)  # 4h / 4h5min — large scans (10k+ assets)
def run_enrichment_chain(self, org_id: str, scan_run_id: str | None = None) -> dict:
    """Full enrichment chain (confirmed_alive assets only):
    tlsx → httpx → cdncheck → katana → nmap_dispatch → auto-tag → delta.
    """

    async def _run():
        sf = get_task_session()

        # Enrichment chain is organized into parallel groups. Steps inside a
        # group run concurrently (via asyncio.gather); groups run sequentially.
        # Total logical stage count is still ENRICHMENT_STEP_COUNT = 5 so that
        # discovery's base_stage_index math keeps working.
        #
        # Group 1 runs tlsx/httpx/cdncheck together to collapse the slowest
        # three stages into ~max(tlsx, httpx) wall time. Tradeoff: httpx's
        # opportunistic TLS-cert lookup (for CPE inference) may miss certs
        # that tlsx hasn't written yet — acceptable since most CPE hits
        # come from banner/body/header signals, not cert subject.
        step_groups: list[list[tuple[str, object]]] = [
            [
                ("tlsx", _do_tlsx),
                ("httpx", _do_httpx),
                ("cdncheck", _do_cdncheck),
            ],
            [
                ("js_fingerprint", _do_js_fingerprint),
                ("katana", _do_katana),
            ],
            [("nmap_dispatch", None)],  # handled separately
        ]
        # Flat list preserved for step-count bookkeeping.
        steps = [s for group in step_groups for s in group]

        # Check if continuing from a prior phase (e.g., discovery → enrichment
        # in a full scan) and read the target_domain scope for the scan run.
        base_stage_index = 0
        prior_log = []
        target_scope: str | None = None
        async with sf() as db:
            if scan_run_id:
                row = await db.execute(
                    text("""
                        SELECT stage_index, total_stages, stage_log, target_domain
                        FROM scan_runs WHERE id = :id
                    """),
                    {"id": scan_run_id},
                )
                existing = row.fetchone()
                if existing and existing.total_stages > 0:
                    # Continuing from discovery — offset step indices
                    base_stage_index = existing.total_stages - len(steps)
                    if existing.stage_log:
                        prior_log = existing.stage_log if isinstance(existing.stage_log, list) else json.loads(existing.stage_log)
                if existing:
                    target_scope = existing.target_domain

                # For standalone enrichment scans, set total; for full scans it's already set by discovery
                total = existing.total_stages if (existing and existing.total_stages > len(steps)) else len(steps)
                await db.execute(
                    text("""
                        UPDATE scan_runs SET
                            status = 'running',
                            started_at = COALESCE(started_at, :now),
                            total_stages = :total
                        WHERE id = :id
                    """),
                    {"id": scan_run_id, "now": datetime.now(timezone.utc), "total": total},
                )
                await db.commit()

        # Snapshot before enrichment for delta. Scope the snapshot to the same
        # target as the scan so post-run change detection only compares within
        # the same domain.
        snapshot = await _get_asset_snapshot(sf, org_id, target_scope=target_scope)

        results = {}
        stage_log = list(prior_log)

        async def _run_step(step_name: str, step_fn) -> tuple[str, dict, float, Exception | None]:
            """Run a single enrichment step, capturing duration + errors."""
            step_start = datetime.now(timezone.utc)
            try:
                if step_name == "nmap_dispatch":
                    out = await _dispatch_nmap(
                        get_task_session(), org_id, target_scope=target_scope,
                    )
                else:
                    out = await step_fn(
                        get_task_session(), org_id, target_scope=target_scope,
                    )
                duration = (datetime.now(timezone.utc) - step_start).total_seconds()
                return step_name, out, duration, None
            except Exception as e:
                duration = (datetime.now(timezone.utc) - step_start).total_seconds()
                logger.error("enrichment step %s failed for org %s: %s", step_name, org_id, e)
                return step_name, {"error": str(e)}, duration, e

        step_cursor = 0
        for group in step_groups:
            # Display stage_index/current_stage as the FIRST step in the group
            # (the UI shows one active stage at a time; batches of parallel
            # steps collapse under that banner).
            group_names = [name for name, _ in group]
            first_step_name = group_names[0]
            first_absolute_idx = base_stage_index + step_cursor + 1

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
                                first_step_name if len(group) == 1
                                else "+".join(group_names)
                            ),
                            "idx": first_absolute_idx,
                            "now": datetime.now(timezone.utc),
                        },
                    )
                    await db.commit()

            logger.info("org=%s enrichment group starting: %s", org_id, group_names)
            # Fire all steps in the group concurrently.
            group_outputs = await asyncio.gather(
                *(_run_step(name, fn) for name, fn in group),
                return_exceptions=False,  # _run_step already traps exceptions
            )

            # Record each step's result into stage_log (preserves per-stage
            # duration reporting even though they ran in parallel).
            for step_name, out, duration, err in group_outputs:
                results[step_name if step_name != "nmap_dispatch" else "nmap"] = out
                stage_log.append({
                    "stage": step_name,
                    "status": "error" if err else "done",
                    "duration_s": round(duration, 1),
                    **({"error": str(err)} if err else {}),
                })

            step_cursor += len(group)

            # Persist stage_log + advance stage_index to the end of the group
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
                            "idx": base_stage_index + step_cursor,
                        },
                    )
                    await db.commit()

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
                            assets_changed = :changed,
                            current_stage = NULL, stage_log = :log
                        WHERE id = :id
                    """),
                    {
                        "id": scan_run_id,
                        "now": datetime.now(timezone.utc),
                        "changed": total_updated,
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
