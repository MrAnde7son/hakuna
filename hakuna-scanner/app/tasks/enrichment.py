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

ENRICHMENT_STEP_COUNT = 16  # tlsx, httpx, cdncheck, js_fingerprint, favicon, endpoint_probe, katana, protocol_probe, kiterunner, trufflehog, llm_js_extraction, openapi_discovery, graphql_introspection, classify_assets, ai_exposure, nmap_dispatch

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session

from app.ingest.assets import update_enrichment, update_tls, update_cdn
from app.ingest.delta import detect_cert_expiring, auto_tag_assets, detect_changes
from app.ingest.enrichment import (
    ENDPOINT_PROBE_ENABLED,
    FAVICON_FINGERPRINT_ENABLED,
    JS_FINGERPRINT_ENABLED,
    store_endpoint_probe_results,
    store_favicon_fingerprints,
    store_httpx_enrichment,
    store_jarm_fingerprints,
    store_js_fingerprints,
    store_katana_endpoints,
    store_tlsx_per_port,
)
from app.ingest.asset_classifier import classify_asset
from app.ingest.endpoint_probe import probe_assets
from app.ingest.favicon_fingerprint import fingerprint_assets as favicon_fingerprint_assets
from app.ingest.js_fingerprint import fingerprint_assets
from app.ingest.protocol_probe import probe_batch as protocol_probe_batch
from app.runner.base import BaseRunner, batch_hosts, run_batches_parallel
from app.runner.tools import CdncheckRunner, HttpxRunner, KatanaRunner, KiterunnerRunner, TlsxRunner, TrufflehogRunner
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
KITERUNNER_BATCH_SIZE = 50  # heavier per-host than katana

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
    stale_column: str = "last_enriched",
) -> list[dict]:
    """Get confirmed_alive (or HTTP-responsive unconfirmed) assets with ports for enrichment routing."""
    scope_sql, scope_params = build_target_scope(target_scope)
    stale_sql = build_stale_clause(enabled=apply_stale, stale_hours=stale_hours, column=stale_column)
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

    # Feed newly discovered SANs back as assets
    san_upserted = 0
    new_sans = per_port_result.get("new_sans", [])
    if new_sans:
        from app.ingest.assets import upsert_discovered_hosts
        from app.ingest.delta import emit_new_asset_events
        san_hosts = [{"host": h} for h in new_sans]
        async with sf() as db:
            san_upserted, new_ids = await upsert_discovered_hosts(
                db, uuid.UUID(org_id), san_hosts, "tls_san",
            )
            await emit_new_asset_events(db, uuid.UUID(org_id), new_ids)
        logger.info("org=%s tlsx SAN feedback: upserted=%d new=%d", org_id, san_upserted, len(new_ids))

    # Store JARM fingerprints and run JARM → CPE inference
    jarm_result = {"jarm_matched": 0, "c2_detected": 0}
    jarm_entries = [e for e in all_results if e.get("jarm_hash") or e.get("jarm")]
    if jarm_entries:
        async with sf() as db:
            jarm_result = await store_jarm_fingerprints(db, uuid.UUID(org_id), jarm_entries)

    return {
        "inspected": len(all_results),
        "per_port_updated": per_port_result["updated"],
        "new_sans_discovered": len(new_sans),
        "san_upserted": san_upserted,
        "jarm_matched": jarm_result["jarm_matched"],
        "c2_detected": jarm_result["c2_detected"],
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

            # Look up the TLS cert and JARM hash for the port this httpx entry hit.
            tls_cert = None
            jarm_hash = None
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
                    jarm_hash = tls_cert.get("jarm_hash") if isinstance(tls_cert, dict) else None

            await store_httpx_enrichment(
                db, uuid.UUID(org_id), asset_row.id, entry,
                tls_cert=tls_cert, jarm_hash=jarm_hash,
            )
        await db.commit()

    return {"probed": len(all_results), "updated": updated, "batches": len(batches)}


async def _do_tls_deep_audit(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Run sslyze cipher-enumeration + chain validation + OCSP + CAA on
    TLS-capable ports that tlsx already fingerprinted.

    Gated by ``settings.tls_deep_audit_enabled`` because sslyze is 10-30s
    per host and can trip WAF rate limits.
    """
    if not settings.tls_deep_audit_enabled:
        return {"audited": 0, "disabled": True}

    # Pull TLS-capable (host, port) pairs — only ports that already have a
    # tls_cert row from tlsx. That filters out plain HTTP ports and ports
    # where tlsx couldn't handshake, both of which sslyze would waste time on.
    async with sf() as db:
        rows = await db.execute(
            text("""
                SELECT a.hostname, ap.port, ap.id as port_id
                FROM assets a
                JOIN asset_ports ap ON ap.asset_id = a.id
                WHERE a.org_id = :org_id
                  AND a.liveness_state = 'confirmed_alive'
                  AND ap.tls_cert IS NOT NULL
                  AND (:scope IS NULL OR a.hostname LIKE :scope_like)
                ORDER BY a.hostname, ap.port
                LIMIT :cap
            """),
            {
                "org_id": uuid.UUID(org_id),
                "scope": target_scope,
                "scope_like": f"%{target_scope}" if target_scope else None,
                "cap": settings.tls_deep_audit_max_hosts,
            },
        )
        targets = [(r.hostname, r.port, r.port_id) for r in rows.fetchall()]

    if not targets:
        logger.info("org=%s tls_deep_audit: no TLS-capable targets", org_id)
        return {"audited": 0}

    logger.info(
        "org=%s tls_deep_audit: auditing %d targets concurrency=%d",
        org_id, len(targets), settings.tls_deep_audit_concurrency,
    )

    # sslyze is blocking + CPU-bound on cryptography. Run in a thread pool
    # with asyncio.Semaphore to bound concurrency.
    import asyncio
    from app.ingest.tls_deep_audit import audit_host

    sem = asyncio.Semaphore(settings.tls_deep_audit_concurrency)

    async def _audit(host: str, port: int, port_id):
        async with sem:
            try:
                return port_id, await asyncio.wait_for(
                    asyncio.to_thread(audit_host, host, port),
                    timeout=settings.tls_deep_audit_host_timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("tls_deep_audit timeout host=%s port=%d", host, port)
                return port_id, None
            except Exception as exc:  # noqa: BLE001
                logger.warning("tls_deep_audit failed host=%s port=%d err=%s", host, port, exc)
                return port_id, None

    results = await asyncio.gather(*(_audit(h, p, pid) for h, p, pid in targets))

    # Persist — one UPDATE per port_id.
    audited = 0
    issues_total = 0
    async with sf() as db:
        for port_id, audit in results:
            if audit is None:
                continue
            await db.execute(
                text("""
                    UPDATE asset_ports
                    SET tls_deep_audit = cast(:audit as jsonb), updated_at = :now
                    WHERE id = :pid
                """),
                {
                    "audit": json.dumps(audit),
                    "now": datetime.now(timezone.utc),
                    "pid": port_id,
                },
            )
            audited += 1
            issues_total += len(audit.get("issues", []))
        await db.commit()

    return {"audited": audited, "targets": len(targets), "issues": issues_total}


async def _do_js_fingerprint(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Run JS library fingerprinting on confirmed_alive HTTP assets.

    Fetches HTML pages, parses <script> tags, downloads JS files, and matches
    version patterns to detect client-side libraries (jQuery, Moment.js, etc.)
    that httpx's Wappalyzer misses. Results are merged into asset_ports.cpe_list.
    """
    if not JS_FINGERPRINT_ENABLED:
        return {"fingerprinted": 0, "disabled": True}

    # Use a dedicated stale column so we aren't blocked by last_enriched
    # (which is set by httpx/cdncheck in Group 1 before we run).
    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope,
        apply_stale=True, stale_column="last_js_fingerprinted",
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

    # Stamp all scanned assets (including those with no detections) so the
    # stale check skips them on the next run.
    scanned_ids = [a["id"] for a in http_assets]
    async with sf() as db:
        await db.execute(
            text("UPDATE assets SET last_js_fingerprinted = NOW() WHERE id = ANY(:ids)"),
            {"ids": scanned_ids},
        )
        await db.commit()

    total_libs = sum(len(dets) for dets in js_results.values())
    return {
        "fingerprinted": len(http_assets),
        "assets_with_js": len(js_results),
        "total_libs_detected": total_libs,
        **store_result,
    }


async def _do_favicon_fingerprint(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Run favicon hash fingerprinting on confirmed_alive HTTP assets.

    Downloads /favicon.ico (and <link rel=icon> paths), computes mmh3 hashes,
    and matches against a known hash database to identify technologies like
    Jenkins, Grafana, Tomcat, etc. Results are merged into asset_ports.cpe_list.
    """
    if not FAVICON_FINGERPRINT_ENABLED:
        return {"fingerprinted": 0, "disabled": True}

    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=False,
    )
    if not assets:
        logger.info("org=%s favicon_fingerprint: no assets to fingerprint", org_id)
        return {"fingerprinted": 0}

    HTTP_PORTS = {80, 443, 8080, 8443}
    http_assets = [a for a in assets if set(a.get("open_ports") or []) & HTTP_PORTS]

    if not http_assets:
        return {"fingerprinted": 0}

    logger.info("org=%s favicon_fingerprint: scanning %d assets", org_id, len(http_assets))

    favicon_results = await favicon_fingerprint_assets(
        http_assets,
        concurrency=settings.favicon_fingerprint_concurrency,
        connect_timeout=settings.favicon_fingerprint_connect_timeout,
    )

    async with sf() as db:
        store_result = await store_favicon_fingerprints(db, uuid.UUID(org_id), favicon_results)

    total_detected = sum(len(dets) for dets in favicon_results.values())
    return {
        "fingerprinted": len(http_assets),
        "assets_with_favicon_match": len(favicon_results),
        "total_detected": total_detected,
        **store_result,
    }


async def _do_endpoint_probe(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Run default endpoint probing on confirmed_alive HTTP assets.

    Sends requests to known application paths (/wp-login.php, /owa/auth/logon.aspx,
    /actuator/health, etc.) and confirms technology by checking status codes and
    response body patterns. Results are merged into asset_ports.cpe_list.
    """
    if not ENDPOINT_PROBE_ENABLED:
        return {"probed": 0, "disabled": True}

    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=False,
    )
    if not assets:
        logger.info("org=%s endpoint_probe: no assets to probe", org_id)
        return {"probed": 0}

    HTTP_PORTS = {80, 443, 8080, 8443}
    # Skip CDN assets — endpoint probes against CDN origins are noisy and slow.
    http_assets = [
        a for a in assets
        if set(a.get("open_ports") or []) & HTTP_PORTS
        and not a.get("cdn_provider")
        and "cdn" not in (a.get("tags") or [])
    ]

    if not http_assets:
        skipped_cdn = len(assets) - len(http_assets) if assets else 0
        logger.info("org=%s endpoint_probe: no non-CDN HTTP assets to probe (skipped_cdn=%d)", org_id, skipped_cdn)
        return {"probed": 0, "skipped_cdn": skipped_cdn}

    logger.info("org=%s endpoint_probe: probing %d assets", org_id, len(http_assets))

    probe_results = await probe_assets(
        http_assets,
        concurrency=settings.endpoint_probe_concurrency,
        connect_timeout=settings.endpoint_probe_connect_timeout,
    )

    async with sf() as db:
        store_result = await store_endpoint_probe_results(db, uuid.UUID(org_id), probe_results)

    total_detected = sum(len(dets) for dets in probe_results.values())
    return {
        "probed": len(http_assets),
        "assets_with_matches": len(probe_results),
        "total_detected": total_detected,
        **store_result,
    }


async def _do_protocol_probe(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Probe non-HTTP protocols (Modbus, S7, MQTT, RTSP, etc.) on open ports.

    Sends lightweight read-only identification payloads to detect OT/ICS,
    IoT, and AI infrastructure. Creates critical/high findings for
    internet-exposed industrial protocols.
    """
    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=False,
    )
    if not assets:
        return {"probed": 0}

    # Only probe assets that have non-HTTP ports open
    from app.ingest.protocol_probe import PROTOCOL_PROBES
    probe_ports = {p["port"] for p in PROTOCOL_PROBES}
    candidates = [
        a for a in assets
        if set(a.get("open_ports") or []) & probe_ports
    ]
    if not candidates:
        return {"probed": 0, "no_protocol_ports": True}

    logger.info("org=%s protocol_probe: probing %d assets with OT/IoT/AI ports", org_id, len(candidates))

    probe_results = await protocol_probe_batch(candidates, concurrency=10)

    # Store results and create findings
    total_detections = 0
    findings_created = 0
    async with sf() as db:
        for hostname, detections in probe_results.items():
            total_detections += len(detections)
            # Find asset
            row = await db.execute(
                text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
                {"org_id": org_id, "host": hostname},
            )
            asset_row = row.fetchone()
            if not asset_row:
                continue

            # Store protocol detections on asset
            await db.execute(
                text("UPDATE assets SET protocol_detections = :det WHERE id = :id"),
                {"det": json.dumps(detections), "id": asset_row.id},
            )

            # Create findings for critical/high exposed protocols
            for det in detections:
                finding_id = uuid.uuid4()
                await db.execute(
                    text("""
                        INSERT INTO findings (id, org_id, asset_id, finding_type, severity,
                                              title, description, metadata, status, created_at)
                        VALUES (:id, :org_id, :aid, :ftype, :sev, :title, :desc, :meta, 'open', :now)
                        ON CONFLICT DO NOTHING
                    """),
                    {
                        "id": finding_id,
                        "org_id": org_id,
                        "aid": asset_row.id,
                        "ftype": f"exposed_{det['protocol']}",
                        "sev": det["severity"],
                        "title": det["finding_title"],
                        "desc": (
                            f"Detected {det['name']} on port {det['port']}. "
                            f"This service should not be exposed to the internet."
                        ),
                        "meta": json.dumps(det.get("metadata", {})),
                        "now": datetime.now(timezone.utc),
                    },
                )
                findings_created += 1

        await db.commit()

    return {
        "probed": len(candidates),
        "assets_with_detections": len(probe_results),
        "total_detections": total_detections,
        "findings_created": findings_created,
    }


async def _do_classify_assets(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Classify all enriched assets by type (AI, IoT, OT, IT).

    Runs after all fingerprinting stages to aggregate signals from:
    endpoint probes, protocol probes, nmap banners, tech stack, and ports.
    """
    scope_sql, scope_params = build_target_scope(target_scope)
    extra = compose_where(scope_sql)
    params = {"org_id": org_id, **scope_params}
    async with sf() as db:
        result = await db.execute(
            text(f"""
                SELECT a.id, a.hostname, a.open_ports, a.tech_stack,
                       a.protocol_detections, a.asset_type as current_type,
                       array_agg(ap.service_name) FILTER (WHERE ap.service_name IS NOT NULL) as service_names,
                       array_agg(ap.banner) FILTER (WHERE ap.banner IS NOT NULL) as banners
                FROM assets a
                LEFT JOIN asset_ports ap ON ap.asset_id = a.id
                WHERE a.org_id = :org_id
                  AND (a.liveness_state = 'confirmed_alive'
                       OR (a.liveness_state = 'unconfirmed' AND a.http_status IS NOT NULL))
                  {extra}
                GROUP BY a.id
            """),
            params,
        )
        assets = result.fetchall()

    classified = 0
    async with sf() as db:
        for asset in assets:
            tech_stack = asset.tech_stack
            tech_list = []
            if isinstance(tech_stack, dict):
                tech_list = list(tech_stack.keys()) if tech_stack else []
            elif isinstance(tech_stack, list):
                tech_list = tech_stack

            asset_type = classify_asset(
                open_ports=asset.open_ports,
                service_names=list(asset.service_names or []),
                banners=list(asset.banners or []),
                tech_stack=tech_list,
                protocol_probe_results=asset.protocol_detections if isinstance(asset.protocol_detections, list) else None,
            )

            if asset_type and asset_type != asset.current_type:
                await db.execute(
                    text("UPDATE assets SET asset_type = :atype WHERE id = :id"),
                    {"atype": asset_type, "id": asset.id},
                )
                classified += 1

        await db.commit()

    return {"total_assets": len(assets), "classified": classified}


async def _do_ai_exposure(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Probe AI/LLM/vector-DB assets for unauthenticated exposure.

    Runs after classify_assets so ``assets.asset_type`` has been set. Each
    probe defined in ``ai_exposure_probes.json`` sends a read-only request
    and, when the response matches the probe's success_when criteria, emits
    a Finding via the existing Finding write path.
    """
    from app.ingest.ai_exposure_probe import (
        AI_ASSET_TYPES,
        probe_assets as ai_probe_assets,
        store_ai_exposure_findings,
    )

    scope_sql, scope_params = build_target_scope(target_scope)
    extra = compose_where(scope_sql)
    params = {"org_id": org_id, **scope_params}

    # Only pull assets already classified as AI/LLM/vector-db to keep the
    # probe surface minimal. asset_type is set by _do_classify_assets which
    # runs in the preceding step group.
    ai_types = list(AI_ASSET_TYPES)
    async with sf() as db:
        result = await db.execute(
            text(f"""
                SELECT id, hostname, host(ip) as ip, open_ports, asset_type, tags
                FROM assets
                WHERE org_id = :org_id
                  AND asset_type = ANY(:ai_types)
                  AND (liveness_state = 'confirmed_alive'
                       OR (liveness_state = 'unconfirmed' AND http_status IS NOT NULL))
                  {extra}
            """),
            {**params, "ai_types": ai_types},
        )
        assets = [
            {
                "id": row.id,
                "hostname": row.hostname,
                "ip": row.ip,
                "open_ports": row.open_ports or [],
                "asset_type": row.asset_type,
                "tags": row.tags or [],
            }
            for row in result.fetchall()
        ]

    if not assets:
        return {"probed": 0, "no_ai_assets": True}

    logger.info("org=%s ai_exposure: probing %d AI assets", org_id, len(assets))

    try:
        probe_results = await ai_probe_assets(
            assets,
            concurrency=settings.endpoint_probe_concurrency,
        )
    except Exception as exc:
        # Probe orchestration failures must never break the enrichment chain.
        logger.error("org=%s ai_exposure: probe_assets failed: %s", org_id, exc)
        return {"probed": len(assets), "error": str(exc)}

    async with sf() as db:
        store_result = await store_ai_exposure_findings(
            db, uuid.UUID(org_id), probe_results,
        )

    return {
        "probed": len(assets),
        "assets_exposed": store_result["hosts_affected"],
        "findings_created": store_result["findings_created"],
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


async def _do_kiterunner(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Run kiterunner API endpoint brute-forcing on confirmed_alive HTTP assets (skip CDN)."""
    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not assets:
        logger.info("org=%s kiterunner: no fresh assets", org_id)
        return {"bruted": 0, "skipped_fresh": True}

    HTTP_PORTS = {80, 443, 8080, 8443}
    targets: list[str] = []
    target_asset_map: dict[str, uuid.UUID] = {}

    for asset in assets:
        if asset.get("cdn_provider") or "cdn" in (asset.get("tags") or []):
            continue
        ports = set(asset.get("open_ports") or [])
        if ports & HTTP_PORTS:
            hostname = asset["hostname"]
            url = f"https://{hostname}" if 443 in ports else f"http://{hostname}"
            targets.append(url)
            target_asset_map[hostname] = asset["id"]

    if not targets:
        return {"bruted": 0}

    batches = batch_hosts(targets, KITERUNNER_BATCH_SIZE)
    per_batch_timeout = BaseRunner.timeout_for_host_count(KITERUNNER_BATCH_SIZE, per_host_seconds=10.0)
    logger.info("org=%s kiterunner targets=%d batches=%d", org_id, len(targets), len(batches))

    all_results = await run_batches_parallel(
        build_runner=lambda batch: KiterunnerRunner(batch, timeout=per_batch_timeout),
        batches=batches,
        org_id=org_id,
        concurrency=settings.enrichment_batch_concurrency,
        stage_name="kiterunner",
    )

    from app.ingest.kiterunner import store_kiterunner_results
    async with sf() as db:
        store_result = await store_kiterunner_results(
            db, uuid.UUID(org_id), all_results, target_asset_map,
        )

    return {"bruted": len(targets), **store_result}


async def _do_trufflehog(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Scan katana-discovered JS bundles for leaked secrets using trufflehog."""
    import aiohttp
    import tempfile
    import shutil

    # Query JS endpoints discovered by katana
    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT ae.asset_id, ae.url
                FROM asset_endpoints ae
                JOIN assets a ON a.id = ae.asset_id
                WHERE a.org_id = :org_id
                  AND (ae.url LIKE '%%.js' OR ae.url LIKE '%%.js.map' OR ae.url LIKE '%%.bundle.js')
                ORDER BY ae.discovered_at DESC
                LIMIT 500
            """),
            {"org_id": org_id},
        )
        js_endpoints = result.fetchall()

    if not js_endpoints:
        return {"scanned": 0, "no_js_files": True}

    # Group by asset, limit per asset
    from collections import defaultdict
    asset_urls: dict[uuid.UUID, list[str]] = defaultdict(list)
    for row in js_endpoints:
        if len(asset_urls[row.asset_id]) < 10:
            asset_urls[row.asset_id].append(row.url)

    logger.info("org=%s trufflehog: %d JS files across %d assets", org_id, len(js_endpoints), len(asset_urls))

    total_secrets = 0
    total_verified = 0
    assets_scanned = 0

    for asset_id, urls in asset_urls.items():
        tmpdir = tempfile.mkdtemp(prefix="trufflehog_")
        try:
            # Download JS files
            downloaded = 0
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False),
            ) as session:
                for url in urls:
                    try:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                content = await resp.read()
                                safe_name = url.split("/")[-1][:64].replace("..", "_")
                                filepath = os.path.join(tmpdir, f"{downloaded}_{safe_name}")
                                with open(filepath, "wb") as f:
                                    f.write(content)
                                downloaded += 1
                    except Exception:
                        continue

            if downloaded == 0:
                continue

            # Run trufflehog on the directory
            runner = TrufflehogRunner(
                tmpdir, only_verified=settings.trufflehog_only_verified,
            )
            result = await runner.run(org_id=org_id)

            if result.results:
                from app.ingest.secrets import store_trufflehog_results
                async with sf() as db:
                    store_result = await store_trufflehog_results(
                        db, uuid.UUID(org_id), asset_id, result.results,
                    )
                    total_secrets += store_result["secrets_found"]
                    total_verified += store_result["verified"]

            assets_scanned += 1
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return {
        "assets_scanned": assets_scanned,
        "secrets_found": total_secrets,
        "verified": total_verified,
    }


async def _do_llm_js_extraction(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Extract hidden API endpoints from JS bundles using LLM + regex fallback."""
    import aiohttp

    if not settings.llm_js_extraction_enabled:
        return {"extracted": 0, "disabled": True}

    # Query JS endpoints discovered by katana
    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT ae.asset_id, ae.url
                FROM asset_endpoints ae
                JOIN assets a ON a.id = ae.asset_id
                WHERE a.org_id = :org_id
                  AND ae.url LIKE '%%.js'
                  AND ae.url NOT LIKE '%%.min.js.map'
                ORDER BY ae.discovered_at DESC
                LIMIT 200
            """),
            {"org_id": org_id},
        )
        js_endpoints = result.fetchall()

    if not js_endpoints:
        return {"extracted": 0, "no_js_files": True}

    from collections import defaultdict
    asset_urls: dict[uuid.UUID, list[str]] = defaultdict(list)
    for row in js_endpoints:
        if len(asset_urls[row.asset_id]) < settings.llm_js_extraction_max_files_per_asset:
            asset_urls[row.asset_id].append(row.url)

    logger.info("org=%s llm_js_extraction: %d JS files across %d assets", org_id, sum(len(v) for v in asset_urls.values()), len(asset_urls))

    from app.ingest.llm_js_endpoints import extract_endpoints_llm, extract_endpoints_regex, store_llm_js_endpoints

    total_endpoints = 0
    assets_processed = 0

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30),
        connector=aiohttp.TCPConnector(ssl=False),
    ) as session:
        for asset_id, urls in asset_urls.items():
            for url in urls:
                try:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            continue
                        content = await resp.text(errors="replace")

                    if len(content) < settings.llm_js_extraction_min_file_size:
                        continue

                    # Try LLM first, fall back to regex
                    endpoints = await extract_endpoints_llm(content)
                    if not endpoints:
                        endpoints = extract_endpoints_regex(content)

                    if endpoints:
                        async with sf() as db:
                            stored = await store_llm_js_endpoints(
                                db, uuid.UUID(org_id), asset_id, endpoints,
                            )
                            total_endpoints += stored

                except Exception as e:
                    logger.debug("llm_js_extraction failed for %s: %s", url, e)
                    continue

            assets_processed += 1

    return {"assets_processed": assets_processed, "endpoints_extracted": total_endpoints}


async def _dispatch_nmap(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Extension 4: Dispatch nmap_enrich_asset tasks for confirmed_alive assets.

    Note: apply_stale is NOT set here because nmap_enrich_asset has its own
    idempotency (it checks the asset's nmap-specific freshness inside the
    sub-task). We scope to the target domain but let the sub-task decide
    whether to actually re-scan.
    """
    from app.tasks.nmap import nmap_enrich_asset, nmap_udp_enrich_asset

    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    tcp_dispatched = 0
    udp_dispatched = 0

    for asset in assets:
        if asset.get("open_ports"):
            nmap_enrich_asset.apply_async(
                args=[str(asset["id"])],
                queue="nmap_queue",
            )
            tcp_dispatched += 1

        # Dispatch UDP scan for all confirmed_alive assets
        nmap_udp_enrich_asset.apply_async(
            args=[str(asset["id"])],
            queue="nmap_queue",
        )
        udp_dispatched += 1

    logger.info("org=%s nmap dispatched: tcp=%d udp=%d to nmap_queue", org_id, tcp_dispatched, udp_dispatched)
    return {"nmap_tcp_dispatched": tcp_dispatched, "nmap_udp_dispatched": udp_dispatched}


# --- Individual tasks ---


@celery.task(bind=True, name="enrichment.run_js_fingerprint")
def run_js_fingerprint(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_js_fingerprint(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_favicon_fingerprint")
def run_favicon_fingerprint(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_favicon_fingerprint(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_endpoint_probe")
def run_endpoint_probe(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_endpoint_probe(get_task_session(), org_id, target_scope=target_scope))


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


@celery.task(bind=True, name="enrichment.run_kiterunner")
def run_kiterunner(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_kiterunner(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_trufflehog")
def run_trufflehog(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_trufflehog(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_llm_js_extraction")
def run_llm_js_extraction(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_llm_js_extraction(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_ai_exposure")
def run_ai_exposure(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_ai_exposure(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_openapi_discovery")
def run_openapi_discovery(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_openapi_discovery(get_task_session(), org_id, target_scope=target_scope))


@celery.task(bind=True, name="enrichment.run_graphql_introspection")
def run_graphql_introspection(self, org_id: str, target_scope: str | None = None) -> dict:
    return _run_async(_do_graphql_introspection(get_task_session(), org_id, target_scope=target_scope))


# ── API discovery enrichers (PR 3 of Adaptive Scan Plan) ───────────


async def _do_openapi_discovery(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Probe each web-facing asset's well-known OpenAPI/Swagger paths.

    Hooks into the same confirmed-alive web-port asset list katana uses so
    the cost is one extra HTTP probe round-trip per asset (cheap compared
    to katana). Specs found turn into per-endpoint scan targets that the
    adaptive planner can drive precisely.
    """
    if not settings.openapi_discovery_enabled:
        return {"skipped": True, "reason": "disabled"}

    from app.ingest.openapi_discoverer import discover_openapi_specs

    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not assets:
        return {"specs_found": 0, "skipped_fresh": True}

    HTTP_PORTS = {80, 443, 8080, 8443}
    targets: list[dict] = []
    for asset in assets:
        ports = set(asset.get("open_ports") or [])
        if not (ports & HTTP_PORTS):
            continue
        if asset.get("cdn_provider"):
            # Probing a CDN's well-known paths returns the CDN's responses,
            # not the origin's spec — skip to keep noise down.
            continue
        hostname = asset.get("hostname")
        if not hostname:
            continue
        scheme = "https" if 443 in ports or 8443 in ports else "http"
        targets.append({
            "asset_id": asset["id"],
            "base_url": f"{scheme}://{hostname}",
        })

    if not targets:
        return {"specs_found": 0, "endpoints_stored": 0}

    async with sf() as db:
        result = await discover_openapi_specs(
            db, uuid.UUID(org_id), targets,
            concurrency=settings.openapi_discovery_concurrency,
            timeout=settings.openapi_discovery_timeout,
            max_spec_bytes=settings.openapi_discovery_max_spec_bytes,
            max_endpoints_per_asset=settings.openapi_discovery_max_endpoints,
        )
    return result


async def _do_graphql_introspection(sf, org_id: str, target_scope: str | None = None) -> dict:
    """Probe candidate GraphQL paths and run introspection.

    Same target shape as openapi discovery — confirmed-alive HTTP assets,
    skip CDNs. Successful introspection produces per-operation endpoints
    plus a graphql_schema artifact stored in asset_js_artifacts.
    """
    if not settings.graphql_introspection_enabled:
        return {"skipped": True, "reason": "disabled"}

    from app.ingest.graphql_introspector import introspect_graphql

    assets = await _get_confirmed_alive_assets(
        sf, org_id, target_scope=target_scope, apply_stale=True,
    )
    if not assets:
        return {"introspection_hits": 0, "skipped_fresh": True}

    HTTP_PORTS = {80, 443, 8080, 8443}
    targets: list[dict] = []
    for asset in assets:
        ports = set(asset.get("open_ports") or [])
        if not (ports & HTTP_PORTS):
            continue
        if asset.get("cdn_provider"):
            continue
        hostname = asset.get("hostname")
        if not hostname:
            continue
        scheme = "https" if 443 in ports or 8443 in ports else "http"
        targets.append({
            "asset_id": asset["id"],
            "base_url": f"{scheme}://{hostname}",
        })

    if not targets:
        return {"introspection_hits": 0, "endpoints_stored": 0}

    async with sf() as db:
        result = await introspect_graphql(
            db, uuid.UUID(org_id), targets,
            concurrency=settings.graphql_introspection_concurrency,
            timeout=settings.graphql_introspection_timeout,
        )
    return result


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
        # Build step_groups either from the scanner registry (when
        # settings.use_scanner_registry is True) or from the hardcoded
        # literal below (the safe default). The registry-driven output
        # is expected to be identical to the literal — it's a pure
        # refactor gated by the feature flag.
        if settings.use_scanner_registry:
            from app.runner.registry import build_step_groups
            step_groups: list[list[tuple[str, object]]] = build_step_groups("enrichment")
            logger.info(
                "org=%s enrichment: using scanner registry (%d groups)",
                org_id, len(step_groups),
            )
        else:
            step_groups = [
                [
                    ("tlsx", _do_tlsx),
                    ("httpx", _do_httpx),
                    ("cdncheck", _do_cdncheck),
                ],
                # Deep TLS audit runs after tlsx/httpx because it reads
                # asset_ports.tls_cert to pick which ports to audit. In its
                # own group so the sslyze wall time doesn't bottleneck the
                # fast fingerprint stages below. Disabled by default — see
                # settings.tls_deep_audit_enabled.
                [
                    ("tls_deep_audit", _do_tls_deep_audit),
                ],
                [
                    ("js_fingerprint", _do_js_fingerprint),
                    ("favicon_fingerprint", _do_favicon_fingerprint),
                    ("endpoint_probe", _do_endpoint_probe),
                    ("protocol_probe", _do_protocol_probe),
                    ("katana", _do_katana),
                    ("kiterunner", _do_kiterunner),
                ],
                [
                    # Post-katana analysis: secrets scanning + LLM JS extraction
                    # depend on katana's discovered JS endpoints from Group 2.
                    # OpenAPI/GraphQL discovery share Group 2's web-asset
                    # candidate set so they can run alongside trufflehog/LLM —
                    # they're cheap (~2 HTTP probes per asset) and produce
                    # the highest-signal endpoints the planner consumes.
                    ("trufflehog", _do_trufflehog),
                    ("llm_js_extraction", _do_llm_js_extraction),
                    ("openapi_discovery", _do_openapi_discovery),
                    ("graphql_introspection", _do_graphql_introspection),
                ],
                [
                    ("classify_assets", _do_classify_assets),
                ],
                [
                    # ai_exposure depends on asset_type set by classify_assets,
                    # so it must run in a later group. Emits Findings for
                    # unauthenticated Ollama / vLLM / Qdrant / MCP / LangServe
                    # / LiteLLM / Milvus / Chroma endpoints.
                    ("ai_exposure", _do_ai_exposure),
                ],
                [("nmap_dispatch", None)],  # handled separately; includes UDP
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
                            )[:64],
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
