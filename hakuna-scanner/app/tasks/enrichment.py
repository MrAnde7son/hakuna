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

ENRICHMENT_STEP_COUNT = 5  # tlsx, httpx, cdncheck, katana, nmap_dispatch

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session

from app.ingest.assets import update_enrichment, update_tls, update_cdn
from app.ingest.delta import detect_cert_expiring, auto_tag_assets, detect_changes
from app.ingest.enrichment import (
    store_httpx_enrichment,
    store_katana_endpoints,
    store_tlsx_per_port,
)
from app.runner.tools import CdncheckRunner, HttpxRunner, KatanaRunner, TlsxRunner

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _get_confirmed_alive_hostnames(sf, org_id: str) -> list[str]:
    """Get hostnames of confirmed_alive or HTTP-responsive unconfirmed assets."""
    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT hostname FROM assets
                WHERE org_id = :org_id
                  AND (liveness_state = 'confirmed_alive'
                       OR (liveness_state = 'unconfirmed' AND http_status IS NOT NULL))
            """),
            {"org_id": org_id},
        )
        return [row.hostname for row in result.fetchall()]


async def _get_confirmed_alive_assets(sf, org_id: str) -> list[dict]:
    """Get confirmed_alive (or HTTP-responsive unconfirmed) assets with ports for enrichment routing."""
    async with sf() as db:
        result = await db.execute(
            text("""
                SELECT id, hostname, host(ip) as ip, open_ports, cdn_provider, tags
                FROM assets
                WHERE org_id = :org_id
                  AND (liveness_state = 'confirmed_alive'
                       OR (liveness_state = 'unconfirmed' AND http_status IS NOT NULL))
            """),
            {"org_id": org_id},
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


async def _do_tlsx(sf, org_id: str) -> dict:
    """Extension 3: Run tlsx on all open ports (not just 443) for confirmed_alive assets."""
    assets = await _get_confirmed_alive_assets(sf, org_id)
    if not assets:
        return {"inspected": 0}

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

    runner = TlsxRunner(tlsx_targets)
    result = await runner.run(org_id=org_id)

    # Store per-port TLS data and collect SANs for discovery feedback
    async with sf() as db:
        per_port_result = await store_tlsx_per_port(db, uuid.UUID(org_id), result.results)

    # Also update the legacy tls_cert field on the asset
    async with sf() as db:
        await update_tls(db, uuid.UUID(org_id), result.results)

    return {
        "inspected": len(result.results),
        "per_port_updated": per_port_result["updated"],
        "new_sans_discovered": per_port_result["new_sans"],
    }


async def _do_httpx(sf, org_id: str) -> dict:
    """Extension 3: Run httpx with full flags + screenshots on confirmed_alive assets."""
    hostnames = await _get_confirmed_alive_hostnames(sf, org_id)
    if not hostnames:
        return {"probed": 0}

    # Try with screenshots first, fall back to without if browser is unavailable
    ss_dir = os.path.join(settings.screenshot_dir, str(org_id))
    runner = HttpxRunner(hostnames, screenshots=True, screenshot_dir=ss_dir)
    result = await runner.run(org_id=org_id)

    if result.exit_code != 0 and "browser" in (result.stderr or "").lower():
        logger.warning("org=%s httpx screenshot failed (no browser), retrying without screenshots", org_id)
        runner = HttpxRunner(hostnames, screenshots=False)
        result = await runner.run(org_id=org_id)

    async with sf() as db:
        # Legacy enrichment (http_status, http_title, tech_stack, etc.)
        updated = await update_enrichment(db, uuid.UUID(org_id), result.results)

    # Store full httpx JSON as AssetEnrichment records
    async with sf() as db:
        for entry in result.results:
            host = (entry.get("input") or entry.get("host") or "").strip().lower()
            if not host:
                continue
            row = await db.execute(
                text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
                {"org_id": org_id, "host": host},
            )
            asset_row = row.fetchone()
            if asset_row:
                await store_httpx_enrichment(db, uuid.UUID(org_id), asset_row.id, entry)
        await db.commit()

    return {"probed": len(result.results), "updated": updated}


async def _do_cdncheck(sf, org_id: str) -> dict:
    hostnames = await _get_confirmed_alive_hostnames(sf, org_id)
    if not hostnames:
        return {"checked": 0}

    runner = CdncheckRunner(hostnames)
    result = await runner.run(org_id=org_id)

    async with sf() as db:
        updated = await update_cdn(db, uuid.UUID(org_id), result.results)

    return {"checked": len(result.results), "updated": updated}


async def _do_katana(sf, org_id: str) -> dict:
    """Extension 3: Run katana on confirmed_alive HTTP/HTTPS assets (skip CDN)."""
    assets = await _get_confirmed_alive_assets(sf, org_id)
    if not assets:
        return {"crawled": 0}

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

    runner = KatanaRunner(targets)
    result = await runner.run(org_id=org_id)

    # Group results by asset
    asset_results: dict[uuid.UUID, list[dict]] = {}
    for entry in result.results:
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


async def _dispatch_nmap(sf, org_id: str) -> dict:
    """Extension 4: Dispatch nmap_enrich_asset tasks for confirmed_alive assets."""
    from app.tasks.nmap import nmap_enrich_asset

    assets = await _get_confirmed_alive_assets(sf, org_id)
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


@celery.task(bind=True, name="enrichment.run_httpx")
def run_httpx(self, org_id: str) -> dict:
    return _run_async(_do_httpx(get_task_session(), org_id))


@celery.task(bind=True, name="enrichment.run_tlsx")
def run_tlsx(self, org_id: str) -> dict:
    return _run_async(_do_tlsx(get_task_session(), org_id))


@celery.task(bind=True, name="enrichment.run_cdncheck")
def run_cdncheck(self, org_id: str) -> dict:
    return _run_async(_do_cdncheck(get_task_session(), org_id))


@celery.task(bind=True, name="enrichment.run_katana")
def run_katana(self, org_id: str) -> dict:
    return _run_async(_do_katana(get_task_session(), org_id))


@celery.task(bind=True, name="enrichment.run_enrichment_chain",
             soft_time_limit=5400, time_limit=5700)  # 90 min / 95 min
def run_enrichment_chain(self, org_id: str, scan_run_id: str | None = None) -> dict:
    """Full enrichment chain (confirmed_alive assets only):
    tlsx → httpx → cdncheck → katana → nmap_dispatch → auto-tag → delta.
    """

    async def _run():
        sf = get_task_session()

        steps = [
            ("tlsx", _do_tlsx),
            ("httpx", _do_httpx),
            ("cdncheck", _do_cdncheck),
            ("katana", _do_katana),
            ("nmap_dispatch", None),  # handled separately
        ]

        # Check if continuing from a prior phase (e.g., discovery → enrichment in a full scan)
        base_stage_index = 0
        prior_log = []
        async with sf() as db:
            if scan_run_id:
                row = await db.execute(
                    text("SELECT stage_index, total_stages, stage_log FROM scan_runs WHERE id = :id"),
                    {"id": scan_run_id},
                )
                existing = row.fetchone()
                if existing and existing.total_stages > 0:
                    # Continuing from discovery — offset step indices
                    base_stage_index = existing.total_stages - len(steps)
                    if existing.stage_log:
                        prior_log = existing.stage_log if isinstance(existing.stage_log, list) else json.loads(existing.stage_log)

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

        # Snapshot before enrichment for delta
        snapshot = await _get_asset_snapshot(sf, org_id)

        results = {}
        stage_log = list(prior_log)

        for i, (step_name, step_fn) in enumerate(steps):
            step_start = datetime.now(timezone.utc)
            absolute_idx = base_stage_index + i + 1

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
                        {"id": scan_run_id, "stage": step_name, "idx": absolute_idx, "now": step_start},
                    )
                    await db.commit()

            try:
                if step_name == "nmap_dispatch":
                    results["nmap"] = await _dispatch_nmap(get_task_session(), org_id)
                else:
                    results[step_name] = await step_fn(get_task_session(), org_id)
                duration = (datetime.now(timezone.utc) - step_start).total_seconds()
                stage_log.append({"stage": step_name, "status": "done", "duration_s": round(duration, 1)})
            except Exception as e:
                logger.error("enrichment step %s failed for org %s: %s", step_name, org_id, e)
                results[step_name] = {"error": str(e)}
                duration = (datetime.now(timezone.utc) - step_start).total_seconds()
                stage_log.append({"stage": step_name, "status": "error", "duration_s": round(duration, 1), "error": str(e)})

            # Persist stage_log so frontend can show completed steps
            if scan_run_id:
                async with get_task_session()() as db:
                    await db.execute(
                        text("UPDATE scan_runs SET stage_log = :log WHERE id = :id"),
                        {"id": scan_run_id, "log": json.dumps(stage_log)},
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
