"""Celery Beat scheduler for VM scanner jobs."""

import asyncio
import json
import logging
import os
import urllib.request

from celery.schedules import crontab

from scanner.vm.celery_app import celery_app
from scanner.vm.config import DATABASE_URL, TEMPLATES_DIR
from scanner.vm.db import _normalize_dsn

logger = logging.getLogger(__name__)

HANDOFF_QUERY = """
    SELECT
        a.*,
        ap.cpe_list,
        ap.service_name,
        ap.service_version,
        ae.tech_stack,
        ae.httpx_full
    FROM assets a
    LEFT JOIN asset_ports ap
        ON ap.asset_id = a.id AND ap.nmap_status = 'complete'
    LEFT JOIN asset_enrichments ae
        ON ae.asset_id = a.id
    WHERE a.liveness_state = 'confirmed_alive'
    AND a.last_validated_at > NOW() - INTERVAL '7 days'
"""


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(queue="vm_queue", name="vm.weekly_scan")
def weekly_vm_scan() -> dict:
    """Weekly scan: enqueue run_nuclei_scan for all confirmed-alive assets."""
    return _run_async(_weekly_vm_scan_async())


async def _weekly_vm_scan_async() -> dict:
    import asyncpg

    dsn = _normalize_dsn(DATABASE_URL)
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch(HANDOFF_QUERY)
    finally:
        await conn.close()

    # Import here to avoid circular import at module level
    from scanner.vm.nuclei_worker import run_nuclei_scan

    queued = 0
    for i, row in enumerate(rows):
        asset_id = str(row["id"])
        run_nuclei_scan.apply_async(
            args=[asset_id],
            countdown=i * 30,  # Stagger: 30s between each
        )
        queued += 1

    logger.info("weekly_vm_scan: queued %d assets", queued)
    return {"assets_queued": queued}


@celery_app.task(queue="vm_queue", name="vm.template_sync_check")
def template_sync_check() -> dict:
    """Check for nuclei-templates updates and trigger re-scans if needed."""
    return _run_async(_template_sync_check_async())


async def _template_sync_check_async() -> dict:
    # 1. Get current local version
    local_version = _get_local_template_version()

    # 2. Check GitHub releases API for latest version
    latest_version = _get_latest_github_release()
    if not latest_version:
        return {"status": "error", "message": "Could not fetch latest release"}

    if local_version == latest_version:
        return {"status": "up_to_date", "version": local_version}

    # 3. Pull updated templates
    logger.info("Template update available: %s -> %s", local_version, latest_version)
    updated = _pull_template_update()
    if not updated:
        return {"status": "update_failed", "local": local_version, "remote": latest_version}

    # 4. Rebuild routing table tag mappings
    _rebuild_routing_tags()

    # 5. Enqueue targeted re-scans for assets matching new template tags
    import asyncpg
    from scanner.vm.nuclei_worker import run_nuclei_scan

    dsn = _normalize_dsn(DATABASE_URL)
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch(HANDOFF_QUERY)
    finally:
        await conn.close()

    queued = 0
    for i, row in enumerate(rows):
        # Only re-scan assets that have tech_stack (likely affected by template updates)
        if row.get("tech_stack"):
            run_nuclei_scan.apply_async(
                args=[str(row["id"])],
                countdown=i * 30,
            )
            queued += 1

    return {
        "status": "updated",
        "old_version": local_version,
        "new_version": latest_version,
        "assets_requeued": queued,
    }


def _get_local_template_version() -> str:
    """Read local nuclei-templates version from .templates-config.json or similar."""
    config_paths = [
        os.path.expanduser("~/.local/nuclei-templates/.templates-config.json"),
        os.path.expanduser("~/nuclei-templates/.templates-config.json"),
    ]
    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                return data.get("nuclei-templates-version", "unknown")
            except Exception:
                pass
    return "unknown"


def _get_latest_github_release() -> str | None:
    """Query GitHub API for latest nuclei-templates release tag."""
    url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hakuna-vm-scanner"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("tag_name", "")
    except Exception:
        logger.warning("Failed to check GitHub for template updates", exc_info=True)
        return None


def _pull_template_update() -> bool:
    """Run nuclei -update-templates to pull latest."""
    import subprocess

    from scanner.vm.config import NUCLEI_BIN

    try:
        result = subprocess.run(
            [NUCLEI_BIN, "-update-templates"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            logger.info("Template update succeeded")
            return True
        logger.warning("Template update failed: %s", result.stderr[:500])
        return False
    except Exception:
        logger.exception("Template update subprocess failed")
        return False


def _rebuild_routing_tags() -> None:
    """Reload routing table after template sync."""
    from scanner.vm.router import reload_routing_table
    reload_routing_table()


# Beat schedule
celery_app.conf.beat_schedule.update({
    "weekly-vm-scan-monday-2am": {
        "task": "vm.weekly_scan",
        "schedule": crontab(hour=2, minute=0, day_of_week=1),  # Monday
    },
    "template-sync-every-6h": {
        "task": "vm.template_sync_check",
        "schedule": crontab(hour="*/6", minute=0),
    },
})
