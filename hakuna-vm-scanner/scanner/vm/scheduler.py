"""Celery Beat scheduler for VM scanner maintenance tasks.

Per-asset vulnerability scans are no longer scheduled from inside this
container — the backend (services/vm_scanner.py) owns scan scheduling
and dispatches jobs via the /vm/scans/ HTTP API so that results flow
back through the backend's ingest pipeline (services/post_ingest.
finalize_scan), which is the single source of dedup, tagging, SLA,
threat intel, and risk scoring.

This module retains only container-local maintenance jobs (template
sync).
"""

import asyncio
import glob
import json
import logging
import os
import shutil
import socket
import subprocess
import urllib.error
import urllib.request

from celery.schedules import crontab

from scanner.vm.celery_app import celery_app
from scanner.vm.config import (
    DAST_TEMPLATES_DIR,
    DAST_TEMPLATES_REPO,
    DATABASE_URL,
    TEMPLATES_DIR,
)
from scanner.vm.db import _normalize_dsn

logger = logging.getLogger(__name__)


def _template_sync_disabled() -> bool:
    """True when operator has opted out (air-gapped / egress-restricted).

    Reads at call-time so tests and restarts pick up the flag without
    module reloads.
    """
    return os.environ.get("TEMPLATE_SYNC_DISABLED", "").lower() in ("1", "true", "yes")


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(queue="vm_queue", name="vm.template_sync_check")
def template_sync_check() -> dict:
    """Check for nuclei-templates updates and pull them if available.

    Unlike the old weekly_vm_scan task, this does NOT enqueue per-asset
    scans after updating. Re-scanning on template update is a scheduling
    decision that belongs to the backend.
    """
    return _run_async(_template_sync_check_async())


async def _template_sync_check_async() -> dict:
    if _template_sync_disabled():
        # Explicit opt-out — don't hit the network, don't emit a warning.
        # Air-gapped deployments set TEMPLATE_SYNC_DISABLED=1 and sync
        # templates via their own artifact pipeline.
        return {"status": "disabled"}

    # 1. Get current local version
    local_version = _get_local_template_version()

    # 2. Check GitHub releases API for latest version
    latest_version = _get_latest_github_release()
    if latest_version is None:
        # Network / DNS error — treated as soft failure so the 6-hourly
        # task doesn't flood logs when the container has no egress.
        return {"status": "unreachable", "local_version": local_version}
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

    return {
        "status": "updated",
        "old_version": local_version,
        "new_version": latest_version,
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
    """Query GitHub API for latest nuclei-templates release tag.

    Returns None on any error; callers distinguish "no egress" from real
    failures by the log level — DNS/URL errors log a compact info message
    (the container runs this every 6h, so a stack trace per cycle would
    drown real issues), anything else logs a warning with traceback.
    """
    url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hakuna-vm-scanner"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("tag_name", "")
    except (urllib.error.URLError, socket.gaierror, TimeoutError) as exc:
        logger.info("Template sync: GitHub unreachable (%s) — skipping this cycle", exc)
        return None
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


@celery_app.task(queue="vm_queue", name="vm.dast_template_sync")
def dast_template_sync() -> dict:
    """Clone or fast-forward reewardius/nuclei-dast-templates into custom/dast/.

    These are auto-included by router._get_custom_templates when the asset
    has a web-serving port open (no separate scan profile needed — DAST
    runs as part of every VM scan against HTTP-facing targets).

    Scheduled daily; the upstream repo is low-volume so more frequent syncs
    would just waste API calls.
    """
    return _dast_template_sync_impl()


def _dast_template_sync_impl(
    repo_url: str | None = None,
    target_dir: str | None = None,
) -> dict:
    """Sync implementation — parameters exist for testability."""
    repo = repo_url or DAST_TEMPLATES_REPO
    dest = target_dir or DAST_TEMPLATES_DIR

    os.makedirs(os.path.dirname(dest), exist_ok=True)

    if os.path.isdir(os.path.join(dest, ".git")):
        cmd = ["git", "-C", dest, "pull", "--ff-only", "--quiet"]
        action = "pull"
    else:
        # Fresh clone — wipe any stale non-git dir first so clone doesn't fail.
        if os.path.exists(dest):
            shutil.rmtree(dest)
        cmd = ["git", "clone", "--depth", "1", "--quiet", repo, dest]
        action = "clone"

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as exc:
        logger.exception("DAST template %s subprocess failed", action)
        return {"status": "error", "action": action, "error": str(exc)}

    if result.returncode != 0:
        logger.warning("DAST template %s failed: %s", action, result.stderr[:500])
        return {
            "status": "error",
            "action": action,
            "stderr": result.stderr[:500],
        }

    template_count = len(
        glob.glob(os.path.join(dest, "**", "*.yaml"), recursive=True)
    )
    logger.info("DAST template %s succeeded: %d templates", action, template_count)
    return {"status": "ok", "action": action, "template_count": template_count}


# Beat schedule — only template sync runs here. Scan scheduling lives in the backend.
celery_app.conf.beat_schedule.update({
    "template-sync-every-6h": {
        "task": "vm.template_sync_check",
        "schedule": crontab(hour="*/6", minute=0),
    },
    "dast-template-sync-daily": {
        "task": "vm.dast_template_sync",
        "schedule": crontab(hour=3, minute=0),  # 03:00 UTC
    },
})

