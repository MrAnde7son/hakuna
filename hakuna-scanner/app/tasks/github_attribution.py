"""Celery task: run EASM GitHub/npm attribution for a target domain.

Returns the unified DiscoveryResult JSON in the task result payload. The
backend imports the result like it does for vm-scanner nuclei runs.

In 'full' mode, also dispatches vm-scanner 'code_repo.scan_repo' tasks for
each high-confidence repo and each npm package.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.celery_app import celery
from app.ingest.github_npm.engine import DEFAULT_CONFIDENCE_THRESHOLD, EASMEngine, Mode

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery.task(
    bind=True,
    name="easm.run_github_npm_attribution",
    autoretry_for=(ConnectionError,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_kwargs={"max_retries": 3},
    soft_time_limit=3600,
    time_limit=3900,
)
def run_github_npm_attribution(
    self,
    target_domain: str,
    *,
    org_id: str | None = None,
    mode: str = Mode.DISCOVERY.value,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    enable_keyword_search: bool = True,
    org_login_hints: list[str] | None = None,
    github_tokens: list[str] | None = None,
    dispatch_vm_scans: bool = False,
) -> dict[str, Any]:
    """Run the EASM GitHub/npm engine. Returns the full DiscoveryResult dict.

    When dispatch_vm_scans=True (or mode=='full'), after discovery finishes
    we enqueue vm-scanner code_repo tasks by name (no cross-container import).
    """
    engine = EASMEngine(
        github_tokens=github_tokens,
        confidence_threshold=confidence_threshold,
        enable_keyword_search=enable_keyword_search,
        org_login_hints=org_login_hints or [],
    )
    mode_enum = Mode(mode)
    result = _run_async(engine.run(target_domain, mode=mode_enum))
    payload = result.to_dict()
    payload["org_id"] = org_id

    should_dispatch = dispatch_vm_scans or mode_enum is Mode.FULL
    if should_dispatch:
        dispatched = _dispatch_vm_scans(org_id, payload)
        payload["dispatched_vm_scans"] = dispatched
        logger.info(
            "easm attribution for %s dispatched %d vm-scanner tasks",
            target_domain, dispatched,
        )

    logger.info(
        "easm attribution for %s: orgs=%d users=%d repos=%d npm=%d errors=%d",
        target_domain,
        payload["stats"].get("orgs_kept", 0),
        payload["stats"].get("users_kept", 0),
        payload["stats"].get("repos_kept", 0),
        payload["stats"].get("npm_kept", 0),
        payload["stats"].get("errors", 0),
    )
    return payload


def _dispatch_vm_scans(org_id: str | None, result: dict[str, Any]) -> int:
    """Send a signature to the vm-scanner Celery broker for each high-
    confidence repo and each npm package.

    We use celery.send_task (by name) so this process doesn't need to import
    vm-scanner code — the two containers share a broker, not a codebase.
    """
    repos = result.get("attributed_assets", {}).get("github_repos") or []
    npm_pkgs = result.get("attributed_assets", {}).get("npm_packages") or []
    dispatched = 0

    for repo in repos:
        celery.send_task(
            "code_repo.scan_repo",
            kwargs={
                "clone_url": repo["clone_url"],
                "full_name": repo["full_name"],
                "default_branch": repo.get("default_branch") or "main",
                "org_id": org_id,
                "confidence_score": repo.get("confidence_score"),
                "attribution_reasons": repo.get("reasons") or [],
            },
            queue="code_repo_queue",
        )
        dispatched += 1

    for pkg in npm_pkgs:
        celery.send_task(
            "code_repo.scan_npm_package",
            kwargs={
                "name": pkg["name"],
                "version": pkg.get("version"),
                "org_id": org_id,
                "repository_url": pkg.get("repository_url"),
                "confidence_score": pkg.get("confidence_score"),
            },
            queue="code_repo_queue",
        )
        dispatched += 1

    return dispatched
