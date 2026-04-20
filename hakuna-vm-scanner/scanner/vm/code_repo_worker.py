"""Celery tasks for the code_repo pipeline.

Consumed by the vm-scanner worker. Dispatched from hakuna-scanner's
easm.run_github_npm_attribution task (by name over the shared broker).
"""

from __future__ import annotations

import asyncio
import logging

from scanner.vm.celery_app import celery_app
from scanner.vm.code_repo.engine import scan_npm_package as _scan_npm_package
from scanner.vm.code_repo.engine import scan_repo as _scan_repo

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            # Force GC so finalizers that schedule cleanup coroutines
            # enqueue their tasks before we drain the loop.
            import gc
            gc.collect()
            pending = asyncio.all_tasks(loop)
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()


@celery_app.task(
    name="code_repo.scan_repo",
    queue="code_repo_queue",
    bind=True,
    max_retries=2,
    soft_time_limit=1800,
    time_limit=2100,
)
def scan_repo_task(
    self,
    clone_url: str,
    full_name: str,
    *,
    default_branch: str = "main",
    org_id: str | None = None,
    confidence_score: float | None = None,
    attribution_reasons: list[str] | None = None,
) -> dict:
    try:
        result = _run_async(_scan_repo(
            clone_url=clone_url,
            full_name=full_name,
            default_branch=default_branch,
            confidence_score=confidence_score,
            attribution_reasons=attribution_reasons,
        ))
        result["org_id"] = org_id
        logger.info(
            "code_repo scan_repo %s: secrets=%d risks=%d errors=%d",
            full_name,
            len(result.get("secrets") or []),
            len(result.get("workflow_risks") or []),
            len(result.get("errors") or []),
        )
        return result
    except Exception as exc:
        logger.exception("code_repo.scan_repo failed for %s", full_name)
        return {
            "repo": full_name,
            "status": "error",
            "error": str(exc),
            "secrets": [],
            "workflow_risks": [],
            "dependency_cves": [],
            "org_id": org_id,
        }


@celery_app.task(
    name="code_repo.scan_npm_package",
    queue="code_repo_queue",
    bind=True,
    max_retries=2,
    soft_time_limit=300,
    time_limit=360,
)
def scan_npm_package_task(
    self,
    name: str,
    version: str | None = None,
    *,
    org_id: str | None = None,
    repository_url: str | None = None,
    confidence_score: float | None = None,
) -> dict:
    try:
        result = _run_async(_scan_npm_package(
            name=name,
            version=version,
            repository_url=repository_url,
            confidence_score=confidence_score,
        ))
        result["org_id"] = org_id
        logger.info(
            "code_repo scan_npm_package %s@%s: cves=%d unmaintained=%s",
            name, version or "latest",
            len(result.get("dependency_cves") or []),
            result.get("meta", {}).get("unmaintained"),
        )
        return result
    except Exception as exc:
        logger.exception("code_repo.scan_npm_package failed for %s", name)
        return {
            "repo": f"npm:{name}",
            "status": "error",
            "error": str(exc),
            "secrets": [],
            "workflow_risks": [],
            "dependency_cves": [],
            "org_id": org_id,
        }
