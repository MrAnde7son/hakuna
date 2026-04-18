"""Orchestrator for scanning one GitHub repo or one npm package.

Called from scanner.vm.code_repo_worker Celery tasks. Returns a
JSON-serializable dict so the backend can import findings on its side.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from scanner.vm.code_repo import secrets as secrets_mod
from scanner.vm.code_repo import supply_chain, validators, workflow_audit
from scanner.vm.code_repo.clone import CloneError, shallow_clone

logger = logging.getLogger(__name__)


@dataclass
class RepoScanResult:
    repo: str
    status: str = "complete"
    duration_seconds: float = 0.0
    secrets: list[dict] = field(default_factory=list)
    workflow_risks: list[dict] = field(default_factory=list)
    dependency_cves: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def scan_repo(
    clone_url: str,
    full_name: str,
    *,
    default_branch: str = "main",
    confidence_score: float | None = None,
    attribution_reasons: list[str] | None = None,
) -> dict[str, Any]:
    """Clone, secrets-scan, workflow-audit. Returns dict payload."""
    start = time.monotonic()
    result = RepoScanResult(repo=full_name)
    result.meta = {
        "clone_url": clone_url,
        "default_branch": default_branch,
        "confidence_score": confidence_score,
        "attribution_reasons": attribution_reasons or [],
    }

    try:
        async with shallow_clone(clone_url, branch=default_branch) as path:
            # Secrets
            secrets_out = await secrets_mod.scan_directory(path)
            if secrets_out.get("error"):
                result.errors.append(f"secrets: {secrets_out['error']}")
            for f in secrets_out.get("findings") or []:
                f_with_validation = dict(f)
                f_with_validation["repo"] = full_name
                recipe = validators.build_validation(f["detector"], f.get("redacted", ""))
                if recipe is not None:
                    f_with_validation["validation_nuclei"] = recipe
                result.secrets.append(f_with_validation)

            # Workflows
            try:
                risks = workflow_audit.audit_workflows(path, full_name)
                result.workflow_risks.extend(risks)
            except Exception as e:
                logger.exception("workflow audit failed for %s", full_name)
                result.errors.append(f"workflow_audit: {e}")

    except CloneError as e:
        result.status = "clone_failed"
        result.errors.append(str(e))
    except Exception as e:
        logger.exception("repo scan unexpected failure for %s", full_name)
        result.status = "error"
        result.errors.append(str(e))

    result.duration_seconds = round(time.monotonic() - start, 2)
    return result.to_dict()


async def scan_npm_package(
    name: str,
    version: str | None = None,
    *,
    repository_url: str | None = None,
    confidence_score: float | None = None,
) -> dict[str, Any]:
    """npm packages: supply-chain checks only (no clone). If the package
    points at a GitHub repo, the caller can additionally run scan_repo()
    on repository_url separately — we don't chain it here to keep one-task-
    one-thing."""
    start = time.monotonic()
    result = RepoScanResult(repo=f"npm:{name}")
    result.meta = {
        "name": name,
        "version": version,
        "repository_url": repository_url,
        "confidence_score": confidence_score,
    }

    try:
        info = await supply_chain.check_package(name, version)
        result.meta["last_published"] = info.get("last_published")
        result.meta["unmaintained"] = info.get("unmaintained", False)
        if info.get("unmaintained"):
            result.dependency_cves.append({
                "package": name,
                "installed_version": info.get("installed_version"),
                "cve": None,
                "severity": "low",
                "advisory_url": None,
                "fix_available": False,
                "unmaintained": True,
            })
        result.dependency_cves.extend(info.get("cves") or [])
    except Exception as e:
        logger.exception("npm supply-chain failed for %s", name)
        result.status = "error"
        result.errors.append(str(e))

    result.duration_seconds = round(time.monotonic() - start, 2)
    return result.to_dict()
