"""EASM engine orchestrator.

Coordinates discovery phases, deduplicates artifacts, emits the unified
DiscoveryResult JSON object.

Modes:
    - discovery: Phase 1 only (attribution + artifact discovery)
    - scan: Phase 2/3 only (expects input artifacts; runs in hakuna-vm-scanner)
    - full: discovery + scan hand-off signal (vm-scanner picks up via task)
"""

from __future__ import annotations

import asyncio
import enum
import logging
from dataclasses import asdict
from datetime import datetime, timezone

from app.ingest.github_npm.attribution import (
    filter_above_threshold,
    is_noisy_target,
)
from app.ingest.github_npm.clients import GitHubClient, NpmClient
from app.ingest.github_npm.discovery import (
    enrich_repos_with_package_json,
    find_npm_packages_by_domain,
    find_orgs_by_domain,
    find_users_by_domain,
    repos_from_keyword_search,
    repos_from_npm_packages,
    repos_from_orgs,
    repos_from_users,
    scan_exposed_secret_files,
)
from app.ingest.github_npm.models import (
    AttributedRepo,
    DiscoveryResult,
)

logger = logging.getLogger(__name__)


class Mode(str, enum.Enum):
    DISCOVERY = "discovery"
    SCAN = "scan"
    FULL = "full"


DEFAULT_CONFIDENCE_THRESHOLD = 0.3


class EASMEngine:
    def __init__(
        self,
        *,
        github_tokens: list[str] | None = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        enable_keyword_search: bool = True,
        enable_package_json_enrichment: bool = True,
        enable_exposed_file_scan: bool = True,
        max_users: int = 200,
        max_packages: int = 250,
        max_keyword_results: int = 50,
        org_login_hints: list[str] | None = None,
    ):
        self.github_tokens = github_tokens
        self.confidence_threshold = confidence_threshold
        self.enable_keyword_search = enable_keyword_search
        self.enable_package_json_enrichment = enable_package_json_enrichment
        self.enable_exposed_file_scan = enable_exposed_file_scan
        self.max_users = max_users
        self.max_packages = max_packages
        self.max_keyword_results = max_keyword_results
        self.org_login_hints = org_login_hints or []

    async def run(
        self, target_domain: str, mode: Mode = Mode.DISCOVERY,
    ) -> DiscoveryResult:
        started = datetime.now(timezone.utc)
        result = DiscoveryResult(
            target_domain=target_domain,
            mode=mode.value,
            started_at=started.isoformat(),
        )

        if is_noisy_target(target_domain):
            result.errors.append(
                f"refusing to attribute noisy public domain '{target_domain}'"
            )
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        if mode is Mode.SCAN:
            # Scan-only mode means the caller already has artifacts and wants
            # the vm-scanner side. The engine here just returns an empty
            # discovery payload — the Celery dispatch path is separate.
            result.finished_at = datetime.now(timezone.utc).isoformat()
            result.errors.append("scan-only mode is handled in hakuna-vm-scanner")
            return result

        await self._run_discovery(target_domain, result)

        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result

    async def _run_discovery(self, target_domain: str, result: DiscoveryResult) -> None:
        async with GitHubClient(tokens=self.github_tokens) as gh, NpmClient() as npm:
            # GitHub's /search/code endpoint refuses unauthenticated requests
            # with a 422. Rather than silently 422 on every call, auto-disable
            # keyword search when no tokens are available and record it.
            has_gh_auth = bool(gh._tokens)
            if self.enable_keyword_search and not has_gh_auth:
                result.errors.append(
                    "keyword code search disabled: requires a GitHub token "
                    "(unauthenticated /search/code returns 422). Other "
                    "discovery phases run at the 60 req/hr unauth limit."
                )
                run_keyword_search = False
            else:
                run_keyword_search = self.enable_keyword_search

            # Phase 1a — orgs + users + npm packages in parallel
            orgs_task = asyncio.create_task(
                find_orgs_by_domain(gh, target_domain, candidate_logins=self.org_login_hints),
            )
            users_task = asyncio.create_task(
                find_users_by_domain(gh, target_domain, max_results=self.max_users),
            )
            packages_task = asyncio.create_task(
                find_npm_packages_by_domain(npm, target_domain, max_packages=self.max_packages),
            )

            orgs, users, npm_packages = await asyncio.gather(
                orgs_task, users_task, packages_task, return_exceptions=True,
            )

            if isinstance(orgs, Exception):
                result.errors.append(f"orgs: {orgs}")
                orgs = []
            if isinstance(users, Exception):
                result.errors.append(f"users: {users}")
                users = []
            if isinstance(npm_packages, Exception):
                result.errors.append(f"npm: {npm_packages}")
                npm_packages = []

            # Phase 1b — repos derived from orgs/users/npm, plus keyword search
            org_repos_task = asyncio.create_task(
                repos_from_orgs(gh, orgs, target_domain),
            )
            user_repos_task = asyncio.create_task(
                repos_from_users(gh, users, target_domain),
            )
            attributed_org_logins = {o.login for o in orgs}
            keyword_repos_task: asyncio.Task | None = None
            if run_keyword_search:
                keyword_repos_task = asyncio.create_task(
                    repos_from_keyword_search(
                        gh,
                        target_domain,
                        max_results=self.max_keyword_results,
                        attributed_org_logins=attributed_org_logins,
                    ),
                )

            org_repos, user_repos = await asyncio.gather(
                org_repos_task, user_repos_task, return_exceptions=True,
            )
            if isinstance(org_repos, Exception):
                result.errors.append(f"org_repos: {org_repos}")
                org_repos = []
            if isinstance(user_repos, Exception):
                result.errors.append(f"user_repos: {user_repos}")
                user_repos = []

            keyword_repos: list[AttributedRepo] = []
            if keyword_repos_task is not None:
                try:
                    keyword_repos = await keyword_repos_task
                except Exception as e:
                    result.errors.append(f"keyword: {e}")

            npm_derived_repos = repos_from_npm_packages(npm_packages, target_domain)

            all_repos = self._dedupe_repos([
                *org_repos, *user_repos, *keyword_repos, *npm_derived_repos,
            ])

            # Reverse-attribution: for any repo we haven't yet corroborated via
            # package.json, try fetching it from raw.githubusercontent.com (no
            # API budget cost) and upgrade confidence on a match. This is the
            # workaround for /search/code needing auth — we still get the
            # user's "package.json references domain" signal.
            if self.enable_package_json_enrichment and all_repos:
                try:
                    await enrich_repos_with_package_json(gh, all_repos, target_domain)
                except Exception as e:
                    result.errors.append(f"pkg_enrich: {e}")

            # Apply confidence threshold
            orgs_kept = filter_above_threshold(orgs, self.confidence_threshold)
            users_kept = filter_above_threshold(users, self.confidence_threshold)
            repos_kept = filter_above_threshold(all_repos, self.confidence_threshold)
            packages_kept = filter_above_threshold(npm_packages, self.confidence_threshold)

            # Phase 1c — exposed-file probes on kept repos. Runs against the
            # filtered list so we don't waste calls on low-confidence hits.
            exposed_files = []
            if self.enable_exposed_file_scan and repos_kept:
                try:
                    exposed_files = await scan_exposed_secret_files(gh, repos_kept)
                except Exception as e:
                    result.errors.append(f"exposed_files: {e}")

            result.attributed_assets["github_orgs"] = [asdict(o) for o in orgs_kept]
            result.attributed_assets["github_users"] = [asdict(u) for u in users_kept]
            result.attributed_assets["github_repos"] = [asdict(r) for r in repos_kept]
            result.attributed_assets["npm_packages"] = [asdict(p) for p in packages_kept]
            result.vulnerabilities["exposed_files"] = [asdict(f) for f in exposed_files]

            result.stats = {
                "orgs_found": len(orgs),
                "orgs_kept": len(orgs_kept),
                "users_found": len(users),
                "users_kept": len(users_kept),
                "repos_raw": len(all_repos),
                "repos_kept": len(repos_kept),
                "npm_found": len(npm_packages),
                "npm_kept": len(packages_kept),
                "exposed_files": len(exposed_files),
                "errors": len(result.errors),
            }

    @staticmethod
    def _dedupe_repos(repos: list[AttributedRepo]) -> list[AttributedRepo]:
        """Merge duplicates by full_name, unioning reasons and taking the
        max confidence_score."""
        by_name: dict[str, AttributedRepo] = {}
        for r in repos:
            existing = by_name.get(r.full_name)
            if existing is None:
                by_name[r.full_name] = r
                continue
            merged_reasons = list({*existing.reasons, *r.reasons})
            # Recompute score with the union of reasons so multiple
            # corroborating signals get the small bonus.
            from app.ingest.github_npm.attribution import top_level_confidence
            existing.reasons = merged_reasons
            existing.confidence_score = top_level_confidence(merged_reasons)
            # Keep richer metadata when the other copy has it.
            if not existing.language and r.language:
                existing.language = r.language
            if not existing.pushed_at and r.pushed_at:
                existing.pushed_at = r.pushed_at
            existing.stars = max(existing.stars, r.stars)
        return list(by_name.values())
