"""npm supply-chain checks.

Two signals per package:
  - unmaintained: no publish in > STALE_THRESHOLD_DAYS (default 365)
  - advisory_cves: GitHub Advisory DB via the /advisories endpoint
    (no auth required for public advisories).
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import aiohttp

logger = logging.getLogger(__name__)

NPM_REGISTRY = "https://registry.npmjs.org"
STALE_THRESHOLD_DAYS = int(os.environ.get("NPM_STALE_THRESHOLD_DAYS", "365"))

# GitHub REST advisory endpoint — public, no auth needed for reads.
GH_ADVISORIES = "https://api.github.com/advisories"


async def check_package(
    name: str,
    version: str | None = None,
    *,
    session: aiohttp.ClientSession | None = None,
) -> dict:
    """Return {package, installed_version, unmaintained, last_published,
    cves: [DependencyCVE-shaped dicts]}."""
    owns_session = session is None
    if owns_session:
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "hakuna-easm/1.0"},
        )

    try:
        encoded = name.replace("/", "%2F")
        last_published, installed_version = await _fetch_last_published(
            session, encoded, version,
        )
        unmaintained = _is_unmaintained(last_published)

        cves = await _fetch_advisories(session, name, installed_version)

        return {
            "package": name,
            "installed_version": installed_version,
            "last_published": last_published.isoformat() if last_published else None,
            "unmaintained": unmaintained,
            "cves": cves,
        }
    finally:
        if owns_session and session is not None:
            await session.close()


async def _fetch_last_published(
    session: aiohttp.ClientSession, encoded_name: str, version: str | None,
) -> tuple[datetime | None, str | None]:
    async with session.get(f"{NPM_REGISTRY}/{encoded_name}") as resp:
        if resp.status != 200:
            return None, version
        data = await resp.json()

    dist_tags = data.get("dist-tags") or {}
    latest = dist_tags.get("latest")
    installed = version or latest
    time_map = data.get("time") or {}

    ts = None
    if installed and installed in time_map:
        ts = time_map[installed]
    elif latest and latest in time_map:
        ts = time_map[latest]
    elif "modified" in time_map:
        ts = time_map["modified"]

    if not ts:
        return None, installed

    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")), installed
    except (ValueError, AttributeError):
        return None, installed


def _is_unmaintained(last_published: datetime | None) -> bool:
    if last_published is None:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_THRESHOLD_DAYS)
    return last_published < cutoff


async def _fetch_advisories(
    session: aiohttp.ClientSession, pkg_name: str, version: str | None,
) -> list[dict]:
    """Best-effort advisory lookup. Public endpoint returns 60 req/hr unauth;
    we make one request per package, so that's fine for <60 packages per hour.
    """
    params = {"ecosystem": "npm", "affects": pkg_name, "per_page": 30}
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with session.get(GH_ADVISORIES, params=params, headers=headers) as resp:
            if resp.status != 200:
                return []
            items = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.info("advisory fetch failed for %s: %s", pkg_name, e)
        return []

    cves: list[dict] = []
    if not isinstance(items, list):
        return []
    for adv in items:
        severity = (adv.get("severity") or "medium").lower()
        cve_id = adv.get("cve_id")
        vulns = adv.get("vulnerabilities") or []
        fix_available = False
        package_version_match = version is None  # default to "might affect"
        for v in vulns:
            pkg = v.get("package") or {}
            if (pkg.get("ecosystem") != "npm") or (pkg.get("name") != pkg_name):
                continue
            first_patched = (v.get("first_patched_version") or {}).get("identifier")
            if first_patched:
                fix_available = True
            ranges = v.get("vulnerable_version_range") or ""
            if version and ranges and _version_in_range(version, ranges):
                package_version_match = True

        if not package_version_match:
            continue

        cves.append({
            "package": pkg_name,
            "installed_version": version,
            "cve": cve_id,
            "severity": severity,
            "advisory_url": adv.get("html_url"),
            "fix_available": fix_available,
            "unmaintained": False,
        })
    return cves


def _version_in_range(version: str, range_spec: str) -> bool:
    """Permissive version-range check. Returns True on parse failure so we
    err on the side of reporting rather than dropping.

    Supports the basic forms returned by the GitHub advisories endpoint:
      ">= 1.0.0", "< 2.3.1", ">= 1.0, < 2.0", "= 1.2.3".
    """
    try:
        from packaging.version import Version
    except ImportError:
        return True  # best-effort

    def _parse(v: str) -> "Version | None":
        try:
            return Version(v.strip().lstrip("v"))
        except Exception:
            return None

    pv = _parse(version)
    if pv is None:
        return True

    for clause in range_spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        for op in (">=", "<=", ">", "<", "=="):
            if clause.startswith(op):
                bound = _parse(clause[len(op):])
                if bound is None:
                    return True
                if op == ">=" and not (pv >= bound):
                    return False
                if op == ">" and not (pv > bound):
                    return False
                if op == "<=" and not (pv <= bound):
                    return False
                if op == "<" and not (pv < bound):
                    return False
                if op == "==" and not (pv == bound):
                    return False
                break
        else:
            # Bare version or "=" (no operator form)
            if clause.startswith("="):
                bound = _parse(clause[1:])
            else:
                bound = _parse(clause)
            if bound is not None and pv != bound:
                return False
    return True
