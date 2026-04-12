"""Default endpoint probing — detect technologies by probing known paths.

Sends HEAD/GET requests to a curated list of known application paths
(e.g. /wp-login.php, /owa/auth/logon.aspx, /actuator/health) and confirms
the technology by checking status codes and response body patterns.

This catches applications that:
  - Don't leak technology in HTTP headers or HTML meta tags.
  - Are behind reverse proxies that strip Server headers.
  - Use custom favicons (defeating favicon hashing).
  - Run on non-standard ports without banner leaks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re

import aiohttp

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(__file__), "endpoint_probe_db.json")

# Only read the first N bytes of the response body for pattern matching.
_MAX_BODY_BYTES = 32_000


def _load_db() -> list[dict]:
    try:
        with open(_DB_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("endpoint_probe: failed to load %s: %s", _DB_PATH, exc)
        return []
    probes = data.get("probes", [])
    for probe in probes:
        probe["_body_rx"] = (
            re.compile(probe["body_pattern"], re.IGNORECASE)
            if probe.get("body_pattern")
            else None
        )
        probe["_version_rx"] = (
            re.compile(probe["version_pattern"], re.IGNORECASE)
            if probe.get("version_pattern")
            else None
        )
    return probes


_DB: list[dict] = _load_db()


def _format_cpe(vendor: str, product: str, version: str = "*") -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


async def _probe_one(
    session: aiohttp.ClientSession,
    base_url: str,
    probe: dict,
) -> dict | None:
    """Send a single probe request and check for a match.

    Returns a detection dict or None.
    """
    url = base_url.rstrip("/") + probe["path"]
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=8),
            allow_redirects=False,
        ) as resp:
            status = resp.status
            if status not in probe.get("match_status", [200]):
                return None

            # Read body for pattern matching.
            body = ""
            if probe["_body_rx"]:
                raw = await resp.content.read(_MAX_BODY_BYTES)
                body = raw.decode("utf-8", errors="replace")
                if not probe["_body_rx"].search(body):
                    return None

            # Extract version if possible.
            version = "*"
            if probe["_version_rx"] and body:
                vm = probe["_version_rx"].search(body)
                if vm and "version" in vm.groupdict():
                    version = vm.group("version")

            return {
                "name": probe["name"],
                "cpe_vendor": probe["cpe_vendor"],
                "cpe_product": probe["cpe_product"],
                "version": version,
                "cpe": _format_cpe(probe["cpe_vendor"], probe["cpe_product"], version),
                "source": "endpoint_probe",
                "path": probe["path"],
                "status": status,
            }
    except Exception:
        return None


async def probe_url(
    session: aiohttp.ClientSession,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """Probe a single base URL against all known endpoints.

    Returns list of detection dicts. Never raises.
    """
    async with semaphore:
        try:
            return await _probe_url_inner(session, base_url)
        except Exception as exc:
            logger.debug("endpoint_probe: error for %s: %s", base_url, exc)
            return []


async def _probe_url_inner(
    session: aiohttp.ClientSession,
    base_url: str,
) -> list[dict]:
    detections: list[dict] = []
    seen: set[str] = set()

    # Run probes concurrently in small batches to avoid hammering a single host.
    batch_size = 5
    for i in range(0, len(_DB), batch_size):
        batch = _DB[i:i + batch_size]
        results = await asyncio.gather(
            *(_probe_one(session, base_url, probe) for probe in batch),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception) or result is None:
                continue
            key = f"{result['cpe_vendor']}:{result['cpe_product']}"
            if key not in seen:
                seen.add(key)
                detections.append(result)

    return detections


async def probe_assets(
    assets: list[dict],
    concurrency: int = 10,
    connect_timeout: int = 8,
) -> dict[str, list[dict]]:
    """Probe known endpoints for a batch of assets.

    Args:
        assets: list of dicts with keys: hostname, open_ports, id
        concurrency: max parallel host probing (each host sends ~30 probes)
        connect_timeout: TCP connect timeout

    Returns:
        dict mapping hostname -> list of detection dicts.
    """
    if not _DB:
        logger.warning("endpoint_probe: probe DB is empty, skipping")
        return {}

    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency * 5, ssl=False)
    timeout = aiohttp.ClientTimeout(total=60, connect=connect_timeout)

    results: dict[str, list[dict]] = {}
    targets: list[tuple[str, str]] = []

    for asset in assets:
        hostname = asset["hostname"]
        ports = set(asset.get("open_ports") or [])
        if 443 in ports:
            targets.append((hostname, f"https://{hostname}"))
        elif 8443 in ports:
            targets.append((hostname, f"https://{hostname}:8443"))
        if 80 in ports:
            targets.append((hostname, f"http://{hostname}"))
        elif 8080 in ports:
            targets.append((hostname, f"http://{hostname}:8080"))
        if not ports & {80, 443, 8080, 8443}:
            targets.append((hostname, f"https://{hostname}"))

    if not targets:
        return results

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; HakunaScanner/1.0)",
        "Accept": "text/html,application/json,*/*",
    }

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=headers,
    ) as session:
        tasks = [
            _run_one(session, semaphore, hostname, url, results)
            for hostname, url in targets
        ]
        await asyncio.gather(*tasks)

    return results


async def _run_one(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    hostname: str,
    url: str,
    results: dict[str, list[dict]],
):
    detections = await probe_url(session, url, semaphore)
    if detections:
        existing = results.get(hostname, [])
        seen = {f"{d['cpe_vendor']}:{d['cpe_product']}" for d in existing}
        for det in detections:
            key = f"{det['cpe_vendor']}:{det['cpe_product']}"
            if key not in seen:
                seen.add(key)
                existing.append(det)
        results[hostname] = existing


def reload_db() -> None:
    """Force-reload the probe DB from disk. For tests."""
    global _DB
    _DB = _load_db()
