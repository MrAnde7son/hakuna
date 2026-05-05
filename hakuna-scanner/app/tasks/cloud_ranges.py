"""Daily refresh of cloud-provider IP ranges.

Fetches the authoritative IP-range feed for each provider and writes a
small per-provider JSON file (``{provider}.json``) into
``settings.cloud_ranges_dir``. The matcher (``app.ingest.cloud_ranges``)
loads them on first lookup and falls back to a bundled seed when files
are missing — so a single failed fetch doesn't break attribution.

Providers covered:

* AWS — ``ip-ranges.json`` (the canonical published feed)
* GCP — ``cloud.json`` (note: ``goog.json`` is broader and includes
  user-facing IPs like Maps, which we don't want)
* Cloudflare — ``ips-v4`` newline-delimited list
* Oracle — ``public_ip_ranges.json``
* DigitalOcean — ``google.csv`` (yes, that's the real filename)
* Fastly — ``public-ip-list`` JSON

Azure is intentionally not refreshed: their JSON download URL rotates
weekly and requires HTML scraping the download page. The matcher's seed
covers the major Azure /16s, and that coverage is good enough for
takeover-flagging in v1. Wire Azure in once we have a stable feed source.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import tempfile
from datetime import datetime, timezone

import aiohttp

from app.celery_app import celery
from app.config import settings
from app.ingest import cloud_ranges as cloud_ranges_matcher

logger = logging.getLogger(__name__)


_AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
_GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
_CLOUDFLARE_URL = "https://www.cloudflare.com/ips-v4"
_CLOUDFLARE_V6_URL = "https://www.cloudflare.com/ips-v6"
_ORACLE_URL = "https://docs.oracle.com/iaas/tools/public_ip_ranges.json"
_DIGITALOCEAN_URL = "https://www.digitalocean.com/geo/google.csv"
_FASTLY_URL = "https://api.fastly.com/public-ip-list"

_TIMEOUT = aiohttp.ClientTimeout(total=60)


async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str | None:
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                logger.warning("cloud_ranges fetch: HTTP %d for %s", resp.status, url)
                return None
            return await resp.text()
    except Exception as exc:
        logger.warning("cloud_ranges fetch: failed for %s: %s", url, exc)
        return None


async def _fetch_aws(session) -> list[str]:
    body = await _fetch_text(session, _AWS_URL)
    if not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    cidrs: set[str] = set()
    for entry in data.get("prefixes", []) or []:
        prefix = entry.get("ip_prefix")
        if prefix:
            cidrs.add(prefix)
    for entry in data.get("ipv6_prefixes", []) or []:
        prefix = entry.get("ipv6_prefix")
        if prefix:
            cidrs.add(prefix)
    return sorted(cidrs)


async def _fetch_gcp(session) -> list[str]:
    body = await _fetch_text(session, _GCP_URL)
    if not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    cidrs: set[str] = set()
    for entry in data.get("prefixes", []) or []:
        prefix = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        if prefix:
            cidrs.add(prefix)
    return sorted(cidrs)


async def _fetch_cloudflare(session) -> list[str]:
    cidrs: set[str] = set()
    for url in (_CLOUDFLARE_URL, _CLOUDFLARE_V6_URL):
        body = await _fetch_text(session, url)
        if not body:
            continue
        for line in body.splitlines():
            line = line.strip()
            if line:
                cidrs.add(line)
    return sorted(cidrs)


async def _fetch_oracle(session) -> list[str]:
    body = await _fetch_text(session, _ORACLE_URL)
    if not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    cidrs: set[str] = set()
    for region in data.get("regions", []) or []:
        for entry in region.get("cidrs", []) or []:
            cidr = entry.get("cidr")
            if cidr:
                cidrs.add(cidr)
    return sorted(cidrs)


async def _fetch_digitalocean(session) -> list[str]:
    body = await _fetch_text(session, _DIGITALOCEAN_URL)
    if not body:
        return []
    cidrs: set[str] = set()
    for row in csv.reader(io.StringIO(body)):
        if not row:
            continue
        cidr = row[0].strip()
        if "/" in cidr:
            cidrs.add(cidr)
    return sorted(cidrs)


async def _fetch_fastly(session) -> list[str]:
    body = await _fetch_text(session, _FASTLY_URL)
    if not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    cidrs: set[str] = set()
    for cidr in data.get("addresses", []) or []:
        cidrs.add(cidr)
    for cidr in data.get("ipv6_addresses", []) or []:
        cidrs.add(cidr)
    return sorted(cidrs)


_FETCHERS = {
    "aws": _fetch_aws,
    "gcp": _fetch_gcp,
    "cloudflare": _fetch_cloudflare,
    "oracle": _fetch_oracle,
    "digitalocean": _fetch_digitalocean,
    "fastly": _fetch_fastly,
}


def _atomic_write_json(path: str, payload: dict) -> None:
    """Write JSON to ``path`` via tmp + rename. Caller ensures dir exists."""
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".cloud_ranges_", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


async def _refresh_all() -> dict:
    target_dir = settings.cloud_ranges_dir
    os.makedirs(target_dir, exist_ok=True)

    summary: dict[str, dict] = {}
    async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
        results = await asyncio.gather(
            *(fetcher(session) for fetcher in _FETCHERS.values()),
            return_exceptions=True,
        )

    now = datetime.now(timezone.utc).isoformat()
    for provider, result in zip(_FETCHERS.keys(), results):
        if isinstance(result, Exception):
            logger.warning("cloud_ranges refresh: %s raised %s", provider, result)
            summary[provider] = {"status": "error", "error": str(result)}
            continue
        cidrs = result
        if not cidrs:
            summary[provider] = {"status": "empty"}
            continue
        path = os.path.join(target_dir, f"{provider}.json")
        try:
            _atomic_write_json(path, {"updated_at": now, "cidrs": cidrs})
            summary[provider] = {"status": "ok", "count": len(cidrs)}
        except Exception as exc:
            logger.warning("cloud_ranges refresh: write failed for %s: %s", provider, exc)
            summary[provider] = {"status": "write_failed", "error": str(exc)}

    # Refresh the in-process matcher so the next liveness pass sees the
    # new ranges without waiting for a worker restart.
    try:
        cloud_ranges_matcher.reload()
    except Exception as exc:
        logger.warning("cloud_ranges refresh: matcher reload failed: %s", exc)

    logger.info("cloud_ranges refresh summary: %s", summary)
    return summary


@celery.task(name="cloud_ranges.refresh", soft_time_limit=300, time_limit=360)
def refresh_cloud_ranges() -> dict:
    """Fetch all provider IP ranges and write per-provider JSON files."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_refresh_all())
    finally:
        loop.close()
