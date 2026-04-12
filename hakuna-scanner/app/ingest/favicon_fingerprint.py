"""Favicon hash fingerprinting — identify technologies by favicon mmh3 hash.

Downloads /favicon.ico (and alternate paths), computes the mmh3 hash of the
base64-encoded response body, and matches against a known hash database.
This is the same hashing scheme Shodan uses, so community hash DBs are
directly compatible.

Favicon hashing is one of the highest-signal passive fingerprinting
techniques because:
  1. Favicons rarely change across deployments of the same product.
  2. Custom error pages and CDNs usually don't alter favicon responses.
  3. Many products (Jenkins, Grafana, Tomcat) ship unique favicons that
     are never customized by operators.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
from html.parser import HTMLParser
from urllib.parse import urljoin

import aiohttp

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(__file__), "favicon_hash_db.json")

# Max favicon size to download (most are <50KB; skip unusually large ones).
_MAX_FAVICON_BYTES = 200_000

# Paths to try when looking for a favicon.
_FAVICON_PATHS = ["/favicon.ico", "/favicon.png"]


def _mmh3_hash(data: bytes) -> int:
    """Compute mmh3 hash of base64-encoded data (Shodan-compatible)."""
    try:
        import mmh3
    except ImportError:
        # Fallback: pure-Python murmurhash3 for the 32-bit x86 variant.
        return _mmh3_pure(base64.encodebytes(data))
    return mmh3.hash(base64.encodebytes(data))


def _mmh3_pure(data: bytes) -> int:
    """Pure-Python MurmurHash3 x86_32 implementation for environments
    without the mmh3 C extension."""
    import struct

    def _fmix(h: int) -> int:
        h ^= h >> 16
        h = (h * 0x85EBCA6B) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xC2B2AE35) & 0xFFFFFFFF
        h ^= h >> 16
        return h

    length = len(data)
    nblocks = length // 4
    h1 = 0  # seed=0
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(nblocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 = _fmix(h1)

    # Convert to signed 32-bit.
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


class _LinkExtractor(HTMLParser):
    """Extract <link rel="icon"> href from HTML."""

    def __init__(self):
        super().__init__()
        self.icon_hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        if tag.lower() != "link":
            return
        attr_dict = {k.lower(): v for k, v in attrs}
        rel = (attr_dict.get("rel") or "").lower()
        if "icon" in rel:
            href = attr_dict.get("href")
            if href:
                self.icon_hrefs.append(href)

    def error(self, message):
        pass


def _load_db() -> dict[str, dict]:
    try:
        with open(_DB_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("favicon_fingerprint: failed to load %s: %s", _DB_PATH, exc)
        return {}
    return data.get("hashes", {})


_DB: dict[str, dict] = _load_db()


def _format_cpe(vendor: str, product: str, version: str = "*") -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


async def _fetch_favicon(
    session: aiohttp.ClientSession,
    url: str,
) -> bytes | None:
    """Download a favicon URL, return bytes or None."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return None
            ct = resp.headers.get("Content-Type", "")
            # Reject HTML error pages served as 200.
            if "text/html" in ct.lower():
                return None
            body = await resp.read()
            if not body or len(body) > _MAX_FAVICON_BYTES:
                return None
            return body
    except Exception:
        return None


async def _find_favicon_urls(
    session: aiohttp.ClientSession,
    base_url: str,
) -> list[str]:
    """Discover favicon URLs: try <link rel=icon> in HTML, then default paths."""
    urls: list[str] = []

    # First try parsing <link rel="icon"> from the page.
    try:
        async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                html = await resp.text(errors="replace")
                parser = _LinkExtractor()
                parser.feed(html[:256_000])
                for href in parser.icon_hrefs[:3]:
                    href = href.strip()
                    if href.startswith("//"):
                        href = "https:" + href
                    elif href.startswith("/") or "://" not in href:
                        href = urljoin(base_url, href)
                    urls.append(href)
    except Exception:
        pass

    # Append default paths as fallbacks.
    for path in _FAVICON_PATHS:
        urls.append(urljoin(base_url, path))

    # Deduplicate preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


async def fingerprint_url(
    session: aiohttp.ClientSession,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """Fingerprint a single URL by its favicon hash.

    Returns a list of detection dicts (usually 0 or 1):
    {name, cpe_vendor, cpe_product, cpe, source, favicon_hash}.
    """
    async with semaphore:
        try:
            return await _fingerprint_url_inner(session, base_url)
        except Exception as exc:
            logger.debug("favicon_fingerprint: error for %s: %s", base_url, exc)
            return []


async def _fingerprint_url_inner(
    session: aiohttp.ClientSession,
    base_url: str,
) -> list[dict]:
    favicon_urls = await _find_favicon_urls(session, base_url)

    for fav_url in favicon_urls:
        body = await _fetch_favicon(session, fav_url)
        if not body:
            continue

        fav_hash = _mmh3_hash(body)
        hash_str = str(fav_hash)

        match = _DB.get(hash_str)
        if match:
            return [{
                "name": match["name"],
                "cpe_vendor": match["cpe_vendor"],
                "cpe_product": match["cpe_product"],
                "cpe": _format_cpe(match["cpe_vendor"], match["cpe_product"]),
                "source": "favicon",
                "favicon_hash": fav_hash,
            }]

    return []


async def fingerprint_assets(
    assets: list[dict],
    concurrency: int = 20,
    connect_timeout: int = 10,
) -> dict[str, list[dict]]:
    """Fingerprint favicons for a batch of assets.

    Args:
        assets: list of dicts with keys: hostname, open_ports, id
        concurrency: max parallel HTTP connections
        connect_timeout: TCP connect timeout

    Returns:
        dict mapping hostname -> list of detection dicts.
    """
    if not _DB:
        logger.warning("favicon_fingerprint: hash DB is empty, skipping")
        return {}

    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    timeout = aiohttp.ClientTimeout(total=30, connect=connect_timeout)

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
        "Accept": "*/*",
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
    detections = await fingerprint_url(session, url, semaphore)
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
    """Force-reload the hash DB from disk. For tests."""
    global _DB
    _DB = _load_db()
