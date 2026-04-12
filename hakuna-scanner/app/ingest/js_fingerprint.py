"""JavaScript library fingerprinting — detect client-side libraries with versions.

Fetches HTML pages, extracts <script> tags, downloads JS files, and matches
version patterns against a fingerprint database (js_fingerprint_db.json).

This fills the gap where httpx's Wappalyzer-based -tech-detect catches
server-side tech (nginx, ASP.NET) but misses client-side libraries like
jQuery 3.1.1 or Moment.js 2.29.1 that Tenable ASM detects.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import aiohttp

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(__file__), "js_fingerprint_db.json")

# How many bytes to read from each JS file (version banners are at the top).
_JS_HEAD_BYTES = 8192
# Max script tags to process per page.
_MAX_SCRIPTS_PER_PAGE = 50
# Max total JS files to download per page.
_MAX_JS_DOWNLOADS_PER_PAGE = 30


def _load_db() -> list[dict]:
    try:
        with open(_DB_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("js_fingerprint: failed to load %s: %s", _DB_PATH, exc)
        return []
    libs = data.get("libraries", [])
    # Pre-compile regexes.
    for lib in libs:
        lib["_url_compiled"] = [
            re.compile(p, re.IGNORECASE) for p in lib.get("url_patterns", [])
        ]
        lib["_content_compiled"] = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in lib.get("content_patterns", [])
        ]
    return libs


_DB: list[dict] = _load_db()


class _ScriptExtractor(HTMLParser):
    """Extract script src URLs and inline script content from HTML."""

    def __init__(self):
        super().__init__()
        self.script_srcs: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._current_script = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        if tag.lower() != "script":
            return
        attr_dict = dict(attrs)
        src = attr_dict.get("src")
        if src:
            self.script_srcs.append(src)
        else:
            self._in_script = True
            self._current_script = []

    def handle_data(self, data: str):
        if self._in_script:
            self._current_script.append(data)

    def handle_endtag(self, tag: str):
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            self.inline_scripts.append("".join(self._current_script))

    def error(self, message):
        pass


def _match_url(url: str) -> list[dict]:
    """Match a script URL against fingerprint patterns. Returns detected libs."""
    results = []
    for lib in _DB:
        for rx in lib["_url_compiled"]:
            m = rx.search(url)
            if m:
                version = m.group("version") if "version" in rx.groupindex else None
                results.append({
                    "name": lib["name"],
                    "version": version,
                    "cpe_vendor": lib["cpe_vendor"],
                    "cpe_product": lib["cpe_product"],
                    "source": "url",
                })
                break  # One match per lib per URL is enough.
    return results


def _match_content(content: str) -> list[dict]:
    """Match JS file content against fingerprint patterns."""
    results = []
    for lib in _DB:
        for rx in lib["_content_compiled"]:
            m = rx.search(content)
            if m:
                version = m.group("version") if "version" in rx.groupindex else None
                results.append({
                    "name": lib["name"],
                    "version": version,
                    "cpe_vendor": lib["cpe_vendor"],
                    "cpe_product": lib["cpe_product"],
                    "source": "content",
                })
                break
    return results


def _resolve_script_urls(base_url: str, srcs: list[str]) -> list[str]:
    """Resolve relative/protocol-relative script URLs against the page URL."""
    resolved = []
    for src in srcs:
        src = src.strip()
        if not src:
            continue
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/") or not urlparse(src).scheme:
            src = urljoin(base_url, src)
        resolved.append(src)
    return resolved


def _format_cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


async def fingerprint_url(
    session: aiohttp.ClientSession,
    url: str,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """Fingerprint JS libraries on a single URL.

    Returns a list of dicts: {name, version, cpe_vendor, cpe_product, cpe, source}.
    Never raises — errors are logged and return [].
    """
    async with semaphore:
        try:
            return await _fingerprint_url_inner(session, url)
        except Exception as exc:
            logger.debug("js_fingerprint: error processing %s: %s", url, exc)
            return []


async def _fingerprint_url_inner(
    session: aiohttp.ClientSession,
    url: str,
) -> list[dict]:
    """Inner implementation — may raise."""
    # Step 1: Fetch the HTML page.
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
        if resp.status != 200:
            return []
        # Read up to 512KB of HTML (enough for script tags in <head> + <body>).
        html = await resp.text(errors="replace")
        if len(html) > 512_000:
            html = html[:512_000]

    # Step 2: Extract script tags.
    parser = _ScriptExtractor()
    try:
        parser.feed(html)
    except Exception:
        return []

    all_detections: list[dict] = []
    seen: set[str] = set()  # vendor:product dedup

    def _add(det: dict):
        key = f"{det['cpe_vendor']}:{det['cpe_product']}"
        if key in seen:
            return
        seen.add(key)
        det["cpe"] = _format_cpe(
            det["cpe_vendor"], det["cpe_product"], det.get("version") or "*",
        )
        all_detections.append(det)

    # Step 3: Match script src URLs (fast — no HTTP needed).
    script_srcs = parser.script_srcs[:_MAX_SCRIPTS_PER_PAGE]
    resolved_urls = _resolve_script_urls(url, script_srcs)

    for script_url in resolved_urls:
        for det in _match_url(script_url):
            _add(det)

    # Step 4: Match inline script content.
    for inline in parser.inline_scripts[:20]:
        # Only scan first 8KB of each inline script.
        for det in _match_content(inline[:_JS_HEAD_BYTES]):
            _add(det)

    # Step 5: Download and scan external JS files (only those not already matched by URL).
    download_urls = []
    for script_url in resolved_urls:
        # Skip if we already detected a lib from this URL pattern.
        if any(_match_url(script_url)):
            continue
        # Only download .js files.
        path = urlparse(script_url).path.lower()
        if path.endswith(".js"):
            download_urls.append(script_url)

    for js_url in download_urls[:_MAX_JS_DOWNLOADS_PER_PAGE]:
        try:
            async with session.get(
                js_url, timeout=aiohttp.ClientTimeout(total=10),
            ) as js_resp:
                if js_resp.status != 200:
                    continue
                # Read only the head of the file.
                chunk = await js_resp.content.read(_JS_HEAD_BYTES)
                js_text = chunk.decode("utf-8", errors="replace")
        except Exception:
            continue

        for det in _match_content(js_text):
            _add(det)

    return all_detections


async def fingerprint_assets(
    assets: list[dict],
    concurrency: int = 20,
    connect_timeout: int = 10,
) -> dict[str, list[dict]]:
    """Fingerprint JS libraries for a batch of assets.

    Args:
        assets: list of dicts with keys: hostname, open_ports, id
        concurrency: max parallel HTTP connections
        connect_timeout: TCP connect timeout

    Returns:
        dict mapping hostname → list of detection dicts.
    """
    if not _DB:
        logger.warning("js_fingerprint: fingerprint DB is empty, skipping")
        return {}

    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(
        limit=concurrency,
        ssl=False,  # Don't verify SSL for scanning.
    )
    timeout = aiohttp.ClientTimeout(
        total=30, connect=connect_timeout,
    )

    results: dict[str, list[dict]] = {}
    targets: list[tuple[str, str]] = []  # (hostname, url)

    for asset in assets:
        hostname = asset["hostname"]
        ports = set(asset.get("open_ports") or [])
        # Build URL — prefer HTTPS.
        if 443 in ports:
            targets.append((hostname, f"https://{hostname}"))
        elif 8443 in ports:
            targets.append((hostname, f"https://{hostname}:8443"))
        if 80 in ports:
            targets.append((hostname, f"http://{hostname}"))
        elif 8080 in ports:
            targets.append((hostname, f"http://{hostname}:8080"))
        # If only non-standard ports, try HTTPS on 443 anyway.
        if not ports & {80, 443, 8080, 8443}:
            targets.append((hostname, f"https://{hostname}"))

    if not targets:
        return results

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; HakunaScanner/1.0)",
        "Accept": "text/html,application/xhtml+xml,*/*",
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
    """Run fingerprinting for one URL, merge into results by hostname."""
    detections = await fingerprint_url(session, url, semaphore)
    if detections:
        existing = results.get(hostname, [])
        # Merge — dedup by vendor:product.
        seen = {f"{d['cpe_vendor']}:{d['cpe_product']}" for d in existing}
        for det in detections:
            key = f"{det['cpe_vendor']}:{det['cpe_product']}"
            if key not in seen:
                seen.add(key)
                existing.append(det)
        results[hostname] = existing


def reload_db() -> None:
    """Force-reload the fingerprint DB from disk. For tests."""
    global _DB
    _DB = _load_db()
