"""JavaScript library + HTML meta tag fingerprinting.

Fetches HTML pages, extracts <script> tags, downloads JS files, and matches
version patterns against a fingerprint database (js_fingerprint_db.json).

Also extracts <meta name="generator"> and other HTML artifacts to detect CMS
platforms (WordPress, Drupal, Joomla, etc.) using meta_fingerprint_db.json.

This fills the gap where httpx's Wappalyzer-based -tech-detect catches
server-side tech (nginx, ASP.NET) but misses client-side libraries like
jQuery 3.1.1 or Moment.js 2.29.1 that Tenable ASM detects, and also misses
CMS/framework identification that meta generator tags reveal.
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

try:
    from playwright.async_api import async_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

logger = logging.getLogger(__name__)

# Chromium path baked into the Docker image (also used by httpx screenshots).
_CHROMIUM_PATH = os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium")

# Patterns that indicate a WAF/bot challenge page (not the real site content).
_CHALLENGE_INDICATORS = [
    "Just a moment...",
    "cf_chl_opt",
    "challenge-platform",
    "Checking your browser",
    "Attention Required! | Cloudflare",
    "Enable JavaScript and cookies to continue",
]


def _is_challenge_page(html: str) -> bool:
    """Detect Cloudflare and similar WAF challenge/interstitial pages."""
    # Challenge pages are typically small and contain specific markers.
    if len(html) > 100_000:
        return False
    return any(indicator in html for indicator in _CHALLENGE_INDICATORS)

_DB_PATH = os.path.join(os.path.dirname(__file__), "js_fingerprint_db.json")
_META_DB_PATH = os.path.join(os.path.dirname(__file__), "meta_fingerprint_db.json")

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


def _load_meta_db() -> dict:
    try:
        with open(_META_DB_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("js_fingerprint: failed to load meta DB %s: %s", _META_DB_PATH, exc)
        return {"generator_patterns": [], "html_patterns": []}
    gen = data.get("generator_patterns", [])
    for entry in gen:
        entry["_compiled"] = re.compile(entry["pattern"], re.IGNORECASE)
    html = data.get("html_patterns", [])
    for entry in html:
        entry["_compiled"] = re.compile(entry["pattern"], re.IGNORECASE)
    return {"generator_patterns": gen, "html_patterns": html}


_DB: list[dict] = _load_db()
_META_DB: dict = _load_meta_db()


class _ScriptExtractor(HTMLParser):
    """Extract script src URLs, inline script content, and meta tags from HTML."""

    def __init__(self):
        super().__init__()
        self.script_srcs: list[str] = []
        self.inline_scripts: list[str] = []
        self.meta_generators: list[str] = []
        self._in_script = False
        self._current_script = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        tag_lower = tag.lower()
        if tag_lower == "script":
            attr_dict = dict(attrs)
            src = attr_dict.get("src")
            if src:
                self.script_srcs.append(src)
            else:
                self._in_script = True
                self._current_script = []
        elif tag_lower == "meta":
            attr_dict = {(k or "").lower(): v for k, v in attrs}
            name = (attr_dict.get("name") or "").lower()
            content = attr_dict.get("content") or ""
            if name == "generator" and content:
                self.meta_generators.append(content)

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


# Limit concurrent browser renders — Chromium is memory-heavy.
_BROWSER_SEMAPHORE = asyncio.Semaphore(3)


# JS globals to probe in the browser — maps global accessor → (name, cpe_vendor, cpe_product).
# The accessor is evaluated in page context; it should return a version string or null.
_JS_GLOBAL_PROBES: list[dict] = [
    {"expr": "window.jQuery && jQuery.fn.jquery", "name": "jQuery", "cpe_vendor": "jquery", "cpe_product": "jquery"},
    {"expr": "window.jQuery && jQuery.ui && jQuery.ui.version", "name": "jQuery UI", "cpe_vendor": "jquery", "cpe_product": "jquery_ui"},
    {"expr": "window.moment && moment.version", "name": "Moment.js", "cpe_vendor": "momentjs", "cpe_product": "moment"},
    {"expr": "window.React && React.version", "name": "React", "cpe_vendor": "facebook", "cpe_product": "react"},
    {"expr": "window.Vue && Vue.version", "name": "Vue.js", "cpe_vendor": "vuejs", "cpe_product": "vue"},
    {"expr": "window.angular && angular.version && angular.version.full", "name": "Angular", "cpe_vendor": "angularjs", "cpe_product": "angular.js"},
    {"expr": "window._ && _.VERSION", "name": "Lodash", "cpe_vendor": "lodash", "cpe_product": "lodash"},
    {"expr": "window.Backbone && Backbone.VERSION", "name": "Backbone.js", "cpe_vendor": "backbonejs", "cpe_product": "backbone.js"},
    {"expr": "window.Ember && Ember.VERSION", "name": "Ember.js", "cpe_vendor": "emberjs", "cpe_product": "ember.js"},
    {"expr": "window.d3 && d3.version", "name": "D3.js", "cpe_vendor": "d3js", "cpe_product": "d3"},
    {"expr": "window.Handlebars && Handlebars.VERSION", "name": "Handlebars", "cpe_vendor": "handlebarsjs", "cpe_product": "handlebars"},
    {"expr": "window.Modernizr && Modernizr._version", "name": "Modernizr", "cpe_vendor": "modernizr", "cpe_product": "modernizr"},
    {"expr": "window.Mustache && Mustache.version", "name": "Mustache.js", "cpe_vendor": "mustache.js_project", "cpe_product": "mustache.js"},
    {"expr": "window.Bootstrap && Bootstrap.VERSION", "name": "Bootstrap", "cpe_vendor": "getbootstrap", "cpe_product": "bootstrap"},
]


async def _render_with_browser(url: str) -> tuple[str | None, list[dict]]:
    """Render a page with headless Chromium via Playwright.

    Used as a fallback when the initial HTTP fetch returns a WAF challenge
    page (e.g. Cloudflare "Just a moment..."). Returns (rendered_html, global_detections).
    Also probes window.* globals to detect bundled libraries that have no
    version banners in their source code.
    """
    if not _HAS_PLAYWRIGHT:
        return None, []
    if not os.path.isfile(_CHROMIUM_PATH):
        logger.debug("js_fingerprint: chromium not found at %s, skipping browser render", _CHROMIUM_PATH)
        return None, []

    try:
        async with _BROWSER_SEMAPHORE, async_playwright() as pw:
            browser = await pw.chromium.launch(
                executable_path=_CHROMIUM_PATH,
                headless=True,
                # --disable-crash-reporter / --disable-breakpad: crashpad handler
                # subprocesses survive their parent renderer and, with no init
                # process reaping orphans in the container, accumulate as zombies
                # until the container's cgroup pids ceiling is hit (EAGAIN /
                # "can't start new thread" on every subsequent fork). See
                # easm-worker's `init: true` in terraform/compute_scanners.tf for
                # the reaping side of this fix.
                args=[
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-crash-reporter",
                    "--disable-breakpad",
                ],
            )
            try:
                page = await browser.new_page(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ignore_https_errors=True,
                )
                await page.goto(url, wait_until="networkidle", timeout=20_000)
                html = await page.content()

                # Probe JS globals for library versions.
                global_detections: list[dict] = []
                for probe in _JS_GLOBAL_PROBES:
                    try:
                        version = await page.evaluate(f"() => {{ try {{ return {probe['expr']} || null; }} catch {{ return null; }} }}")
                        if version and isinstance(version, str):
                            global_detections.append({
                                "name": probe["name"],
                                "version": version,
                                "cpe_vendor": probe["cpe_vendor"],
                                "cpe_product": probe["cpe_product"],
                                "source": "js_global",
                            })
                    except Exception:
                        pass

                html = html[:512_000] if len(html) > 512_000 else html
                return html, global_detections
            finally:
                await browser.close()
    except Exception as exc:
        logger.debug("js_fingerprint: browser render failed for %s: %s", url, exc)
        return None, []


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

    # Step 1b: If we got a WAF challenge page, try rendering with a real browser.
    browser_detections: list[dict] = []
    if _is_challenge_page(html):
        logger.info("js_fingerprint: challenge page detected for %s, trying browser render", url)
        rendered, browser_detections = await _render_with_browser(url)
        if rendered and not _is_challenge_page(rendered):
            html = rendered
        else:
            logger.debug("js_fingerprint: browser render didn't bypass challenge for %s", url)
            return []

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

    # Step 3a: Match meta generator tags against meta_fingerprint_db.
    for gen_content in parser.meta_generators:
        for entry in _META_DB.get("generator_patterns", []):
            m = entry["_compiled"].search(gen_content)
            if m:
                version = m.group("version") if "version" in m.groupdict() else None
                _add({
                    "name": entry["name"],
                    "version": version,
                    "cpe_vendor": entry["cpe_vendor"],
                    "cpe_product": entry["cpe_product"],
                    "source": "meta_generator",
                })
                break  # One match per generator string.

    # Step 3b: Match HTML body artifacts (framework-specific paths, comments, etc.)
    for entry in _META_DB.get("html_patterns", []):
        m = entry["_compiled"].search(html)
        if m:
            version = m.group("version") if "version" in m.groupdict() else None
            _add({
                "name": entry["name"],
                "version": version,
                "cpe_vendor": entry["cpe_vendor"],
                "cpe_product": entry["cpe_product"],
                "source": entry.get("source", "html_artifact"),
            })

    # Step 3c: Match script src URLs (fast — no HTTP needed).
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

    # Step 6: Add browser global detections (from Playwright page.evaluate).
    for det in browser_detections:
        _add(det)

    # Step 7: If regex-based detection found nothing but the page has scripts,
    # try browser global probing as a fallback. Bundled/minified JS strips
    # version banners but the runtime globals (window.jQuery, etc.) still exist.
    if not all_detections and (parser.script_srcs or parser.inline_scripts) and _HAS_PLAYWRIGHT:
        logger.info("js_fingerprint: no regex matches on %s, trying browser global probing", url)
        _, global_dets = await _render_with_browser(url)
        for det in global_dets:
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
    global _DB, _META_DB
    _DB = _load_db()
    _META_DB = _load_meta_db()
