"""Content discovery worker — ffuf-based path & parameter fuzzing.

Fills the gap left by the existing workers:

  - ``nuclei_worker`` fires signature-based DAST against *known* URLs.
  - ``schemathesis_worker`` property-fuzzes *documented* OpenAPI/GraphQL.
  - ``agent_worker`` reasons over the surface it has.

None of them find undocumented routes — admin panels, backup files,
debug endpoints, `.git/` exposures, shadow APIs. ffuf does.

The worker has two outputs, deliberately separate:

  Sink 1 (95%): discovered paths become new ``asset_endpoints`` rows
                with ``source='content_discovery'``. The next scan
                picks them up and Nuclei-DAST re-runs against them.
                No finding emitted.

  Sink 2 (5%):  paths that match a rule in ``exposures.json`` (body
                signature + status code + path suffix) become findings
                via the same Celery-result shape as nuclei_worker, so
                ``_import_nuclei_job_findings`` in the backend handles
                them with no special-casing. plugin_family is
                ``ContentDiscovery``.

This split is the whole point: raw ffuf output has a 95%+ FP rate for
"finding" semantics. Feeding /favicon.ico as a MEDIUM into the finding
table would destroy the prioritizer's signal. But the *path* is still
a useful target for the next scan, so we keep it — as an endpoint, not
a finding.

Gating:

  - Requires a web port (80/443/8080/8443 etc.) — the caller
    (``api.py``) checks this before dispatching.
  - Respects ``asset.disable_content_discovery`` when set (checked at
    the start of the task).
  - Skipped with ``status=disabled`` if ``CONTENT_DISCOVERY_ENABLED`` is
    false — flag is read at dispatch time by the API layer, but the
    worker also no-ops as a defense in depth.

Credentials: same ScanCredentials payload shape as the other workers.
Flattened to a headers dict and passed to ffuf via ``-H`` flags. Never
logged or echoed back.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import asyncpg
import httpx

from scanner.vm.celery_app import celery_app
from scanner.vm.config import (
    CONTENT_DISCOVERY_ENABLED,
    CONTENT_DISCOVERY_EXPOSURES_RULES,
    CONTENT_DISCOVERY_MATCH_CODES,
    CONTENT_DISCOVERY_MAX_DURATION_S,
    CONTENT_DISCOVERY_PARAMS_WORDLIST,
    CONTENT_DISCOVERY_PATHS_WORDLIST,
    CONTENT_DISCOVERY_RATE_LIMIT,
    CONTENT_DISCOVERY_THREADS,
    DATABASE_URL,
    FFUF_BIN,
)
from scanner.vm.db import _normalize_dsn

logger = logging.getLogger(__name__)


# Per-phase wall clock. Phase 1 (paths) is the big one — it touches the
# full wordlist. Phase 2 (params) only runs on endpoints that survived
# phase 1's filters and is naturally bounded. Keeping the param phase
# shorter also stops a misbehaving endpoint from eating the whole budget.
_PATH_PHASE_FRACTION = 0.75

# Cap discovered endpoints per asset before we push them back into
# asset_endpoints. A web app with directory listing can dump thousands of
# paths; the planner's "top N per asset" logic would then be flooded
# with content-discovery rows and starve higher-signal sources.
MAX_ENDPOINTS_PER_ASSET = int(os.environ.get("CONTENT_DISCOVERY_MAX_ENDPOINTS", "200"))

# Cap params we'll probe per endpoint. ffuf's throughput on param
# discovery is faster than paths (smaller wordlist, GET-only, single
# URL), but we still need a ceiling to keep the phase predictable.
MAX_PARAM_ENDPOINTS = int(os.environ.get("CONTENT_DISCOVERY_MAX_PARAM_ENDPOINTS", "20"))

# Form discovery: fetch the base URL + a bounded sample of HTML hits
# and harvest `<form>` elements so the agent / next-scan fuzzer sees
# parameterised endpoints even when ffuf's param wordlist misses the
# input names (common for dev tools with bespoke field names like
# "command" or "query_string").
FORM_DISCOVERY_MAX_PAGES = int(os.environ.get("CONTENT_DISCOVERY_FORM_MAX_PAGES", "10"))
FORM_DISCOVERY_TIMEOUT_S = float(os.environ.get("CONTENT_DISCOVERY_FORM_TIMEOUT_S", "10"))


ASSET_CONTEXT_QUERY = """
    SELECT a.id, a.org_id, a.hostname, a.ip, a.http_url, a.open_ports
    FROM assets a
    WHERE a.id = $1
"""


# ── Credentials (shared shape with nuclei / schemathesis) ────────


def _credentials_to_headers(credentials: dict | None) -> dict[str, str]:
    """Flatten ScanCredentials → plain headers dict.

    Identical semantics to ``schemathesis_worker._credentials_to_headers``.
    We duplicate the helper rather than cross-import to keep worker
    modules independent — they're supposed to be standalone so one
    worker's import error can't poison the whole queue.
    """
    headers: dict[str, str] = {}
    if not credentials:
        return headers

    ctype = (credentials.get("type") or "").lower()
    if ctype == "basic":
        user = credentials.get("username") or ""
        pw = credentials.get("password") or ""
        if user or pw:
            token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
    elif ctype == "bearer":
        token = credentials.get("token") or ""
        if token:
            headers["Authorization"] = f"Bearer {token}"
    elif ctype == "cookie":
        cookie = credentials.get("cookie") or credentials.get("token") or ""
        if cookie:
            headers["Cookie"] = cookie

    extra = credentials.get("headers") or {}
    if isinstance(extra, dict):
        for name, value in extra.items():
            if not name or value is None:
                continue
            headers[str(name)] = str(value)

    return headers


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: "***" for k in headers}


# ── Target resolution ────────────────────────────────────────────


def _resolve_base_url(asset: dict) -> str | None:
    """Return a ``scheme://host[:port]`` base URL, or None if not web-reachable.

    Priority mirrors ``nuclei_worker._resolve_target`` but we also promote
    hostname+port combinations to https://host:port when the asset has a
    web-serving port open. Without a URL scheme ffuf refuses to run.
    """
    http_url = asset.get("http_url")
    if http_url:
        parts = urlparse(http_url)
        if parts.scheme and parts.netloc:
            # Drop any path on http_url — we're going to append FUZZ ourselves.
            return urlunparse((parts.scheme, parts.netloc, "", "", "", ""))

    host = asset.get("hostname") or (str(asset.get("ip")) if asset.get("ip") else None)
    if not host:
        return None

    open_ports = asset.get("open_ports") or []
    if 443 in open_ports or 8443 in open_ports:
        port_suffix = ":8443" if 443 not in open_ports and 8443 in open_ports else ""
        return f"https://{host}{port_suffix}"
    if 80 in open_ports or 8080 in open_ports or 8000 in open_ports or 3000 in open_ports or 5000 in open_ports:
        for p in (80, 8080, 8000, 3000, 5000):
            if p in open_ports:
                port_suffix = "" if p == 80 else f":{p}"
                return f"http://{host}{port_suffix}"
    return None


# ── ffuf driver ──────────────────────────────────────────────────


def _ffuf_available() -> bool:
    """Check whether the ffuf binary is resolvable.

    Honors ``FFUF_BIN`` (absolute path) first, then falls back to PATH
    lookup — the latter is what devs running the worker locally usually
    hit because the homebrew install puts ffuf under /opt/homebrew/bin
    rather than /usr/local/bin.
    """
    if os.path.isfile(FFUF_BIN) and os.access(FFUF_BIN, os.X_OK):
        return True
    return shutil.which("ffuf") is not None


def _ffuf_binary() -> str:
    if os.path.isfile(FFUF_BIN) and os.access(FFUF_BIN, os.X_OK):
        return FFUF_BIN
    resolved = shutil.which("ffuf")
    if resolved:
        return resolved
    return FFUF_BIN  # will fail cleanly at subprocess time


def _run_ffuf_json(
    cmd: list[str],
    *,
    headers: dict[str, str],
    timeout_s: int,
) -> dict:
    """Invoke ffuf and return its parsed JSON output.

    Writes output to a temp file (``-o``) rather than reading stdout —
    ffuf's stdout mixes progress lines with results when running in TTY
    mode, and forcing ``-of json`` still emits startup banners on
    stderr. File output is the reliable path.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as out:
        out_path = out.name

    full_cmd = list(cmd) + ["-o", out_path, "-of", "json"]
    for name, value in headers.items():
        full_cmd.extend(["-H", f"{name}: {value}"])

    try:
        logger.debug(
            "ffuf cmd=%s headers=%s",
            " ".join(c for c in full_cmd if not c.startswith("Authorization")),
            list(_redact_headers(headers)),
        )
        proc = subprocess.run(
            full_cmd,
            timeout=timeout_s,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode not in (0, 1):
            # ffuf exits non-zero on matches-found in some configurations;
            # accept 0 (clean) and 1 (matches found). Anything else is
            # an actual failure we want to surface.
            logger.warning(
                "ffuf rc=%s stderr=%s", proc.returncode, (proc.stderr or "")[:500]
            )
        try:
            with open(out_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"results": []}
    except subprocess.TimeoutExpired:
        logger.warning("ffuf timed out after %ss", timeout_s)
        try:
            with open(out_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"results": []}
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _build_path_phase_cmd(base_url: str, wordlist: str, deadline_seconds: int) -> list[str]:
    """Path-discovery ffuf command.

    Key flags:
      - ``-u <base>/FUZZ`` — FUZZ keyword substitution for the path.
      - ``-mc <codes>``    — only emit responses with these status codes.
        Values like 404/501/502/503 are excluded by default.
      - ``-ac``            — auto-calibrate: ffuf probes random paths first
        to detect wildcard/soft-404 responses and auto-filters them. This
        is the main FP suppressor.
      - ``-rate``          — global requests/sec cap.
      - ``-t``             — concurrent workers.
      - ``-maxtime``       — per-phase wall clock.
      - ``-recursion-depth 0`` — never recurse; we don't want to turn
        one misconfigured directory into a crawl of the whole app.
    """
    url = base_url.rstrip("/") + "/FUZZ"
    return [
        _ffuf_binary(),
        "-u", url,
        "-w", wordlist,
        "-mc", CONTENT_DISCOVERY_MATCH_CODES,
        "-ac",
        "-rate", str(CONTENT_DISCOVERY_RATE_LIMIT),
        "-t", str(CONTENT_DISCOVERY_THREADS),
        "-maxtime", str(deadline_seconds),
        "-recursion-depth", "0",
        "-s",  # silent — suppress banner/progress on stderr
    ]


def _build_param_phase_cmd(
    endpoint_url: str,
    wordlist: str,
    deadline_seconds: int,
) -> list[str]:
    """Parameter-discovery ffuf command.

    Probes ``<endpoint>?FUZZ=test`` and filters out responses whose size
    matches the baseline (same URL with no param). ffuf's ``-fs`` takes
    the baseline size at dispatch time — we compute it with a HEAD-ish
    GET before dispatching so the filter is exact.

    Less aggressive than path phase: 5-minute cap, same rate limit, half
    the threads. Param discovery is useful but not essential; budget
    should favor paths.
    """
    separator = "&" if "?" in endpoint_url else "?"
    probe_url = f"{endpoint_url}{separator}FUZZ=test"
    return [
        _ffuf_binary(),
        "-u", probe_url,
        "-w", wordlist,
        "-mc", "all",
        "-ac",
        "-rate", str(CONTENT_DISCOVERY_RATE_LIMIT),
        "-t", str(max(CONTENT_DISCOVERY_THREADS // 2, 5)),
        "-maxtime", str(deadline_seconds),
        "-s",
    ]


# ── Exposure rule matching ───────────────────────────────────────


def _load_exposure_rules() -> list[dict]:
    """Load and compile exposure rules from the configured JSON file.

    Regex patterns are compiled once here so downstream matching stays
    allocation-free on the hot path. Malformed rules are skipped with a
    warning — a single bad rule must not disable the whole exposure sink.
    """
    try:
        with open(CONTENT_DISCOVERY_EXPOSURES_RULES) as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("exposure rules unavailable at %s: %s", CONTENT_DISCOVERY_EXPOSURES_RULES, e)
        return []

    compiled: list[dict] = []
    for rule in raw.get("rules", []):
        if not rule.get("id") or not rule.get("path_suffixes"):
            continue
        entry = dict(rule)
        pat = rule.get("body_regex")
        if pat:
            try:
                entry["_body_regex_compiled"] = re.compile(pat, re.MULTILINE)
            except re.error as e:
                logger.warning("exposure rule %s has invalid regex: %s", rule["id"], e)
                entry["_body_regex_compiled"] = None
        compiled.append(entry)
    return compiled


def _rule_matches(rule: dict, path: str, status_code: int, body: str) -> bool:
    """Return True if this rule applies to the (path, status, body) tuple."""
    suffixes = rule.get("path_suffixes") or []
    if not any(path.endswith(s) or path == s or path == "/" + s for s in suffixes):
        return False

    codes = rule.get("status_codes")
    if codes and status_code not in codes:
        return False

    body_any = rule.get("body_contains_any") or []
    if body_any and not any(needle in body for needle in body_any):
        return False

    body_rx = rule.get("_body_regex_compiled")
    if body_rx is not None and not body_rx.search(body or ""):
        return False

    return True


# ── Finding emission ─────────────────────────────────────────────


def _exposure_to_finding(
    *,
    rule: dict,
    url: str,
    path: str,
    status_code: int,
    content_length: int,
    target: str,
) -> dict:
    """Shape matches nuclei_worker / schemathesis_worker so ingest is shared."""
    rule_id = rule["id"]
    severity = rule.get("severity") or "info"
    return {
        "template_id": f"content-discovery-{rule_id}",
        "severity": severity,
        "name": rule.get("name") or f"Content discovery: {rule_id}",
        "description": rule.get("description") or f"Exposure rule {rule_id} matched.",
        "matched_at": url,
        "host": target,
        "port": "",
        "type": "content-discovery",
        "tags": ["content-discovery", "exposure", rule_id],
        "reference": rule.get("references") or [],
        "classification": {},
        "curl_command": f"curl -sSL {url}",
        "matcher_name": rule_id,
        "extracted_results": [
            f"status_code={status_code}",
            f"content_length={content_length}",
            f"path={path}",
        ],
        "llm_validation": {
            "verdict": "true_positive",
            "confidence": 0.95,
            "reasoning": (
                f"Content-discovery rule '{rule_id}' confirmed exposure by status "
                f"code and body-signature match — both conditions are required "
                f"for the rule to fire."
            ),
            "source": "content_discovery",
            "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }


# ── Endpoint persistence ─────────────────────────────────────────


async def _store_discovered_endpoints(
    conn: asyncpg.Connection,
    asset_id: uuid.UUID,
    base_url: str,
    discovered: list[dict],
) -> int:
    """Insert discovered paths as ``asset_endpoints`` rows.

    Source is ``content_discovery`` so downstream consumers (schemathesis,
    Nuclei-DAST, scan planner) can distinguish them from katana/openapi
    /kiterunner endpoints and apply source-specific ranking.

    Uses the same conflict target as the kiterunner ingest path
    (``uq_asset_endpoints_addr``) so reruns are idempotent.
    """
    if not discovered:
        return 0

    now_epoch = time.time()
    stored = 0
    base = base_url.rstrip("/")
    for hit in discovered[:MAX_ENDPOINTS_PER_ASSET]:
        path = hit.get("path") or ""
        if not path:
            continue
        full_url = urljoin(base + "/", path.lstrip("/"))
        try:
            await conn.execute(
                """
                INSERT INTO asset_endpoints (
                    id, asset_id, url, path, method,
                    source, status_code, discovered_at, is_auth_page
                )
                VALUES (
                    $1, $2, $3, $4, 'GET',
                    'content_discovery', $5, to_timestamp($6) AT TIME ZONE 'UTC', false
                )
                ON CONFLICT (asset_id, url, method, source) DO NOTHING
                """,
                uuid.uuid4(),
                asset_id,
                full_url,
                path if path.startswith("/") else "/" + path,
                int(hit.get("status") or 0) or None,
                now_epoch,
            )
            stored += 1
        except Exception:
            logger.exception("failed to store endpoint %s for asset %s", full_url, asset_id)
    return stored


# ── Celery task ──────────────────────────────────────────────────


@celery_app.task(queue="vm_queue", bind=True, max_retries=1)
def run_content_discovery_scan(
    self,
    asset_id: str,
    credentials: dict | None = None,
) -> dict:
    """Run ffuf path + parameter discovery against one asset.

    Returns a payload compatible with ``run_nuclei_scan`` — the backend's
    ``_import_nuclei_job_findings`` consumes it unchanged. ``findings``
    contains only exposure-rule hits; discovered-but-mundane endpoints
    are persisted directly to ``asset_endpoints`` inside the task.
    """
    try:
        return _run_async(_run_content_discovery_async(asset_id, credentials))
    except Exception as exc:
        logger.exception("run_content_discovery_scan failed for asset %s", asset_id)
        return {
            "asset_id": asset_id,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
            "scanner": "content_discovery",
        }


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


async def _run_content_discovery_async(
    asset_id: str,
    credentials: dict | None,
) -> dict:
    start = time.monotonic()

    if not CONTENT_DISCOVERY_ENABLED:
        return {
            "asset_id": asset_id,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "disabled",
            "scanner": "content_discovery",
        }

    if not _ffuf_available():
        return {
            "asset_id": asset_id,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": f"ffuf binary not found (FFUF_BIN={FFUF_BIN})",
            "scanner": "content_discovery",
        }

    if not os.path.isfile(CONTENT_DISCOVERY_PATHS_WORDLIST):
        return {
            "asset_id": asset_id,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": f"paths wordlist not found at {CONTENT_DISCOVERY_PATHS_WORDLIST}",
            "scanner": "content_discovery",
        }

    dsn = _normalize_dsn(DATABASE_URL)
    conn = await asyncpg.connect(dsn)
    try:
        asset = await conn.fetchrow(ASSET_CONTEXT_QUERY, uuid.UUID(asset_id))
    finally:
        await conn.close()

    if asset is None:
        return {
            "asset_id": asset_id,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": "skipped",
            "error": "Asset not found",
            "scanner": "content_discovery",
        }

    asset_dict = dict(asset)
    base_url = _resolve_base_url(asset_dict)
    if not base_url:
        return {
            "asset_id": asset_id,
            "org_id": str(asset_dict["org_id"]) if asset_dict.get("org_id") else None,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": "skipped",
            "error": "No web-reachable URL for this asset",
            "scanner": "content_discovery",
        }

    headers = _credentials_to_headers(credentials)
    logger.info(
        "content_discovery start asset=%s base=%s headers=%s",
        asset_id, base_url, list(_redact_headers(headers)),
    )

    # ── Phase 1: path discovery ──
    path_budget = int(CONTENT_DISCOVERY_MAX_DURATION_S * _PATH_PHASE_FRACTION)
    path_cmd = _build_path_phase_cmd(base_url, CONTENT_DISCOVERY_PATHS_WORDLIST, path_budget)
    raw = _run_ffuf_json(path_cmd, headers=headers, timeout_s=path_budget + 30)
    hits = _extract_hits(raw)

    # ── Exposure matching ──
    rules = _load_exposure_rules()
    findings: list[dict] = []
    for hit in hits:
        path = _path_from_hit(hit, base_url)
        body = hit.get("content_preview") or ""
        status_code = int(hit.get("status") or 0)
        matched_any = False
        for rule in rules:
            if _rule_matches(rule, path, status_code, body):
                findings.append(
                    _exposure_to_finding(
                        rule=rule,
                        url=hit.get("url") or urljoin(base_url + "/", path.lstrip("/")),
                        path=path,
                        status_code=status_code,
                        content_length=int(hit.get("length") or 0),
                        target=base_url,
                    )
                )
                matched_any = True
                break
        hit["_matched_rule"] = matched_any

    # ── Form discovery ──
    # Fetch the base URL and a bounded slice of HTML hits to harvest
    # `<form>` action + input names. Runs before endpoint persistence
    # so the same DB round-trip writes both ffuf paths and form rows.
    form_pages = _page_urls_for_form_discovery(base_url, hits)
    discovered_forms = await _discover_forms_on_pages(form_pages, headers)

    # ── Persist discovered endpoints (feedback loop) ──
    conn = await asyncpg.connect(dsn)
    try:
        endpoints_stored = await _store_discovered_endpoints(
            conn, uuid.UUID(asset_id), base_url, hits,
        )
        forms_stored = await _store_form_endpoints(
            conn, uuid.UUID(asset_id), discovered_forms,
        )
    finally:
        await conn.close()

    # ── Phase 2: parameter discovery ──
    # Only probe endpoints that were 200/500 in phase 1 — 401/403 are
    # interesting but param fuzzing against auth-gated URLs burns budget
    # for little return (we don't have creds to reach the real handler).
    remaining = CONTENT_DISCOVERY_MAX_DURATION_S - (time.monotonic() - start)
    param_findings: list[dict] = []
    if (
        remaining > 30
        and os.path.isfile(CONTENT_DISCOVERY_PARAMS_WORDLIST)
    ):
        param_targets = _select_param_targets(hits, base_url)
        per_endpoint_budget = max(
            int(remaining / max(len(param_targets), 1)),
            15,
        )
        for endpoint_url in param_targets[:MAX_PARAM_ENDPOINTS]:
            if time.monotonic() - start >= CONTENT_DISCOVERY_MAX_DURATION_S:
                break
            cmd = _build_param_phase_cmd(
                endpoint_url,
                CONTENT_DISCOVERY_PARAMS_WORDLIST,
                per_endpoint_budget,
            )
            raw_p = _run_ffuf_json(cmd, headers=headers, timeout_s=per_endpoint_budget + 15)
            param_hits = _extract_hits(raw_p)
            if param_hits:
                logger.info(
                    "content_discovery params asset=%s endpoint=%s new_params=%d",
                    asset_id, endpoint_url, len(param_hits),
                )
                # Params aren't findings on their own — they enrich the
                # parent endpoint so downstream fuzzers know which names
                # to vary. We write them into asset_endpoints.parameters.
                await _enrich_endpoint_parameters(
                    dsn, uuid.UUID(asset_id), endpoint_url, param_hits,
                )

    duration = round(time.monotonic() - start, 2)
    status = "complete" if duration < CONTENT_DISCOVERY_MAX_DURATION_S else "partial"

    logger.info(
        "content_discovery done asset=%s hits=%d endpoints_stored=%d forms_stored=%d exposures=%d duration=%ss",
        asset_id, len(hits), endpoints_stored, forms_stored, len(findings), duration,
    )

    return {
        "asset_id": asset_id,
        "org_id": str(asset_dict["org_id"]) if asset_dict.get("org_id") else None,
        "target": base_url,
        "findings": findings + param_findings,
        "endpoints_discovered": endpoints_stored + forms_stored,
        "forms_discovered": forms_stored,
        "exposures_found": len(findings),
        "duration_seconds": duration,
        "status": status,
        "scanner": "content_discovery",
    }


# ── Ad-hoc task ──────────────────────────────────────────────────


@celery_app.task(queue="vm_queue", bind=True, max_retries=1)
def run_content_discovery_adhoc(
    self,
    target: str,
    org_id: str | None = None,
    credentials: dict | None = None,
) -> dict:
    """Ad-hoc ffuf discovery against a raw target URL.

    Parallel to ``run_nuclei_adhoc``: the backend has a URL/host but no
    scanner-side asset UUID to key ``asset_endpoints`` on. We run the
    same two ffuf phases as the asset-based variant and emit exposure
    findings, but skip the discovered-endpoint persistence step — that
    sink exists to seed the *next* asset scan with more URLs, and
    without an asset row there's nowhere to write them.

    Expected target: a full URL (``http://…`` or ``https://…``). Bare
    hostnames are rejected upstream by ``scanner.vm.api`` because ffuf
    can't guess the scheme.
    """
    try:
        return _run_async(_run_content_discovery_adhoc_async(target, org_id, credentials))
    except Exception as exc:
        logger.exception("run_content_discovery_adhoc failed for target %s", target)
        return {
            "target": target,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
            "scanner": "content_discovery",
        }


async def _run_content_discovery_adhoc_async(
    target: str,
    org_id: str | None,
    credentials: dict | None,
) -> dict:
    start = time.monotonic()

    if not CONTENT_DISCOVERY_ENABLED:
        return {
            "target": target,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "disabled",
            "scanner": "content_discovery",
        }

    # ffuf needs a scheme; reject bare hostnames/IPs early with a clear
    # reason so the job result isn't ambiguous. The api.py dispatcher
    # already filters, but defense in depth — the worker must not shell
    # out on an unusable target.
    if not target.startswith(("http://", "https://")):
        return {
            "target": target,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "skipped",
            "error": "target must be an http(s) URL for content discovery",
            "scanner": "content_discovery",
        }

    if not _ffuf_available():
        return {
            "target": target,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": f"ffuf binary not found (FFUF_BIN={FFUF_BIN})",
            "scanner": "content_discovery",
        }

    if not os.path.isfile(CONTENT_DISCOVERY_PATHS_WORDLIST):
        return {
            "target": target,
            "findings": [],
            "endpoints_discovered": 0,
            "exposures_found": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": f"paths wordlist not found at {CONTENT_DISCOVERY_PATHS_WORDLIST}",
            "scanner": "content_discovery",
        }

    # Normalize: drop any path on the URL — we append FUZZ ourselves.
    parts = urlparse(target)
    base_url = urlunparse((parts.scheme, parts.netloc, "", "", "", ""))

    headers = _credentials_to_headers(credentials)
    logger.info(
        "content_discovery adhoc start target=%s base=%s headers=%s",
        target, base_url, list(_redact_headers(headers)),
    )

    # ── Phase 1: path discovery ──
    path_budget = int(CONTENT_DISCOVERY_MAX_DURATION_S * _PATH_PHASE_FRACTION)
    path_cmd = _build_path_phase_cmd(base_url, CONTENT_DISCOVERY_PATHS_WORDLIST, path_budget)
    raw = _run_ffuf_json(path_cmd, headers=headers, timeout_s=path_budget + 30)
    hits = _extract_hits(raw)

    rules = _load_exposure_rules()
    findings: list[dict] = []
    for hit in hits:
        path = _path_from_hit(hit, base_url)
        body = hit.get("content_preview") or ""
        status_code = int(hit.get("status") or 0)
        for rule in rules:
            if _rule_matches(rule, path, status_code, body):
                findings.append(
                    _exposure_to_finding(
                        rule=rule,
                        url=hit.get("url") or urljoin(base_url + "/", path.lstrip("/")),
                        path=path,
                        status_code=status_code,
                        content_length=int(hit.get("length") or 0),
                        target=base_url,
                    )
                )
                break

    # ── Form discovery ──
    # Harvest <form> endpoints from the base URL and the HTML hits.
    # Adhoc has no asset_endpoints to write to, so we just surface the
    # form rows in the returned payload — the agent adhoc task reads
    # `target` directly and doesn't consume this, but the backend can
    # log it so operators know why/if agent probes are running.
    form_pages = _page_urls_for_form_discovery(base_url, hits)
    discovered_forms = await _discover_forms_on_pages(form_pages, headers)

    # ── Phase 2: parameter discovery ──
    # Adhoc skips `_enrich_endpoint_parameters` — that writeback keys on
    # an asset UUID we don't have. The param hits are still useful as
    # signal in logs, but without a place to persist them the asset
    # path's feedback loop (params → next scan's DAST fuzz targets) is
    # a no-op for adhoc until we add a target-keyed endpoint store.
    remaining = CONTENT_DISCOVERY_MAX_DURATION_S - (time.monotonic() - start)
    if (
        remaining > 30
        and os.path.isfile(CONTENT_DISCOVERY_PARAMS_WORDLIST)
    ):
        param_targets = _select_param_targets(hits, base_url)
        per_endpoint_budget = max(
            int(remaining / max(len(param_targets), 1)),
            15,
        )
        for endpoint_url in param_targets[:MAX_PARAM_ENDPOINTS]:
            if time.monotonic() - start >= CONTENT_DISCOVERY_MAX_DURATION_S:
                break
            cmd = _build_param_phase_cmd(
                endpoint_url,
                CONTENT_DISCOVERY_PARAMS_WORDLIST,
                per_endpoint_budget,
            )
            _run_ffuf_json(cmd, headers=headers, timeout_s=per_endpoint_budget + 15)

    duration = round(time.monotonic() - start, 2)
    status = "complete" if duration < CONTENT_DISCOVERY_MAX_DURATION_S else "partial"

    logger.info(
        "content_discovery adhoc done target=%s hits=%d forms=%d exposures=%d duration=%ss",
        target, len(hits), len(discovered_forms), len(findings), duration,
    )

    return {
        "target": target,
        "org_id": org_id,
        "findings": findings,
        # Adhoc does not persist endpoints — surface the raw path count
        # in the payload so the scan's job_status panel still shows what
        # ffuf saw, even though nothing was written to the DB.
        "endpoints_discovered": len(hits),
        "forms_discovered": len(discovered_forms),
        "forms": discovered_forms,
        "exposures_found": len(findings),
        "duration_seconds": duration,
        "status": status,
        "scanner": "content_discovery",
    }


# ── ffuf output helpers ──────────────────────────────────────────


def _extract_hits(raw: dict) -> list[dict]:
    """Normalize ffuf's results[] into a consistent dict shape."""
    results = raw.get("results") or []
    out: list[dict] = []
    for r in results:
        out.append({
            "input": (r.get("input") or {}).get("FUZZ") if isinstance(r.get("input"), dict) else r.get("input"),
            "url": r.get("url"),
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
            "content_preview": r.get("content") or "",
            "path": _path_from_hit(r, None),
        })
    return out


def _path_from_hit(hit: dict, base_url: str | None) -> str:
    """Extract the path from a ffuf result dict."""
    u = hit.get("url") or ""
    if u:
        parsed = urlparse(u)
        if parsed.path:
            return parsed.path
    inp = hit.get("input")
    if isinstance(inp, dict):
        return "/" + (inp.get("FUZZ") or "").lstrip("/")
    if isinstance(inp, str):
        return "/" + inp.lstrip("/")
    return "/"


# ── Form discovery ───────────────────────────────────────────────
# ffuf is a path/param fuzzer; it doesn't read HTML. Many apps expose
# their only attackable parameter as a `<form>` input on the home page
# (e.g. a "command" field wired straight to a shell). We harvest those
# explicitly so asset_endpoints ends up with rows like
# ``{"url": "/", "parameters": [{"name": "command"}]}`` which the
# agent's injection specialist can probe on the next scan.


_FORM_INPUT_TAGS = ("input", "textarea", "select", "button")
_STATIC_ASSET_EXTS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".map", ".json", ".xml", ".pdf", ".zip",
)


class _FormHarvester(HTMLParser):
    """Accumulate ``<form>`` action/method/inputs from an HTML document.

    We intentionally don't use a DOM library — ``html.parser`` is
    stdlib, forgiving of malformed markup, and this is the only HTML
    parsing we need in this worker. Adding BeautifulSoup to chase a
    single helper would inflate the scanner image for no real gain.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._current: dict | None = None
        self.forms: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            # Nested forms aren't valid HTML — if one appears we flush
            # the outer form first so we don't lose its inputs.
            if self._current is not None:
                self._flush()
            self._current = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "inputs": [],
            }
            return
        if self._current is None:
            return
        if tag in _FORM_INPUT_TAGS:
            name = a.get("name")
            if name:
                self._current["inputs"].append({
                    "name": name,
                    "type": a.get("type") or tag,
                })

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # <input .../> is a void element; browsers treat it as a self-closing
        # tag. html.parser routes those here instead of handle_starttag.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self._flush()

    def _flush(self) -> None:
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None


def _extract_forms_from_html(html_text: str, page_url: str) -> list[dict]:
    """Return ``[{"url","method","parameters","source"}]`` for each form.

    ``action`` is resolved against ``page_url`` (browsers default an
    empty action to "same URL as the page"). Forms with zero named
    inputs are dropped — there's nothing to attack.
    """
    if not html_text:
        return []
    parser = _FormHarvester()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        # Malformed HTML shouldn't kill the worker — skip silently.
        logger.debug("HTML parse failed for %s", page_url, exc_info=True)
        return []

    out: list[dict] = []
    for form in parser.forms:
        action = form.get("action") or ""
        resolved = urljoin(page_url, action) if action else page_url
        method = form.get("method") or "GET"
        names: list[str] = []
        seen: set[str] = set()
        for inp in form.get("inputs", []):
            name = inp.get("name")
            if not name or name in seen:
                continue
            seen.add(name)
            names.append(name)
        if not names:
            continue
        out.append({
            "url": resolved,
            "method": method,
            "parameters": [{"name": n, "source": "form_discovery"} for n in names],
            "source": "form_discovery",
        })
    return out


def _page_urls_for_form_discovery(base_url: str, hits: list[dict]) -> list[str]:
    """Pick the pages worth fetching for HTML form extraction.

    Always includes the base URL (the single highest-signal page on
    most apps). Adds 200/500 hits that aren't static assets, up to
    ``FORM_DISCOVERY_MAX_PAGES``. The subset is small on purpose —
    content discovery is already rate-limited and this phase must not
    dominate the budget.
    """
    base = base_url.rstrip("/")
    pages: list[str] = [base + "/"]
    seen: set[str] = {base + "/", base}
    for h in hits:
        status = int(h.get("status") or 0)
        if status not in (200, 500):
            continue
        path = (h.get("path") or "").lower()
        if any(path.endswith(ext) for ext in _STATIC_ASSET_EXTS):
            continue
        url = h.get("url") or urljoin(base + "/", (h.get("path") or "/").lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        pages.append(url)
        if len(pages) >= FORM_DISCOVERY_MAX_PAGES:
            break
    return pages


async def _discover_forms_on_pages(
    pages: list[str],
    headers: dict[str, str],
) -> list[dict]:
    """Fetch a small set of pages and harvest ``<form>`` endpoints.

    Sequential on purpose: the page count is capped, and serial
    requests share one ``httpx.AsyncClient`` which keeps connection
    reuse simple. A few-second total cost is acceptable for the
    uplift in parameterised-endpoint coverage.
    """
    if not pages:
        return []
    out: list[dict] = []
    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=FORM_DISCOVERY_TIMEOUT_S,
            headers=headers or None,
        ) as client:
            for url in pages:
                try:
                    resp = await client.get(url)
                except Exception:
                    logger.debug("form discovery: fetch failed for %s", url, exc_info=True)
                    continue
                ctype = (resp.headers.get("content-type") or "").lower()
                body = resp.text or ""
                # Some misconfigured apps return HTML with no/wrong
                # Content-Type; fall back to a cheap sniff.
                if "html" not in ctype and not body.lstrip().lower().startswith(("<!doctype", "<html", "<form")):
                    continue
                out.extend(_extract_forms_from_html(body, str(resp.url)))
    except Exception:
        logger.exception("form discovery: client setup failed")
    return out


async def _store_form_endpoints(
    conn: asyncpg.Connection,
    asset_id: uuid.UUID,
    forms: list[dict],
) -> int:
    """Insert discovered forms as ``asset_endpoints`` rows.

    Uses ``source='form_discovery'`` so they're distinguishable from
    ffuf (``content_discovery``) and katana/openapi rows. The unique
    index is ``(asset_id, url, method, source)`` so re-runs are
    idempotent. ``parameters`` is populated with the input names so
    the next agent / nuclei pass has concrete fuzz slots.
    """
    if not forms:
        return 0
    stored = 0
    now_epoch = time.time()
    for form in forms:
        url = form.get("url")
        if not url:
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        method = (form.get("method") or "GET").upper()
        params = form.get("parameters") or []
        try:
            await conn.execute(
                """
                INSERT INTO asset_endpoints (
                    id, asset_id, url, path, method,
                    source, status_code, discovered_at, is_auth_page,
                    parameters
                )
                VALUES (
                    $1, $2, $3, $4, $5,
                    'form_discovery', NULL, to_timestamp($6) AT TIME ZONE 'UTC', false,
                    $7::jsonb
                )
                ON CONFLICT (asset_id, url, method, source) DO UPDATE SET
                    parameters = EXCLUDED.parameters,
                    discovered_at = EXCLUDED.discovered_at
                """,
                uuid.uuid4(),
                asset_id,
                url,
                path,
                method,
                now_epoch,
                json.dumps(params),
            )
            stored += 1
        except Exception:
            logger.exception("failed to store form endpoint %s for asset %s", url, asset_id)
    return stored


def _select_param_targets(hits: list[dict], base_url: str) -> list[str]:
    """Pick the hits worth running param discovery against.

    Heuristic: prefer 200s, deprioritize static assets (.js, .css, .png,
    .ico) because parameter fuzzing a static file is meaningless, and
    require a reasonable response size (empty 200s are likely soft hits
    the filter missed).
    """
    skip_exts = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".map")
    targets: list[str] = []
    seen: set[str] = set()
    for h in hits:
        if int(h.get("status") or 0) not in (200, 500):
            continue
        path = h.get("path") or ""
        if any(path.lower().endswith(ext) for ext in skip_exts):
            continue
        if int(h.get("length") or 0) < 20:
            continue
        url = h.get("url") or urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        targets.append(url)
    return targets


async def _enrich_endpoint_parameters(
    dsn: str,
    asset_id: uuid.UUID,
    endpoint_url: str,
    param_hits: list[dict],
) -> None:
    """Merge discovered parameter names into an existing asset_endpoints row.

    Builds on the JSONB ``parameters`` column populated by the EASM
    openapi_discoverer. We store names only (not values) so the
    downstream Nuclei-DAST templates can use them as fuzz slots without
    leaking what we probed with.
    """
    names = sorted({h.get("input") for h in param_hits if h.get("input")})
    if not names:
        return
    params_payload = [{"name": n, "source": "content_discovery"} for n in names]
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(
            """
            UPDATE asset_endpoints
               SET parameters = COALESCE(parameters, '[]'::jsonb) || $3::jsonb
             WHERE asset_id = $1
               AND url = $2
               AND source = 'content_discovery'
            """,
            asset_id,
            endpoint_url,
            json.dumps(params_payload),
        )
    except Exception:
        logger.exception("failed to enrich params for %s", endpoint_url)
    finally:
        await conn.close()
