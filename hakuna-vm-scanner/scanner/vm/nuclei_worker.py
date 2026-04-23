"""Nuclei worker — runs vulnerability scans against individual assets.

This container is pure compute. It:
  1. Looks up asset context (target hostname/IP, CPE, tech stack, open ports)
     from the shared database via asyncpg (read-only).
  2. Routes to the right Nuclei templates via TemplateRouter.
  3. Executes Nuclei, parses the JSONL stream, and returns findings in the
     Celery task result payload.

It does NOT write findings to the database. The backend polls completed
Celery results and imports findings through the ORM so every ingest path
flows through services/post_ingest.finalize_scan — which is the only
place deduplication, tagging, SLA, threat intel, and risk scoring live.
"""

import asyncio
import base64
import json
import logging
import os
import re
import time
import uuid

import asyncpg

# Nuclei inspects a handful of provider env vars at startup and aborts with
# exit=2 if it sees a partial config (e.g. GOOGLE_API_KEY without
# GOOGLE_API_CX). The agent worker containers share an image/env with the
# nuclei worker, so LLM keys leak into this process and break every scan.
# Strip them before spawning nuclei — the binary never needs them.
_NUCLEI_ENV_STRIP = (
    "GOOGLE_API_KEY",
    "GOOGLE_API_CX",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
)


def _nuclei_subprocess_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in _NUCLEI_ENV_STRIP}


from scanner.vm.celery_app import celery_app
from scanner.vm.config import (
    DATABASE_URL,
    NUCLEI_BIN,
    NUCLEI_BULK_CONCURRENCY,
    NUCLEI_COMMUNITY_TEMPLATES,
    NUCLEI_CONCURRENCY,
    NUCLEI_EXCLUDE_TAGS,
    NUCLEI_RATE_LIMIT,
    NUCLEI_RETRIES,
    NUCLEI_TIMEOUT,
    SCAN_TIMEOUT_SECONDS,
    TEMPLATES_DIR,
)

# Web ports that cause the adhoc path to include `custom/dast/` templates
# under `-dast`. Mirrors router._WEB_PORTS — duplicated as a literal here
# so this module doesn't have to import the router (which pulls the whole
# routing table into memory for what's otherwise a string check).
_ADHOC_WEB_PORTS: frozenset[int] = frozenset({80, 443, 3000, 5000, 8000, 8001, 8080, 8443, 8888, 9090, 9443})
from scanner.vm.db import _normalize_dsn
from scanner.vm.plan_executor import (
    ScanPlanInvalidError,
    build_nuclei_commands_from_plan,
    cleanup_tempfiles,
)
from scanner.vm.router import TemplateRouter

logger = logging.getLogger(__name__)

# Handoff query — reads confirmed-alive assets with port/enrichment data.
# Appends WHERE a.id = $1 for single-asset lookups.
HANDOFF_QUERY = """
    SELECT
        a.*,
        ap.cpe_list,
        ap.service_name,
        ap.service_version,
        ae.tech_stack,
        ae.httpx_full
    FROM assets a
    LEFT JOIN asset_ports ap
        ON ap.asset_id = a.id AND a.nmap_status = 'complete'
    LEFT JOIN asset_enrichments ae
        ON ae.asset_id = a.id
    WHERE a.liveness_state = 'confirmed_alive'
    AND a.last_validated_at > NOW() - INTERVAL '7 days'
"""

HANDOFF_QUERY_BY_ID = HANDOFF_QUERY + "\n    AND a.id = $1"

_router = TemplateRouter()


def _nuclei_perf_args() -> list[str]:
    """Common performance-tuning flags appended to every nuclei invocation.

    Composed from env-overridable config so ops can dial these per deployment
    without a code change. Empty NUCLEI_EXCLUDE_TAGS drops the -etags flag
    entirely (passing ``-etags ""`` would make nuclei error).
    """
    # Nuclei v3.x renamed `-bc` (bulk-concurrency) to `-bs` (bulk-size).
    # Passing the old flag makes the binary exit=2 with "flag provided but
    # not defined: -bc" before any request goes out, silently producing
    # 0-finding scans. Keep the env var name for backcompat with existing
    # deployments and map it to the current flag.
    args = [
        "-c", str(NUCLEI_CONCURRENCY),
        "-bs", str(NUCLEI_BULK_CONCURRENCY),
        "-retries", str(NUCLEI_RETRIES),
        # Disable nuclei's "skip host after N errors" throttle. Against a
        # single web target, 10k+ templates routinely generate 50+ errors
        # in the first few seconds (templates probing vendor-specific
        # endpoints, weird URL encodings, non-existent services). Once the
        # default -mhe 50 trips, nuclei marks the host "unresponsive
        # permanently" and silently skips every remaining template — the
        # scan completes exit=0 with 0 matches even when real vulns are
        # present (e.g. DVWA default login, exposed .gitignore).
        "-nmhe",
        # Fall back to /etc/resolv.conf when nuclei's bundled public DNS
        # can't resolve the target. Keeps docker-internal and k8s-internal
        # hostnames resolvable without maintaining a separate resolvers
        # file.
        "-sr",
    ]
    if NUCLEI_EXCLUDE_TAGS.strip():
        args.extend(["-etags", NUCLEI_EXCLUDE_TAGS])
    return args


def _parse_nuclei_stats(stderr_lines: list[str]) -> dict:
    """Extract execution stats from Nuclei stderr output.

    Nuclei's output format has drifted across versions; we match several
    shapes so the parser survives template/binary upgrades:

      - Startup banner (authoritative count at scan start):
          ``[INF] Templates loaded for current scan: 4820``
          ``[INF] Executing 4820 signed templates from ...``
      - Periodic `-stats` ticker and final summary:
          ``| Templates: 389/389 | Requests: 566/566 | Matched: 0 |``
          ``Duration: 00:00:12 | Requests: 566 | Matched: 0 | Templates: 389 |``
      - Legacy summary:
          ``[INF] Total requests: 45210``
          ``[INF] Results found: 3``

    For ratio forms (``N/M``) we capture the first number (executed so
    far); at 100%% progress this equals the total, which is what callers
    expect for ``templates_loaded`` / ``requests_sent``.
    """
    stats: dict = {}
    for line in stderr_lines:
        m = re.search(r"Templates loaded for current scan:\s*(\d+)", line, re.IGNORECASE)
        if m:
            stats["templates_loaded"] = int(m.group(1))
            continue
        m = re.search(r"Executing\s+(\d+)\s+(?:signed\s+)?templates", line, re.IGNORECASE)
        if m:
            stats.setdefault("templates_loaded", int(m.group(1)))
            continue
        m = re.search(r"Templates:\s*(\d+)", line)
        if m:
            stats["templates_loaded"] = int(m.group(1))
        m = re.search(r"Total requests:\s*(\d+)", line, re.IGNORECASE)
        if m:
            stats["requests_sent"] = int(m.group(1))
            continue
        m = re.search(r"Requests:\s*(\d+)", line, re.IGNORECASE)
        if m:
            stats["requests_sent"] = int(m.group(1))
        m = re.search(r"Results found:\s*(\d+)", line, re.IGNORECASE)
        if m:
            stats["results_found"] = int(m.group(1))
        m = re.search(r"Matched:\s*(\d+)", line, re.IGNORECASE)
        if m:
            stats["results_found"] = int(m.group(1))
    return stats


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


def _credentials_to_header_args(credentials: dict | None) -> list[str]:
    """Translate a credentials payload into a sequence of Nuclei `-H` args.

    Supported `type` values:
      - basic:   username + password → "Authorization: Basic <base64>"
      - bearer:  token → "Authorization: Bearer <token>"
      - cookie:  cookie → "Cookie: <value>"
      - header:  headers dict → one `-H` per key

    Unknown types and missing required fields are silently skipped — the
    caller remains responsible for validating input. Never logs the values.
    """
    if not credentials:
        return []

    args: list[str] = []
    ctype = (credentials.get("type") or "").lower()

    if ctype == "basic":
        user = credentials.get("username") or ""
        pw = credentials.get("password") or ""
        if user or pw:
            token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
            args.extend(["-H", f"Authorization: Basic {token}"])
    elif ctype == "bearer":
        token = credentials.get("token") or ""
        if token:
            args.extend(["-H", f"Authorization: Bearer {token}"])
    elif ctype == "cookie":
        cookie = credentials.get("cookie") or credentials.get("token") or ""
        if cookie:
            args.extend(["-H", f"Cookie: {cookie}"])
    elif ctype == "header":
        # nothing to add beyond the arbitrary-headers block below
        pass

    # `headers` dict is always additive — works alongside any of the schemes.
    extra_headers = credentials.get("headers") or {}
    if isinstance(extra_headers, dict):
        for name, value in extra_headers.items():
            if not name or value is None:
                continue
            args.extend(["-H", f"{name}: {value}"])

    return args


def _adhoc_is_web_target(target: str) -> bool:
    """True if an adhoc ``target`` points at something ffuf/nuclei-DAST can reach.

    The adhoc path has no asset record to consult, so we infer web-ness
    from the target string itself:

      - An explicit ``http://`` / ``https://`` URL.
      - A host:port tuple whose port is in ``_ADHOC_WEB_PORTS``.

    Bare hostnames/IPs (``example.com``, ``10.0.0.1``) return False.
    Those can still be valid nuclei targets — nuclei itself will try
    common web ports — but we don't want to blindly include DAST
    templates for something that may actually be an SSH or DB endpoint.
    """
    if not target:
        return False
    if target.startswith(("http://", "https://")):
        return True
    if ":" in target and not target.startswith("["):  # skip IPv6 [::]:port for now
        try:
            _, port_str = target.rsplit(":", 1)
            port = int(port_str.split("/", 1)[0])
            return port in _ADHOC_WEB_PORTS
        except (ValueError, IndexError):
            return False
    return False


def _adhoc_dast_dir() -> str | None:
    """Return the ``custom/dast/`` directory path if it exists and is non-empty.

    Returns None when the dast set hasn't been synced yet (fresh install
    or sync job never ran). Nuclei would error on a nonexistent ``-t``
    path, so callers must skip the DAST command when this is None.
    """
    dast_dir = os.path.join(TEMPLATES_DIR, "custom", "dast")
    if not os.path.isdir(dast_dir):
        return None
    try:
        for _root, _dirs, files in os.walk(dast_dir):
            if any(f.endswith((".yaml", ".yml")) for f in files):
                return dast_dir
    except OSError:
        return None
    return None


def _has_dast_template(template_args: list[str]) -> bool:
    """True if any ``-t <path>`` in ``template_args`` points inside custom/dast/.

    The router emits DAST template paths via ``-t`` pairs (see
    scanner.vm.router._get_custom_templates). Checking the assembled args
    keeps this logic colocated with the command build — rather than
    re-deriving inclusion rules from open_ports here.
    """
    needles = (f"{os.sep}custom{os.sep}dast{os.sep}", "/custom/dast/")
    return any(any(n in arg for n in needles) for arg in template_args)


def _redacted_cmd_for_log(cmd: list[str]) -> str:
    """Join a command for logging, redacting the value of every -H flag.

    Nuclei takes `-H "Header: value"` as two args; the value follows the flag.
    We don't care which headers are sensitive — redact all of them so a leaked
    log line never contains decrypted vault material.
    """
    redacted: list[str] = []
    i = 0
    while i < len(cmd):
        part = cmd[i]
        if part == "-H" and i + 1 < len(cmd):
            header_value = cmd[i + 1]
            header_name = header_value.split(":", 1)[0] if ":" in header_value else header_value
            redacted.extend(["-H", f"{header_name}: ***"])
            i += 2
            continue
        redacted.append(part)
        i += 1
    return " ".join(redacted)


def _result_to_finding(result: dict) -> dict:
    """Normalize a Nuclei JSONL result into the payload shape the backend's
    import function expects. Intentionally the same shape for both
    run_nuclei_scan and run_nuclei_adhoc so one import path handles both.
    """
    info = result.get("info", {})
    template_id = result.get("template-id", result.get("templateID", "unknown"))
    severity = (info.get("severity") or "info").lower()
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "info"
    return {
        "template_id": template_id,
        "severity": severity,
        "name": info.get("name", template_id),
        "description": info.get("description", ""),
        "matched_at": result.get("matched-at", result.get("matched", "")),
        "host": result.get("host", ""),
        "port": result.get("port", ""),
        "type": result.get("type", ""),
        "tags": info.get("tags", []),
        "reference": info.get("reference", []),
        "classification": info.get("classification", {}),
        "curl_command": result.get("curl-command", ""),
        "matcher_name": result.get("matcher-name", result.get("matcher_name", "")),
        "extracted_results": result.get("extracted-results", []),
    }


@celery_app.task(queue="vm_queue", bind=True, max_retries=2)
def run_nuclei_scan(
    self,
    asset_id: str,
    credentials: dict | None = None,
    scan_plan: dict | None = None,
) -> dict:
    """Run Nuclei scan against a single asset. Returns findings in the result
    payload — the backend imports them through the normal ingest pipeline.

    ``credentials`` is an optional dict shaped by scanner.vm.api.ScanCredentials
    and is translated into `-H` header args before invoking Nuclei. The raw
    values are never logged; see ``_redacted_cmd_for_log``.

    ``scan_plan`` is an optional precomputed adaptive plan from the backend
    (services/scan_planner). Shape: ``{"plan": <ScanPlan dict>, "version": int}``.
    PR 1 plumbs it through and echoes the version back in the result; the
    actual plan-driven command builder lands in PR 2 (until then the legacy
    TemplateRouter remains the sole authority on template selection).
    """
    try:
        return _run_async(_run_nuclei_scan_async(self, asset_id, credentials, scan_plan))
    except Exception as exc:
        logger.exception("run_nuclei_scan failed for asset %s", asset_id)
        return {
            "asset_id": asset_id,
            "findings": [],
            "templates_matched": 0,
            "templates_loaded": 0,
            "requests_sent": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
        }


async def _run_nuclei_scan_async(
    task,
    asset_id: str,
    credentials: dict | None = None,
    scan_plan: dict | None = None,
) -> dict:
    start = time.monotonic()
    dsn = _normalize_dsn(DATABASE_URL)
    conn = await asyncpg.connect(dsn)

    try:
        # 1. Fetch asset context (read-only — no writes from this process).
        asset = await conn.fetchrow(HANDOFF_QUERY_BY_ID, uuid.UUID(asset_id))
        if asset is None:
            return {
                "asset_id": asset_id,
                "findings": [],
                "templates_matched": 0,
                "templates_loaded": 0,
                "requests_sent": 0,
                "duration_seconds": time.monotonic() - start,
                "status": "skipped",
                "error": "Asset not found or not confirmed_alive",
            }

        target = _resolve_target(asset)
        org_id = asset["org_id"]
        open_ports = asset["open_ports"] or []

        cpe_list = _extract_cpe_list(asset.get("cpe_list"))
        tech_stack = asset.get("tech_stack")

        # 2. Get template args + routing debug info
        template_args = _router.get_templates_for_asset(cpe_list, tech_stack, open_ports)
        routing_info = _router.get_routing_debug(cpe_list, tech_stack, open_ports)
    finally:
        # Connection is only needed for the asset context lookup.
        await conn.close()

    # 3. Decide the command(s) to run.
    # Credentials (if any) become -H flags; never log their decrypted values
    # (see _redacted_cmd_for_log).
    cred_args = _credentials_to_header_args(credentials)

    plan_consumed = False
    plan_skip_reason: str | None = None
    commands: list[dict] = []  # [{cmd, tempfiles, action?}]
    plan_dict = (scan_plan or {}).get("plan") if scan_plan else None

    if plan_dict:
        try:
            built = build_nuclei_commands_from_plan(
                plan=plan_dict,
                target=target,
                nuclei_bin=NUCLEI_BIN,
                cred_args=cred_args,
                nuclei_timeout=NUCLEI_TIMEOUT,
                rate_limit=NUCLEI_RATE_LIMIT,
            )
            if not built:
                # Empty list means the planner asked us to skip this asset
                # entirely — record the reason and emit a SUCCESS-with-no-
                # findings payload instead of running nuclei.
                plan_skip_reason = plan_dict.get("skip_reason") or "planner skip"
            else:
                # Augment plan-derived tags with router port-tags (e.g. modbus,
                # ollama) so OT/IoT routing survives even when the LLM forgets.
                # Append as an extra command rather than mutating plan commands
                # so the plan's reasoning stays auditable.
                port_only_tags = sorted(_router._route_from_ports(open_ports, _router_table()))
                if port_only_tags:
                    port_cmd = [
                        NUCLEI_BIN,
                        "-target", target,
                        "-tags", ",".join(port_only_tags),
                        *cred_args,
                        "-jsonl",
                        "-timeout", str(NUCLEI_TIMEOUT),
                        "-rate-limit", str(NUCLEI_RATE_LIMIT),
                        *_nuclei_perf_args(),
                        "-no-color",
                        "-stats",
                    ]
                    built.append({"cmd": port_cmd, "tempfiles": [], "action": {"reasoning": "router port-tag union"}})
                commands = built
                plan_consumed = True
                logger.info("Using plan v%s with %d nuclei action(s) for asset %s",
                            scan_plan.get("version"), len(plan_dict.get("actions") or []), asset_id)
        except ScanPlanInvalidError as e:
            logger.warning("Scan plan invalid for asset %s (%s) — falling back to router", asset_id, e)
            commands = []  # falls through to legacy build below
            plan_dict = None  # signal fallback in result payload

    if not commands and not plan_skip_reason:
        # Legacy path: TemplateRouter selects template args.
        template_args = _router.get_templates_for_asset(cpe_list, tech_stack, open_ports)
        # -dast unlocks nuclei's fuzzing engine so DAST templates (those with
        # `fuzzing:` blocks, e.g. the reewardius set under custom/dast/)
        # actually execute instead of being silently skipped. We only pass it
        # when such templates were actually selected by the router — for
        # OT/IoT/SSH-only assets there's nothing to fuzz and the flag is a no-op
        # anyway, but keeping it conditional also keeps scan profiles honest.
        dast_args = ["-dast"] if _has_dast_template(template_args) else []
        legacy_cmd = [
            NUCLEI_BIN,
            "-target", target,
            *template_args,
            *dast_args,
            *cred_args,
            "-jsonl",
            "-timeout", str(NUCLEI_TIMEOUT),
            "-rate-limit", str(NUCLEI_RATE_LIMIT),
            *_nuclei_perf_args(),
            "-no-color",
            "-stats",
        ]
        commands = [{"cmd": legacy_cmd, "tempfiles": [], "action": None}]

    # 4. Execute each command in sequence, sharing the per-asset wall-clock
    # budget. Aggregate findings across runs.
    findings: list[dict] = []
    templates_run: set[str] = set()
    nuclei_stats: dict = {}
    stderr_text = ""
    status = "complete" if commands else "skipped"
    deadline = start + SCAN_TIMEOUT_SECONDS

    try:
        for entry in commands:
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                logger.warning("Asset %s: per-asset budget exhausted, %d cmd(s) left unrun", asset_id, len(commands) - commands.index(entry))
                status = "partial"
                break
            cmd = entry["cmd"]
            logger.info("nuclei cmd: %s", _redacted_cmd_for_log(cmd))
            try:
                run_result = await _run_one_nuclei(cmd, timeout_seconds=int(remaining))
            except asyncio.TimeoutError:
                logger.error("nuclei timed out for asset %s", asset_id)
                status = "timeout"
                if task.request.retries < task.max_retries:
                    task.retry(countdown=60)
                break

            findings.extend(run_result["findings"])
            templates_run.update(run_result["templates_run"])
            stderr_text = "\n".join(filter(None, [stderr_text, run_result["stderr_text"]]))
            # Nuclei stats from the LAST command win for templates_loaded/
            # requests_sent — the values from earlier commands have already
            # been logged and accumulating them across commands would be
            # misleading (templates_loaded is per-invocation).
            nuclei_stats = run_result["nuclei_stats"] or nuclei_stats
            if run_result["exit_code"] != 0 and status == "complete":
                status = "partial"
            logger.info(
                "nuclei finished for %s: exit=%d templates_loaded=%s requests=%s matched=%d",
                asset_id, run_result["exit_code"],
                nuclei_stats.get("templates_loaded", "?"),
                nuclei_stats.get("requests_sent", "?"),
                len(templates_run),
            )
    finally:
        # Always clean up tmpfiles (per-endpoint target lists).
        for entry in commands:
            cleanup_tempfiles(entry.get("tempfiles") or [])

    result_payload = {
        "asset_id": asset_id,
        "org_id": str(org_id) if org_id is not None else None,
        "target": target,
        "findings": findings,
        "templates_matched": len(templates_run),
        "templates_loaded": nuclei_stats.get("templates_loaded", 0),
        "requests_sent": nuclei_stats.get("requests_sent", 0),
        "duration_seconds": round(time.monotonic() - start, 2),
        "status": status,
        "routing_info": routing_info,
    }
    if plan_skip_reason:
        result_payload["plan_skip_reason"] = plan_skip_reason
    # Echo back the plan version we executed against (None when no plan was
    # supplied). Backend uses this to detect drift between the plan that was
    # current when this scan was dispatched and the plan that's current now,
    # so a stale plan can trigger a fresh recompute on next scan.
    if scan_plan:
        result_payload["plan_version_executed"] = scan_plan.get("version")
        result_payload["plan_consumed"] = plan_consumed
    # Include nuclei stderr when templates didn't load — helps diagnose 0/0 template issues
    if nuclei_stats.get("templates_loaded", 0) == 0:
        result_payload["nuclei_stderr"] = stderr_text[:3000]
    return result_payload


async def _run_one_nuclei(cmd: list[str], timeout_seconds: int) -> dict:
    """Execute a single Nuclei subprocess and return its parsed output.

    Encapsulates the stdout/stderr drain + JSONL parsing loop so callers
    can run multiple commands per asset (plan-driven mode) without
    duplicating the streaming code. Raises asyncio.TimeoutError on the
    per-command timeout — caller decides whether to retry the whole task.
    """
    findings: list[dict] = []
    templates_run: set[str] = set()
    stderr_chunks: list[str] = []

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL,
        limit=1024 * 1024,
        env=_nuclei_subprocess_env(),
    )

    async def drain_stderr():
        assert proc.stderr is not None
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            stderr_chunks.append(line.decode("utf-8", errors="replace").strip())

    stderr_task = asyncio.create_task(drain_stderr())

    try:
        assert proc.stdout is not None
        while True:
            raw_line = await proc.stdout.readline()
            if not raw_line:
                break
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping malformed JSONL: %s", line[:200])
                continue

            template_id = result.get("template-id", result.get("templateID", ""))
            templates_run.add(template_id)
            findings.append(_result_to_finding(result))

        await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)
        await stderr_task
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise

    return {
        "findings": findings,
        "templates_run": templates_run,
        "stderr_chunks": stderr_chunks,
        "stderr_text": "\n".join(stderr_chunks),
        "nuclei_stats": _parse_nuclei_stats(stderr_chunks),
        "exit_code": proc.returncode if proc.returncode is not None else -1,
    }


def _router_table() -> dict:
    """Expose the loaded routing table to nuclei_worker for port-tag union."""
    from scanner.vm.router import _load_routing_table
    return _load_routing_table()


def _resolve_target(asset) -> str:
    """Build the scan target — prefer hostname with http_url, fall back to IP."""
    http_url = asset.get("http_url")
    if http_url:
        return http_url
    hostname = asset.get("hostname")
    if hostname:
        return hostname
    ip = asset.get("ip")
    return str(ip) if ip else ""


def _extract_cpe_list(cpe_data) -> list[str] | None:
    """Normalize cpe_list from JSONB (may be list of strings or list of dicts)."""
    if not cpe_data:
        return None
    if isinstance(cpe_data, list):
        return [str(c) for c in cpe_data]
    if isinstance(cpe_data, dict):
        return list(cpe_data.values()) if cpe_data else None
    return None


async def fetch_alive_assets() -> list[dict]:
    """Run the handoff query and return all confirmed-alive asset rows."""
    dsn = _normalize_dsn(DATABASE_URL)
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch(HANDOFF_QUERY)
        return [dict(r) for r in rows]
    finally:
        await conn.close()


# ── Ad-hoc scan (raw target, no asset record required) ──────────


ASSET_LOOKUP_BY_TARGET = """
    SELECT id, org_id FROM assets
    WHERE org_id = $1
    AND (hostname = $2 OR ip::text = $2 OR http_url = $2)
    LIMIT 1
"""


@celery_app.task(queue="vm_queue", bind=True, max_retries=2)
def run_nuclei_adhoc(
    self,
    target: str,
    org_id: str | None = None,
    credentials: dict | None = None,
    scan_plan: dict | None = None,
) -> dict:
    """Run Nuclei scan against a raw target (IP, hostname, or URL).

    When org_id is provided, findings are persisted to the findings table
    if a matching asset can be resolved from the target.

    ``credentials`` is an optional dict shaped by scanner.vm.api.ScanCredentials
    and is translated into `-H` header args. Raw values are never logged.

    ``scan_plan`` carries the optional precomputed plan from the backend.
    PR 1 plumbs it through; the adhoc path doesn't yet branch on it (PR 2).
    """
    try:
        return _run_async(_run_nuclei_adhoc_async(self, target, org_id, credentials, scan_plan))
    except Exception as exc:
        logger.exception("run_nuclei_adhoc failed for target %s", target)
        return {
            "target": target,
            "findings": [],
            "templates_matched": 0,
            "templates_loaded": 0,
            "requests_sent": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
        }


async def _run_nuclei_adhoc_async(
    task,
    target: str,
    org_id: str | None,
    credentials: dict | None = None,
    scan_plan: dict | None = None,
) -> dict:
    """Execute Nuclei against a raw target with generic templates.

    When org_id is provided, tries to resolve the target to a known asset and
    persists findings to the findings table via _emit_finding().
    """
    start = time.monotonic()
    dsn = _normalize_dsn(DATABASE_URL)
    conn = await asyncpg.connect(dsn) if org_id else None

    try:
        # Resolve target → asset_id when we have an org context
        asset_id: uuid.UUID | None = None
        resolved_org_id = None
        if conn and org_id:
            # Strip protocol for hostname lookup
            lookup_target = target
            for prefix in ("https://", "http://"):
                if lookup_target.startswith(prefix):
                    lookup_target = lookup_target[len(prefix):].rstrip("/")
                    break
            asset_row = await conn.fetchrow(
                ASSET_LOOKUP_BY_TARGET, uuid.UUID(org_id), lookup_target,
            )
            if asset_row:
                asset_id = asset_row["id"]
                resolved_org_id = asset_row["org_id"]
                logger.info("adhoc: resolved target %s → asset %s", target, asset_id)
            else:
                # Also try with the full URL in case http_url matches
                asset_row = await conn.fetchrow(
                    ASSET_LOOKUP_BY_TARGET, uuid.UUID(org_id), target,
                )
                if asset_row:
                    asset_id = asset_row["id"]
                    resolved_org_id = asset_row["org_id"]

        # Build nuclei commands. For web-shaped targets we run two
        # passes so the adhoc path gets the same coverage the asset path
        # gets via TemplateRouter:
        #   1. Community templates (no -dast) — detection/exposure
        #      signatures that make up the bulk of the feed.
        #   2. custom/dast/ templates (WITH -dast) — the reewardius
        #      fuzzing set. These templates contain `fuzzing:` blocks
        #      which only execute when -dast is set; without it nuclei
        #      loads them but silently skips execution, which is what
        #      was producing the 0-match scans against vulnerable web
        #      apps.
        # Combining both under a single -dast flag is wrong: -dast
        # restricts execution to fuzzing templates, so it would suppress
        # the whole community set. Two sequential commands is the
        # cheapest way to cover both classes.
        # Credentials (if any) become -H flags; values are never logged.
        cred_args = _credentials_to_header_args(credentials)
        base_cmd_tail = [
            *cred_args,
            "-jsonl",
            "-timeout", str(NUCLEI_TIMEOUT),
            "-rate-limit", str(NUCLEI_RATE_LIMIT),
            *_nuclei_perf_args(),
            "-no-color",
            "-stats",
            "-severity", "info,low,medium,high,critical",
        ]

        commands: list[tuple[str, list[str]]] = [
            (
                "community",
                [
                    NUCLEI_BIN,
                    "-target", target,
                    "-t", NUCLEI_COMMUNITY_TEMPLATES,
                    *base_cmd_tail,
                ],
            ),
        ]

        dast_dir = _adhoc_dast_dir() if _adhoc_is_web_target(target) else None
        if dast_dir:
            commands.append(
                (
                    "dast",
                    [
                        NUCLEI_BIN,
                        "-target", target,
                        "-t", dast_dir,
                        "-dast",
                        *base_cmd_tail,
                    ],
                )
            )

        findings_emitted = 0
        findings_persisted = 0
        templates_run: set[str] = set()
        findings: list[dict] = []
        stderr_chunks: list[str] = []
        nuclei_stats: dict = {}
        status = "complete"
        exit_code = 0
        stages_run: list[str] = []
        deadline = start + SCAN_TIMEOUT_SECONDS

        for label, cmd in commands:
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                logger.warning(
                    "adhoc %s: per-target budget exhausted before %s stage", target, label,
                )
                status = "partial"
                break

            logger.info("nuclei adhoc cmd (%s): %s", label, _redacted_cmd_for_log(cmd))

            proc = None
            cmd_stderr: list[str] = []

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.DEVNULL,
                    limit=1024 * 1024,
                    env=_nuclei_subprocess_env(),
                )

                async def drain_stderr(_proc, _sink: list[str]):
                    assert _proc.stderr is not None
                    while True:
                        line = await _proc.stderr.readline()
                        if not line:
                            break
                        _sink.append(line.decode("utf-8", errors="replace").strip())

                stderr_task = asyncio.create_task(drain_stderr(proc, cmd_stderr))

                assert proc.stdout is not None
                while True:
                    raw_line = await proc.stdout.readline()
                    if not raw_line:
                        break
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        result = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    template_id = result.get("template-id", result.get("templateID", ""))
                    templates_run.add(template_id)
                    findings_emitted += 1

                    info = result.get("info", {})
                    findings.append({
                        "template_id": template_id,
                        "severity": (info.get("severity") or "info").lower(),
                        "name": info.get("name", template_id),
                        "description": info.get("description", ""),
                        "matched_at": result.get("matched-at", ""),
                        "host": result.get("host", ""),
                        "port": result.get("port", ""),
                        "type": result.get("type", ""),
                        "tags": info.get("tags", []),
                        "reference": info.get("reference", []),
                        "classification": info.get("classification", {}),
                        "curl_command": result.get("curl-command", ""),
                        "matcher_name": result.get("matcher-name", ""),
                        "extracted_results": result.get("extracted-results", []),
                    })

                    # Persist to findings table when we have a resolved asset
                    if conn and asset_id and resolved_org_id:
                        persisted = await _emit_finding(conn, resolved_org_id, asset_id, result)
                        if persisted:
                            findings_persisted += 1

                await asyncio.wait_for(proc.wait(), timeout=int(remaining))
                await stderr_task
                stages_run.append(label)

                exit_code = proc.returncode or 0
                cmd_stats = _parse_nuclei_stats(cmd_stderr)
                # Stats from the most recent command win — each -t selection
                # loads a different template set so carrying forward the
                # community count would misreport the DAST stage.
                nuclei_stats = cmd_stats or nuclei_stats
                stderr_chunks.extend(cmd_stderr)
                logger.info(
                    "nuclei adhoc %s stage done for %s: exit=%d templates_loaded=%s requests=%s matched=%d",
                    label, target, exit_code,
                    cmd_stats.get("templates_loaded", "?"),
                    cmd_stats.get("requests_sent", "?"),
                    len(templates_run),
                )
                if exit_code != 0 and status == "complete":
                    status = "partial"
                    stderr_text = "\n".join(cmd_stderr)[:1000]
                    logger.warning(
                        "nuclei adhoc %s exited %d for %s: %s",
                        label, exit_code, target, stderr_text,
                    )

            except asyncio.TimeoutError:
                if proc is not None:
                    proc.kill()
                    await proc.wait()
                logger.error("nuclei adhoc %s timed out for target %s", label, target)
                cmd_stats = _parse_nuclei_stats(cmd_stderr)
                nuclei_stats = cmd_stats or nuclei_stats
                stderr_chunks.extend(cmd_stderr)
                status = "timeout"
                if task.request.retries < task.max_retries:
                    task.retry(countdown=60)
                break

        logger.info(
            "nuclei adhoc finished for %s: stages=%d templates_matched=%d persisted=%d status=%s",
            target, len(commands), len(templates_run), findings_persisted, status,
        )

        adhoc_payload = {
            "target": target,
            "findings_emitted": findings_emitted,
            "findings_persisted": findings_persisted,
            "templates_matched": len(templates_run),
            "templates_loaded": nuclei_stats.get("templates_loaded", 0),
            "requests_sent": nuclei_stats.get("requests_sent", 0),
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": status,
            "findings": findings,
            "asset_id": str(asset_id) if asset_id else None,
            "stages_run": stages_run,
        }
        # Mirror run_nuclei_scan: when nothing was loaded, surface stderr so
        # the backend can triage template path / -dast / auth issues without
        # needing shell access to the worker.
        if nuclei_stats.get("templates_loaded", 0) == 0:
            adhoc_payload["nuclei_stderr"] = "\n".join(stderr_chunks)[:3000]
        if scan_plan:
            adhoc_payload["plan_version_executed"] = scan_plan.get("version")
            adhoc_payload["plan_consumed"] = False  # PR 2 flips this to True
        return adhoc_payload

    finally:
        if conn:
            await conn.close()
