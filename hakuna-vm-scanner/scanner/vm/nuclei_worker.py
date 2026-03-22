"""Nuclei worker — runs vulnerability scans against individual assets."""

import asyncio
import json
import logging
import re
import time
import uuid

import asyncpg

from scanner.vm.celery_app import celery_app
from scanner.vm.config import (
    DATABASE_URL,
    NUCLEI_BIN,
    NUCLEI_COMMUNITY_TEMPLATES,
    NUCLEI_RATE_LIMIT,
    NUCLEI_TIMEOUT,
    SCAN_TIMEOUT_SECONDS,
)
from scanner.vm.db import _normalize_dsn
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

FINDING_CHECK = """
    SELECT id FROM findings
    WHERE org_id = $1 AND asset_id = $2 AND finding_type = $3 AND title = $4
    AND status = 'open'
    LIMIT 1
"""

FINDING_INSERT = """
    INSERT INTO findings (id, org_id, asset_id, finding_type, severity, title, description, metadata, status, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open', NOW(), NOW())
"""

FINDING_UPDATE = """
    UPDATE findings SET metadata = $2, updated_at = NOW()
    WHERE id = $1
"""

_router = TemplateRouter()


def _parse_nuclei_stats(stderr_lines: list[str]) -> dict:
    """Extract execution stats from Nuclei stderr output.

    Nuclei prints lines like:
      [INF] Templates: 12352 | ...
      [INF] Total requests: 45210 | ...
    """
    stats: dict = {}
    for line in stderr_lines:
        # Templates loaded count
        m = re.search(r"Templates:\s*(\d+)", line)
        if m:
            stats["templates_loaded"] = int(m.group(1))
        # Total requests sent
        m = re.search(r"Total requests:\s*(\d+)", line, re.IGNORECASE)
        if m:
            stats["requests_sent"] = int(m.group(1))
        # Results found
        m = re.search(r"Results found:\s*(\d+)", line, re.IGNORECASE)
        if m:
            stats["results_found"] = int(m.group(1))
    return stats


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(queue="vm_queue", bind=True, max_retries=2)
def run_nuclei_scan(self, asset_id: str) -> dict:
    """Run Nuclei scan against a single asset, feed findings into the pipeline."""
    try:
        return _run_async(_run_nuclei_scan_async(self, asset_id))
    except Exception as exc:
        logger.exception("run_nuclei_scan failed for asset %s", asset_id)
        return {
            "asset_id": asset_id,
            "findings_emitted": 0,
            "templates_matched": 0,
            "templates_loaded": 0,
            "requests_sent": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
        }


async def _run_nuclei_scan_async(task, asset_id: str) -> dict:
    start = time.monotonic()
    dsn = _normalize_dsn(DATABASE_URL)
    conn = await asyncpg.connect(dsn)

    try:
        # 1. Fetch asset via handoff query
        asset = await conn.fetchrow(HANDOFF_QUERY_BY_ID, uuid.UUID(asset_id))
        if asset is None:
            return {
                "asset_id": asset_id,
                "findings_emitted": 0,
                "templates_matched": 0,
                "templates_loaded": 0,
                "requests_sent": 0,
                "duration_seconds": time.monotonic() - start,
                "status": "skipped",
                "error": "Asset not found or not confirmed_alive",
            }

        # Determine scan target
        target = _resolve_target(asset)
        org_id = asset["org_id"]
        open_ports = asset["open_ports"] or []

        # Collect cpe_list across all port rows (handoff query may return multiple)
        cpe_list = _extract_cpe_list(asset.get("cpe_list"))
        tech_stack = asset.get("tech_stack")

        # 2. Get template args + routing debug info
        template_args = _router.get_templates_for_asset(cpe_list, tech_stack, open_ports)
        routing_info = _router.get_routing_debug(cpe_list, tech_stack, open_ports)

        # 3. Build nuclei command
        cmd = [
            NUCLEI_BIN,
            "-target", target,
            *template_args,
            "-jsonl",
            "-timeout", str(NUCLEI_TIMEOUT),
            "-rate-limit", str(NUCLEI_RATE_LIMIT),
            "-no-color",
            "-stats",
        ]

        logger.info("nuclei cmd: %s", " ".join(cmd))

        # 4. Execute and stream JSONL output
        findings_emitted = 0
        templates_run = set()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                limit=1024 * 1024,  # 1MB line limit
            )

            stderr_chunks: list[str] = []

            async def drain_stderr():
                assert proc.stderr is not None
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    stderr_chunks.append(line.decode("utf-8", errors="replace").strip())

            stderr_task = asyncio.create_task(drain_stderr())

            # Stream stdout line by line
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

                # 5. Parse into finding
                template_id = result.get("template-id", result.get("templateID", ""))
                templates_run.add(template_id)

                # 6. Feed into findings table
                emitted = await _emit_finding(conn, org_id, uuid.UUID(asset_id), result)
                if emitted:
                    findings_emitted += 1

            await asyncio.wait_for(proc.wait(), timeout=SCAN_TIMEOUT_SECONDS)
            await stderr_task

            exit_code = proc.returncode
            stderr_text = "\n".join(stderr_chunks)
            nuclei_stats = _parse_nuclei_stats(stderr_chunks)
            logger.info(
                "nuclei finished for %s: exit=%d templates_loaded=%s requests=%s matched=%d",
                asset_id, exit_code,
                nuclei_stats.get("templates_loaded", "?"),
                nuclei_stats.get("requests_sent", "?"),
                len(templates_run),
            )
            if exit_code != 0:
                logger.warning("nuclei exited %d for %s: %s", exit_code, asset_id, stderr_text[:1000])

            status = "complete" if exit_code == 0 else "partial"

        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.error("nuclei timed out for asset %s", asset_id)
            nuclei_stats = _parse_nuclei_stats(stderr_chunks)
            stderr_text = "\n".join(stderr_chunks)
            status = "timeout"

            # Retry once on timeout
            if task.request.retries < task.max_retries:
                task.retry(countdown=60)

        result = {
            "asset_id": asset_id,
            "findings_emitted": findings_emitted,
            "templates_matched": len(templates_run),
            "templates_loaded": nuclei_stats.get("templates_loaded", 0),
            "requests_sent": nuclei_stats.get("requests_sent", 0),
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": status,
            "routing_info": routing_info,
        }
        # Include nuclei stderr when templates didn't load — helps diagnose 0/0 template issues
        if nuclei_stats.get("templates_loaded", 0) == 0:
            result["nuclei_stderr"] = stderr_text[:3000]
        return result

    finally:
        await conn.close()


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


async def _emit_finding(conn: asyncpg.Connection, org_id, asset_id: uuid.UUID, result: dict) -> bool:
    """Parse a Nuclei JSONL result and INSERT/upsert into findings table.

    Returns True if a row was inserted/updated.
    """
    info = result.get("info", {})
    template_id = result.get("template-id", result.get("templateID", "unknown"))
    matched_at = result.get("matched-at", result.get("matched", ""))
    matcher_name = result.get("matcher-name", result.get("matcher_name", ""))

    severity_raw = info.get("severity", "info")
    severity = severity_raw.lower() if isinstance(severity_raw, str) else "info"
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "info"

    title = info.get("name", template_id)
    description = info.get("description", "")
    finding_type = "nuclei"

    metadata = {
        "scan_source": "nuclei",
        "template_id": template_id,
        "matcher_name": matcher_name,
        "matched_at": matched_at,
        "severity": severity,
        "tags": info.get("tags", []),
        "reference": info.get("reference", []),
        "classification": info.get("classification", {}),
        "extracted_results": result.get("extracted-results", []),
        "curl_command": result.get("curl-command", ""),
        "host": result.get("host", ""),
        "port": result.get("port", ""),
        "type": result.get("type", ""),
    }

    try:
        # Check-then-insert dedup (avoids needing a unique constraint)
        existing = await conn.fetchrow(
            FINDING_CHECK, org_id, asset_id, finding_type, title,
        )
        if existing:
            await conn.execute(FINDING_UPDATE, existing["id"], json.dumps(metadata))
        else:
            await conn.execute(
                FINDING_INSERT,
                uuid.uuid4(),   # id
                org_id,         # org_id
                asset_id,       # asset_id
                finding_type,   # finding_type
                severity,       # severity
                title,          # title
                description,    # description
                json.dumps(metadata),  # metadata
            )
        return True
    except Exception:
        logger.exception("Failed to emit finding for template %s on asset %s", template_id, asset_id)
        return False


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


@celery_app.task(queue="vm_queue", bind=True, max_retries=2)
def run_nuclei_adhoc(self, target: str, org_id: str | None = None) -> dict:
    """Run Nuclei scan against a raw target (IP, hostname, or URL)."""
    try:
        return _run_async(_run_nuclei_adhoc_async(self, target, org_id))
    except Exception as exc:
        logger.exception("run_nuclei_adhoc failed for target %s", target)
        return {
            "target": target,
            "findings_emitted": 0,
            "templates_matched": 0,
            "templates_loaded": 0,
            "requests_sent": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
        }


async def _run_nuclei_adhoc_async(task, target: str, org_id: str | None) -> dict:
    """Execute Nuclei against a raw target with generic templates."""
    start = time.monotonic()

    # Build nuclei command — broad template selection for ad-hoc scans
    # Note: -silent is omitted so stderr contains execution stats
    cmd = [
        NUCLEI_BIN,
        "-target", target,
        "-t", NUCLEI_COMMUNITY_TEMPLATES,
        "-jsonl",
        "-timeout", str(NUCLEI_TIMEOUT),
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-no-color",
        "-stats",
        "-severity", "info,low,medium,high,critical",
    ]

    logger.info("nuclei adhoc cmd: %s", " ".join(cmd))

    findings_emitted = 0
    templates_run: set[str] = set()
    findings: list[dict] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            limit=1024 * 1024,  # 1MB line limit (nuclei JSONL can be large)
        )

        stderr_chunks: list[str] = []

        async def drain_stderr():
            assert proc.stderr is not None
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                stderr_chunks.append(line.decode("utf-8", errors="replace").strip())

        stderr_task = asyncio.create_task(drain_stderr())

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
            })

        await asyncio.wait_for(proc.wait(), timeout=SCAN_TIMEOUT_SECONDS)
        await stderr_task

        exit_code = proc.returncode
        nuclei_stats = _parse_nuclei_stats(stderr_chunks)
        logger.info(
            "nuclei adhoc finished for %s: exit=%d templates_loaded=%s requests=%s matched=%d",
            target, exit_code,
            nuclei_stats.get("templates_loaded", "?"),
            nuclei_stats.get("requests_sent", "?"),
            len(templates_run),
        )
        if exit_code != 0:
            stderr_text = "\n".join(stderr_chunks)[:1000]
            logger.warning("nuclei adhoc exited %d for %s: %s", exit_code, target, stderr_text)

        status = "complete" if exit_code == 0 else "partial"

    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.error("nuclei adhoc timed out for target %s", target)
        nuclei_stats = _parse_nuclei_stats(stderr_chunks)
        status = "timeout"

        if task.request.retries < task.max_retries:
            task.retry(countdown=60)

    return {
        "target": target,
        "findings_emitted": findings_emitted,
        "templates_matched": len(templates_run),
        "templates_loaded": nuclei_stats.get("templates_loaded", 0),
        "requests_sent": nuclei_stats.get("requests_sent", 0),
        "duration_seconds": round(time.monotonic() - start, 2),
        "status": status,
        "findings": findings,
    }
