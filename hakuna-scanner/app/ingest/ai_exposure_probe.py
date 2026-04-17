"""AI/LLM/vector-DB unauthenticated-exposure probes.

The existing ``endpoint_probe`` stage classifies assets by service (Ollama,
vLLM, Qdrant, MCP, LangServe, etc.) but only writes CPE/asset-type metadata.
Many of these services ship without authentication by default, so a
"detected = exposed" distinction isn't useful on its own — we also want a
Finding when the endpoint actively accepts requests without credentials.

This module consumes ``ai_exposure_probes.json`` and, for each confirmed AI
asset, sends the probe request and matches the response against the probe's
``success_when`` criteria. On success it writes a Finding following the same
schema used by ``liveness.create_dangling_dns_finding`` and the exposed-
protocol finding in ``tasks/enrichment.py`` — the Finding ORM columns
``finding_type / severity / title / description / metadata``.

The probes are read-only by design: every body is ``{}`` or minimal
placeholder; success criteria are tuned to the *unauthenticated-and-
responsive* shape (e.g. 400 "missing required field") rather than a
successfully-exploited response. Probe failures are swallowed silently.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import aiohttp
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(__file__), "ai_exposure_probes.json")

# Cap response body read. Success fingerprints are short and near the start
# of the body; reading further wastes memory on large streaming responses
# (vLLM, LangServe).
_MAX_BODY_BYTES = 16_000

# Per-probe HTTP timeout — long enough for cold Ollama/vLLM startups but
# short enough that a few hundred probes don't stall enrichment.
_PROBE_TIMEOUT = 8.0

# Asset types the probes target. Keeping this as a set lets a caller cheaply
# filter candidate assets before we spin up an HTTP session.
AI_ASSET_TYPES = {"ai_inference", "ai_agent", "ai_gateway", "vector_db"}


def _load_db() -> list[dict]:
    try:
        with open(_DB_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("ai_exposure_probe: failed to load %s: %s", _DB_PATH, exc)
        return []
    return data.get("probes", [])


_DB: list[dict] = _load_db()


def reload_db() -> None:
    """Force-reload the probe DB. For tests."""
    global _DB
    _DB = _load_db()


def _applies_to_asset_type(probe: dict, asset_type: str | None) -> bool:
    """True if the probe targets the given asset type (or has no restriction)."""
    allowed = probe.get("asset_types")
    if not allowed:
        return True
    return asset_type in allowed


def _matches_success(probe: dict, status: int, body: str) -> bool:
    """Return True if the probe's success_when criteria match the response."""
    success = probe.get("success_when") or {}
    fail = probe.get("fail_when") or {}

    # Fail-fast: explicit auth-required status codes disqualify the probe.
    fail_statuses = fail.get("status_in") or []
    if fail_statuses and status in fail_statuses:
        return False

    statuses = success.get("status_in") or []
    if statuses and status not in statuses:
        return False

    body_any = success.get("body_contains_any") or []
    body_all = success.get("body_contains") or []

    if body_any and not any(fp in body for fp in body_any if fp):
        return False
    if body_all and not all(fp in body for fp in body_all if fp):
        return False

    return True


async def _run_probe(
    session: aiohttp.ClientSession,
    base_url: str,
    probe: dict,
) -> dict | None:
    """Execute a single probe against a base URL. Returns match evidence or None.

    Never raises — any transport/parse failure returns None so enrichment
    continues uninterrupted.
    """
    method = (probe.get("method") or "GET").upper()
    path = probe.get("path") or "/"
    url = base_url.rstrip("/") + path
    headers = dict(probe.get("headers") or {})
    body = probe.get("body")
    json_body = body if isinstance(body, (dict, list)) else None

    try:
        async with session.request(
            method,
            url,
            headers=headers,
            json=json_body,
            timeout=aiohttp.ClientTimeout(total=_PROBE_TIMEOUT),
            allow_redirects=False,
            ssl=False,
        ) as resp:
            status = resp.status
            raw = await resp.content.read(_MAX_BODY_BYTES)
            body_text = raw.decode("utf-8", errors="replace")
    except Exception:
        return None

    if not _matches_success(probe, status, body_text):
        return None

    # Capture a short evidence snippet — useful for the Finding metadata
    # without ballooning the JSONB column.
    snippet = body_text[:400].strip()

    return {
        "probe": probe.get("name"),
        "service": probe.get("service"),
        "url": url,
        "method": method,
        "http_status": status,
        "severity": probe.get("severity", "high"),
        "title": probe.get("title") or f"Unauthenticated AI endpoint: {probe.get('service')}",
        "description": probe.get("description", ""),
        "evidence_snippet": snippet,
    }


def _pick_base_urls(asset: dict) -> list[str]:
    """Choose base URLs to probe for an asset.

    Mirrors the logic used by endpoint_probe: prefer HTTPS on 443/8443, add
    HTTP on 80/8080, fall back to https if no HTTP ports are open.
    Additionally include the AI-specific default ports (Ollama 11434, Qdrant
    6333, Milvus 19530, vLLM 8000, LiteLLM 4000) over HTTP when present —
    most of these services only bind plaintext.
    """
    hostname = asset.get("hostname")
    if not hostname:
        return []

    ports = set(asset.get("open_ports") or [])
    urls: list[str] = []

    if 443 in ports:
        urls.append(f"https://{hostname}")
    if 8443 in ports:
        urls.append(f"https://{hostname}:8443")
    if 80 in ports:
        urls.append(f"http://{hostname}")
    if 8080 in ports:
        urls.append(f"http://{hostname}:8080")

    # Service-specific default ports (HTTP only).
    for port in (11434, 6333, 19530, 8000, 4000, 8001):
        if port in ports:
            urls.append(f"http://{hostname}:{port}")

    if not urls:
        urls.append(f"https://{hostname}")

    # Dedup while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


async def _probe_asset(
    session: aiohttp.ClientSession,
    asset: dict,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """Probe a single asset against every applicable probe in the DB."""
    asset_type = asset.get("asset_type")
    candidates = [p for p in _DB if _applies_to_asset_type(p, asset_type)]
    if not candidates:
        return []

    base_urls = _pick_base_urls(asset)
    if not base_urls:
        return []

    async with semaphore:
        hits: list[dict] = []
        # Dedup on (probe name, service) so multi-port hosts don't double-file.
        seen: set[str] = set()
        for base_url in base_urls:
            for probe in candidates:
                key = f"{probe.get('name')}:{probe.get('service')}"
                if key in seen:
                    continue
                try:
                    result = await _run_probe(session, base_url, probe)
                except Exception:
                    result = None
                if result is not None:
                    seen.add(key)
                    hits.append(result)
        return hits


async def probe_assets(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[uuid.UUID, list[dict]]:
    """Probe a batch of AI assets for unauthenticated-exposure findings.

    ``assets`` is expected to contain dicts with keys: ``id`` (uuid.UUID),
    ``hostname``, ``open_ports``, ``asset_type``. Assets whose asset_type is
    not in ``AI_ASSET_TYPES`` are skipped.

    Returns a mapping of asset_id -> list of probe-hit dicts. Never raises.
    """
    if not _DB:
        logger.warning("ai_exposure_probe: probe DB is empty, skipping")
        return {}

    candidates = [
        a for a in assets
        if a.get("asset_type") in AI_ASSET_TYPES and a.get("hostname")
    ]
    if not candidates:
        return {}

    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency * 4, ssl=False)
    timeout = aiohttp.ClientTimeout(total=60, connect=_PROBE_TIMEOUT)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; HakunaScanner/1.0 ai-exposure-probe)",
        "Accept": "application/json, text/event-stream, */*",
    }

    results: dict[uuid.UUID, list[dict]] = {}
    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=headers,
    ) as session:
        tasks = [
            _probe_asset(session, asset, semaphore)
            for asset in candidates
        ]
        per_asset = await asyncio.gather(*tasks, return_exceptions=True)

    for asset, hits in zip(candidates, per_asset):
        if isinstance(hits, Exception):
            logger.debug("ai_exposure_probe: asset %s errored: %s", asset.get("hostname"), hits)
            continue
        if hits:
            results[asset["id"]] = hits

    return results


async def store_ai_exposure_findings(
    db: AsyncSession,
    org_id: uuid.UUID,
    probe_results: dict[uuid.UUID, list[dict]],
) -> dict:
    """Persist probe hits as Finding rows.

    Mirrors the write path used by ``liveness.create_dangling_dns_finding``
    and the exposed-protocol finding block in ``tasks/enrichment.py``.
    """
    now = datetime.now(timezone.utc)
    findings_created = 0
    hosts_affected = 0

    for asset_id, hits in probe_results.items():
        if not hits:
            continue
        hosts_affected += 1

        for hit in hits:
            finding_id = uuid.uuid4()
            await db.execute(
                text("""
                    INSERT INTO findings (
                        id, org_id, asset_id, finding_type, severity,
                        title, description, metadata, status,
                        created_at, updated_at
                    ) VALUES (
                        :id, :org_id, :asset_id, :ftype, :sev,
                        :title, :desc, cast(:meta as jsonb), 'open',
                        :now, :now
                    )
                    ON CONFLICT DO NOTHING
                """),
                {
                    "id": finding_id,
                    "org_id": org_id,
                    "asset_id": asset_id,
                    "ftype": f"ai_exposure_{hit.get('service', 'unknown')}",
                    "sev": hit.get("severity", "high"),
                    "title": hit.get("title"),
                    "desc": hit.get("description", ""),
                    "meta": json.dumps({
                        "probe": hit.get("probe"),
                        "service": hit.get("service"),
                        "url": hit.get("url"),
                        "method": hit.get("method"),
                        "http_status": hit.get("http_status"),
                        "evidence_snippet": hit.get("evidence_snippet"),
                    }),
                    "now": now,
                },
            )
            findings_created += 1

    await db.commit()
    return {
        "hosts_affected": hosts_affected,
        "findings_created": findings_created,
    }
