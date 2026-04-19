"""Specialist vulnerability agent worker.

Runs the five specialist agents (injection, XSS, SSRF, authn, authz)
against a single asset and emits findings in the Celery result payload
using the same shape as ``nuclei_worker`` / ``schemathesis_worker`` so
the backend's ``_import_nuclei_job_findings`` ingest path handles them
with no special-casing.

Relationship to the other VM workers:

  - nuclei_worker        — signature-based DAST (finds known template
                           matches, highest-volume worker)
  - schemathesis_worker  — property-based API fuzzing (schema-driven)
  - agent_worker (this)  — LLM-driven specialists for bug classes that
                           template scanners can't see: chained logic
                           flaws, business-logic IDOR, context-dependent
                           XSS, SSRF on URL params, authn misconfigs

The agents use an Anthropic tool-use loop. Each specialist gets the
asset context + endpoint slice, a budget (max iterations from
``SpecialistSpec.max_iterations``), and the shared ``TOOLS`` registry
(http_request, check_pattern, emit_finding, summary).

Credentials flow: identical to nuclei/schemathesis — a ScanCredentials
dict arrives from the backend (already merged with any session-broker
cookies by ``services/vm_scanner._resolve_auth_profile``). We flatten
it to a plain headers dict once and hand it to every specialist.

LLM provider: Anthropic only in this scaffold. Adding OpenAI/Gemini
means one more adapter in ``_anthropic_turn`` — the rest of the loop
(tool calling, finding capture, budget checks) is provider-agnostic.
Gracefully degrades to ``status=skipped`` when no ANTHROPIC_API_KEY is
set — a scanner that crashes because an LLM key is missing is useless
in air-gapped deployments.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any

import asyncpg
import httpx

from scanner.vm.agent_specialists import (
    AGENT_CATEGORIES,
    AgentContext,
    SpecialistSpec,
    TOOLS,
    select_applicable_specialists,
    tool_schemas_for_anthropic,
)
from scanner.vm.celery_app import celery_app
from scanner.vm.config import DATABASE_URL, SCAN_TIMEOUT_SECONDS
from scanner.vm.db import _normalize_dsn
from scanner.vm.llm_provider import (
    LLMAdapter,
    LLMProviderError,
    build_adapter,
    fetch_integration_configs,
    resolve_provider,
)

logger = logging.getLogger(__name__)


# Per-specialist wall-clock budget inside the per-asset SCAN_TIMEOUT_SECONDS.
# Five specialists × 60s = 5min max, which fits inside the default
# 600s asset budget and still leaves headroom for nuclei/schemathesis
# to finish on the same asset.
SPECIALIST_TIMEOUT_SECONDS = int(os.environ.get("AGENT_SPECIALIST_TIMEOUT", "60"))

# Hard cap on the number of tool-call turns per specialist. Belt-and-
# braces with SpecialistSpec.max_iterations so a buggy prompt can't
# loop forever.
ABSOLUTE_MAX_ITERATIONS = int(os.environ.get("AGENT_MAX_ITERATIONS", "20"))

# Max tokens per agent API call. Tight so the specialist is forced to
# make decisions quickly rather than write essays.
DEFAULT_MAX_TOKENS = int(os.environ.get("AGENT_MAX_TOKENS", "2048"))


# Handoff query — identical subset of assets as nuclei_worker consumes,
# plus the endpoint slice so specialists can pick targets without a
# second round-trip. LEFT JOIN so assets with zero discovered endpoints
# still run (the specialists will most likely skip themselves via
# applicable_when, but the architecture stays uniform).
ASSET_CONTEXT_QUERY = """
    SELECT a.id, a.org_id, a.hostname, a.ip, a.http_url, a.open_ports
    FROM assets a
    WHERE a.id = $1
"""

ENDPOINT_SLICE_QUERY = """
    SELECT
        ae.url, ae.path, ae.method, ae.source,
        ae.auth_required, ae.content_type, ae.parameters
    FROM asset_endpoints ae
    WHERE ae.asset_id = $1
    ORDER BY
        (ae.auth_required IS TRUE) DESC,
        (ae.source IN ('openapi','graphql')) DESC,
        ae.discovered_at ASC
    LIMIT 50
"""


# ── Credential flattening ────────────────────────────────────────
# Same shape as schemathesis_worker's version so agents see the same
# auth material Nuclei would see. Kept local (not imported) to avoid a
# cross-module dependency between two worker modules.


def _credentials_to_headers(credentials: dict | None) -> dict[str, str]:
    import base64
    headers: dict[str, str] = {}
    if not credentials:
        return headers
    ctype = (credentials.get("type") or "").lower()
    if ctype == "basic":
        user = credentials.get("username") or ""
        pw = credentials.get("password") or ""
        if user or pw:
            tok = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {tok}"
    elif ctype == "bearer":
        if credentials.get("token"):
            headers["Authorization"] = f"Bearer {credentials['token']}"
    elif ctype == "cookie":
        c = credentials.get("cookie") or credentials.get("token") or ""
        if c:
            headers["Cookie"] = c
    extra = credentials.get("headers") or {}
    if isinstance(extra, dict):
        for name, value in extra.items():
            if name and value is not None:
                headers[str(name)] = str(value)
    return headers


# ── Finding translation ──────────────────────────────────────────


def _agent_payload_to_finding(
    *, specialist: SpecialistSpec, payload: dict, target: str,
) -> dict:
    """Translate the LLM's emit_finding payload into the nuclei-compatible shape."""
    severity = (payload.get("severity") or "info").lower()
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "info"
    verdict = (payload.get("verdict") or "needs_review").lower()
    if verdict not in ("true_positive", "needs_review"):
        verdict = "needs_review"

    title = payload.get("title") or f"{specialist.display_name} finding"
    description = payload.get("description") or ""
    evidence_url = payload.get("evidence_url") or target
    request_str = payload.get("evidence_request") or ""
    response_str = payload.get("evidence_response") or ""

    # Stable template_id so dedup collapses repeat runs on the same
    # vuln. Hash over category + title + evidence_url — different
    # description wording shouldn't create a dupe, but probing the same
    # endpoint should.
    digest_src = f"{specialist.category}|{title.lower()}|{evidence_url}"
    digest = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()[:12]
    template_id = f"agent-{specialist.category}-{digest}"

    confidence = payload.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else (0.85 if verdict == "true_positive" else 0.5)
    except (TypeError, ValueError):
        confidence = 0.5

    return {
        "template_id": template_id,
        "severity": severity,
        "name": title,
        "description": description,
        "matched_at": evidence_url,
        "host": target,
        "port": "",
        "type": "agent-vuln",
        "tags": ["agent", specialist.category],
        "reference": [],
        "classification": {},
        "curl_command": request_str if request_str.startswith("curl") else "",
        "matcher_name": f"agent-{specialist.category}",
        "extracted_results": _trim_evidence(request_str, response_str),
        "llm_validation": {
            "verdict": verdict,
            "confidence": max(0.0, min(1.0, confidence)),
            "reasoning": description[:1000],
            "source": f"agent-{specialist.category}",
            "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }


def _trim_evidence(request_str: str, response_str: str) -> list[str]:
    """Bound the evidence payload so a chatty LLM can't balloon plugin_output."""
    out: list[str] = []
    if request_str:
        out.append(f"request: {request_str[:500]}")
    if response_str:
        out.append(f"response: {response_str[:500]}")
    return out


# ── Celery task ──────────────────────────────────────────────────


@celery_app.task(queue="vm_queue", bind=True, max_retries=1)
def run_agent_scan(
    self,
    asset_id: str,
    credentials: dict | None = None,
    categories: list[str] | None = None,
) -> dict:
    """Run the specialist agents against one asset.

    ``categories`` lets the backend pin specialists explicitly (e.g.,
    "only run authz on this re-test"). When None, runs all five and
    lets ``select_applicable_specialists`` gate individual agents.
    """
    try:
        return _run_async(_run_agent_scan_async(self, asset_id, credentials, categories))
    except Exception as exc:
        logger.exception("run_agent_scan failed for asset %s", asset_id)
        return {
            "asset_id": asset_id,
            "findings": [],
            "specialists_run": [],
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
            "scanner": "agent",
        }


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _run_agent_scan_async(
    task,
    asset_id: str,
    credentials: dict | None,
    categories: list[str] | None,
) -> dict:
    start = time.monotonic()

    # Single DB connection does double duty: resolve LLM provider (reads
    # integration_configs) AND fetch asset + endpoint context. One
    # asyncpg round-trip per provider lookup would be wasteful per-task.
    conn = await asyncpg.connect(_normalize_dsn(DATABASE_URL))
    try:
        integration_configs = await fetch_integration_configs(conn)
        provider_info = resolve_provider(integration_configs)
        if provider_info is None:
            return {
                "asset_id": asset_id,
                "findings": [],
                "specialists_run": [],
                "duration_seconds": round(time.monotonic() - start, 2),
                "status": "skipped",
                "error": (
                    "no LLM provider configured — set one of ANTHROPIC_API_KEY, "
                    "OPENAI_API_KEY, GOOGLE_CLOUD_PROJECT (vertex_ai), "
                    "GOOGLE_API_KEY (gemini), GROQ_API_KEY, or enable Ollama "
                    "in integration_configs"
                ),
                "scanner": "agent",
            }

        asset = await conn.fetchrow(ASSET_CONTEXT_QUERY, uuid.UUID(asset_id))
        if asset is None:
            return {
                "asset_id": asset_id,
                "findings": [],
                "specialists_run": [],
                "duration_seconds": round(time.monotonic() - start, 2),
                "status": "skipped",
                "error": "asset not found",
                "scanner": "agent",
            }
        endpoint_rows = await conn.fetch(ENDPOINT_SLICE_QUERY, uuid.UUID(asset_id))
    finally:
        await conn.close()

    try:
        adapter = build_adapter(provider_info)
    except LLMProviderError as e:
        # SDK missing or misconfig surfaced by the adapter itself — distinct
        # from resolver output (which only checked credential presence).
        return {
            "asset_id": asset_id,
            "findings": [],
            "specialists_run": [],
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": "error",
            "error": f"LLM adapter init failed: {e}",
            "scanner": "agent",
            "llm_provider": provider_info.provider,
            "llm_model": provider_info.model,
        }

    endpoints = [_coerce_endpoint(dict(r)) for r in endpoint_rows]
    target = _resolve_target(asset)
    headers = _credentials_to_headers(credentials)

    ctx = AgentContext(
        asset_id=asset_id,
        org_id=str(asset["org_id"]) if asset["org_id"] is not None else None,
        target=target,
        endpoints=endpoints,
        headers=headers,
        deadline=start + SCAN_TIMEOUT_SECONDS,
    )

    selected = select_applicable_specialists(ctx, categories)
    if not selected:
        return {
            "asset_id": asset_id,
            "org_id": ctx.org_id,
            "target": target,
            "findings": [],
            "specialists_run": [],
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": "skipped",
            "error": "no applicable specialists for this asset",
            "scanner": "agent",
        }

    logger.info(
        "agent_worker start asset=%s target=%s specialists=%s endpoints=%d",
        asset_id, target, [s.category for s in selected], len(endpoints),
    )

    findings: list[dict] = []
    specialists_run: list[dict] = []

    async with httpx.AsyncClient(verify=False) as _async_client:
        # The tool handlers are sync (httpx.Client is sync) so specialists
        # share a sync client too — simpler than converting tool schemas
        # to async. The outer worker loop stays async for DB + LLM I/O.
        pass

    with httpx.Client(verify=False, follow_redirects=False) as sync_client:
        ctx.http_client = sync_client
        for spec in selected:
            if time.monotonic() >= ctx.deadline:
                specialists_run.append({
                    "category": spec.category, "status": "skipped",
                    "reason": "asset deadline reached",
                })
                continue

            spec_start = time.monotonic()
            spec_deadline = min(ctx.deadline, spec_start + SPECIALIST_TIMEOUT_SECONDS)

            try:
                spec_findings, iterations, stop_reason = await _run_specialist(
                    spec=spec, ctx=ctx, deadline=spec_deadline, adapter=adapter,
                )
            except LLMProviderError as e:
                # Provider-level outage — stop running specialists for
                # this asset; retrying the next category against the
                # same broken provider wastes time.
                return {
                    "asset_id": asset_id,
                    "org_id": ctx.org_id,
                    "findings": findings,
                    "specialists_run": specialists_run + [{
                        "category": spec.category, "status": "error", "reason": str(e),
                    }],
                    "duration_seconds": round(time.monotonic() - start, 2),
                    "status": "error",
                    "error": f"LLM provider error: {e}",
                    "scanner": "agent",
                    "llm_provider": provider_info.provider,
                    "llm_model": provider_info.model,
                }
            except Exception as e:
                logger.exception("specialist %s crashed for asset %s", spec.category, asset_id)
                specialists_run.append({
                    "category": spec.category, "status": "error",
                    "reason": str(e)[:200], "iterations": 0,
                })
                continue

            findings.extend(spec_findings)
            specialists_run.append({
                "category": spec.category,
                "status": stop_reason,
                "iterations": iterations,
                "findings": len(spec_findings),
                "duration_seconds": round(time.monotonic() - spec_start, 2),
            })

    return {
        "asset_id": asset_id,
        "org_id": ctx.org_id,
        "target": target,
        "findings": findings,
        "specialists_run": specialists_run,
        "duration_seconds": round(time.monotonic() - start, 2),
        "status": "complete" if findings or any(s["status"] == "summary" for s in specialists_run) else "partial",
        "scanner": "agent",
        "llm_provider": provider_info.provider,
        "llm_model": provider_info.model,
    }


def _resolve_target(asset) -> str:
    """Same precedence as the other workers — http_url > hostname > ip."""
    http_url = asset["http_url"] if "http_url" in asset.keys() else None
    if http_url:
        return http_url
    hostname = asset["hostname"] if "hostname" in asset.keys() else None
    if hostname:
        return hostname
    ip = asset["ip"] if "ip" in asset.keys() else None
    return str(ip) if ip else ""


def _coerce_endpoint(row: dict) -> dict:
    """asyncpg returns parameters JSONB as str sometimes — normalize."""
    out = dict(row)
    params = out.get("parameters")
    if isinstance(params, str):
        try:
            out["parameters"] = json.loads(params)
        except (TypeError, ValueError):
            out["parameters"] = None
    return out


# ── Specialist runner ────────────────────────────────────────────


async def _run_specialist(
    *, spec: SpecialistSpec, ctx: AgentContext, deadline: float, adapter: LLMAdapter,
) -> tuple[list[dict], int, str]:
    """Tool-use loop for one specialist. Returns (findings, iterations, stop_reason).

    Stop reasons:
      - ``summary``         — agent called the ``summary`` tool (normal exit)
      - ``iterations``      — hit the iteration cap
      - ``deadline``        — wall-clock budget reached
      - ``end_turn``        — model returned a final text response without calling summary

    Provider-level failures (SDK auth/5xx) raise LLMProviderError up so
    the outer loop aborts the asset rather than marching through the
    rest of the specialists against a broken upstream.
    """
    iteration_cap = min(spec.max_iterations, ABSOLUTE_MAX_ITERATIONS)
    findings: list[dict] = []
    iterations = 0

    initial_user_message = _build_initial_message(ctx, spec)
    messages: list[dict] = [{"role": "user", "content": initial_user_message}]
    system_prompt = spec.system_prompt
    tool_schemas = tool_schemas_for_anthropic()

    stop_reason = "iterations"

    while iterations < iteration_cap:
        if time.monotonic() >= deadline:
            stop_reason = "deadline"
            break

        iterations += 1
        turn = await asyncio.to_thread(
            adapter.turn,
            system=system_prompt,
            messages=messages,
            tools=tool_schemas,
            max_tokens=DEFAULT_MAX_TOKENS,
        )

        assistant_content = turn["content"]
        messages.append({"role": "assistant", "content": assistant_content})

        tool_uses = [b for b in assistant_content if b.get("type") == "tool_use"]

        if not tool_uses:
            # Model returned plain text — treat it as an implicit summary.
            stop_reason = "end_turn"
            break

        # Execute every tool use in this turn and hand results back.
        tool_results_content: list[dict] = []
        saw_summary = False
        for block in tool_uses:
            name = block.get("name") or ""
            params = block.get("input") or {}
            use_id = block.get("id") or ""
            tool = TOOLS.get(name)
            if tool is None:
                tool_results_content.append({
                    "type": "tool_result",
                    "tool_use_id": use_id,
                    "content": json.dumps({"error": f"unknown tool {name!r}"}),
                    "is_error": True,
                })
                continue

            if name == "emit_finding":
                finding = _agent_payload_to_finding(
                    specialist=spec, payload=params, target=ctx.target,
                )
                findings.append(finding)
            if name == "summary":
                saw_summary = True

            try:
                result = tool.handler(params, ctx)
            except Exception as e:
                result = {"error": f"tool handler raised: {e}"}

            tool_results_content.append({
                "type": "tool_result",
                "tool_use_id": use_id,
                "content": json.dumps(result)[:8_000],
            })

        messages.append({"role": "user", "content": tool_results_content})

        if saw_summary:
            stop_reason = "summary"
            break

    return findings, iterations, stop_reason


def _build_initial_message(ctx: AgentContext, spec: SpecialistSpec) -> str:
    """First user message — enough context for the agent to pick targets.

    Kept compact: the system prompt is long, but the user message is
    just the asset + a capped endpoint slice. Dumping every field of
    every endpoint would bloat the prompt without helping the model
    pick targets.
    """
    # Trim endpoint detail aggressively — the specialist uses http_request
    # to gather more detail on demand.
    ep_slice = []
    for ep in ctx.endpoints[:20]:
        ep_slice.append({
            "url": ep.get("url"),
            "method": ep.get("method"),
            "source": ep.get("source"),
            "auth_required": ep.get("auth_required"),
            "content_type": ep.get("content_type"),
            "parameter_names": [
                p.get("name") for p in (ep.get("parameters") or [])
                if isinstance(p, dict) and p.get("name")
            ][:10],
        })

    lines = [
        f"SPECIALIST: {spec.display_name}",
        f"TARGET: {ctx.target}",
        f"ASSET_ID: {ctx.asset_id}",
        f"AUTH_HEADERS_PROVIDED: {sorted(ctx.headers.keys())}",
        f"ENDPOINTS (first {len(ep_slice)} of {len(ctx.endpoints)}):",
        json.dumps(ep_slice, indent=2),
        "",
        "Begin. Use tools to probe. Call emit_finding for every confirmed vuln. Call summary when done.",
    ]
    return "\n".join(lines)


# Expose AGENT_CATEGORIES at module level so callers can introspect the
# set without importing from agent_specialists directly.
__all__ = [
    "run_agent_scan",
    "AGENT_CATEGORIES",
    "_agent_payload_to_finding",
    "_credentials_to_headers",
]
