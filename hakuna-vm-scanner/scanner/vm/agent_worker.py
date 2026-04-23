"""Specialist vulnerability agent worker.

Runs the six specialist agents (injection, XSS, SSRF, authn, authz, files)
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
    seed_base_endpoint,
    select_applicable_specialists,
    tool_schemas_for_anthropic,
)
from scanner.vm.agent_scheduler import FrontierScheduler
from scanner.vm.celery_app import celery_app
from scanner.vm.config import DATABASE_URL, SCAN_TIMEOUT_SECONDS
from scanner.vm.db import _normalize_dsn
from scanner.vm.llm_provider import (
    LLMAdapter,
    LLMProviderError,
    build_adapter,
    fetch_integration_configs,
    resolve_provider,
    resolve_specific_provider,
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


def _build_adapter_map(
    selected: list[SpecialistSpec],
    integration_configs: dict,
    default_adapter: LLMAdapter,
    default_provider_info,
) -> dict[str, LLMAdapter]:
    """Resolve a per-specialist adapter, falling back to the default.

    Most specialists share the scan-wide default adapter. A handful
    (authn today; potentially post-auth-enum / authz later) prefer a
    stronger model because their orchestration matters more than raw
    cost. When the preferred provider isn't configured, silently fall
    back — a scanner in an air-gapped Vertex-only environment must
    still run authn, just on the weaker default.

    Adapters are cached module-level by (provider, model, key
    fingerprint) so building two adapters per scan doesn't double the
    SDK connection count.
    """
    out: dict[str, LLMAdapter] = {}
    for spec in selected:
        preferred_provider = spec.preferred_provider
        preferred_model = spec.preferred_model

        # Short-circuit to default only when BOTH provider AND model
        # match (or no preference is declared). Previously this keyed
        # on provider alone, which silently swallowed "same provider,
        # different model" preferences — critical now that vertex_ai
        # serves both Gemini (gemini-*) and Claude (claude-*) and a
        # spec may want Claude while the scan default is Gemini.
        if not preferred_provider:
            out[spec.category] = default_adapter
            continue
        same_provider = preferred_provider == default_provider_info.provider
        same_model = (
            preferred_model is None
            or preferred_model == default_provider_info.model
        )
        if same_provider and same_model:
            out[spec.category] = default_adapter
            continue

        info = resolve_specific_provider(
            preferred_provider, integration_configs,
            model_override=preferred_model,
        )
        if info is None:
            logger.info(
                "agent_worker: preferred provider %s not configured for %s — using default %s",
                preferred_provider, spec.category, default_provider_info.provider,
            )
            out[spec.category] = default_adapter
            continue
        try:
            out[spec.category] = build_adapter(info)
            logger.info(
                "agent_worker: specialist %s routed to %s (model=%s)",
                spec.category, info.provider, info.model,
            )
        except LLMProviderError as e:
            logger.warning(
                "agent_worker: could not build preferred adapter for %s (%s) — using default",
                spec.category, e,
            )
            out[spec.category] = default_adapter
    return out


def _seed_scan_config_capability(
    ctx: AgentContext, credentials: dict | None,
) -> None:
    """Promote scan-configured credentials into a typed capability.

    Before: passing ``credentials={...}`` to the task set
    ``ctx.headers["Authorization"]`` and nothing else. The CAPABILITIES
    block stayed empty, COMPOSITION hints never fired, and every
    specialist ran as if no auth primitive existed — the LLM had no
    steer toward post-auth endpoints.

    After: basic/bearer/cookie scan-config materialises as a CRED or
    SESSION capability tagged ``provenance=scan_config``. The rest of
    composition (hints, scheduler idempotency, identity refresh) then
    works uniformly whether the primitive came from scan config or
    from authn's discovery path. Seeding here is cheap and one-shot
    per asset scan — the capability store's dedup keeps re-seeds
    (e.g. from a retry) from multiplying rows.

    Extra headers on the credentials dict are treated as raw config,
    not a capability — they might be anti-CSRF tokens or trace IDs
    rather than auth material.
    """
    if not credentials:
        return
    from scanner.vm.capabilities import (
        Capability,
        CapabilityType,
        asset_scope,
    )
    scope = asset_scope(ctx.asset_id)
    ctype = (credentials.get("type") or "").lower()

    if ctype == "basic":
        user = (credentials.get("username") or "").strip()
        pw = (credentials.get("password") or "").strip()
        if user or pw:
            ctx.capabilities.add(Capability(
                type=CapabilityType.CRED, scope=scope,
                value={"scheme": "basic", "username": user, "password": pw},
                confidence=1.0,
                provenance="scan_config",
            ))
    elif ctype == "bearer":
        token = (credentials.get("token") or "").strip()
        if token:
            ctx.capabilities.add(Capability(
                type=CapabilityType.SESSION, scope=scope,
                value={"jwt": token},
                confidence=1.0,
                provenance="scan_config",
            ))
    elif ctype == "cookie":
        cookie = (credentials.get("cookie") or credentials.get("token") or "").strip()
        if cookie:
            ctx.capabilities.add(Capability(
                type=CapabilityType.SESSION, scope=scope,
                value={"cookie": cookie},
                confidence=1.0,
                provenance="scan_config",
            ))


def _apply_discovered_identity(ctx: AgentContext) -> list[str]:
    """Fill missing auth headers from capability store. Return names injected.

    The step 4 half of exploit composition: once authn commits a CRED
    capability (or anyone commits a SESSION), subsequent specialists
    need to actually *use* it. Without this, the LLM sees the primitive
    in the CAPABILITIES block but has to construct headers manually on
    every http_request call — slow, error-prone, and specialists that
    don't know about the block skip it entirely.

    Non-destructive: scan-configured headers always win. Only fills
    slots the operator left empty (``Authorization`` / ``Cookie``).
    That keeps explicit scan configuration authoritative — if the
    operator passed ``credentials={...}`` to the task, their choice
    isn't silently replaced by whatever the LLM stumbled across.

    Ties broken by confidence, then insertion order (CapabilityStore
    preserves insertion). CRED is preferred over SESSION for
    ``Authorization`` because concrete user:pass lets future runs
    re-authenticate if a bearer token expires mid-scan.
    """
    import base64
    from scanner.vm.capabilities import CapabilityType, asset_scope

    scope = asset_scope(ctx.asset_id)
    added: list[str] = []

    # Header lookup is case-insensitive per RFC 7230. Callers might
    # have injected "Authorization" or "authorization" — check both so
    # we don't double-set.
    def _has_header(name: str) -> bool:
        lower = name.lower()
        return any(k.lower() == lower for k in ctx.headers)

    if not _has_header("Authorization"):
        creds = sorted(
            ctx.capabilities.query(type=CapabilityType.CRED, scope=scope),
            key=lambda c: c.confidence, reverse=True,
        )
        if creds:
            top = creds[0]
            user = top.value.get("username") or ""
            pw = top.value.get("password") or ""
            if user or pw:
                tok = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
                ctx.headers["Authorization"] = f"Basic {tok}"
                added.append("Authorization")
        if "Authorization" not in added:
            sessions_with_jwt = [
                s for s in ctx.capabilities.query(
                    type=CapabilityType.SESSION, scope=scope,
                )
                if s.value.get("jwt")
            ]
            sessions_with_jwt.sort(key=lambda c: c.confidence, reverse=True)
            if sessions_with_jwt:
                ctx.headers["Authorization"] = f"Bearer {sessions_with_jwt[0].value['jwt']}"
                added.append("Authorization")

    if not _has_header("Cookie"):
        sessions_with_cookie = [
            s for s in ctx.capabilities.query(
                type=CapabilityType.SESSION, scope=scope,
            )
            if s.value.get("cookie")
        ]
        sessions_with_cookie.sort(key=lambda c: c.confidence, reverse=True)
        if sessions_with_cookie:
            ctx.headers["Cookie"] = sessions_with_cookie[0].value["cookie"]
            added.append("Cookie")

    return added


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
    parameter = (payload.get("parameter") or "").strip().lower()
    request_str = payload.get("evidence_request") or ""
    response_str = payload.get("evidence_response") or ""

    # Stable template_id so dedup collapses repeat runs on the same
    # vuln. Key on category + evidence_url + parameter. Title is
    # deliberately excluded — the LLM rewords it between runs
    # ("parameter in" vs "Parameter at", etc.), so including it defeats
    # dedup. Parameter keeps two genuinely distinct vulns on the same
    # endpoint (e.g. SQLi on ?id= AND SQLi on ?name=) as separate
    # findings. Empty parameter is normalised to "-" so endpoint-level
    # vulns (default login, exposed panel) still collapse cleanly.
    param_key = parameter or "-"
    digest_src = f"{specialist.category}|{evidence_url}|{param_key}"
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
    "only run authz on this re-test"). When None, runs all six and
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
        try:
            # Force GC so finalizers that schedule cleanup coroutines
            # (notably google-genai's BaseApiClient, which fires aclose()
            # from __del__) enqueue their tasks before we drain.
            import gc
            gc.collect()
            pending = asyncio.all_tasks(loop)
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
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

    # If prior scanners (katana, ffuf, openapi) produced no endpoints,
    # seed a synthetic base-URL row so the specialists have a starting
    # point to probe and harvest forms from.
    endpoints = seed_base_endpoint(endpoints, target)

    ctx = AgentContext(
        asset_id=asset_id,
        org_id=str(asset["org_id"]) if asset["org_id"] is not None else None,
        target=target,
        endpoints=endpoints,
        headers=headers,
        deadline=start + SCAN_TIMEOUT_SECONDS,
    )
    _seed_scan_config_capability(ctx, credentials)

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

    scheduler = FrontierScheduler(specialists=selected)
    adapter_map = _build_adapter_map(
        selected, integration_configs, adapter, provider_info,
    )

    with httpx.Client(verify=False, follow_redirects=False) as sync_client:
        ctx.http_client = sync_client
        while True:
            scheduled = scheduler.next(ctx)
            if scheduled is None:
                break
            spec = scheduled.spec
            spec_adapter = adapter_map.get(spec.category, adapter)

            spec_start = time.monotonic()
            spec_deadline = min(ctx.deadline, spec_start + SPECIALIST_TIMEOUT_SECONDS)

            try:
                spec_findings, iterations, stop_reason = await _run_specialist(
                    spec=spec, ctx=ctx, deadline=spec_deadline, adapter=spec_adapter,
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
                        "run_number": scheduled.run_number,
                        "scheduler_reason": scheduled.reason,
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
                    "run_number": scheduled.run_number,
                    "scheduler_reason": scheduled.reason,
                })
                continue

            findings.extend(spec_findings)
            specialists_run.append({
                "category": spec.category,
                "status": stop_reason,
                "iterations": iterations,
                "findings": len(spec_findings),
                "duration_seconds": round(time.monotonic() - spec_start, 2),
                "run_number": scheduled.run_number,
                "scheduler_reason": scheduled.reason,
            })

    return {
        "asset_id": asset_id,
        "org_id": ctx.org_id,
        "target": target,
        "findings": findings,
        "specialists_run": specialists_run,
        "capabilities": ctx.capabilities.summarize(),
        "duration_seconds": round(time.monotonic() - start, 2),
        "status": "complete" if findings or any(s["status"] == "summary" for s in specialists_run) else "partial",
        "scanner": "agent",
        "llm_provider": provider_info.provider,
        "llm_model": provider_info.model,
    }


# ── Ad-hoc task ──────────────────────────────────────────────────


@celery_app.task(queue="vm_queue", bind=True, max_retries=1)
def run_agent_scan_adhoc(
    self,
    target: str,
    org_id: str | None = None,
    credentials: dict | None = None,
    categories: list[str] | None = None,
) -> dict:
    """Ad-hoc specialist agents against a raw target URL.

    Peers with ``run_nuclei_adhoc`` / ``run_content_discovery_adhoc``:
    fires against a URL the backend has but for which we don't have a
    scanner-side asset record. We skip the ASSET_CONTEXT_QUERY +
    ENDPOINT_SLICE_QUERY steps — the AgentContext is built directly
    from ``target`` plus a synthetic base-URL endpoint seeded by
    ``seed_base_endpoint``.

    With the synthetic row in place, injection / xss / ssrf all apply
    as long as the target is http(s). Their prompts tell them to fetch
    the base URL and harvest `<form>` action + input names before
    picking candidates, so the agent does endpoint discovery on its
    first tool call rather than depending on a prior crawl. Authn and
    authz still require explicit auth material (headers or an
    ``auth_required`` endpoint) to diff against.
    """
    try:
        return _run_async(_run_agent_scan_adhoc_async(self, target, org_id, credentials, categories))
    except Exception as exc:
        logger.exception("run_agent_scan_adhoc failed for target %s", target)
        return {
            "target": target,
            "findings": [],
            "specialists_run": [],
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
            "scanner": "agent",
        }


async def _run_agent_scan_adhoc_async(
    task,
    target: str,
    org_id: str | None,
    credentials: dict | None,
    categories: list[str] | None,
) -> dict:
    start = time.monotonic()

    # LLM provider resolution still needs a DB read (integration_configs).
    # Closed right after so we don't hold the connection open across the
    # full specialist loop — provider lookup is the only DB work here.
    conn = await asyncpg.connect(_normalize_dsn(DATABASE_URL))
    try:
        integration_configs = await fetch_integration_configs(conn)
        provider_info = resolve_provider(integration_configs)
    finally:
        await conn.close()

    if provider_info is None:
        return {
            "target": target,
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

    try:
        adapter = build_adapter(provider_info)
    except LLMProviderError as e:
        return {
            "target": target,
            "findings": [],
            "specialists_run": [],
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": "error",
            "error": f"LLM adapter init failed: {e}",
            "scanner": "agent",
            "llm_provider": provider_info.provider,
            "llm_model": provider_info.model,
        }

    headers = _credentials_to_headers(credentials)

    # Adhoc has no DB-backed endpoint slice — seed the synthetic base
    # row so the specialists can start probing (and harvest HTML forms
    # on their first tool call).
    ctx = AgentContext(
        asset_id="adhoc",
        org_id=org_id,
        target=target,
        endpoints=seed_base_endpoint([], target),
        headers=headers,
        deadline=start + SCAN_TIMEOUT_SECONDS,
    )
    _seed_scan_config_capability(ctx, credentials)

    selected = select_applicable_specialists(ctx, categories)
    if not selected:
        return {
            "target": target,
            "org_id": org_id,
            "findings": [],
            "specialists_run": [],
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": "skipped",
            "error": "no applicable specialists for adhoc target (empty endpoint set)",
            "scanner": "agent",
        }

    logger.info(
        "agent_worker adhoc start target=%s specialists=%s",
        target, [s.category for s in selected],
    )

    findings: list[dict] = []
    specialists_run: list[dict] = []

    scheduler = FrontierScheduler(specialists=selected)
    adapter_map = _build_adapter_map(
        selected, integration_configs, adapter, provider_info,
    )

    with httpx.Client(verify=False, follow_redirects=False) as sync_client:
        ctx.http_client = sync_client
        while True:
            scheduled = scheduler.next(ctx)
            if scheduled is None:
                break
            spec = scheduled.spec
            spec_adapter = adapter_map.get(spec.category, adapter)

            spec_start = time.monotonic()
            spec_deadline = min(ctx.deadline, spec_start + SPECIALIST_TIMEOUT_SECONDS)

            try:
                spec_findings, iterations, stop_reason = await _run_specialist(
                    spec=spec, ctx=ctx, deadline=spec_deadline, adapter=spec_adapter,
                )
            except LLMProviderError as e:
                return {
                    "target": target,
                    "org_id": org_id,
                    "findings": findings,
                    "specialists_run": specialists_run + [{
                        "category": spec.category, "status": "error", "reason": str(e),
                        "run_number": scheduled.run_number,
                        "scheduler_reason": scheduled.reason,
                    }],
                    "duration_seconds": round(time.monotonic() - start, 2),
                    "status": "error",
                    "error": f"LLM provider error: {e}",
                    "scanner": "agent",
                    "llm_provider": provider_info.provider,
                    "llm_model": provider_info.model,
                }
            except Exception as e:
                logger.exception("specialist %s crashed for adhoc target %s", spec.category, target)
                specialists_run.append({
                    "category": spec.category, "status": "error",
                    "reason": str(e)[:200], "iterations": 0,
                    "run_number": scheduled.run_number,
                    "scheduler_reason": scheduled.reason,
                })
                continue

            findings.extend(spec_findings)
            specialists_run.append({
                "category": spec.category,
                "status": stop_reason,
                "iterations": iterations,
                "findings": len(spec_findings),
                "duration_seconds": round(time.monotonic() - spec_start, 2),
                "run_number": scheduled.run_number,
                "scheduler_reason": scheduled.reason,
            })

    return {
        "target": target,
        "org_id": org_id,
        "findings": findings,
        "specialists_run": specialists_run,
        "capabilities": ctx.capabilities.summarize(),
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

    # Tag any capability this specialist produces with its category so
    # provenance chains stay intact across the full asset run. The
    # outer loop overwrites this before the next specialist starts, and
    # ctx is discarded once the asset finishes, so there's no need to
    # clear it explicitly.
    ctx.current_specialist = spec.category

    # Refresh identity headers from the capability store BEFORE building
    # the initial message so AUTH_HEADERS_PROVIDED reflects the real
    # headers the specialist's http_request calls will carry. Returns
    # the names of any headers we injected; the audit log records them
    # so scan traces show the moment composition unlocked auth.
    injected_auth = _apply_discovered_identity(ctx)
    if injected_auth:
        logger.info(
            "specialist %s: injected auth from capability store: %s",
            spec.category, injected_auth,
        )

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


def _composition_hints(ctx: AgentContext) -> list[str]:
    """Return prompt-ready bullets describing how to use typed capabilities.

    Short, targeted, capability-conditional. Each hint is one line and
    tells the model the *actionable* consequence of a primitive (not
    what the primitive is — that's in the CAPABILITIES block). Silent
    when nothing applies so baseline-run prompts stay lean.

    Kept separate from the specialist system prompts so composition
    behaviour evolves in one place: adding a new capability type with
    an associated probe strategy is a single edit here rather than
    seven prompt surgeries.
    """
    from scanner.vm.capabilities import CapabilityType, asset_scope

    scope = asset_scope(ctx.asset_id)
    hints: list[str] = []

    has_cred = bool(ctx.capabilities.query(type=CapabilityType.CRED, scope=scope))
    has_session = bool(ctx.capabilities.query(type=CapabilityType.SESSION, scope=scope))
    if has_cred or has_session:
        hints.append(
            "- Authentication primitives are available. Your http_request "
            "calls already carry the right Authorization/Cookie headers — "
            "treat every probe as authenticated unless you deliberately "
            "strip auth. Spend this run on endpoints that REJECT anonymous "
            "traffic (admin/, /api/me, /settings, /account/*) — these "
            "weren't testable in earlier runs and are where the highest-"
            "yield post-auth bugs live."
        )

    if ctx.capabilities.query(type=CapabilityType.IDENTIFIER, scope=scope):
        hints.append(
            "- IDENTIFIER primitives list concrete user/resource IDs leaked "
            "earlier. For IDOR / authz diffing, use these as the 'other' "
            "identity instead of guessing id±1 — they're guaranteed to "
            "exist and to belong to a different principal."
        )

    if ctx.capabilities.query(type=CapabilityType.INTERNAL_HOST, scope=scope):
        hints.append(
            "- INTERNAL_HOST primitives list routable internal services "
            "reachable via server-side fetch. For SSRF follow-up, target "
            "these concrete hosts (with port) rather than fuzzing "
            "127.0.0.1/localhost aliases."
        )

    if ctx.capabilities.query(type=CapabilityType.WEB_ROOT, scope=scope):
        hints.append(
            "- WEB_ROOT primitive reveals the server's filesystem layout. "
            "Use the absolute path to craft precise LFI / SSTI payloads "
            "(e.g. include application config files at known paths) "
            "rather than ../../.. traversal guesses."
        )

    return hints


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

    # Surface what earlier specialists stashed via memory_set. Strip
    # internal bookkeeping keys (leading underscore) so the model only
    # sees actionable hints, not our OOB token list.
    visible_memory = {
        k: v for k, v in ctx.shared_memory.items() if not k.startswith("_")
    }

    # Typed capabilities from earlier specialists. Rendered alongside
    # (not replacing) MEMORY so existing prompts keep working and typed
    # primitives gain structured visibility. Notes are excluded — the
    # MEMORY block already shows them in their original string form.
    typed_caps = ctx.capabilities.summarize(include_notes=False)

    # Composition guidance — surface targeted advice for the specialist
    # when typed primitives exist that change how it should probe.
    # Kept out of per-specialist system prompts so adding a new typed
    # capability doesn't require editing seven prompt bodies, and so
    # the hint only appears when the capability is actually present
    # (avoids prompt noise on baseline runs).
    composition_hints = _composition_hints(ctx)

    lines = [
        f"SPECIALIST: {spec.display_name}",
        f"TARGET: {ctx.target}",
        f"ASSET_ID: {ctx.asset_id}",
        f"AUTH_HEADERS_PROVIDED: {sorted(ctx.headers.keys())}",
    ]
    if typed_caps:
        lines.extend([
            "",
            "CAPABILITIES (typed primitives discovered so far — each one is a confirmed fact you can build on):",
            json.dumps(typed_caps, indent=2),
        ])
    if composition_hints:
        lines.extend([
            "",
            "COMPOSITION GUIDANCE (how to exploit the capabilities above):",
            *composition_hints,
        ])
    if visible_memory:
        lines.extend([
            "",
            "MEMORY (from earlier specialists on this asset — trust these hints, they're concrete facts not guesses):",
            json.dumps(visible_memory, indent=2),
        ])
    lines.extend([
        "",
        f"ENDPOINTS (first {len(ep_slice)} of {len(ctx.endpoints)}):",
        json.dumps(ep_slice, indent=2),
        "",
        "Begin. Use tools to probe. Call emit_finding for every confirmed vuln. Call summary when done.",
    ])
    return "\n".join(lines)


# Expose AGENT_CATEGORIES at module level so callers can introspect the
# set without importing from agent_specialists directly.
__all__ = [
    "run_agent_scan",
    "run_agent_scan_adhoc",
    "AGENT_CATEGORIES",
    "_agent_payload_to_finding",
    "_credentials_to_headers",
]
