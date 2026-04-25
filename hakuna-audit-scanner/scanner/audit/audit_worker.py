"""Celery task that runs one credentialed protocol audit.

Mirrors hakuna-vm-scanner/scanner/vm/agent_worker.py:

  1. Open one asyncpg connection.
  2. Read integration_configs to resolve the LLM provider.
  3. Read the asset row + the credential row for context.
  4. Close the connection (held only for context fetch).
  5. Build the LLM adapter.
  6. Run the ReAct loop via ``audit_engine.run_audit``.
  7. Return ``{findings, steps, status, ...}`` in the Celery payload.

Backend ingest (``services.audit_runner._import_audit_findings``)
reads ``findings`` off the result and inserts rows into the
``findings`` table — the worker never writes to that table directly.
This keeps the OSS scanner schema-coupling-free and reuses the same
ingest path the VM scanner uses for nuclei findings.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any

import asyncpg

# Side-effect import: registers protocol tools and audits.
from scanner.audit import tools as _registered_tools  # noqa: F401
from scanner.audit.agent_context import AuditContext, build_context_section
from scanner.audit.audit_engine import run_audit
from scanner.audit.audit_registry import AUDITS, get_audit
from scanner.audit.celery_app import celery_app
from scanner.audit.config import (
    AUDIT_DEFAULT_MAX_STEPS,
    AUDIT_DEFAULT_WALLCLOCK_S,
    DATABASE_URL,
    REDIS_PUBSUB_URL,
)
from scanner.audit.db import _normalize_dsn, get_pool
from scanner.audit.llm_provider import (
    LLMProviderError,
    build_adapter,
    fetch_integration_configs,
    resolve_provider,
    resolve_specific_provider,
)
from scanner.audit.publisher import make_publisher
from scanner.audit.quota import QuotaExceeded, get_provider as get_quota_provider
from scanner.audit.relay_client import get_transport as get_relay_transport

logger = logging.getLogger(__name__)


# ── SQL — same shape as VM scanner's ASSET_CONTEXT_QUERY ──────────


_ASSET_CONTEXT_QUERY = """
    SELECT
        a.id, a.org_id, a.hostname, a.fqdn, a.ip,
        a.os, a.open_ports, a.easm_data
    FROM assets a
    WHERE a.id = $1
"""

# Reads the encrypted credential blob. Decryption is the caller's
# responsibility — the backend's ``services.audit_runner`` decrypts
# via the credential vault before dispatching the Celery task and
# passes plaintext in the ``credentials`` arg, exactly the way the
# VM scanner consumes ``ScanCredentials``. OSS users running this
# package standalone supply a plaintext dict from a YAML mission file.
_CREDENTIAL_QUERY = """
    SELECT id, connector_id, encrypted_data
    FROM integration_credentials
    WHERE id = $1 AND org_id = $2
"""


# ── Celery task ───────────────────────────────────────────────────


@celery_app.task(queue="audit_queue", bind=True, max_retries=0)
def run_audit_scan(
    self,
    *,
    asset_id: str,
    protocol: str,
    mission_key: str,
    credentials: dict,
    relay_agent_id: str | None = None,
    credential_id: str | None = None,
    max_steps: int | None = None,
    wallclock_s: int | None = None,
    model_override: str | None = None,
    org_id: str | None = None,
) -> dict:
    """Entry point. Backend dispatches with ``credentials`` already
    resolved from the vault — same contract as VM scanner's
    ``run_agent_scan``."""
    try:
        return _run_async(_run_audit_scan_async(
            asset_id=asset_id,
            protocol=protocol,
            mission_key=mission_key,
            credentials=credentials,
            relay_agent_id=relay_agent_id,
            credential_id=credential_id,
            max_steps=max_steps,
            wallclock_s=wallclock_s,
            model_override=model_override,
            org_id=org_id,
        ))
    except Exception as exc:
        logger.exception("run_audit_scan failed for asset %s", asset_id)
        return {
            "asset_id": asset_id,
            "protocol": protocol,
            "mission": mission_key,
            "findings": [],
            "steps": [],
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
            "scanner": "audit",
        }


def _run_async(coro):
    """Run coroutine in a fresh loop and drain finalisers.

    Same shape as VM scanner's _run_async — google-genai's BaseApiClient
    schedules aclose() on __del__, so we GC + drain pending tasks before
    closing the loop to avoid 'Task was destroyed but it is pending'.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            import gc
            gc.collect()
            pending = asyncio.all_tasks(loop)
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()


async def _run_audit_scan_async(
    *,
    asset_id: str,
    protocol: str,
    mission_key: str,
    credentials: dict,
    relay_agent_id: str | None,
    credential_id: str | None,
    max_steps: int | None,
    wallclock_s: int | None,
    model_override: str | None,
    org_id: str | None,
) -> dict:
    start = time.monotonic()
    run_id = str(uuid.uuid4())

    audit = AUDITS.get(protocol)
    if audit is None:
        return _skip(asset_id, protocol, mission_key, start,
                     f"unknown protocol {protocol!r}; registered: {sorted(AUDITS.keys())}")

    mission = audit.mission(mission_key)
    if mission is None:
        return _skip(asset_id, protocol, mission_key, start,
                     f"unknown mission {mission_key!r} for protocol {protocol!r}")

    # ── 1+2+3: provider lookup + asset row ────────────────────────
    conn = await asyncpg.connect(_normalize_dsn(DATABASE_URL))
    try:
        integration_configs = await fetch_integration_configs(conn)
        provider_info = (
            resolve_specific_provider(
                _provider_for_model(model_override),
                integration_configs,
                model_override=model_override,
            )
            if model_override
            else resolve_provider(integration_configs)
        )
        if provider_info is None:
            return _skip(asset_id, protocol, mission_key, start,
                         "no LLM provider configured — set ANTHROPIC_API_KEY, "
                         "OPENAI_API_KEY, GOOGLE_CLOUD_PROJECT (vertex_ai), "
                         "GOOGLE_API_KEY (gemini), GROQ_API_KEY, or enable Ollama")

        try:
            asset_row = await conn.fetchrow(_ASSET_CONTEXT_QUERY, _to_uuid(asset_id))
        except Exception as e:
            return _error(asset_id, protocol, mission_key, start, f"asset query failed: {e}")
        if asset_row is None:
            return _skip(asset_id, protocol, mission_key, start, "asset not found")
    finally:
        await conn.close()

    # ── 4: build adapter ──────────────────────────────────────────
    try:
        adapter = build_adapter(provider_info)
    except LLMProviderError as e:
        return _error(asset_id, protocol, mission_key, start,
                      f"LLM adapter init failed: {e}",
                      provider=provider_info.provider, model=provider_info.model)

    # ── 5: build run context ──────────────────────────────────────
    asset = dict(asset_row)
    target = asset.get("fqdn") or asset.get("hostname") or asset.get("ip") or ""
    open_ports = asset.get("open_ports") or []

    # Preflight — bail when required ports are clearly not open. Empty
    # open_ports means "never scanned", which we treat conservatively
    # (skip the check, dispatch as usual). Same semantics as backend
    # services.audit_runner.
    if audit.required_ports and open_ports:
        if not any(p in open_ports for p in audit.required_ports):
            return _skip(asset_id, protocol, mission_key, start,
                         f"required ports {audit.required_ports} not open on asset")

    # Publisher, quota, and transport are resolved from module-level
    # singletons (or constructed here for the publisher because it
    # needs the run-level Redis URL). Backend overrides via
    # ``set_provider`` / ``set_transport`` before workers boot — same
    # pattern Celery itself uses for its result backend.
    publisher = make_publisher(REDIS_PUBSUB_URL)
    quota = get_quota_provider()
    relay_transport = get_relay_transport()

    # Pre-emptive quota check — blocks the run before adapter init when
    # the org is already over. Avoids paying for SDK construction +
    # ADC token fetch on a doomed run.
    try:
        quota.check(str(asset.get("org_id")) if asset.get("org_id") else org_id)
    except QuotaExceeded as e:
        return _skip(asset_id, protocol, mission_key, start, f"quota exceeded: {e}")

    ctx = AuditContext(
        run_id=run_id,
        agent_id=run_id,  # OSS runs have no persistent Agent record; reuse run_id
        org_id=str(asset.get("org_id")) if asset.get("org_id") else org_id,
        asset=asset,
        target=str(target),
        target_port=None,
        relay_agent_id=relay_agent_id,
        credential_id=credential_id,
        credentials=credentials or {},
        protocol=protocol,
        mission_key=mission_key,
        relay_transport=relay_transport,
        publisher=publisher,
        quota=quota,
        db_pool=await get_pool(),
    )

    # ── 6: load mission prompt + run loop ─────────────────────────
    system_prompt = _resolve_mission_prompt(mission.prompt_key, ctx)
    initial_user_message = _initial_message_for(audit.protocol, asset)

    try:
        result = await run_audit(
            ctx=ctx,
            adapter=adapter,
            system_prompt=system_prompt,
            initial_user_message=initial_user_message,
            tool_names=list(audit.tool_names),
            max_steps=max_steps or mission.suggested_budget or AUDIT_DEFAULT_MAX_STEPS,
            wallclock_s=wallclock_s or audit.default_wallclock_s or AUDIT_DEFAULT_WALLCLOCK_S,
        )
    except Exception as e:
        logger.exception("audit loop crashed")
        return _error(asset_id, protocol, mission_key, start, f"audit loop crashed: {e}",
                      provider=provider_info.provider, model=provider_info.model)

    return {
        "asset_id": str(asset_id),
        "org_id": ctx.org_id,
        "protocol": protocol,
        "mission": mission_key,
        "target": ctx.target,
        "findings": result["findings"],
        "steps": result["steps"],
        "iterations": result["iterations"],
        "stop_reason": result["stop_reason"],
        "input_tokens": result.get("input_tokens", 0),
        "output_tokens": result.get("output_tokens", 0),
        "duration_seconds": round(time.monotonic() - start, 2),
        "status": "ok" if result["stop_reason"] != "quota_exceeded" else "quota_exceeded",
        "scanner": "audit",
        "llm_provider": provider_info.provider,
        "llm_model": provider_info.model,
    }


# ── Helpers ───────────────────────────────────────────────────────


def _to_uuid(value: Any) -> Any:
    """Pass through if already a UUID; coerce strings; let asyncpg
    raise on integers (assets.id is uuid in the canonical schema)."""
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, str):
        try:
            return uuid.UUID(value)
        except ValueError:
            return value
    return value


def _provider_for_model(model_id: str | None) -> str:
    """Coarse mapping from model id to provider name.

    Matches the backend's PROVIDER_FOR_MODEL table well enough for the
    OSS scanner — full disambiguation lives upstream in the dispatcher.
    """
    m = (model_id or "").lower()
    if m.startswith("claude-"):
        return "anthropic"
    if m.startswith("gpt-") or m.startswith("o1") or m.startswith("o3"):
        return "openai"
    if m.startswith("vertex/") or m.startswith("gemini-"):
        return "vertex_ai" if m.startswith("vertex/") else "google_gemini"
    if m.startswith("llama-") or "groq" in m:
        return "groq"
    if m.startswith("ollama/"):
        return "ollama"
    return "anthropic"


def _resolve_mission_prompt(prompt_key: str, ctx: AuditContext) -> str:
    """Look up the mission prompt.

    Phase 1: only the YAML mission loader populates the cache. Phase 2:
    add a fallback to ENHANCED_PROMPTS if we end up porting the
    backend's prompt module wholesale. Today, an unknown key returns a
    generic credentialed-audit instruction so the engine still runs.
    """
    from scanner.audit.mission_loader import get_prompt  # lazy to avoid cold start cost

    prompt = get_prompt(prompt_key)
    if prompt:
        return prompt + build_context_section(ctx.agent_id)

    logger.warning("mission prompt %r not found; using generic system prompt", prompt_key)
    return (
        "You are a credentialed protocol auditor running against a single "
        f"{ctx.protocol} target ({ctx.target}). Use only the read-only tools "
        "in your palette to enumerate posture, identify weaknesses, and emit "
        "findings via emit_finding. Stop when you have enough evidence."
    ) + build_context_section(ctx.agent_id)


def _initial_message_for(protocol: str, asset: dict) -> str:
    return (
        f"Audit asset {asset.get('id')} via {protocol}. "
        f"Target: {asset.get('fqdn') or asset.get('hostname') or asset.get('ip')}. "
        f"OS hint: {asset.get('os') or 'unknown'}. "
        "Begin by gathering orientation information, then proceed through your mission checklist."
    )


def _skip(asset_id, protocol, mission_key, start, reason: str) -> dict:
    return {
        "asset_id": str(asset_id),
        "protocol": protocol,
        "mission": mission_key,
        "findings": [],
        "steps": [],
        "duration_seconds": round(time.monotonic() - start, 2),
        "status": "skipped",
        "error": reason,
        "scanner": "audit",
    }


def _error(asset_id, protocol, mission_key, start, reason: str, **extra) -> dict:
    out = {
        "asset_id": str(asset_id),
        "protocol": protocol,
        "mission": mission_key,
        "findings": [],
        "steps": [],
        "duration_seconds": round(time.monotonic() - start, 2),
        "status": "error",
        "error": reason,
        "scanner": "audit",
    }
    out.update(extra)
    return out
