"""ReAct loop for credentialed protocol audits.

Trimmed port of ``backend/agents/agent_engine.py``. Drops:

  - SQLAlchemy ORM access (``Agent`` / ``AgentRun`` / ``AgentApproval``)
    — run state is held in memory and returned in the Celery result,
    same shape as the VM scanner. Backend wraps the Celery dispatch
    with ``AgentRun`` bookkeeping.
  - ``core.llm_router`` / ``core.token_quota`` — replaced by
    ``llm_provider.build_adapter`` and a free-running token counter
    that just logs.
  - Streaming SSE — phase 2; OSS callers poll Celery state.
  - Approval gates — single-asset audits don't pause for human
    approval, and a CLI-driven OSS user wouldn't see the prompt.

Tool registration mirrors the backend's ``@agent_tool`` decorator so
the protocol tool files port over with mechanical edits — only the
``models.models`` / ``services.*`` imports change. The tool handler
signature is ``(ctx: AuditContext, params: dict) -> dict``; the old
``(db, params)`` signature is replaced because the OSS scanner has no
SQLAlchemy session to hand around.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Callable

from scanner.audit.agent_context import AuditContext, compress_tool_result
from scanner.audit.config import (
    AUDIT_DEFAULT_MAX_STEPS,
    AUDIT_DEFAULT_WALLCLOCK_S,
    AUDIT_MAX_TOKENS_PER_TURN,
)
from scanner.audit.llm_provider import (
    LLMAdapter,
    LLMProviderError,
)
from scanner.audit.publisher import event as _ev
from scanner.audit.quota import QuotaExceeded

logger = logging.getLogger(__name__)


# ── Tool registry ────────────────────────────────────────────────


class _RegisteredTool:
    __slots__ = ("name", "description", "parameters", "handler")

    def __init__(self, name: str, description: str, parameters: dict, handler: Callable):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler


TOOL_REGISTRY: dict[str, _RegisteredTool] = {}


def agent_tool(name: str, description: str, parameters: dict):
    """Register a tool in ``TOOL_REGISTRY``.

    Decorated functions take ``(ctx: AuditContext, params: dict)`` and
    return a JSON-serialisable dict. The decorator preserves the
    underlying callable so handlers can still be unit-tested directly.
    """

    def decorator(fn: Callable) -> Callable:
        if name in TOOL_REGISTRY:
            logger.warning("agent_tool: %r registered twice — overriding", name)
        TOOL_REGISTRY[name] = _RegisteredTool(
            name=name,
            description=description,
            parameters=parameters,
            handler=fn,
        )
        return fn

    return decorator


def get_claude_tool_schemas(tool_names: list[str]) -> list[dict]:
    """Return Anthropic-shape ``tools`` schemas for the named tools.

    The ``llm_provider`` adapter pipes these straight into the SDK, then
    the OpenAI / Gemini adapters convert them to provider-native format
    via ``_anthropic_to_openai_messages`` etc. So the engine only ever
    speaks Anthropic shape — same convention as the VM scanner.
    """
    schemas: list[dict] = []
    for tname in tool_names:
        tool = TOOL_REGISTRY.get(tname)
        if tool is None:
            logger.warning("get_claude_tool_schemas: unknown tool %r — skipping", tname)
            continue
        schemas.append({
            "name": tool.name,
            "description": tool.description,
            "input_schema": {
                "type": "object",
                "properties": tool.parameters,
                "required": list(tool.parameters.keys()),
            },
        })
    return schemas


# ── Run loop ─────────────────────────────────────────────────────


async def run_audit(
    *,
    ctx: AuditContext,
    adapter: LLMAdapter,
    system_prompt: str,
    initial_user_message: str,
    tool_names: list[str],
    max_steps: int | None = None,
    wallclock_s: int | None = None,
) -> dict:
    """Execute one ReAct audit run end-to-end.

    Returns ``{"steps": [...], "findings": [...], "stop_reason": ...,
    "iterations": int}``. The Celery worker wraps this with provider
    metadata, asset id, and timing — keeps this function adapter- and
    persistence-agnostic so it's unit-testable with a stub adapter.
    """
    cap = max_steps or AUDIT_DEFAULT_MAX_STEPS
    deadline = time.monotonic() + (wallclock_s or AUDIT_DEFAULT_WALLCLOCK_S)

    tool_schemas = get_claude_tool_schemas(tool_names)
    messages: list[dict] = [{"role": "user", "content": initial_user_message}]

    iterations = 0
    stop_reason = "iterations"
    total_input_tokens = 0
    total_output_tokens = 0

    publisher = ctx.publisher
    quota = ctx.quota

    publisher.publish(ctx.run_id, _ev(
        "run_start", ctx.run_id,
        protocol=ctx.protocol, mission=ctx.mission_key,
        target=ctx.target, asset_id=ctx.asset.get("id") if ctx.asset else None,
        max_steps=cap, tool_count=len(tool_schemas),
    ))

    while iterations < cap:
        if time.monotonic() >= deadline:
            stop_reason = "deadline"
            break

        iterations += 1

        # Quota check is BEFORE the LLM call so we don't consume the
        # turn's tokens just to discover the org is over-limit. The
        # backend's SqlAlchemyQuotaProvider raises immediately; the
        # engine catches and exits with a structured stop_reason.
        try:
            quota.check(ctx.org_id)
        except QuotaExceeded as e:
            stop_reason = "quota_exceeded"
            publisher.publish(ctx.run_id, _ev(
                "run_end", ctx.run_id,
                stop_reason=stop_reason, iterations=iterations - 1, error=str(e),
            ))
            return {
                "steps": ctx.steps, "findings": ctx.findings,
                "stop_reason": stop_reason, "iterations": iterations - 1,
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
                "error": str(e),
            }

        publisher.publish(ctx.run_id, _ev("thinking", ctx.run_id, iteration=iterations))

        try:
            turn = await asyncio.to_thread(
                adapter.turn,
                system=system_prompt,
                messages=messages,
                tools=tool_schemas,
                max_tokens=AUDIT_MAX_TOKENS_PER_TURN,
            )
        except LLMProviderError as e:
            stop_reason = "llm_error"
            ctx.steps.append({"iteration": iterations, "error": str(e)})
            publisher.publish(ctx.run_id, _ev(
                "run_end", ctx.run_id, stop_reason=stop_reason, iterations=iterations, error=str(e),
            ))
            break

        # Record usage AFTER the call returned — even partial responses
        # spent tokens. Anthropic includes usage on every successful
        # response; OpenAI sometimes returns null on streamed tool-use
        # responses (we use sync, so usage is present).
        usage = turn.get("usage") or {}
        in_t = int(usage.get("input_tokens") or 0)
        out_t = int(usage.get("output_tokens") or 0)
        total_input_tokens += in_t
        total_output_tokens += out_t
        try:
            quota.record(ctx.org_id, in_t, out_t)
        except Exception:
            # Recording failure must NOT abort the run — the org is
            # already over its accounting boundary; better to complete
            # the audit and let the next ``check`` block the next run.
            logger.exception("quota.record failed (run=%s)", ctx.run_id)

        assistant_content = turn["content"]
        messages.append({"role": "assistant", "content": assistant_content})

        tool_uses = [b for b in assistant_content if b.get("type") == "tool_use"]
        text_blocks = [b.get("text", "") for b in assistant_content if b.get("type") == "text"]
        text_combined = " ".join(t for t in text_blocks if t)[:2000] or None

        ctx.steps.append({
            "iteration": iterations,
            "text": text_combined,
            "tool_calls": [{"name": b.get("name"), "input": b.get("input")} for b in tool_uses],
            "input_tokens": in_t,
            "output_tokens": out_t,
        })

        if text_combined:
            publisher.publish(ctx.run_id, _ev(
                "text", ctx.run_id, iteration=iterations, text=text_combined,
            ))

        if not tool_uses:
            stop_reason = "end_turn"
            publisher.publish(ctx.run_id, _ev(
                "run_end", ctx.run_id,
                stop_reason=stop_reason, iterations=iterations,
                input_tokens=total_input_tokens, output_tokens=total_output_tokens,
            ))
            break

        tool_results_content: list[dict] = []
        findings_before = len(ctx.findings)
        for block in tool_uses:
            tname = block.get("name") or ""
            tparams = block.get("input") or {}
            use_id = block.get("id") or ""

            publisher.publish(ctx.run_id, _ev(
                "tool_call", ctx.run_id, iteration=iterations,
                name=tname, input=_redact_input(tname, tparams),
            ))

            tool = TOOL_REGISTRY.get(tname)
            if tool is None:
                err = {"error": f"unknown tool {tname!r}"}
                publisher.publish(ctx.run_id, _ev(
                    "tool_result", ctx.run_id, iteration=iterations,
                    name=tname, error=err["error"],
                ))
                tool_results_content.append({
                    "type": "tool_result",
                    "tool_use_id": use_id,
                    "content": json.dumps(err),
                    "is_error": True,
                })
                continue

            try:
                if asyncio.iscoroutinefunction(tool.handler):
                    raw_result = await tool.handler(ctx, tparams)
                else:
                    raw_result = await asyncio.to_thread(tool.handler, ctx, tparams)
            except Exception as e:
                logger.exception("tool %s raised", tname)
                raw_result = {"error": f"tool handler raised: {e}"}

            compressed = compress_tool_result(tname, raw_result)
            tool_results_content.append({
                "type": "tool_result",
                "tool_use_id": use_id,
                "content": json.dumps(compressed, default=str)[:8_000],
            })

            publisher.publish(ctx.run_id, _ev(
                "tool_result", ctx.run_id, iteration=iterations,
                name=tname, preview=_preview(compressed),
            ))

        # Any new findings emitted during this turn — surface each so
        # the live viewer can render them as they appear.
        for f in ctx.findings[findings_before:]:
            publisher.publish(ctx.run_id, _ev("finding", ctx.run_id, finding=f))

        messages.append({"role": "user", "content": tool_results_content})

    if stop_reason == "iterations":
        publisher.publish(ctx.run_id, _ev(
            "run_end", ctx.run_id,
            stop_reason=stop_reason, iterations=iterations,
            input_tokens=total_input_tokens, output_tokens=total_output_tokens,
        ))
    elif stop_reason == "deadline":
        publisher.publish(ctx.run_id, _ev(
            "run_end", ctx.run_id,
            stop_reason=stop_reason, iterations=iterations,
            input_tokens=total_input_tokens, output_tokens=total_output_tokens,
        ))

    return {
        "steps": ctx.steps,
        "findings": ctx.findings,
        "stop_reason": stop_reason,
        "iterations": iterations,
        "input_tokens": total_input_tokens,
        "output_tokens": total_output_tokens,
    }


# ── Streaming helpers ────────────────────────────────────────────


_REDACT_KEYS = {"password", "private_key", "private_key_passphrase", "token", "api_key", "secret"}


def _redact_input(tool_name: str, params: dict) -> dict:
    """Strip credential-like keys before publishing tool_call events.

    Tool params shouldn't contain credentials in practice — credentials
    flow on AuditContext, not as LLM-provided arguments — but a poorly
    designed tool could expose them. Defensive: drop anything that
    looks secret. Only the published event is redacted; the engine
    still hands the full params to the tool handler.
    """
    if not isinstance(params, dict):
        return {}
    out = {}
    for k, v in params.items():
        if isinstance(k, str) and any(s in k.lower() for s in _REDACT_KEYS):
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def _preview(result: Any, limit: int = 600) -> str:
    """Short string preview of a tool result, suitable for SSE.

    The full result still flows back to the LLM via the tool_results
    block — this is just for the live viewer's per-tool collapsed
    summary."""
    try:
        s = json.dumps(result, default=str)
    except Exception:
        s = str(result)
    if len(s) > limit:
        return s[:limit] + "..."
    return s
