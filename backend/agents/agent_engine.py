"""
Mini Agent Execution Engine — runs user-defined agents using multiple LLM providers with tool use.

Supported providers: Anthropic (Claude), OpenAI (GPT), Google (Gemini), Groq (Llama/Mixtral),
Ollama (local models), Google Vertex AI (GCP-native Gemini).
"""
import os
import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from hakuna.utils.token_tracker import get_tracker
from hakuna.utils.context_manager import rolling_context
from core.database import SessionLocal
from core.token_quota import check_token_quota, increment_token_usage
from core.llm_router import router as llm_router, PROVIDER_FOR_MODEL

from models.models import Agent, AgentRun, AgentApproval, IntegrationConfig
from agents.agent_tools import (
    TOOL_REGISTRY, get_claude_tool_schemas, get_openai_tool_schemas,
    NeedsApproval,
)
from agents.agent_context import compress_tool_result, build_context_section

logger = logging.getLogger(__name__)


# ── Router-backed shims ───────────────────────────────────────────────
#
# Provider/model resolution and client construction live in
# ``core.llm_router``. The wrappers below exist so callers that already
# import these names from agent_engine don't all have to change at once.
# New code should import ``core.llm_router.router`` directly.

def detect_provider(model: str) -> str:
    return llm_router.detect_provider(model)


def _get_anthropic_client(db: Session, model: str | None = None):
    return llm_router.get_anthropic_client(db, model)


def _get_openai_client(db: Session):
    return llm_router.get_openai_client(db)


def _get_gemini_client(db: Session):
    return llm_router.get_gemini_client(db)


def _get_groq_client(db: Session):
    return llm_router.get_groq_client(db)


def _get_ollama_client(db: Session):
    return llm_router.get_ollama_client(db)


def _get_vertex_client(db: Session):
    return llm_router.get_vertex_client(db)


def get_available_providers(db: Session) -> list:
    return llm_router.get_available_providers(db)


def get_default_model(db: Session) -> str:
    return llm_router.get_default_model(db)


def _find_fallback_model(db: Session, exclude_providers: set, *, tool_count: int = 0) -> Optional[tuple]:
    # Called from the primary-dispatch error handler, where `db` may have a
    # broken transaction (Cloud SQL reaping the connection while a long LLM
    # HTTP call held the session). Rollback defensively and issue the lookup
    # on a fresh session so we don't cascade into PendingRollbackError.
    try:
        db.rollback()
    except Exception:
        logger.warning("Rollback before fallback lookup failed; using fresh session anyway", exc_info=True)
    with SessionLocal() as fallback_db:
        return llm_router.find_fallback_model(fallback_db, exclude=exclude_providers, tool_count=tool_count)


def _validate_provider_configured(db: Session, provider: str):
    llm_router.validate_provider(db, provider)


# ── Shared helpers ────────────────────────────────────────────────────

# Max user input chars per provider (leave room for system prompt + tools schema)
_MAX_INPUT_CHARS = {
    "groq": 8_000,       # Groq on-demand tier is strict (~128k ctx but small request limits)
    "openai": 80_000,
    "anthropic": 150_000,
    "google_gemini": 150_000,
    "vertex_ai": 150_000,    # Same Gemini models, same context limits
    "ollama": 30_000,        # Conservative — depends on model and available VRAM
}
_TRUNCATION_NOTICE = "\n\n[Note: Input was truncated to fit model context limits.]"


def _truncate_user_input(user_input: str, provider: str) -> str:
    """Truncate user_input to stay within provider context limits."""
    limit = _MAX_INPUT_CHARS.get(provider, 80_000)
    if len(user_input) > limit:
        cutoff = limit - len(_TRUNCATION_NOTICE)
        return user_input[:cutoff] + _TRUNCATION_NOTICE
    return user_input


def _compress_openai_messages(messages: list, provider: str) -> list:
    """Rolling context compression for OpenAI-compat message history.

    Keeps system message + initial user message + last N exchanges to prevent
    unbounded token growth. For Groq, aggressive compression (3 exchanges) is
    applied because the on-demand tier has strict per-request token limits;
    exceeding them causes llama-3.3-70b to fall back to its native
    <function=name(args)> format, which Groq's validator rejects with a 400.

    An exchange = one assistant turn + its tool result messages.
    We always start at an assistant message to avoid splitting mid-exchange.
    """
    keep = 3 if provider in ("groq", "ollama") else 5  # exchanges to keep verbatim
    keep_msgs = keep * 2  # rough estimate: 1 assistant + 1 tool per exchange

    if len(messages) <= keep_msgs + 2:  # +2 for system + initial user
        return messages

    system_and_user = messages[:2]  # [system, user]
    recent = messages[-keep_msgs:]

    # Ensure we start at an assistant message (never mid-exchange)
    while recent and recent[0].get("role") != "assistant":
        recent = recent[1:]

    if not recent:
        return messages

    return system_and_user + recent


def _sanitize_messages(messages: list) -> list:
    """Deep-clean messages to strip SDK-injected properties like 'annotations' or 'citations'.

    The Anthropic SDK can inject extra fields into content blocks
    which the API then rejects on subsequent requests.
    """
    clean = json.loads(json.dumps(messages, default=str))
    STRIP_FIELDS = {"annotations", "citations"}
    for msg in clean:
        # Strip at message level
        for f in STRIP_FIELDS:
            msg.pop(f, None)
        # Strip at content block level
        if isinstance(msg.get("content"), list):
            for block in msg["content"]:
                if isinstance(block, dict):
                    for f in STRIP_FIELDS:
                        block.pop(f, None)
    logger.info("Sanitized messages: %s", json.dumps(clean, default=str)[:2000])
    return clean


_INTER_AGENT_PROTOCOL = (
    "\n\n## Inter-Agent Communication Protocol\n"
    "When producing output that will be consumed by another agent or system, "
    "use structured JSON. When producing output for a human user, use clear "
    "markdown with headers, tables, and bullet points.\n"
    "If you are unsure which tool to use or need more information, call the "
    "'request_clarification' tool instead of guessing."
)


def _build_system_prompt(agent: Agent) -> str:
    """Combine agent instructions with memory + scratchpad context."""
    parts = [agent.system_prompt]

    # Add context section (memory + scratchpad)
    ctx = build_context_section(agent.id, agent.memory)
    if ctx:
        parts.append(ctx)

    parts.append(_INTER_AGENT_PROTOCOL)

    return "\n".join(parts)


def _build_system_prompt_cached(agent: Agent) -> list:
    """Return system prompt as a list of content blocks with cache_control.

    Structure:
      Block 0 (cacheable): static role definition + inter-agent protocol
      Block 1 (dynamic, optional): scratchpad state + persistent memory

    The static block is marked cache_control=ephemeral so Anthropic caches it
    across subsequent steps in the same multi-step run, eliminating re-billing
    of the large (1300-1900 token) system prompt on every tool-use step.
    """
    # Static block: role definition + inter-agent protocol (never changes per-agent)
    static_text = agent.system_prompt + _INTER_AGENT_PROTOCOL

    blocks: list = [
        {
            "type": "text",
            "text": static_text,
            "cache_control": {"type": "ephemeral"},
        }
    ]

    # Dynamic block: memory + scratchpad (changes between runs)
    ctx = build_context_section(agent.id, agent.memory)
    if ctx:
        blocks.append({"type": "text", "text": ctx})

    return blocks


def _check_guardrails(agent: Agent, tool_name: str, step: int):
    """Enforce guardrails before a tool call. Raises ValueError on violation."""
    g = agent.guardrails or {}

    max_steps = g.get("max_steps", 15)
    if step >= max_steps:
        raise ValueError(f"Max steps ({max_steps}) exceeded")

    blocked = g.get("blocked_tools", [])
    if tool_name in blocked:
        raise ValueError(f"Tool '{tool_name}' is blocked by guardrails")

    read_only = g.get("read_only", False)
    write_tools = {
        "tag_assets", "update_finding_status", "bulk_tag_findings",
        "create_jira_ticket", "create_servicenow_ticket",
        "send_slack_message", "send_teams_message", "send_email_alert",
        "create_campaign", "create_exception", "create_tag",
        "create_auto_tag_rule", "run_auto_tag_rules", "send_webhook",
    }
    if read_only and tool_name in write_tools:
        raise ValueError(f"Tool '{tool_name}' is a write operation but agent is read-only")


def _coerce_params(params: dict, schema: dict) -> dict:
    """Coerce tool parameters to match their declared schema types.

    LLMs (especially Groq/Llama) often send integers as strings (e.g. "50"
    instead of 50), which breaks SQLAlchemy filters, min(), timedelta(), etc.
    This walks the schema and casts values to the declared type.
    """
    coerced = dict(params)
    for key, spec in schema.items():
        if key not in coerced or coerced[key] is None:
            continue
        val = coerced[key]
        declared_type = spec.get("type")
        try:
            if declared_type == "integer" and not isinstance(val, int):
                coerced[key] = int(val)
            elif declared_type == "number" and not isinstance(val, (int, float)):
                coerced[key] = float(val)
            elif declared_type == "boolean" and not isinstance(val, bool):
                coerced[key] = str(val).lower() in ("true", "1", "yes")
            elif declared_type == "array" and isinstance(val, list):
                item_spec = spec.get("items", {})
                item_type = item_spec.get("type")
                if item_type == "integer":
                    coerced[key] = [int(x) for x in val]
                elif item_type == "number":
                    coerced[key] = [float(x) for x in val]
        except (ValueError, TypeError):
            pass  # leave as-is; tool will handle or error naturally
    return coerced


def _execute_tool(agent: Agent, db: Session, tool_name: str, tool_input: Optional[dict], step: int, trace: list):
    tool_input = tool_input or {}
    """Execute a tool call and return the result string.

    Injects _agent_id for scratchpad tools and compresses output for LLM context.
    """
    import time as _time
    from services import llm_feedback

    started = _time.perf_counter()
    ok = True
    try:
        _check_guardrails(agent, tool_name, step)

        # Check confirmation requirement for destructive tools
        _check_confirmation(tool_name, tool_input)

        tool_def = TOOL_REGISTRY.get(tool_name)
        if not tool_def:
            result = {
                "error": f"Unknown tool: {tool_name}",
                "type": "tool_not_found",
                "available_tools": list(TOOL_REGISTRY.keys())[:20],
                "hint": "Call 'request_clarification' if you're unsure which tool to use.",
            }
            ok = False
        else:
            # Coerce params to match schema types (fixes LLMs sending "50" instead of 50)
            coerced_input = _coerce_params(tool_input, tool_def["parameters"])
            # Inject agent_id for scratchpad tools; merge any per-run context
            # the caller stashed in agent.memory["_run_ctx"] (protocol audits
            # use this to pass relay_agent_id / credential_id / mission to tools
            # without exposing them to the LLM's tool schema).
            run_ctx = (agent.memory or {}).get("_run_ctx") or {}
            enriched_input = {
                **run_ctx,
                **coerced_input,
                "_agent_id": agent.id,
                "_org_id": agent.org_id,
            }
            result = tool_def["fn"](db, enriched_input)
    except NeedsApproval:
        # Per-call approval — let the caller catch this and create an
        # AgentApproval record. Don't trace; the run is about to pause.
        raise
    except ValueError as e:
        result = {"error": str(e)}
        ok = False
    except Exception as e:
        logger.exception(f"Tool '{tool_name}' raised an unexpected error")
        result = {"error": f"Tool execution failed: {str(e)}"}
        ok = False

    # Guard against None results from tools
    if result is None:
        result = {"status": "ok", "note": "Tool returned no data"}

    # Compress result before adding to LLM context
    compressed = compress_tool_result(tool_name, result)

    trace.append({
        "role": "tool",
        "tool_name": tool_name,
        "input": {k: v for k, v in tool_input.items() if not k.startswith("_")},
        "output": compressed if isinstance(compressed, (str, int, float, bool)) else json.dumps(compressed, default=str)[:5000],
        "step": step,
    })

    # Feedback-loop: attach tool call to the active agent span (if any).
    llm_feedback.record_tool_call(
        name=tool_name,
        args={k: v for k, v in tool_input.items() if not k.startswith("_")},
        result=compressed,
        ok=ok,
        duration_ms=int((_time.perf_counter() - started) * 1000),
    )

    return json.dumps(compressed, default=str)


# Tools that require explicit confirmation before execution
CONFIRMATION_REQUIRED_TOOLS = {
    "create_jira_ticket", "create_servicenow_ticket",
    "send_slack_message", "send_teams_message", "send_email_alert",
    "create_campaign", "send_webhook",
    "update_finding_status", "create_exception",
    "call_integration_fetch", "call_integration_push",
    "build_report", "create_agent", "create_agent_schedule",
    # Validation-agent verdict writes — safe-probed context flows into the
    # finding's ctx_* fields and llm_validation JSON; requires human sign-off.
    "update_finding_validation",
}

# Tools gated by HITL approval (superset of confirmation-required tools)
HITL_TOOLS = CONFIRMATION_REQUIRED_TOOLS | {
    "tag_assets", "bulk_tag_findings", "create_tag", "create_auto_tag_rule", "run_auto_tag_rules",
}

# Low-risk write tools that can be auto-approved in "standard" autonomy mode
LOW_RISK_WRITE_TOOLS = {
    "tag_assets", "bulk_tag_findings", "create_tag", "create_auto_tag_rule",
    "run_auto_tag_rules", "update_finding_status", "build_report",
}

# Adaptive autonomy levels:
# - conservative: HITL approval for ALL write tools (current default)
# - standard: auto-approve low-risk writes (tagging, status updates, reports),
#             HITL for high-risk (tickets, notifications, campaigns, integrations)
# - autonomous: auto-approve everything except external integrations
#               (Jira, ServiceNow, Slack, Teams, Email, webhooks)
EXTERNAL_TOOLS = {
    "create_jira_ticket", "create_servicenow_ticket",
    "send_slack_message", "send_teams_message", "send_email_alert",
    "send_webhook", "call_integration_fetch", "call_integration_push",
}


def get_hitl_tools_for_autonomy(autonomy_level: str) -> set:
    """Return the set of tools requiring HITL approval for the given autonomy level."""
    if autonomy_level == "autonomous":
        return EXTERNAL_TOOLS
    elif autonomy_level == "standard":
        return HITL_TOOLS - LOW_RISK_WRITE_TOOLS
    else:  # conservative (default)
        return HITL_TOOLS


class ApprovalRequired(Exception):
    """Raised when a HITL agent tries to call a write tool that needs human approval."""
    def __init__(self, approval_id: int, tool_name: str):
        self.approval_id = approval_id
        self.tool_name = tool_name
        super().__init__(f"Approval required for tool '{tool_name}' (approval_id={approval_id})")


def _create_approval(
    agent: Agent,
    run: AgentRun,
    db: Session,
    tool_name: str,
    tool_input: dict,
    messages_snapshot: list,
    assistant_content: list,
    provider: str,
    model_name: str,
    current_step: int,
    tool_use_id: str,
) -> "AgentApproval":
    """Persist an AgentApproval record and raise ApprovalRequired."""
    approval = AgentApproval(
        org_id=agent.org_id,
        agent_run_id=run.id,
        agent_id=agent.id,
        tool_name=tool_name,
        tool_input=tool_input,
        messages_snapshot=messages_snapshot,
        assistant_content=assistant_content,
        provider=provider,
        model_name=model_name,
        current_step=current_step,
        tool_use_id=tool_use_id,
        status="pending",
    )
    db.add(approval)
    db.flush()  # get id without committing yet
    return approval


def _pause_for_per_call_approval(
    *,
    agent: Agent,
    run: AgentRun,
    db: Session,
    exc: NeedsApproval,
    tool_name: str,
    tool_input: dict,
    messages_snapshot: list,
    assistant_content: list,
    provider: str,
    model: str,
    step: int,
    tool_use_id: str,
    trace: list,
) -> None:
    """Persist a per-call approval and raise ApprovalRequired.

    The reason from the NeedsApproval exception is stashed inside tool_input
    under `_approval_reason` so the UI can surface it; the same payload also
    carries `_per_call=True` so resume logic knows to inject `_approved=True`
    on rerun. The tool body sees `_approved=True` and skips its classifier.
    """
    enriched_input = {
        **tool_input,
        "_approval_reason": exc.reason,
        "_approval_category": exc.category,
        "_approval_details": exc.details,
        "_per_call": True,
    }
    approval = _create_approval(
        agent=agent, run=run, db=db,
        tool_name=tool_name, tool_input=enriched_input,
        messages_snapshot=messages_snapshot,
        assistant_content=assistant_content,
        provider=provider, model_name=model,
        current_step=step, tool_use_id=tool_use_id,
    )
    run.status = "awaiting_approval"
    run.trace = trace
    db.commit()
    raise ApprovalRequired(approval.id, tool_name)


def _check_confirmation(tool_name: str, tool_input: dict):
    """Enforce confirmation for destructive/external-facing tools.

    Agents must pass confirmed=true to execute these tools.
    This prevents accidental ticket creation, notification spam, etc.
    """
    if tool_name not in CONFIRMATION_REQUIRED_TOOLS:
        return
    if not tool_input.get("confirmed"):
        raise ValueError(
            f"Tool '{tool_name}' requires explicit confirmation. "
            f"Set confirmed=true in the tool input after verifying the action with the user. "
            f"Do NOT auto-confirm destructive actions."
        )


# ── Provider-specific execution loops ─────────────────────────────────

def _run_anthropic(agent: Agent, user_input: str, db: Session, run: AgentRun, model: str):
    """Run agent using Anthropic Claude API — direct or via Vertex AI.

    The router picks between ``Anthropic(api_key=...)`` and
    ``AnthropicVertex(project_id=...)`` transparently; same
    ``messages.create`` interface either way. Vertex-prefixed model IDs
    need the prefix stripped before the SDK call.
    """
    trace = []
    user_input = _truncate_user_input(user_input, "anthropic")
    messages = [{"role": "user", "content": user_input}]
    # Use cached system prompt blocks: static role definition cached, dynamic context appended
    system = _build_system_prompt_cached(agent)
    tools = get_claude_tool_schemas(agent.tools or [])
    max_steps = (agent.guardrails or {}).get("max_steps", 15)

    cl = _get_anthropic_client(db, model)
    api_model = model.removeprefix("vertex/") if model.startswith("vertex/") else model

    for step in range(max_steps):
        # Apply rolling context compression after 5 turns to cap history size
        compressed_messages = rolling_context(messages, max_turns=5)

        create_kwargs = {
            "model": api_model,
            "max_tokens": 4096,
            "system": system,
            "messages": _sanitize_messages(compressed_messages),
        }
        if tools:
            create_kwargs["tools"] = tools

        try:
            response = cl.messages.create(**create_kwargs)
        except Exception as exc:
            # Anthropic returns tool_use_failed (400) when the model generates a
            # text-based function call (<function=name|null</function>) instead of
            # a proper tool_use block.  This happens when the compressed context
            # confuses the model.  Retry once with a clean single-message context.
            from anthropic import BadRequestError
            if isinstance(exc, BadRequestError) and "tool_use_failed" in str(exc):
                logger.warning("tool_use_failed on step %d — retrying with clean context", step)
                create_kwargs["messages"] = _sanitize_messages(
                    [{"role": "user", "content": user_input}]
                )
                response = cl.messages.create(**create_kwargs)
            else:
                raise

        # ── Token tracking ────────────────────────────────────────────
        get_tracker().track_call(
            agent_name=agent.name or "unknown",
            model=model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cached_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
            call_metadata={"function": "_run_anthropic", "step": step, "run_id": run.id},
        )
        increment_token_usage(agent.org_id, response.usage.input_tokens + response.usage.output_tokens, db)
        from services import llm_feedback as _lf
        _lf.record_response(None, input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens)

        # Log assistant response to trace
        assistant_content = []
        for block in response.content:
            if block.type == "text":
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                assistant_content.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
        trace.append({"role": "assistant", "content": assistant_content, "step": step})

        # If model is done (no tool calls), extract final text
        if response.stop_reason == "end_turn":
            final_text = ""
            for block in response.content:
                if block.type == "text":
                    final_text += block.text
            run.output = final_text
            run.status = "done"
            break

        # Process tool calls — serialize content to plain dicts to avoid
        # unsupported properties (e.g. 'annotations') from the SDK objects
        approval_mode = (agent.guardrails or {}).get("approval_mode", "auto")
        autonomy_level = (agent.guardrails or {}).get("autonomy_level", "conservative")
        effective_hitl_tools = get_hitl_tools_for_autonomy(autonomy_level)
        messages.append({"role": "assistant", "content": assistant_content})
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            # HITL: pause before any write tool that needs human approval
            if approval_mode == "hitl" and block.name in effective_hitl_tools:
                approval = _create_approval(
                    agent=agent, run=run, db=db,
                    tool_name=block.name, tool_input=block.input or {},
                    messages_snapshot=messages[:-1],  # before the appended assistant msg
                    assistant_content=assistant_content,
                    provider="anthropic", model_name=model,
                    current_step=step, tool_use_id=block.id,
                )
                run.status = "awaiting_approval"
                run.trace = trace
                db.commit()
                raise ApprovalRequired(approval.id, block.name)
            try:
                result_str = _execute_tool(agent, db, block.name, block.input or {}, step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=block.name, tool_input=block.input or {},
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider="anthropic", model=model,
                    step=step, tool_use_id=block.id, trace=trace,
                )
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_str,
            })

        messages.append({"role": "user", "content": tool_results})
        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


def _run_openai_compat(agent: Agent, user_input: str, db: Session, run: AgentRun, model: str, provider: str):
    """Run agent using OpenAI-compatible API (OpenAI, Groq, Ollama)."""
    trace = []
    user_input = _truncate_user_input(user_input, provider)
    system = _build_system_prompt(agent)
    tools = get_openai_tool_schemas(agent.tools or [])
    max_steps = (agent.guardrails or {}).get("max_steps", 15)

    if provider == "groq":
        cl = _get_groq_client(db)
    elif provider == "ollama":
        cl = _get_ollama_client(db)
        model = model.removeprefix("ollama/")  # Ollama expects bare model name
    else:
        cl = _get_openai_client(db)

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_input},
    ]

    for step in range(max_steps):
        # Apply rolling context compression to prevent unbounded token growth.
        # For Groq, this also prevents llama from falling back to its native
        # <function=name(args)> format (which causes tool_use_failed 400 errors).
        compressed_messages = _compress_openai_messages(messages, provider)

        create_kwargs = {
            "model": model,
            "max_tokens": 4096,
            "messages": compressed_messages,
        }
        if tools:
            create_kwargs["tools"] = tools

        try:
            response = cl.chat.completions.create(**create_kwargs)
        except Exception as exc:
            err_str = str(exc)
            if "tool_use_failed" in err_str or "failed_generation" in err_str:
                logger.warning("tool_use_failed on step %d — retrying with clean context", step)
                create_kwargs["messages"] = [
                    {"role": "system", "content": _build_system_prompt(agent)},
                    {"role": "user", "content": user_input},
                ]
                response = cl.chat.completions.create(**create_kwargs)
            else:
                raise
        choice = response.choices[0]
        msg = choice.message

        # Token tracking + quota enforcement for OpenAI-compat providers
        if hasattr(response, "usage") and response.usage:
            _in = getattr(response.usage, "prompt_tokens", 0) or 0
            _out = getattr(response.usage, "completion_tokens", 0) or 0
            get_tracker().track_call(
                agent_name=agent.name or "unknown", model=model,
                input_tokens=_in, output_tokens=_out,
                call_metadata={"function": "_run_openai_compat", "step": step, "run_id": run.id},
            )
            increment_token_usage(agent.org_id, _in + _out, db)
            from services import llm_feedback as _lf
            _lf.record_response(None, input_tokens=_in, output_tokens=_out)

        # Log assistant response
        assistant_content = []
        if msg.content:
            assistant_content.append({"type": "text", "text": msg.content})
        if msg.tool_calls:
            for tc in msg.tool_calls:
                assistant_content.append({
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": json.loads(tc.function.arguments) if tc.function.arguments else {},
                })
        trace.append({"role": "assistant", "content": assistant_content, "step": step})

        # If done (no tool calls)
        if choice.finish_reason in ("stop", "length") or not msg.tool_calls:
            run.output = msg.content or ""
            run.status = "done"
            break

        # Process tool calls — build clean message dict to avoid SDK-injected
        # fields like 'annotations', 'audio', 'refusal' that APIs reject
        approval_mode = (agent.guardrails or {}).get("approval_mode", "auto")
        autonomy_level = (agent.guardrails or {}).get("autonomy_level", "conservative")
        effective_hitl_tools = get_hitl_tools_for_autonomy(autonomy_level)
        assistant_msg = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            assistant_msg["tool_calls"] = [
                {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        messages.append(assistant_msg)
        for tc in msg.tool_calls:
            tool_input = json.loads(tc.function.arguments) if tc.function.arguments else {}
            # HITL: pause before write tool
            if approval_mode == "hitl" and tc.function.name in effective_hitl_tools:
                approval = _create_approval(
                    agent=agent, run=run, db=db,
                    tool_name=tc.function.name, tool_input=tool_input,
                    messages_snapshot=messages[:-1],  # before appended assistant msg
                    assistant_content=assistant_content,
                    provider=provider, model_name=model,
                    current_step=step, tool_use_id=tc.id,
                )
                run.status = "awaiting_approval"
                run.trace = trace
                db.commit()
                raise ApprovalRequired(approval.id, tc.function.name)
            try:
                result_str = _execute_tool(agent, db, tc.function.name, tool_input, step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=tc.function.name, tool_input=tool_input,
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider=provider, model=model,
                    step=step, tool_use_id=tc.id, trace=trace,
                )
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result_str,
            })

        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


def _gemini_upcase_types(schema: dict) -> dict:
    """Recursively convert JSON Schema type values to uppercase for Gemini SDK.

    Gemini's FunctionDeclaration expects OBJECT, STRING, INTEGER, NUMBER,
    BOOLEAN, ARRAY — not the lowercase variants used by OpenAPI/JSON Schema.
    """
    if not isinstance(schema, dict):
        return schema
    out = {}
    for k, v in schema.items():
        if k == "type" and isinstance(v, str):
            out[k] = v.upper()
        elif isinstance(v, dict):
            out[k] = _gemini_upcase_types(v)
        else:
            out[k] = v
    return out


def _gemini_wrap_response(result_str: str) -> dict:
    """Ensure tool result is a dict for Gemini's Part.from_function_response().

    Gemini SDK validates that the response is a dict, but tools can return
    lists, strings, or other JSON types.  Wrap non-dict values.
    """
    try:
        parsed = json.loads(result_str)
    except (json.JSONDecodeError, TypeError):
        return {"result": result_str}
    if isinstance(parsed, dict):
        return parsed
    return {"result": parsed}


def _run_gemini(agent: Agent, user_input: str, db: Session, run: AgentRun, model: str):
    """Run agent using Google Gemini API (direct or Vertex AI)."""
    from google.genai import types as genai_types

    trace = []
    provider = detect_provider(model)
    user_input = _truncate_user_input(user_input, provider)
    system = _build_system_prompt(agent)
    max_steps = (agent.guardrails or {}).get("max_steps", 15)

    if provider == "vertex_ai":
        cl = _get_vertex_client(db)
        model = model.removeprefix("vertex/")  # Vertex uses bare Gemini model names
    else:
        cl = _get_gemini_client(db)

    # Build Gemini tool declarations (types must be UPPERCASE)
    tool_declarations = []
    for name in (agent.tools or []):
        t = TOOL_REGISTRY.get(name)
        if t:
            tool_declarations.append(genai_types.FunctionDeclaration(
                name=t["name"],
                description=t["description"],
                parameters=_gemini_upcase_types({
                    "type": "OBJECT",
                    "properties": t["parameters"],
                }),
            ))

    gemini_tools = [genai_types.Tool(function_declarations=tool_declarations)] if tool_declarations else []

    contents = [genai_types.Content(role="user", parts=[genai_types.Part.from_text(text=user_input)])]

    for step in range(max_steps):
        response = cl.models.generate_content(
            model=model,
            contents=contents,
            config=genai_types.GenerateContentConfig(
                system_instruction=system,
                tools=gemini_tools,
                max_output_tokens=4096,
            ),
        )

        # Token tracking + quota enforcement for Gemini
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            _in = getattr(response.usage_metadata, "prompt_token_count", 0) or 0
            _out = getattr(response.usage_metadata, "candidates_token_count", 0) or 0
            get_tracker().track_call(
                agent_name=agent.name or "unknown", model=model,
                input_tokens=_in, output_tokens=_out,
                call_metadata={"function": "_run_gemini", "step": step, "run_id": run.id},
            )
            increment_token_usage(agent.org_id, _in + _out, db)
            from services import llm_feedback as _lf
            _lf.record_response(None, input_tokens=_in, output_tokens=_out)

        # Parse response
        assistant_content = []
        function_calls = []
        candidates = getattr(response, "candidates", None)
        if not candidates or not candidates[0].content or not candidates[0].content.parts:
            run.output = "Gemini returned an empty response (possibly blocked by safety filters)."
            run.status = "error"
            break
        for part in response.candidates[0].content.parts:
            if part.text:
                assistant_content.append({"type": "text", "text": part.text})
            if part.function_call:
                fc = part.function_call
                assistant_content.append({
                    "type": "tool_use",
                    "id": fc.name,
                    "name": fc.name,
                    "input": dict(fc.args) if fc.args else {},
                })
                function_calls.append(fc)
        trace.append({"role": "assistant", "content": assistant_content, "step": step})

        # If no function calls, we're done
        if not function_calls:
            final_text = ""
            for part in response.candidates[0].content.parts:
                if part.text:
                    final_text += part.text
            run.output = final_text
            run.status = "done"
            break

        # Add assistant response to contents — rebuild from parts to avoid
        # passing native Content objects back into generate_content (which
        # triggers Pydantic serialization warnings in the Gemini SDK).
        assistant_parts = []
        for part in response.candidates[0].content.parts:
            if part.text:
                assistant_parts.append(genai_types.Part.from_text(text=part.text))
            if part.function_call:
                assistant_parts.append(genai_types.Part.from_function_call(
                    name=part.function_call.name,
                    args=dict(part.function_call.args) if part.function_call.args else {},
                ))
        contents.append(genai_types.Content(role="model", parts=assistant_parts))

        # Execute tool calls and build function responses
        function_responses = []
        for fc in function_calls:
            tool_input = dict(fc.args) if fc.args else {}
            try:
                result_str = _execute_tool(agent, db, fc.name, tool_input, step, trace)
            except NeedsApproval as exc:
                # Gemini's resume support is limited (see _resume entry point);
                # we still persist the approval so it surfaces in the UI.
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=fc.name, tool_input=tool_input,
                    messages_snapshot=[],
                    assistant_content=[],
                    provider="google_gemini", model=model,
                    step=step, tool_use_id="", trace=trace,
                )
            function_responses.append(genai_types.Part.from_function_response(
                name=fc.name,
                response=_gemini_wrap_response(result_str),
            ))

        contents.append(genai_types.Content(role="user", parts=function_responses))
        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


# ── Main entry point ──────────────────────────────────────────────────

def run_agent(agent: Agent, user_input: str, db: Session) -> AgentRun:
    """Execute an agent synchronously and return the completed AgentRun."""
    from services import llm_feedback

    check_token_quota(agent.org_id, db)
    run = AgentRun(
        agent_id=agent.id,
        input=user_input,
        status="running",
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    # Use agent's model, fall back to DB default, then hardcoded default.
    # If the agent's configured model requires an API key that isn't set,
    # fall back to whichever provider IS configured.
    model = agent.model or get_default_model(db)
    provider = detect_provider(model)
    try:
        _validate_provider_configured(db, provider)
    except RuntimeError:
        # Configured model's provider has no key — fall back to default
        model = get_default_model(db)
        provider = detect_provider(model)

    def _dispatch(m, p):
        # Claude on Vertex routes through the Anthropic loop — same
        # wire protocol, just a different auth path. Gemini on Vertex
        # stays on the google-genai loop.
        if p == "anthropic" or (p == "vertex_ai" and llm_router.is_claude_model(m)):
            _run_anthropic(agent, user_input, db, run, m)
        elif p in ("openai", "groq", "ollama"):
            _run_openai_compat(agent, user_input, db, run, m, p)
        elif p in ("google_gemini", "vertex_ai"):
            _run_gemini(agent, user_input, db, run, m)
        else:
            raise RuntimeError(f"Unsupported provider: {p}")

    with llm_feedback.span(
        surface="agent",
        org_id=agent.org_id,
        agent_id=agent.id,
        agent_run_id=run.id,
        provider=provider,
        model=model,
        system_prompt=agent.system_prompt,
        messages=[{"role": "user", "content": user_input}],
    ):
        try:
            _dispatch(model, provider)
        except ApprovalRequired:
            # HITL pause — run already set to awaiting_approval and committed.
            # Skip flush: the resumed run will re-open its own span.
            db.refresh(run)
            return run
        except Exception as e:
            # Runtime failure (e.g. permission denied) — try a different provider
            fallback = _find_fallback_model(db, exclude_providers={provider}, tool_count=len(agent.tools or []))
            if fallback:
                fb_model, fb_provider = fallback
                logger.warning("Provider %s failed (%s), falling back to %s/%s", provider, e, fb_provider, fb_model)
                llm_feedback.record_provider(fb_provider, fb_model)
                try:
                    _dispatch(fb_model, fb_provider)
                except ApprovalRequired:
                    db.refresh(run)
                    return run
                except Exception as e2:
                    logger.exception("Fallback provider %s also failed", fb_provider)
                    run.status = "failed"
                    run.error = str(e2)
                    llm_feedback.record_error(e2)
            else:
                logger.exception("Agent run failed (no fallback available)")
                run.status = "failed"
                run.error = str(e)
                llm_feedback.record_error(e)

        # Carry final agent output into the feedback-loop row.
        llm_feedback.record_response(run.output or "")

    run.finished_at = datetime.utcnow()
    db.commit()
    db.refresh(run)
    return run


def run_agent_streaming(agent: Agent, user_input: str, db: Session,
                        conversation_messages: Optional[list] = None):
    """Execute an agent and yield SSE events as it runs.

    Each event is a dict: {type, data} where type is one of:
    - 'start': run started, data has run_id
    - 'thinking': LLM is processing (step number)
    - 'text': partial text output
    - 'tool_call': tool being invoked
    - 'tool_result': tool finished
    - 'done': run completed
    - 'error': run failed

    Args:
        conversation_messages: Optional list of prior conversation messages
            (user/assistant dicts) to prepend as native multi-turn context.
            Enables provider-level prompt caching for repeated prefixes.
    """
    from services import llm_feedback

    check_token_quota(agent.org_id, db)
    run = AgentRun(agent_id=agent.id, input=user_input, status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    yield {"type": "start", "run_id": run.id}

    model = agent.model or get_default_model(db)
    provider = detect_provider(model)
    # If the agent's model requires an API key that isn't configured, fall back
    try:
        _validate_provider_configured(db, provider)
    except RuntimeError:
        model = get_default_model(db)
        provider = detect_provider(model)

    def _dispatch_stream(m, p):
        # Claude-on-Vertex uses the AnthropicVertex SDK — same message
        # protocol as direct Anthropic, so route through _stream_anthropic.
        if p == "anthropic" or (p == "vertex_ai" and llm_router.is_claude_model(m)):
            return _stream_anthropic(agent, user_input, db, run, m,
                                     conversation_messages=conversation_messages)
        elif p in ("openai", "groq", "ollama"):
            return _stream_openai_compat(agent, user_input, db, run, m, p,
                                         conversation_messages=conversation_messages)
        elif p in ("google_gemini", "vertex_ai"):
            return _stream_gemini(agent, user_input, db, run, m,
                                  conversation_messages=conversation_messages)
        else:
            raise RuntimeError(f"Unsupported provider: {p}")

    with llm_feedback.span(
        surface="agent",
        org_id=agent.org_id,
        agent_id=agent.id,
        agent_run_id=run.id,
        provider=provider,
        model=model,
        system_prompt=agent.system_prompt,
        messages=[{"role": "user", "content": user_input}],
    ):
        try:
            yield from _dispatch_stream(model, provider)
        except ApprovalRequired as e:
            # HITL pause — emit event so frontend can show approval UI
            db.refresh(run)
            yield {
                "type": "approval_required",
                "run_id": run.id,
                "approval_id": e.approval_id,
                "tool_name": e.tool_name,
            }
            return
        except Exception as e:
            # Runtime failure (e.g. permission denied) — try a different provider
            fallback = _find_fallback_model(db, exclude_providers={provider}, tool_count=len(agent.tools or []))
            if fallback:
                fb_model, fb_provider = fallback
                logger.warning("Provider %s failed (%s), falling back to %s/%s", provider, e, fb_provider, fb_model)
                llm_feedback.record_provider(fb_provider, fb_model)
                yield {"type": "thinking", "step": 0, "fallback": True, "detail": f"Retrying with {fb_provider}"}
                try:
                    yield from _dispatch_stream(fb_model, fb_provider)
                except ApprovalRequired as e2:
                    db.refresh(run)
                    yield {
                        "type": "approval_required",
                        "run_id": run.id,
                        "approval_id": e2.approval_id,
                        "tool_name": e2.tool_name,
                    }
                    return
                except Exception as e2:
                    logger.exception("Fallback provider %s also failed", fb_provider)
                    run.status = "failed"
                    run.error = str(e2)
                    llm_feedback.record_error(e2)
                    yield {"type": "error", "error": str(e2)}
            else:
                logger.exception("Agent run failed (no fallback available)")
                run.status = "failed"
                run.error = str(e)
                llm_feedback.record_error(e)
                yield {"type": "error", "error": str(e)}

        llm_feedback.record_response(run.output or "")

    run.finished_at = datetime.utcnow()
    try:
        db.commit()
    except Exception:
        db.rollback()
        db.add(run)
        db.commit()
    db.refresh(run)

    if run.status == "done":
        yield {"type": "done", "run_id": run.id, "output": run.output, "steps_used": run.steps_used}


def _stream_anthropic(agent, user_input, db, run, model, *, conversation_messages=None):
    """Streaming variant of _run_anthropic. Direct Anthropic or Vertex."""
    trace = []
    # Build initial messages: native multi-turn history (if provided) + current user message.
    # Native messages enable Anthropic prompt caching on the conversation prefix.
    if conversation_messages:
        messages = list(conversation_messages) + [{"role": "user", "content": user_input}]
    else:
        messages = [{"role": "user", "content": user_input}]
    # Use cached system prompt blocks: static role definition cached, dynamic context appended
    system = _build_system_prompt_cached(agent)
    tools = get_claude_tool_schemas(agent.tools or [])
    max_steps = (agent.guardrails or {}).get("max_steps", 15)
    cl = _get_anthropic_client(db, model)
    api_model = model.removeprefix("vertex/") if model.startswith("vertex/") else model

    for step in range(max_steps):
        yield {"type": "thinking", "step": step}

        # Apply rolling context compression after 5 turns to cap history size
        compressed_messages = rolling_context(messages, max_turns=5)

        create_kwargs = {"model": api_model, "max_tokens": 4096, "system": system, "messages": _sanitize_messages(compressed_messages)}
        if tools:
            create_kwargs["tools"] = tools
        try:
            response = cl.messages.create(**create_kwargs)
        except Exception as exc:
            from anthropic import BadRequestError
            if isinstance(exc, BadRequestError) and "tool_use_failed" in str(exc):
                logger.warning("tool_use_failed on step %d — retrying with clean context", step)
                create_kwargs["messages"] = _sanitize_messages(
                    [{"role": "user", "content": user_input}]
                )
                response = cl.messages.create(**create_kwargs)
            else:
                raise

        # ── Token tracking ────────────────────────────────────────────
        get_tracker().track_call(
            agent_name=agent.name or "unknown",
            model=model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cached_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
            call_metadata={"function": "_stream_anthropic", "step": step, "run_id": run.id},
        )
        increment_token_usage(agent.org_id, response.usage.input_tokens + response.usage.output_tokens, db)
        from services import llm_feedback as _lf
        _lf.record_response(None, input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens)

        assistant_content = []
        for block in response.content:
            if block.type == "text":
                assistant_content.append({"type": "text", "text": block.text})
                yield {"type": "text", "text": block.text, "step": step}
            elif block.type == "tool_use":
                assistant_content.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
                yield {"type": "tool_call", "name": block.name, "input": block.input, "step": step}
        trace.append({"role": "assistant", "content": assistant_content, "step": step})

        if response.stop_reason == "end_turn":
            final_text = "".join(b.text for b in response.content if b.type == "text")
            run.output = final_text
            run.status = "done"
            break

        approval_mode = (agent.guardrails or {}).get("approval_mode", "auto")
        autonomy_level = (agent.guardrails or {}).get("autonomy_level", "conservative")
        effective_hitl_tools = get_hitl_tools_for_autonomy(autonomy_level)
        messages.append({"role": "assistant", "content": assistant_content})
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            if approval_mode == "hitl" and block.name in effective_hitl_tools:
                approval = _create_approval(
                    agent=agent, run=run, db=db,
                    tool_name=block.name, tool_input=block.input or {},
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider="anthropic", model_name=model,
                    current_step=step, tool_use_id=block.id,
                )
                run.status = "awaiting_approval"
                run.trace = trace
                db.commit()
                raise ApprovalRequired(approval.id, block.name)
            try:
                result_str = _execute_tool(agent, db, block.name, block.input or {}, step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=block.name, tool_input=block.input or {},
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider="anthropic", model=model,
                    step=step, tool_use_id=block.id, trace=trace,
                )
            yield {"type": "tool_result", "name": block.name, "result": result_str[:2000], "step": step}
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result_str})

        messages.append({"role": "user", "content": tool_results})
        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


def _stream_openai_compat(agent, user_input, db, run, model, provider, *, conversation_messages=None):
    """Streaming variant of _run_openai_compat."""
    trace = []
    system = _build_system_prompt(agent)
    tools = get_openai_tool_schemas(agent.tools or [])
    max_steps = (agent.guardrails or {}).get("max_steps", 15)
    if provider == "groq":
        cl = _get_groq_client(db)
    elif provider == "ollama":
        cl = _get_ollama_client(db)
        model = model.removeprefix("ollama/")
    else:
        cl = _get_openai_client(db)

    # Build messages: system + native history (if provided) + current user message
    if conversation_messages:
        messages = [{"role": "system", "content": system}] + list(conversation_messages) + [{"role": "user", "content": user_input}]
    else:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user_input}]

    for step in range(max_steps):
        yield {"type": "thinking", "step": step}

        compressed_messages = _compress_openai_messages(messages, provider)
        create_kwargs = {"model": model, "max_tokens": 4096, "messages": compressed_messages}
        if tools:
            create_kwargs["tools"] = tools

        try:
            response = cl.chat.completions.create(**create_kwargs)
        except Exception as exc:
            # Groq/Llama returns tool_use_failed (400) when the model generates a
            # text-based function call instead of a proper tool_use block.
            # Retry once with clean single-message context.
            err_str = str(exc)
            if "tool_use_failed" in err_str or "failed_generation" in err_str:
                logger.warning("tool_use_failed on step %d — retrying with clean context", step)
                create_kwargs["messages"] = [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_input},
                ]
                response = cl.chat.completions.create(**create_kwargs)
            else:
                raise

        choice = response.choices[0]
        msg = choice.message

        assistant_content = []
        if msg.content:
            assistant_content.append({"type": "text", "text": msg.content})
            yield {"type": "text", "text": msg.content, "step": step}
        if msg.tool_calls:
            for tc in msg.tool_calls:
                assistant_content.append({
                    "type": "tool_use", "id": tc.id, "name": tc.function.name,
                    "input": json.loads(tc.function.arguments) if tc.function.arguments else {},
                })
                yield {"type": "tool_call", "name": tc.function.name, "step": step}
        trace.append({"role": "assistant", "content": assistant_content, "step": step})

        if choice.finish_reason in ("stop", "length") or not msg.tool_calls:
            run.output = msg.content or ""
            run.status = "done"
            break

        # Build clean message dict to avoid SDK-injected fields like 'annotations'
        assistant_msg = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            assistant_msg["tool_calls"] = [
                {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        approval_mode = (agent.guardrails or {}).get("approval_mode", "auto")
        messages.append(assistant_msg)
        for tc in msg.tool_calls:
            tool_input = json.loads(tc.function.arguments) if tc.function.arguments else {}
            if approval_mode == "hitl" and tc.function.name in HITL_TOOLS:
                approval = _create_approval(
                    agent=agent, run=run, db=db,
                    tool_name=tc.function.name, tool_input=tool_input,
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider=provider, model_name=model,
                    current_step=step, tool_use_id=tc.id,
                )
                run.status = "awaiting_approval"
                run.trace = trace
                db.commit()
                raise ApprovalRequired(approval.id, tc.function.name)
            try:
                result_str = _execute_tool(agent, db, tc.function.name, tool_input, step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=tc.function.name, tool_input=tool_input,
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider=provider, model=model,
                    step=step, tool_use_id=tc.id, trace=trace,
                )
            yield {"type": "tool_result", "name": tc.function.name, "result": result_str[:2000], "step": step}
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result_str})

        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


def _stream_gemini(agent, user_input, db, run, model, *, conversation_messages=None):
    """Streaming variant of _run_gemini (direct Gemini or Vertex AI)."""
    from google.genai import types as genai_types

    trace = []
    system = _build_system_prompt(agent)
    max_steps = (agent.guardrails or {}).get("max_steps", 15)
    provider = detect_provider(model)
    if provider == "vertex_ai":
        cl = _get_vertex_client(db)
        model = model.removeprefix("vertex/")
    else:
        cl = _get_gemini_client(db)

    tool_declarations = []
    for name in (agent.tools or []):
        t = TOOL_REGISTRY.get(name)
        if t:
            tool_declarations.append(genai_types.FunctionDeclaration(
                name=t["name"], description=t["description"],
                parameters=_gemini_upcase_types({"type": "OBJECT", "properties": t["parameters"]}),
            ))
    gemini_tools = [genai_types.Tool(function_declarations=tool_declarations)] if tool_declarations else []
    # Build contents: native history (if provided) + current user message
    contents = []
    if conversation_messages:
        for msg in conversation_messages:
            role = "model" if msg.get("role") == "assistant" else "user"
            text = msg.get("content", "")
            if isinstance(text, list):
                text = " ".join(b.get("text", "") for b in text if isinstance(b, dict) and b.get("type") == "text")
            if text:
                contents.append(genai_types.Content(role=role, parts=[genai_types.Part.from_text(text=text)]))
    contents.append(genai_types.Content(role="user", parts=[genai_types.Part.from_text(text=user_input)]))

    for step in range(max_steps):
        yield {"type": "thinking", "step": step}

        response = cl.models.generate_content(
            model=model, contents=contents,
            config=genai_types.GenerateContentConfig(system_instruction=system, tools=gemini_tools, max_output_tokens=4096),
        )

        assistant_content = []
        function_calls = []
        for part in response.candidates[0].content.parts:
            if part.text:
                assistant_content.append({"type": "text", "text": part.text})
                yield {"type": "text", "text": part.text, "step": step}
            if part.function_call:
                fc = part.function_call
                assistant_content.append({"type": "tool_use", "id": fc.name, "name": fc.name, "input": dict(fc.args) if fc.args else {}})
                yield {"type": "tool_call", "name": fc.name, "step": step}
                function_calls.append(fc)
        trace.append({"role": "assistant", "content": assistant_content, "step": step})

        if not function_calls:
            final_text = "".join(p.text for p in response.candidates[0].content.parts if p.text)
            run.output = final_text
            run.status = "done"
            break

        # Rebuild from parts to avoid Pydantic serialization warnings
        assistant_parts = []
        for part in response.candidates[0].content.parts:
            if part.text:
                assistant_parts.append(genai_types.Part.from_text(text=part.text))
            if part.function_call:
                assistant_parts.append(genai_types.Part.from_function_call(
                    name=part.function_call.name,
                    args=dict(part.function_call.args) if part.function_call.args else {},
                ))
        contents.append(genai_types.Content(role="model", parts=assistant_parts))

        function_responses = []
        for fc in function_calls:
            tool_input = dict(fc.args) if fc.args else {}
            try:
                result_str = _execute_tool(agent, db, fc.name, tool_input, step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=fc.name, tool_input=tool_input,
                    messages_snapshot=[], assistant_content=[],
                    provider="google_gemini", model=model,
                    step=step, tool_use_id="", trace=trace,
                )
            yield {"type": "tool_result", "name": fc.name, "result": result_str[:2000], "step": step}
            function_responses.append(genai_types.Part.from_function_response(name=fc.name, response=_gemini_wrap_response(result_str)))

        contents.append(genai_types.Content(role="user", parts=function_responses))
        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


def update_agent_memory(agent: Agent, memory_updates: dict, db: Session):
    """Merge updates into agent's persistent memory."""
    mem = agent.memory or {}
    mem.update(memory_updates)
    agent.memory = mem
    db.commit()


def update_run_ctx(db: Session, agent_id: int, updates: dict) -> None:
    """Merge updates into ``agent.memory["_run_ctx"]`` so subsequent tool calls
    in the same run see them. Used by protocol-audit tools that discover a
    fact mid-run (e.g. SNMP probe finding an accepted community) and want
    later tools to fall back to it without exposing it to the LLM schema.
    """
    from sqlalchemy.orm.attributes import flag_modified

    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        return
    mem = dict(agent.memory or {})
    rc = dict(mem.get("_run_ctx") or {})
    rc.update(updates)
    mem["_run_ctx"] = rc
    agent.memory = mem
    flag_modified(agent, "memory")
    db.commit()


# ── HITL Resume ───────────────────────────────────────────────────────

def resume_agent_run(run_id: int, decision: str, reason: Optional[str], decider_id: Optional[int], db: Session) -> AgentRun:
    """Resume a paused agent run after a human approval decision.

    decision: "approved" | "rejected"
    reason:   optional rejection reason shown to the agent
    """
    run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
    if not run:
        raise ValueError(f"Run {run_id} not found")
    if run.status != "awaiting_approval":
        raise ValueError(f"Run {run_id} is not awaiting approval (status: {run.status})")

    approval = (
        db.query(AgentApproval)
        .filter(AgentApproval.agent_run_id == run_id, AgentApproval.status == "pending")
        .order_by(AgentApproval.requested_at.desc())
        .first()
    )
    if not approval:
        raise ValueError(f"No pending approval found for run {run_id}")

    # Record the decision
    approval.status = decision  # "approved" or "rejected"
    approval.decided_at = datetime.utcnow()
    approval.decided_by = decider_id
    approval.rejection_reason = reason
    db.flush()

    agent = db.query(Agent).filter(Agent.id == run.agent_id).first()
    run.status = "running"
    db.commit()

    try:
        provider = approval.provider
        model = approval.model_name or agent.model or get_default_model(db)
        trace = run.trace or []

        if provider == "anthropic":
            _resume_anthropic(agent, run, approval, decision, reason, model, trace, db)
        elif provider in ("openai", "groq"):
            _resume_openai_compat(agent, run, approval, decision, reason, model, provider, trace, db)
        else:
            # Gemini and unknown providers: inject a note and mark done
            run.output = f"Action '{approval.tool_name}' was {decision}. " + (f"Reason: {reason}" if reason else "")
            run.status = "done"
    except ApprovalRequired:
        # Another HITL gate hit during continuation — leave as awaiting_approval
        db.refresh(run)
        return run
    except Exception as e:
        logger.exception("Agent resume failed")
        db.rollback()
        run.status = "failed"
        run.error = str(e)

    run.finished_at = datetime.utcnow()
    db.commit()
    db.refresh(run)
    return run


def _resume_anthropic(agent, run, approval, decision, reason, model, trace, db):
    """Continue an Anthropic run from the point of HITL pause."""
    messages = list(approval.messages_snapshot or [])
    assistant_content = approval.assistant_content or []

    # Re-append the assistant message with all its tool_use blocks
    messages.append({"role": "assistant", "content": assistant_content})

    tool_results = []
    for block in assistant_content:
        if block.get("type") != "tool_use":
            continue
        block_id = block.get("id", "")
        tool_name = block.get("name", "")
        tool_input = block.get("input") or {}

        if block_id == approval.tool_use_id:
            # This is the gated tool — execute or inject rejection.
            # `_approved=True` tells per-call classifiers (e.g. ssh_run_command)
            # to skip their NeedsApproval check; harmless for static-HITL tools.
            if decision == "approved":
                try:
                    result_str = _execute_tool(agent, db, tool_name, {**tool_input, "confirmed": True, "_approved": True}, approval.current_step, trace)
                except NeedsApproval as exc:
                    _pause_for_per_call_approval(
                        agent=agent, run=run, db=db, exc=exc,
                        tool_name=tool_name, tool_input=tool_input,
                        messages_snapshot=approval.messages_snapshot or [],
                        assistant_content=assistant_content,
                        provider="anthropic", model=model,
                        step=approval.current_step, tool_use_id=block_id, trace=trace,
                    )
            else:
                result_str = json.dumps({
                    "status": "rejected",
                    "reason": reason or "Action rejected by reviewer. Please take an alternate action.",
                })
                trace.append({
                    "role": "tool", "tool_name": tool_name,
                    "input": tool_input, "output": result_str,
                    "step": approval.current_step,
                })
        else:
            # Other tool_use blocks in the same step — execute normally
            try:
                result_str = _execute_tool(agent, db, tool_name, tool_input, approval.current_step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=tool_name, tool_input=tool_input,
                    messages_snapshot=approval.messages_snapshot or [],
                    assistant_content=assistant_content,
                    provider="anthropic", model=model,
                    step=approval.current_step, tool_use_id=block_id, trace=trace,
                )

        tool_results.append({"type": "tool_result", "tool_use_id": block_id, "content": result_str})

    messages.append({"role": "user", "content": tool_results})
    run.steps_used = (run.steps_used or 0) + 1

    # Continue from next step
    max_steps = (agent.guardrails or {}).get("max_steps", 15)
    remaining = max_steps - approval.current_step - 1
    system = _build_system_prompt_cached(agent)
    tools = get_claude_tool_schemas(agent.tools or [])
    cl = _get_anthropic_client(db, model)
    api_model = model.removeprefix("vertex/") if model.startswith("vertex/") else model
    approval_mode = (agent.guardrails or {}).get("approval_mode", "auto")

    for step in range(approval.current_step + 1, approval.current_step + 1 + remaining):
        compressed_messages = rolling_context(messages, max_turns=5)
        create_kwargs = {"model": api_model, "max_tokens": 4096, "system": system, "messages": _sanitize_messages(compressed_messages)}
        if tools:
            create_kwargs["tools"] = tools
        try:
            response = cl.messages.create(**create_kwargs)
        except Exception as exc:
            from anthropic import BadRequestError
            if isinstance(exc, BadRequestError) and "tool_use_failed" in str(exc):
                logger.warning("tool_use_failed on step %d — retrying with clean context", step)
                # Fall back to just the original user message from the snapshot
                original_user = messages[:1] if messages else []
                create_kwargs["messages"] = _sanitize_messages(original_user)
                response = cl.messages.create(**create_kwargs)
            else:
                raise

        get_tracker().track_call(
            agent_name=agent.name or "unknown", model=model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cached_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
            call_metadata={"function": "_resume_anthropic", "step": step, "run_id": run.id},
        )
        increment_token_usage(agent.org_id, response.usage.input_tokens + response.usage.output_tokens, db)
        from services import llm_feedback as _lf
        _lf.record_response(None, input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens)

        assistant_content = []
        for block in response.content:
            if block.type == "text":
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                assistant_content.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
        trace.append({"role": "assistant", "content": assistant_content, "step": step})

        if response.stop_reason == "end_turn":
            run.output = "".join(b.text for b in response.content if b.type == "text")
            run.status = "done"
            break

        messages.append({"role": "assistant", "content": assistant_content})
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            if approval_mode == "hitl" and block.name in HITL_TOOLS:
                new_approval = _create_approval(
                    agent=agent, run=run, db=db,
                    tool_name=block.name, tool_input=block.input or {},
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider="anthropic", model_name=model,
                    current_step=step, tool_use_id=block.id,
                )
                run.status = "awaiting_approval"
                run.trace = trace
                db.commit()
                raise ApprovalRequired(new_approval.id, block.name)
            try:
                result_str = _execute_tool(agent, db, block.name, block.input or {}, step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=block.name, tool_input=block.input or {},
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider="anthropic", model=model,
                    step=step, tool_use_id=block.id, trace=trace,
                )
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result_str})

        messages.append({"role": "user", "content": tool_results})
        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


def _resume_openai_compat(agent, run, approval, decision, reason, model, provider, trace, db):
    """Continue an OpenAI-compatible run from the point of HITL pause."""
    messages = list(approval.messages_snapshot or [])
    assistant_content = approval.assistant_content or []

    # Reconstruct the clean assistant_msg with tool_calls
    tool_call_blocks = [b for b in assistant_content if b.get("type") == "tool_use"]
    assistant_msg = {"role": "assistant", "content": ""}
    if tool_call_blocks:
        assistant_msg["tool_calls"] = [
            {"id": b["id"], "type": "function", "function": {"name": b["name"], "arguments": json.dumps(b.get("input", {}))}}
            for b in tool_call_blocks
        ]
    messages.append(assistant_msg)

    for block in tool_call_blocks:
        block_id = block.get("id", "")
        tool_name = block.get("name", "")
        tool_input = block.get("input") or {}

        if block_id == approval.tool_use_id:
            if decision == "approved":
                try:
                    result_str = _execute_tool(agent, db, tool_name, {**tool_input, "confirmed": True, "_approved": True}, approval.current_step, trace)
                except NeedsApproval as exc:
                    _pause_for_per_call_approval(
                        agent=agent, run=run, db=db, exc=exc,
                        tool_name=tool_name, tool_input=tool_input,
                        messages_snapshot=approval.messages_snapshot or [],
                        assistant_content=assistant_content,
                        provider=provider, model=model,
                        step=approval.current_step, tool_use_id=block_id, trace=trace,
                    )
            else:
                result_str = json.dumps({
                    "status": "rejected",
                    "reason": reason or "Action rejected by reviewer. Please take an alternate action.",
                })
                trace.append({"role": "tool", "tool_name": tool_name, "input": tool_input, "output": result_str, "step": approval.current_step})
        else:
            try:
                result_str = _execute_tool(agent, db, tool_name, tool_input, approval.current_step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=tool_name, tool_input=tool_input,
                    messages_snapshot=approval.messages_snapshot or [],
                    assistant_content=assistant_content,
                    provider=provider, model=model,
                    step=approval.current_step, tool_use_id=block_id, trace=trace,
                )

        messages.append({"role": "tool", "tool_call_id": block_id, "content": result_str})

    run.steps_used = (run.steps_used or 0) + 1

    max_steps = (agent.guardrails or {}).get("max_steps", 15)
    remaining = max_steps - approval.current_step - 1
    tools = get_openai_tool_schemas(agent.tools or [])
    cl = _get_groq_client(db) if provider == "groq" else _get_openai_client(db)
    approval_mode = (agent.guardrails or {}).get("approval_mode", "auto")

    for step in range(approval.current_step + 1, approval.current_step + 1 + remaining):
        compressed_messages = _compress_openai_messages(messages, provider)
        create_kwargs = {"model": model, "max_tokens": 4096, "messages": compressed_messages}
        if tools:
            create_kwargs["tools"] = tools
        response = cl.chat.completions.create(**create_kwargs)
        choice = response.choices[0]
        msg = choice.message

        assistant_content = []
        if msg.content:
            assistant_content.append({"type": "text", "text": msg.content})
        if msg.tool_calls:
            for tc in msg.tool_calls:
                assistant_content.append({"type": "tool_use", "id": tc.id, "name": tc.function.name, "input": json.loads(tc.function.arguments) if tc.function.arguments else {}})
        trace.append({"role": "assistant", "content": assistant_content, "step": step})

        if choice.finish_reason in ("stop", "length") or not msg.tool_calls:
            run.output = msg.content or ""
            run.status = "done"
            break

        clean_msg = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            clean_msg["tool_calls"] = [
                {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        messages.append(clean_msg)
        for tc in msg.tool_calls:
            tool_input = json.loads(tc.function.arguments) if tc.function.arguments else {}
            if approval_mode == "hitl" and tc.function.name in HITL_TOOLS:
                new_approval = _create_approval(
                    agent=agent, run=run, db=db,
                    tool_name=tc.function.name, tool_input=tool_input,
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider=provider, model_name=model,
                    current_step=step, tool_use_id=tc.id,
                )
                run.status = "awaiting_approval"
                run.trace = trace
                db.commit()
                raise ApprovalRequired(new_approval.id, tc.function.name)
            try:
                result_str = _execute_tool(agent, db, tc.function.name, tool_input, step, trace)
            except NeedsApproval as exc:
                _pause_for_per_call_approval(
                    agent=agent, run=run, db=db, exc=exc,
                    tool_name=tc.function.name, tool_input=tool_input,
                    messages_snapshot=messages[:-1],
                    assistant_content=assistant_content,
                    provider=provider, model=model,
                    step=step, tool_use_id=tc.id, trace=trace,
                )
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result_str})
        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace
