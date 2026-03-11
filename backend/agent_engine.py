"""
Mini Agent Execution Engine — runs user-defined agents using multiple LLM providers with tool use.

Supported providers: Anthropic (Claude), OpenAI (GPT), Google (Gemini), Groq (Llama/Mixtral).
"""
import os
import json
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from models import Agent, AgentRun, IntegrationConfig
from agent_tools import TOOL_REGISTRY, get_claude_tool_schemas, get_openai_tool_schemas
from agent_context import compress_tool_result, build_context_section

logger = logging.getLogger(__name__)

# Cache clients per provider+key to avoid recreating on every run
_client_cache = {}

# ── Model → Provider mapping ──────────────────────────────────────────

PROVIDER_FOR_MODEL = {
    # Anthropic
    "claude-sonnet-4-6": "anthropic",
    "claude-haiku-4-5-20251001": "anthropic",
    "claude-opus-4-6": "anthropic",
    # OpenAI
    "gpt-4o": "openai",
    "gpt-4o-mini": "openai",
    "gpt-4.1": "openai",
    "gpt-4.1-mini": "openai",
    "o3-mini": "openai",
    # Google Gemini
    "gemini-2.5-flash": "google_gemini",
    "gemini-2.5-pro": "google_gemini",
    "gemini-2.0-flash": "google_gemini",
    # Groq
    "llama-3.3-70b-versatile": "groq",
    "llama-3.1-8b-instant": "groq",
    "mixtral-8x7b-32768": "groq",
    "deepseek-r1-distill-llama-70b": "groq",
}


def detect_provider(model: str) -> str:
    """Detect provider from model name."""
    if model in PROVIDER_FOR_MODEL:
        return PROVIDER_FOR_MODEL[model]
    if model.startswith("claude"):
        return "anthropic"
    if model.startswith("gpt") or model.startswith("o3") or model.startswith("o1"):
        return "openai"
    if model.startswith("gemini"):
        return "google_gemini"
    if model.startswith("llama") or model.startswith("mixtral") or model.startswith("deepseek"):
        return "groq"
    return "anthropic"  # default fallback


# ── Client factories ──────────────────────────────────────────────────

def _get_api_key(db: Session, provider: str, env_var: str) -> str:
    """Load API key from DB integration config, falling back to env var."""
    cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
    api_key = None
    if cfg and cfg.config:
        api_key = cfg.config.get("api_key")
    if not api_key:
        api_key = os.environ.get(env_var)
    if not api_key:
        display = provider.replace("_", " ").title()
        raise RuntimeError(
            f"{display} API key not configured. "
            f"Go to Settings > Integrations to set your API key."
        )
    return api_key


def _get_cached_client(cache_key: str, factory):
    """Get or create a cached client."""
    global _client_cache
    if cache_key not in _client_cache:
        if len(_client_cache) > 10:
            _client_cache.clear()
        _client_cache[cache_key] = factory()
    return _client_cache[cache_key]


def _get_anthropic_client(db: Session):
    api_key = _get_api_key(db, "anthropic", "ANTHROPIC_API_KEY")
    from anthropic import Anthropic
    return _get_cached_client(f"anthropic:{api_key[:12]}", lambda: Anthropic(api_key=api_key))


def _get_openai_client(db: Session):
    api_key = _get_api_key(db, "openai", "OPENAI_API_KEY")
    from openai import OpenAI
    return _get_cached_client(f"openai:{api_key[:12]}", lambda: OpenAI(api_key=api_key))


def _get_gemini_client(db: Session):
    api_key = _get_api_key(db, "google_gemini", "GOOGLE_API_KEY")
    from google import genai
    return _get_cached_client(f"gemini:{api_key[:12]}", lambda: genai.Client(api_key=api_key))


def _get_groq_client(db: Session):
    api_key = _get_api_key(db, "groq", "GROQ_API_KEY")
    from groq import Groq
    return _get_cached_client(f"groq:{api_key[:12]}", lambda: Groq(api_key=api_key))


# ── Default model per provider ────────────────────────────────────────

# Provider → (env var, default model)
_PROVIDER_DEFAULTS = [
    ("anthropic", "ANTHROPIC_API_KEY", "claude-sonnet-4-6"),
    ("groq", "GROQ_API_KEY", "llama-3.3-70b-versatile"),
    ("openai", "OPENAI_API_KEY", "gpt-4o"),
    ("google_gemini", "GOOGLE_API_KEY", "gemini-2.5-flash"),
]


def get_default_model(db: Session) -> str:
    """Get the default model from settings, picking from whichever provider has a key configured."""
    # First check if any provider has an explicit default_model set
    for provider, env_var, fallback_model in _PROVIDER_DEFAULTS:
        cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
        if cfg and cfg.config:
            explicit = cfg.config.get("default_model")
            if explicit:
                return explicit

    # Otherwise, pick the first provider that has an API key
    for provider, env_var, fallback_model in _PROVIDER_DEFAULTS:
        cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
        has_key = (cfg and cfg.config and cfg.config.get("api_key")) or os.environ.get(env_var)
        if has_key:
            return fallback_model

    return "claude-sonnet-4-6"  # ultimate fallback


# ── Shared helpers ────────────────────────────────────────────────────

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


def _build_system_prompt(agent: Agent) -> str:
    """Combine agent instructions with memory + scratchpad context."""
    parts = [agent.system_prompt]

    # Add context section (memory + scratchpad)
    ctx = build_context_section(agent.id, agent.memory)
    if ctx:
        parts.append(ctx)

    # Add structured output instruction
    parts.append(
        "\n\n## Inter-Agent Communication Protocol\n"
        "When producing output that will be consumed by another agent or system, "
        "use structured JSON. When producing output for a human user, use clear "
        "markdown with headers, tables, and bullet points.\n"
        "If you are unsure which tool to use or need more information, call the "
        "'request_clarification' tool instead of guessing."
    )

    return "\n".join(parts)


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
        "run_auto_tag_rules", "send_webhook",
    }
    if read_only and tool_name in write_tools:
        raise ValueError(f"Tool '{tool_name}' is a write operation but agent is read-only")


def _execute_tool(agent: Agent, db: Session, tool_name: str, tool_input: dict, step: int, trace: list):
    """Execute a tool call and return the result string.

    Injects _agent_id for scratchpad tools and compresses output for LLM context.
    """
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
        else:
            # Inject agent_id for scratchpad tools
            enriched_input = {**tool_input, "_agent_id": agent.id}
            result = tool_def["fn"](db, enriched_input)
    except ValueError as e:
        result = {"error": str(e)}
    except Exception as e:
        logger.exception(f"Tool '{tool_name}' raised an unexpected error")
        result = {"error": f"Tool execution failed: {str(e)}"}

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

    return json.dumps(compressed, default=str)


# Tools that require explicit confirmation before execution
CONFIRMATION_REQUIRED_TOOLS = {
    "create_jira_ticket", "create_servicenow_ticket",
    "send_slack_message", "send_teams_message", "send_email_alert",
    "create_campaign", "send_webhook",
    "update_finding_status", "create_exception",
}


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
    """Run agent using Anthropic Claude API."""
    trace = []
    messages = [{"role": "user", "content": user_input}]
    system = _build_system_prompt(agent)
    tools = get_claude_tool_schemas(agent.tools or [])
    max_steps = (agent.guardrails or {}).get("max_steps", 15)

    cl = _get_anthropic_client(db)

    for step in range(max_steps):
        create_kwargs = {
            "model": model,
            "max_tokens": 4096,
            "system": system,
            "messages": _sanitize_messages(messages),
        }
        if tools:
            create_kwargs["tools"] = tools

        response = cl.messages.create(**create_kwargs)

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
        messages.append({"role": "assistant", "content": assistant_content})
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            result_str = _execute_tool(agent, db, block.name, block.input, step, trace)
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
    """Run agent using OpenAI-compatible API (OpenAI, Groq)."""
    trace = []
    system = _build_system_prompt(agent)
    tools = get_openai_tool_schemas(agent.tools or [])
    max_steps = (agent.guardrails or {}).get("max_steps", 15)

    if provider == "groq":
        cl = _get_groq_client(db)
    else:
        cl = _get_openai_client(db)

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_input},
    ]

    for step in range(max_steps):
        create_kwargs = {
            "model": model,
            "max_tokens": 4096,
            "messages": messages,
        }
        if tools:
            create_kwargs["tools"] = tools

        response = cl.chat.completions.create(**create_kwargs)
        choice = response.choices[0]
        msg = choice.message

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
        assistant_msg = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            assistant_msg["tool_calls"] = [
                {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        messages.append(assistant_msg)
        for tc in msg.tool_calls:
            tool_input = json.loads(tc.function.arguments) if tc.function.arguments else {}
            result_str = _execute_tool(agent, db, tc.function.name, tool_input, step, trace)
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


def _run_gemini(agent: Agent, user_input: str, db: Session, run: AgentRun, model: str):
    """Run agent using Google Gemini API."""
    from google.genai import types as genai_types

    trace = []
    system = _build_system_prompt(agent)
    max_steps = (agent.guardrails or {}).get("max_steps", 15)

    cl = _get_gemini_client(db)

    # Build Gemini tool declarations
    tool_declarations = []
    for name in (agent.tools or []):
        t = TOOL_REGISTRY.get(name)
        if t:
            tool_declarations.append(genai_types.FunctionDeclaration(
                name=t["name"],
                description=t["description"],
                parameters={
                    "type": "object",
                    "properties": t["parameters"],
                },
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

        # Parse response
        assistant_content = []
        function_calls = []
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

        # Add assistant response to contents
        contents.append(response.candidates[0].content)

        # Execute tool calls and build function responses
        function_responses = []
        for fc in function_calls:
            tool_input = dict(fc.args) if fc.args else {}
            result_str = _execute_tool(agent, db, fc.name, tool_input, step, trace)
            function_responses.append(genai_types.Part.from_function_response(
                name=fc.name,
                response=json.loads(result_str),
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
    run = AgentRun(
        agent_id=agent.id,
        input=user_input,
        status="running",
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    # Use agent's model, fall back to DB default, then hardcoded default
    model = agent.model or get_default_model(db)
    provider = detect_provider(model)

    try:
        if provider == "anthropic":
            _run_anthropic(agent, user_input, db, run, model)
        elif provider in ("openai", "groq"):
            _run_openai_compat(agent, user_input, db, run, model, provider)
        elif provider == "google_gemini":
            _run_gemini(agent, user_input, db, run, model)
        else:
            raise RuntimeError(f"Unsupported provider: {provider}")
    except Exception as e:
        logger.exception("Agent run failed")
        run.status = "failed"
        run.error = str(e)

    run.finished_at = datetime.utcnow()
    db.commit()
    db.refresh(run)
    return run


def run_agent_streaming(agent: Agent, user_input: str, db: Session):
    """Execute an agent and yield SSE events as it runs.

    Each event is a dict: {type, data} where type is one of:
    - 'start': run started, data has run_id
    - 'thinking': LLM is processing (step number)
    - 'text': partial text output
    - 'tool_call': tool being invoked
    - 'tool_result': tool finished
    - 'done': run completed
    - 'error': run failed
    """
    run = AgentRun(agent_id=agent.id, input=user_input, status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    yield {"type": "start", "run_id": run.id}

    model = agent.model or get_default_model(db)
    provider = detect_provider(model)

    try:
        if provider == "anthropic":
            yield from _stream_anthropic(agent, user_input, db, run, model)
        elif provider in ("openai", "groq"):
            yield from _stream_openai_compat(agent, user_input, db, run, model, provider)
        elif provider == "google_gemini":
            yield from _stream_gemini(agent, user_input, db, run, model)
        else:
            raise RuntimeError(f"Unsupported provider: {provider}")
    except Exception as e:
        logger.exception("Agent run failed")
        run.status = "failed"
        run.error = str(e)
        yield {"type": "error", "error": str(e)}

    run.finished_at = datetime.utcnow()
    db.commit()
    db.refresh(run)

    if run.status == "done":
        yield {"type": "done", "run_id": run.id, "output": run.output, "steps_used": run.steps_used}


def _stream_anthropic(agent, user_input, db, run, model):
    """Streaming variant of _run_anthropic."""
    trace = []
    messages = [{"role": "user", "content": user_input}]
    system = _build_system_prompt(agent)
    tools = get_claude_tool_schemas(agent.tools or [])
    max_steps = (agent.guardrails or {}).get("max_steps", 15)
    cl = _get_anthropic_client(db)

    for step in range(max_steps):
        yield {"type": "thinking", "step": step}

        create_kwargs = {"model": model, "max_tokens": 4096, "system": system, "messages": _sanitize_messages(messages)}
        if tools:
            create_kwargs["tools"] = tools
        response = cl.messages.create(**create_kwargs)

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

        messages.append({"role": "assistant", "content": assistant_content})
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            result_str = _execute_tool(agent, db, block.name, block.input, step, trace)
            yield {"type": "tool_result", "name": block.name, "result": result_str[:2000], "step": step}
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result_str})

        messages.append({"role": "user", "content": tool_results})
        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


def _stream_openai_compat(agent, user_input, db, run, model, provider):
    """Streaming variant of _run_openai_compat."""
    trace = []
    system = _build_system_prompt(agent)
    tools = get_openai_tool_schemas(agent.tools or [])
    max_steps = (agent.guardrails or {}).get("max_steps", 15)
    cl = _get_groq_client(db) if provider == "groq" else _get_openai_client(db)

    messages = [{"role": "system", "content": system}, {"role": "user", "content": user_input}]

    for step in range(max_steps):
        yield {"type": "thinking", "step": step}

        create_kwargs = {"model": model, "max_tokens": 4096, "messages": messages}
        if tools:
            create_kwargs["tools"] = tools
        response = cl.chat.completions.create(**create_kwargs)
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
        messages.append(assistant_msg)
        for tc in msg.tool_calls:
            tool_input = json.loads(tc.function.arguments) if tc.function.arguments else {}
            result_str = _execute_tool(agent, db, tc.function.name, tool_input, step, trace)
            yield {"type": "tool_result", "name": tc.function.name, "result": result_str[:2000], "step": step}
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result_str})

        run.steps_used = step + 1
    else:
        run.output = "Agent reached maximum steps without completing."
        run.status = "done"

    run.trace = trace


def _stream_gemini(agent, user_input, db, run, model):
    """Streaming variant of _run_gemini."""
    from google.genai import types as genai_types

    trace = []
    system = _build_system_prompt(agent)
    max_steps = (agent.guardrails or {}).get("max_steps", 15)
    cl = _get_gemini_client(db)

    tool_declarations = []
    for name in (agent.tools or []):
        t = TOOL_REGISTRY.get(name)
        if t:
            tool_declarations.append(genai_types.FunctionDeclaration(
                name=t["name"], description=t["description"],
                parameters={"type": "object", "properties": t["parameters"]},
            ))
    gemini_tools = [genai_types.Tool(function_declarations=tool_declarations)] if tool_declarations else []
    contents = [genai_types.Content(role="user", parts=[genai_types.Part.from_text(text=user_input)])]

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

        contents.append(response.candidates[0].content)
        function_responses = []
        for fc in function_calls:
            tool_input = dict(fc.args) if fc.args else {}
            result_str = _execute_tool(agent, db, fc.name, tool_input, step, trace)
            yield {"type": "tool_result", "name": fc.name, "result": result_str[:2000], "step": step}
            function_responses.append(genai_types.Part.from_function_response(name=fc.name, response=json.loads(result_str)))

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
