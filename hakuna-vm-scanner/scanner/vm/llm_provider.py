"""Multi-provider LLM resolution for the VM scanner's agent worker.

Mirrors the priority and configuration surface of the backend's
``agents.agent_engine.get_default_model`` so the VM scanner uses the
same model the rest of Hakuna uses — including Vertex AI as the primary
path and the env-var fallback chain for the others.

Resolution order (same as backend _PROVIDER_DEFAULTS):

    1. anthropic       — ANTHROPIC_API_KEY, default claude-sonnet-4-6
    2. openai          — OPENAI_API_KEY, default gpt-4o
    3. vertex_ai       — GOOGLE_CLOUD_PROJECT, default vertex/gemini-2.5-flash
    4. google_gemini   — GOOGLE_API_KEY, default gemini-2.5-flash
    5. groq            — GROQ_API_KEY, default llama-3.3-70b-versatile
    6. ollama          — base_url from integration_configs, default ollama/llama3

Configuration source: this scanner service shares the Postgres DB with
the backend, so we read ``integration_configs`` directly via asyncpg.
When an ``default_model`` override is set on the DB row, that wins over
the hardcoded fallback. When no DB row exists but the env var is
present, we fall back to the env + default model (matches backend
behaviour when integrations aren't stored in the DB).

Each provider has an adapter with a single ``turn(system, messages, tools)``
method that converts the canonical Anthropic-shape content-block format
used by the agent loop into the provider's native tool-use format and
back. That way the agent worker's conversation loop stays provider-
agnostic — it always sees Anthropic-shape blocks regardless of which
LLM actually ran the turn.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Priority + defaults (kept in sync with backend/agents/agent_engine.py) ──


_PROVIDER_DEFAULTS: list[tuple[str, str | None, str]] = [
    ("anthropic",     "ANTHROPIC_API_KEY",     "claude-sonnet-4-6"),
    ("openai",        "OPENAI_API_KEY",        "gpt-4o"),
    ("vertex_ai",     "GOOGLE_CLOUD_PROJECT",  "vertex/gemini-2.5-flash"),
    ("google_gemini", "GOOGLE_API_KEY",        "gemini-2.5-flash"),
    ("groq",          "GROQ_API_KEY",          "llama-3.3-70b-versatile"),
    ("ollama",        None,                    "ollama/llama3"),
]


@dataclass
class LLMProviderInfo:
    """Resolved provider context — what the adapter needs to dispatch a turn."""
    provider: str
    model: str
    config: dict = field(default_factory=dict)


# ── DB read ──────────────────────────────────────────────────────


async def fetch_integration_configs(conn) -> dict[str, dict]:
    """Return {provider_name: {is_enabled, ...config}} for every LLM provider row.

    The ``integration_configs`` table is shared with the backend — we
    only read it here. If the table is missing (fresh install, scanner
    standalone), returns an empty dict and the caller falls back to
    env-var resolution.
    """
    try:
        rows = await conn.fetch(
            """
            SELECT provider, is_enabled, config
            FROM integration_configs
            WHERE provider IN ('anthropic','openai','vertex_ai','google_gemini','groq','ollama')
            """
        )
    except Exception as e:
        logger.warning("llm_provider: integration_configs unreadable (%s) — falling back to env", e)
        return {}

    out: dict[str, dict] = {}
    for row in rows:
        cfg = row["config"] or {}
        # asyncpg returns JSONB as dict already, but older migrations may
        # have stashed a JSON string — normalize.
        if isinstance(cfg, str):
            try:
                cfg = json.loads(cfg)
            except (TypeError, ValueError):
                cfg = {}
        out[row["provider"]] = {"is_enabled": bool(row["is_enabled"]), **cfg}
    return out


# ── Pure resolver (test-friendly) ────────────────────────────────


def resolve_specific_provider(
    provider: str,
    integration_configs: dict[str, dict] | None,
    env: dict[str, str] | None = None,
    model_override: str | None = None,
) -> LLMProviderInfo | None:
    """Try to resolve ONE specific provider, ignoring priority order.

    Used for per-specialist model routing — authn wants Claude Sonnet
    even when Vertex is the default, because authn is the composition
    source and its orchestration matters more than its cost. Returns
    None if the requested provider isn't configured; caller handles
    the fallback to the default.

    ``model_override`` pins a specific model id (e.g.
    ``claude-sonnet-4-6``) when the provider is configured — so a
    specialist can say "Anthropic, specifically Sonnet 4.6" instead of
    accepting whatever default the DB row sets.
    """
    configs = integration_configs or {}
    env = env if env is not None else dict(os.environ)

    entry = next(
        ((p, ev, fallback) for p, ev, fallback in _PROVIDER_DEFAULTS if p == provider),
        None,
    )
    if entry is None:
        return None
    _, env_var, fallback_model = entry

    cfg = configs.get(provider) or {}
    if not _is_provider_configured(provider, cfg, env, env_var):
        return None

    model = model_override or cfg.get("default_model") or fallback_model
    resolved_cfg = _build_resolved_config(provider, cfg, env)
    logger.info(
        "llm_provider: resolved specific %s (model=%s, source=%s)",
        provider, model, _source_for_log(provider, cfg, env, env_var),
    )
    return LLMProviderInfo(provider=provider, model=model, config=resolved_cfg)


def resolve_provider(
    integration_configs: dict[str, dict] | None,
    env: dict[str, str] | None = None,
) -> LLMProviderInfo | None:
    """Pick the highest-priority configured provider and return its info.

    ``integration_configs`` is the dict returned by
    ``fetch_integration_configs`` (or a test stub). ``env`` is a dict
    view of os.environ — injected rather than read directly so tests
    don't have to mutate the real process env.

    Returns ``None`` if no provider is configured anywhere — the agent
    worker treats this as a graceful skip, not an error. A scanner in
    an air-gapped deployment without an LLM key must still nuclei/fuzz
    the asset.
    """
    configs = integration_configs or {}
    env = env if env is not None else dict(os.environ)

    for provider, env_var, fallback_model in _PROVIDER_DEFAULTS:
        cfg = configs.get(provider) or {}

        configured = _is_provider_configured(provider, cfg, env, env_var)
        if not configured:
            continue

        model = cfg.get("default_model") or fallback_model
        resolved_cfg = _build_resolved_config(provider, cfg, env)
        logger.info(
            "llm_provider: resolved %s (model=%s, source=%s)",
            provider, model, _source_for_log(provider, cfg, env, env_var),
        )
        return LLMProviderInfo(provider=provider, model=model, config=resolved_cfg)

    return None


def _is_provider_configured(
    provider: str, cfg: dict, env: dict[str, str], env_var: str | None,
) -> bool:
    """Same gating rules as the backend's get_default_model."""
    if provider == "ollama":
        return bool(cfg.get("is_enabled"))
    if provider == "vertex_ai":
        return bool(
            cfg.get("project_id")
            or env.get("GOOGLE_CLOUD_PROJECT")
            or env.get("GCLOUD_PROJECT")
        )
    # Everyone else needs an api_key — DB value wins, env var is fallback.
    return bool(cfg.get("api_key") or (env_var and env.get(env_var)))


def _build_resolved_config(
    provider: str, cfg: dict, env: dict[str, str],
) -> dict:
    """Collapse DB + env into the single dict the adapter consumes."""
    if provider == "vertex_ai":
        return {
            "project_id": cfg.get("project_id") or env.get("GOOGLE_CLOUD_PROJECT") or env.get("GCLOUD_PROJECT") or "",
            "location": cfg.get("location") or "us-central1",
        }
    if provider == "ollama":
        base_url = (cfg.get("base_url") or "http://localhost:11434").rstrip("/")
        if not base_url.endswith("/v1"):
            base_url = base_url + "/v1"
        return {"base_url": base_url}
    # Key-based providers: DB api_key wins, env fallback.
    env_var_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "google_gemini": "GOOGLE_API_KEY",
        "groq": "GROQ_API_KEY",
    }
    api_key = cfg.get("api_key") or env.get(env_var_map.get(provider, ""), "")
    return {"api_key": api_key}


def _source_for_log(
    provider: str, cfg: dict, env: dict[str, str], env_var: str | None,
) -> str:
    """For log lines — helps operators tell whether DB or env supplied the key."""
    if provider == "vertex_ai":
        return "db" if cfg.get("project_id") else "env"
    if provider == "ollama":
        return "db"
    if cfg.get("api_key"):
        return "db"
    return "env" if (env_var and env.get(env_var)) else "none"


# ── Adapter interface ────────────────────────────────────────────
# Adapters convert the canonical Anthropic-shape content-block format
# used by the agent loop into the provider's native format and back.
# Keeps agent_worker.py free of provider branching.


class LLMProviderError(Exception):
    """Raised when an adapter can't complete a turn — SDK missing, auth
    failure, 4xx/5xx, or network error. agent_worker treats this as a
    hard stop for the current asset."""


class LLMAdapter:
    """Base class with the single required method — override in subclasses."""

    provider_name: str = ""

    def turn(
        self,
        *,
        system: str,
        messages: list[dict],
        tools: list[dict],
        max_tokens: int,
    ) -> dict:
        """Execute one tool-use turn.

        Returns ``{"content": [<anthropic-style blocks>], "stop_reason": str}``.
        Content blocks are either ``{"type":"text", "text":...}`` or
        ``{"type":"tool_use", "id", "name", "input"}``. The caller (the
        agent worker) has no knowledge of which provider actually ran.
        """
        raise NotImplementedError


# Module-level cache so the underlying SDK client (and its async httpx
# pool / Vertex ADC token) survives across Celery tasks. Without this,
# each task constructs a fresh genai.Client whose BaseApiClient schedules
# aclose() on __del__ — landing a pending Task on an event loop we're
# about to close and triggering "Task was destroyed but it is pending".
# Survives for the lifetime of the worker process; Celery worker recycle
# handles eventual cleanup.
_adapter_cache: dict[tuple, LLMAdapter] = {}


def _adapter_cache_key(info: LLMProviderInfo) -> tuple:
    cfg = info.config or {}
    if info.provider == "vertex_ai":
        return ("vertex_ai", info.model, cfg.get("project_id", ""), cfg.get("location", ""))
    if info.provider == "ollama":
        return ("ollama", info.model, cfg.get("base_url", ""))
    # Key-based providers: fingerprint the key so rotation invalidates
    # without logging the secret. Empty/missing key still produces a
    # distinct tuple from a present one.
    api_key = cfg.get("api_key") or ""
    return (info.provider, info.model, api_key[:12])


def _is_claude_model(model: str) -> bool:
    """Claude model IDs look like ``claude-sonnet-4-6`` (direct) or
    ``claude-sonnet-4-5@20250929`` (Vertex-versioned). A ``vertex/``
    prefix is sometimes applied by upstream config — strip it first.

    Used inside ``build_adapter`` to route the vertex_ai provider to
    the AnthropicVertex SDK when the model is Claude-shaped, while
    keeping Gemini models on google-genai. Lets one provider serve
    both model families with transparent dispatch.
    """
    m = (model or "").lower()
    if m.startswith("vertex/"):
        m = m[len("vertex/"):]
    return m.startswith("claude-")


def build_adapter(info: LLMProviderInfo) -> LLMAdapter:
    """Construct (or reuse) the adapter for a resolved provider.

    SDK imports happen inside the adapter constructor so the scanner
    process doesn't need every LLM SDK installed — only the ones for
    the provider it actually resolves to.

    Special case: ``vertex_ai`` + a Claude model id routes to the
    AnthropicVertex SDK instead of google-genai. That's the
    "GCP-billed Claude" path — same ADC, same project, different
    model family. Model-based dispatch avoids creating a fourth
    provider namespace for what is logically still "Vertex".
    """
    key = _adapter_cache_key(info)
    cached = _adapter_cache.get(key)
    if cached is not None:
        return cached

    p = info.provider
    if p == "anthropic":
        adapter: LLMAdapter = AnthropicAdapter(info)
    elif p in ("openai", "groq", "ollama"):
        adapter = OpenAIAdapter(info)
    elif p == "vertex_ai" and _is_claude_model(info.model):
        adapter = AnthropicVertexAdapter(info)
    elif p in ("vertex_ai", "google_gemini"):
        adapter = GoogleGenAIAdapter(info)
    else:
        raise LLMProviderError(f"No adapter for provider {p!r}")

    _adapter_cache[key] = adapter
    return adapter


# ── Anthropic adapter ────────────────────────────────────────────


class AnthropicAdapter(LLMAdapter):
    provider_name = "anthropic"

    def __init__(self, info: LLMProviderInfo):
        try:
            import anthropic  # type: ignore
        except ImportError as e:
            raise LLMProviderError(f"anthropic SDK not installed: {e}")
        api_key = info.config.get("api_key") or ""
        if not api_key:
            raise LLMProviderError("anthropic: api_key not provided")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = info.model

    def turn(self, *, system, messages, tools, max_tokens):
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system,
                tools=tools,
                messages=messages,
            )
        except Exception as e:
            raise LLMProviderError(str(e)[:300])

        blocks: list[dict] = []
        for b in resp.content:
            btype = getattr(b, "type", None)
            if btype == "text":
                blocks.append({"type": "text", "text": getattr(b, "text", "")})
            elif btype == "tool_use":
                blocks.append({
                    "type": "tool_use",
                    "id": getattr(b, "id", ""),
                    "name": getattr(b, "name", ""),
                    "input": getattr(b, "input", {}) or {},
                })
        return {"content": blocks, "stop_reason": getattr(resp, "stop_reason", "")}


# ── Anthropic-on-Vertex adapter ──────────────────────────────────
# Same wire protocol as direct Anthropic, different authentication
# path: uses GCP Application Default Credentials via the anthropic
# SDK's ``AnthropicVertex`` client. Billed through the GCP project
# that owns the ADC token, not an Anthropic account. Claude on
# Vertex is only served in specific regions (us-east5,
# europe-west1, asia-southeast1, and recently us-central1 for some
# models); the Gemini region in ``info.config['location']`` may not
# have Claude enabled, so this adapter honours a separate
# ``claude_location`` / ``AGENT_ANTHROPIC_VERTEX_REGION`` override
# before falling back to the Gemini location.


class AnthropicVertexAdapter(LLMAdapter):
    provider_name = "vertex_ai_claude"

    def __init__(self, info: LLMProviderInfo):
        try:
            from anthropic import AnthropicVertex  # type: ignore
        except ImportError as e:
            raise LLMProviderError(f"anthropic SDK not installed: {e}")

        project = info.config.get("project_id") or ""
        if not project:
            raise LLMProviderError("vertex_ai (claude): project_id not provided")

        # Region resolution — prefer explicit overrides, then default
        # to "global". The global endpoint is Anthropic-on-Vertex's
        # recommended region: Google routes to whichever backend has
        # capacity, eliminating the per-region-deployment guesswork.
        # Do NOT fall through to the Gemini location — Sonnet isn't
        # deployed in the same regions as Gemini (e.g. us-central1
        # serves Gemini but not Claude as of 2026-04), so inheriting
        # the Gemini location would produce 400s.
        region = (
            info.config.get("claude_location")
            or os.environ.get("AGENT_ANTHROPIC_VERTEX_REGION")
            or "global"
        )

        self._client = AnthropicVertex(project_id=project, region=region)
        self._model = info.model
        if self._model.startswith("vertex/"):
            self._model = self._model[len("vertex/"):]
        self._region = region

    def turn(self, *, system, messages, tools, max_tokens):
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system,
                tools=tools,
                messages=messages,
            )
        except Exception as e:
            raise LLMProviderError(str(e)[:300])

        blocks: list[dict] = []
        for b in resp.content:
            btype = getattr(b, "type", None)
            if btype == "text":
                blocks.append({"type": "text", "text": getattr(b, "text", "")})
            elif btype == "tool_use":
                blocks.append({
                    "type": "tool_use",
                    "id": getattr(b, "id", ""),
                    "name": getattr(b, "name", ""),
                    "input": getattr(b, "input", {}) or {},
                })
        return {"content": blocks, "stop_reason": getattr(resp, "stop_reason", "")}


# ── OpenAI-compatible adapter (OpenAI, Groq, Ollama) ─────────────


class OpenAIAdapter(LLMAdapter):
    """OpenAI chat completions API. Covers OpenAI, Groq, Ollama.

    Tool-use mapping:
      Anthropic tool_use block       ↔ OpenAI choice.message.tool_calls[*]
      Anthropic tool_result block    ↔ OpenAI message role="tool"
      Anthropic text block           ↔ OpenAI message content (str)
    """

    def __init__(self, info: LLMProviderInfo):
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as e:
            raise LLMProviderError(f"openai SDK not installed: {e}")
        self.provider_name = info.provider
        self._model = info.model
        cfg = info.config
        if info.provider == "openai":
            key = cfg.get("api_key") or ""
            if not key:
                raise LLMProviderError("openai: api_key not provided")
            self._client = OpenAI(api_key=key)
        elif info.provider == "groq":
            key = cfg.get("api_key") or ""
            if not key:
                raise LLMProviderError("groq: api_key not provided")
            self._client = OpenAI(api_key=key, base_url="https://api.groq.com/openai/v1")
        elif info.provider == "ollama":
            base_url = cfg.get("base_url") or "http://localhost:11434/v1"
            # Ollama accepts any api_key string
            self._client = OpenAI(api_key="ollama", base_url=base_url)
            # Strip the ollama/ prefix from the model name if present —
            # the server itself receives the raw model id.
            if self._model.startswith("ollama/"):
                self._model = self._model[len("ollama/"):]
        else:
            raise LLMProviderError(f"OpenAIAdapter: unsupported provider {info.provider!r}")

    def turn(self, *, system, messages, tools, max_tokens):
        oai_messages = [{"role": "system", "content": system}]
        oai_messages.extend(_anthropic_to_openai_messages(messages))
        oai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                max_tokens=max_tokens,
                messages=oai_messages,
                tools=oai_tools,
                tool_choice="auto",
            )
        except Exception as e:
            raise LLMProviderError(str(e)[:300])

        choice = resp.choices[0]
        msg = choice.message
        blocks: list[dict] = []
        text = (msg.content or "").strip() if hasattr(msg, "content") else ""
        if text:
            blocks.append({"type": "text", "text": text})

        for tc in (getattr(msg, "tool_calls", None) or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except (TypeError, ValueError):
                args = {}
            blocks.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.function.name,
                "input": args,
            })

        return {"content": blocks, "stop_reason": choice.finish_reason or ""}


def _anthropic_to_openai_messages(messages: list[dict]) -> list[dict]:
    """Translate Anthropic-style conversation into OpenAI chat messages.

    Anthropic keeps tool_use and tool_result blocks interleaved inside
    message content arrays. OpenAI emits a single assistant message with
    ``tool_calls`` and expects the matching ``tool`` messages (one per
    tool_use id) as separate messages.
    """
    out: list[dict] = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", [])

        if isinstance(content, str):
            # Legacy plain-string user message.
            out.append({"role": role, "content": content})
            continue

        if role == "assistant":
            text_parts: list[str] = []
            tool_calls: list[dict] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))
                elif block.get("type") == "tool_use":
                    tool_calls.append({
                        "id": block.get("id") or "",
                        "type": "function",
                        "function": {
                            "name": block.get("name") or "",
                            "arguments": json.dumps(block.get("input") or {}),
                        },
                    })
            assistant_msg: dict = {"role": "assistant"}
            if text_parts:
                assistant_msg["content"] = "".join(text_parts)
            else:
                assistant_msg["content"] = None  # OpenAI requires key present
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            out.append(assistant_msg)
            continue

        # role == "user" — may contain a mix of text + tool_result blocks.
        # OpenAI wants each tool_result as a separate `role=tool` message.
        pending_text: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                pending_text.append(block.get("text", ""))
            elif block.get("type") == "tool_result":
                if pending_text:
                    out.append({"role": "user", "content": "\n".join(pending_text)})
                    pending_text = []
                out.append({
                    "role": "tool",
                    "tool_call_id": block.get("tool_use_id") or "",
                    "content": _coerce_tool_result_content(block.get("content")),
                })
        if pending_text:
            out.append({"role": "user", "content": "\n".join(pending_text)})

    return out


def _coerce_tool_result_content(content: Any) -> str:
    """OpenAI tool messages require a string body — JSON-encode dicts/lists."""
    if isinstance(content, str):
        return content
    try:
        return json.dumps(content, default=str)
    except Exception:
        return str(content)


# ── Google GenAI adapter (Vertex AI + Gemini) ────────────────────


class GoogleGenAIAdapter(LLMAdapter):
    """Uses google-genai's unified Client — one SDK, both backends.

    Switches between Vertex (ADC, project+location) and Gemini (API key)
    by passing ``vertexai=True`` vs an ``api_key``.
    """

    def __init__(self, info: LLMProviderInfo):
        try:
            from google import genai  # type: ignore
            from google.genai import types as _types  # noqa: F401 — imported inside turn
        except ImportError as e:
            raise LLMProviderError(f"google-genai SDK not installed: {e}")

        self.provider_name = info.provider
        self._model = info.model
        if info.provider == "vertex_ai":
            project = info.config.get("project_id") or ""
            location = info.config.get("location") or "us-central1"
            if not project:
                raise LLMProviderError("vertex_ai: project_id not provided")
            self._client = genai.Client(vertexai=True, project=project, location=location)
            # Strip vertex/ prefix; SDK takes the bare model id.
            if self._model.startswith("vertex/"):
                self._model = self._model[len("vertex/"):]
        else:  # google_gemini
            key = info.config.get("api_key") or ""
            if not key:
                raise LLMProviderError("google_gemini: api_key not provided")
            self._client = genai.Client(api_key=key)

    def turn(self, *, system, messages, tools, max_tokens):
        from google.genai import types  # type: ignore

        gemini_tools = [
            types.Tool(function_declarations=[
                types.FunctionDeclaration(
                    name=t["name"],
                    description=t["description"],
                    parameters=_clean_gemini_schema(t["input_schema"]),
                )
                for t in tools
            ])
        ]
        gemini_contents = _anthropic_to_gemini_contents(messages)

        cfg = types.GenerateContentConfig(
            system_instruction=system,
            tools=gemini_tools,
            max_output_tokens=max_tokens,
        )

        try:
            resp = self._client.models.generate_content(
                model=self._model,
                contents=gemini_contents,
                config=cfg,
            )
        except Exception as e:
            raise LLMProviderError(str(e)[:300])

        blocks: list[dict] = []
        stop_reason = "end_turn"
        for candidate in (resp.candidates or []):
            stop_reason = getattr(candidate, "finish_reason", None) or stop_reason
            content = getattr(candidate, "content", None)
            if content is None:
                continue
            for part in (getattr(content, "parts", None) or []):
                fn_call = getattr(part, "function_call", None)
                if fn_call:
                    # Gemini doesn't return a stable id per call; synthesize one
                    # the agent loop can match against tool_result replies.
                    blocks.append({
                        "type": "tool_use",
                        "id": f"gemini-{fn_call.name}-{len(blocks)}",
                        "name": fn_call.name,
                        "input": dict(fn_call.args or {}),
                    })
                    continue
                text = getattr(part, "text", None)
                if text:
                    blocks.append({"type": "text", "text": text})

        return {"content": blocks, "stop_reason": str(stop_reason)}


def _clean_gemini_schema(schema: dict) -> dict:
    """Gemini rejects JSON-Schema fields it doesn't know about.

    Strip ``$schema``, ``additionalProperties``, ``definitions``, etc.
    Retain ``type`` / ``properties`` / ``required`` / ``items`` /
    ``enum`` / ``description`` which are the subset Gemini honours.
    """
    KEEP = {"type", "properties", "required", "items", "enum", "description"}
    if not isinstance(schema, dict):
        return {"type": "object"}
    out: dict = {k: v for k, v in schema.items() if k in KEEP}
    # Recurse into properties
    if isinstance(out.get("properties"), dict):
        out["properties"] = {
            k: _clean_gemini_schema(v) if isinstance(v, dict) else v
            for k, v in out["properties"].items()
        }
    if isinstance(out.get("items"), dict):
        out["items"] = _clean_gemini_schema(out["items"])
    return out


def _anthropic_to_gemini_contents(messages: list[dict]) -> list:
    """Convert Anthropic message history to a list[genai.types.Content]."""
    from google.genai import types  # type: ignore

    out: list = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", [])
        # Gemini uses "user" and "model" for roles — translate "assistant".
        g_role = "model" if role == "assistant" else "user"

        if isinstance(content, str):
            out.append(types.Content(role=g_role, parts=[types.Part.from_text(text=content)]))
            continue

        parts = []
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                parts.append(types.Part.from_text(text=block.get("text", "")))
            elif btype == "tool_use":
                parts.append(types.Part.from_function_call(
                    name=block.get("name") or "",
                    args=block.get("input") or {},
                ))
            elif btype == "tool_result":
                response_payload = _coerce_gemini_tool_response(block.get("content"))
                # Gemini identifies function_response by name, not id — we
                # don't have the name here, so we look it up from the
                # paired earlier tool_use. In practice the agent loop
                # always pairs results back-to-back with the preceding
                # assistant turn; fall back to a placeholder if not.
                parts.append(types.Part.from_function_response(
                    name=_guess_tool_name_for_result(messages, block),
                    response=response_payload,
                ))
        if parts:
            out.append(types.Content(role=g_role, parts=parts))

    return out


def _coerce_gemini_tool_response(content: Any) -> dict:
    """Gemini expects tool responses as a dict. JSON-decode if needed."""
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        try:
            decoded = json.loads(content)
            if isinstance(decoded, dict):
                return decoded
        except (TypeError, ValueError):
            pass
        return {"result": content}
    return {"result": str(content)}


def _guess_tool_name_for_result(messages: list[dict], result_block: dict) -> str:
    """Walk back to find the tool_use whose id matches this tool_result.

    Gemini keys function_response by name (not id). The agent loop knows
    them by id, so we reverse-lookup the name from the most recent
    matching tool_use block.
    """
    target_id = result_block.get("tool_use_id") or ""
    for m in reversed(messages):
        content = m.get("content", [])
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("id") == target_id:
                return block.get("name") or "unknown_tool"
    return "unknown_tool"
