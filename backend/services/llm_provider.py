"""Shared multi-provider LLM call helper.

Used by lightweight services that need a one-shot LLM call without the
full agent loop (tool use, traces, approvals). Examples:
  - services.llm_vuln_validator (#11) — classify Nuclei findings
  - services.attack_chain_narrator (#21) — generate attack narratives
  - hakuna-scanner's llm_js_endpoints (#10) — extract endpoints from JS

IMPORTANT: this module follows the SAME provider selection as the agent
engine so it honors whatever provider the system is currently configured
for (Anthropic, OpenAI, Gemini direct, **Vertex AI**, Groq, Ollama).

Provider selection order, handled via agent_engine.get_default_model():
    1. If an IntegrationConfig row has an explicit default_model, use it.
    2. Otherwise, pick the highest-priority provider with credentials:
       vertex_ai → anthropic → openai → google_gemini → groq → ollama.

Call pattern: synchronous, best-effort. Returns "" on any error or when
no provider is configured — callers treat empty as a soft failure.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


def call_llm(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 2048,
    model_env: str | None = None,
    db=None,
) -> str:
    """Provider-agnostic LLM call.

    Args:
        system_prompt: System instructions.
        user_prompt: User message content.
        max_tokens: Max output tokens.
        model_env: Env var name to read a per-feature model override
            (e.g. "LLM_VALIDATION_MODEL"). When set and the env var is
            present, that model is used (and its provider is detected
            from the model name).
        db: Optional SQLAlchemy Session. When provided, IntegrationConfig
            rows are consulted for model defaults and API keys (this is
            how the agent engine discovers Vertex AI / Gemini / Ollama).
            When None, we fall back to env-var-only resolution.

    Returns empty string if no provider is configured or on failure.
    """
    # Resolve model (feature override → system default → hardcoded fallback)
    model = _resolve_model(model_env, db)
    provider = _detect_provider(model)

    logger.debug("LLM call: provider=%s model=%s max_tokens=%d", provider, model, max_tokens)

    try:
        if provider == "anthropic":
            return _call_anthropic(system_prompt, user_prompt, max_tokens, model, db)
        if provider == "openai":
            return _call_openai(system_prompt, user_prompt, max_tokens, model, db)
        if provider in ("vertex_ai", "google_gemini"):
            return _call_gemini(system_prompt, user_prompt, max_tokens, model, provider, db)
        if provider == "groq":
            return _call_groq(system_prompt, user_prompt, max_tokens, model, db)
        if provider == "ollama":
            return _call_ollama(system_prompt, user_prompt, max_tokens, model, db)
    except Exception as e:
        logger.warning("LLM call via %s failed: %s", provider, e)
        return ""

    logger.debug("No LLM provider matched for model=%s", model)
    return ""


# ── Model + provider resolution ────────────────────────────────────────


def _resolve_model(model_env: str | None, db) -> str:
    """Pick the model to use.

    Priority:
      1. Env var named by `model_env` (feature-specific override).
      2. agent_engine.get_default_model(db) — respects IntegrationConfig.
      3. Env var HAKUNA_DEFAULT_MODEL (ops override).
      4. "claude-haiku-4-5-20251001" (last-ditch fallback; many callers
         use Haiku-tier tasks anyway).
    """
    if model_env:
        override = os.environ.get(model_env)
        if override:
            return override

    if db is not None:
        try:
            from agents.agent_engine import get_default_model
            m = get_default_model(db)
            if m:
                return m
        except Exception as e:
            logger.debug("get_default_model failed, falling back: %s", e)

    return os.environ.get("HAKUNA_DEFAULT_MODEL") or "claude-haiku-4-5-20251001"


def _detect_provider(model: str) -> str:
    """Detect provider from model name. Mirrors agent_engine.detect_provider."""
    try:
        from agents.agent_engine import detect_provider
        return detect_provider(model)
    except Exception:
        pass

    # Fallback heuristic if agent_engine isn't importable (e.g. scanner ctx)
    if model.startswith("vertex/"):
        return "vertex_ai"
    if model.startswith("ollama/"):
        return "ollama"
    if model.startswith("claude"):
        return "anthropic"
    if model.startswith(("gpt", "o1", "o3")):
        return "openai"
    if model.startswith("gemini"):
        return "google_gemini"
    if model.startswith(("llama", "mixtral", "deepseek")):
        return "groq"
    return "anthropic"


# ── Per-provider backends ──────────────────────────────────────────────


def _call_anthropic(system_prompt: str, user_prompt: str, max_tokens: int, model: str, db) -> str:
    import httpx

    api_key = _get_key(db, "anthropic", "ANTHROPIC_API_KEY")
    if not api_key:
        return ""

    with httpx.Client() as client:
        resp = client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]


def _call_openai(system_prompt: str, user_prompt: str, max_tokens: int, model: str, db) -> str:
    import httpx

    api_key = _get_key(db, "openai", "OPENAI_API_KEY")
    if not api_key:
        return ""

    with httpx.Client() as client:
        resp = client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


def _call_gemini(system_prompt: str, user_prompt: str, max_tokens: int, model: str, provider: str, db) -> str:
    """Call Gemini via Vertex AI (ADC) or direct API key.

    Uses the same google-genai client factory as the agent engine so
    IntegrationConfig project_id/location settings are respected.
    """
    if db is None:
        logger.debug("Gemini/Vertex call requires db session for client setup")
        return ""

    if provider == "vertex_ai":
        # Vertex uses bare model names (the "vertex/" prefix is stripped)
        model = model.removeprefix("vertex/")
        from agents.agent_engine import _get_vertex_client
        try:
            client = _get_vertex_client(db)
        except RuntimeError as e:
            logger.debug("Vertex client unavailable: %s", e)
            return ""
    else:
        from agents.agent_engine import _get_gemini_client
        try:
            client = _get_gemini_client(db)
        except RuntimeError as e:
            logger.debug("Gemini client unavailable: %s", e)
            return ""

    from google.genai import types as genai_types

    # Gemini takes system instructions via system_instruction, not a message role
    resp = client.models.generate_content(
        model=model,
        contents=user_prompt,
        config=genai_types.GenerateContentConfig(
            system_instruction=system_prompt,
            max_output_tokens=max_tokens,
        ),
    )
    return (resp.text or "").strip()


def _call_groq(system_prompt: str, user_prompt: str, max_tokens: int, model: str, db) -> str:
    import httpx

    api_key = _get_key(db, "groq", "GROQ_API_KEY")
    if not api_key:
        return ""

    with httpx.Client() as client:
        resp = client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


def _call_ollama(system_prompt: str, user_prompt: str, max_tokens: int, model: str, db) -> str:
    """Ollama uses the OpenAI-compatible /v1/chat/completions endpoint."""
    import httpx

    if db is None:
        return ""

    try:
        from models.models import IntegrationConfig
        cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == "ollama").first()
        if not cfg or not cfg.is_enabled:
            return ""
        base_url = (cfg.config or {}).get("base_url") or "http://localhost:11434"
    except Exception:
        base_url = os.environ.get("OLLAMA_BASE_URL") or "http://localhost:11434"

    # Strip the "ollama/" prefix from the model name
    model_name = model.removeprefix("ollama/")

    with httpx.Client() as client:
        resp = client.post(
            f"{base_url}/v1/chat/completions",
            headers={"Content-Type": "application/json"},
            json={
                "model": model_name,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=120.0,  # local models can be slow
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


def _get_key(db, provider: str, env_var: str) -> Optional[str]:
    """Resolve an API key from IntegrationConfig (if db available) or env var.

    Returns None instead of raising — callers will return "" to signal
    the service has gracefully degraded.
    """
    if db is not None:
        try:
            from models.models import IntegrationConfig
            cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
            if cfg and cfg.config:
                key = cfg.config.get("api_key")
                if key:
                    return key
        except Exception as e:
            logger.debug("IntegrationConfig lookup failed for %s: %s", provider, e)
    return os.environ.get(env_var)
