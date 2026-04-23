"""Single source of truth for LLM provider routing.

Everything that needs to talk to an LLM — the agent engine, the copilot,
the pentest-report extractor, the mapping inference, the alert triage,
the attack-chain narrator — goes through this module. Adding a provider,
fixing Claude-on-Vertex, or changing default-model priority happens here
and only here.

Concepts:

- **Provider**: one of ``anthropic`` / ``openai`` / ``google_gemini`` /
  ``vertex_ai`` / ``groq`` / ``ollama``.
- **Model**: a string like ``claude-sonnet-4-6`` or
  ``vertex/gemini-2.5-flash``. The router maps model → provider.
- **Client**: an SDK client object obtained from ``get_client(...)``.
  Claude-on-Vertex is special — a model like ``claude-sonnet-4-6`` on a
  Vertex-configured deployment returns an ``AnthropicVertex`` client so
  the GCP project bills the call. This is the same trick the VM scanner
  already uses in ``hakuna-vm-scanner/scanner/vm/llm_provider.py``.

Why a class and not just module-level functions:

- Tests can swap ``LLMRouter`` subclasses in without monkeypatching a
  half-dozen underscore-prefixed helpers.
- Client cache lives on the instance, not at import scope — no more
  "restart the process to clear the anthropic client" foot-guns.

The module-level ``router`` singleton is what production code uses.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any, Optional

from sqlalchemy.orm import Session

from models.models import IntegrationConfig

logger = logging.getLogger(__name__)


# ── Model → provider mapping ──────────────────────────────────────────

PROVIDER_FOR_MODEL: dict[str, str] = {
    # Anthropic direct
    "claude-sonnet-4-6": "anthropic",
    "claude-haiku-4-5-20251001": "anthropic",
    "claude-opus-4-6": "anthropic",
    # OpenAI
    "gpt-4o": "openai",
    "gpt-4o-mini": "openai",
    "gpt-4.1": "openai",
    "gpt-4.1-mini": "openai",
    "o3-mini": "openai",
    # Google Gemini (direct API key)
    "gemini-2.5-flash": "google_gemini",
    "gemini-2.5-pro": "google_gemini",
    "gemini-2.0-flash": "google_gemini",
    # Groq
    "llama-3.3-70b-versatile": "groq",
    "llama-3.1-8b-instant": "groq",
    "mixtral-8x7b-32768": "groq",
    "deepseek-r1-distill-llama-70b": "groq",
    # Vertex AI (GCP-native — uses ADC, no API key needed)
    "vertex/gemini-2.5-flash": "vertex_ai",
    "vertex/gemini-2.5-pro": "vertex_ai",
    "vertex/gemini-2.0-flash": "vertex_ai",
    # Claude on Vertex — billed through the GCP project instead of an
    # Anthropic account. Model IDs here use Vertex's version-suffix style.
    "vertex/claude-sonnet-4-5@20250929": "vertex_ai",
    "vertex/claude-haiku-4-5@20251001": "vertex_ai",
}


# ── Priority order for "pick the best configured provider" ───────────
#
# Entries: (provider, env_var, fallback_model). Order is preserved —
# first configured provider wins. Anthropic is ahead of vertex_ai to
# match the VM scanner (hakuna-vm-scanner/scanner/vm/llm_provider.py)
# and the backend's prior behavior; deployments that prefer Vertex
# billing simply don't set ANTHROPIC_API_KEY.
_PROVIDER_DEFAULTS: list[tuple[str, Optional[str], str]] = [
    ("anthropic",     "ANTHROPIC_API_KEY",    "claude-sonnet-4-6"),
    ("openai",        "OPENAI_API_KEY",       "gpt-4o"),
    ("vertex_ai",     "GOOGLE_CLOUD_PROJECT", "vertex/gemini-2.5-flash"),
    ("google_gemini", "GOOGLE_API_KEY",       "gemini-2.5-flash"),
    ("groq",          "GROQ_API_KEY",         "llama-3.3-70b-versatile"),
    ("ollama",        None,                   "ollama/llama3"),
]

_ENV_VAR_FOR_PROVIDER: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "google_gemini": "GOOGLE_API_KEY",
    "groq": "GROQ_API_KEY",
}


class LLMRouter:
    """Central routing for LLM provider resolution and client construction.

    Stateless with respect to the DB — every method takes a ``Session``.
    Holds an internal client cache keyed by provider + credential
    fingerprint so we don't rebuild the SDK client on every call.
    """

    def __init__(self) -> None:
        # key → client. Bounded at 10 entries to defend against a runaway
        # multi-tenant config reload. Capacity is plenty for "a few
        # providers with at most a rotated key."
        self._client_cache: dict[str, Any] = {}

    # ── Model → provider resolution ────────────────────────────────

    def detect_provider(self, model: str) -> str:
        """Detect provider from model name.

        Explicit table lookup wins; otherwise fall back to prefix
        heuristics so bare Vertex-style IDs (``vertex/whatever``) or
        future Claude/GPT/Gemini releases don't need a PR to route
        correctly.
        """
        if model in PROVIDER_FOR_MODEL:
            return PROVIDER_FOR_MODEL[model]
        if model.startswith("vertex/"):
            return "vertex_ai"
        if model.startswith("ollama/"):
            return "ollama"
        if model.startswith("claude"):
            return "anthropic"
        if model.startswith("gpt") or model.startswith("o3") or model.startswith("o1"):
            return "openai"
        if model.startswith("gemini"):
            return "google_gemini"
        if model.startswith(("llama", "mixtral", "deepseek")):
            return "groq"
        return "anthropic"  # conservative default

    def is_claude_model(self, model: str) -> bool:
        """True for Claude IDs, direct or Vertex-style.

        Used to decide whether a ``vertex_ai`` provider routes to the
        AnthropicVertex SDK (for Claude) or the google-genai SDK
        (for Gemini). Version suffixes (``@20250929``) are ignored.
        """
        m = (model or "").lower()
        if m.startswith("vertex/"):
            m = m[len("vertex/"):]
        return m.startswith("claude")

    # ── Configuration / validation ─────────────────────────────────

    def _provider_cfg(self, db: Session, provider: str) -> Optional[IntegrationConfig]:
        return db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()

    def _has_api_key(self, cfg: Optional[IntegrationConfig], env_var: Optional[str]) -> bool:
        if cfg and cfg.config and cfg.config.get("api_key"):
            return True
        return bool(env_var and os.environ.get(env_var))

    def _has_vertex_project(self, cfg: Optional[IntegrationConfig]) -> bool:
        if cfg and cfg.config and cfg.config.get("project_id"):
            return True
        return bool(os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT"))

    def is_provider_configured(self, db: Session, provider: str) -> bool:
        """True when the provider has enough config to make a real call.

        Important subtlety: ``anthropic`` returns True if EITHER a direct
        Anthropic key is set OR Vertex is configured — because the
        AnthropicVertex SDK can serve Claude via GCP. Without this the
        audit worker would fall back to Gemini on a Vertex-only
        deployment even when the operator explicitly asked for Claude.
        """
        if provider == "ollama":
            cfg = self._provider_cfg(db, "ollama")
            return bool(cfg and cfg.is_enabled)
        if provider == "vertex_ai":
            return self._has_vertex_project(self._provider_cfg(db, "vertex_ai"))
        if provider == "anthropic":
            if self._has_api_key(self._provider_cfg(db, "anthropic"), "ANTHROPIC_API_KEY"):
                return True
            return self._has_vertex_project(self._provider_cfg(db, "vertex_ai"))
        env_var = _ENV_VAR_FOR_PROVIDER.get(provider)
        return self._has_api_key(self._provider_cfg(db, provider), env_var)

    def validate_provider(self, db: Session, provider: str) -> None:
        """Raise RuntimeError if the provider isn't configured."""
        if self.is_provider_configured(db, provider):
            return
        if provider == "vertex_ai":
            raise RuntimeError(
                "Vertex AI not configured. Set GOOGLE_CLOUD_PROJECT or configure "
                "it in Settings > Integrations."
            )
        if provider == "ollama":
            raise RuntimeError(
                "Ollama not enabled. Go to Settings > Integrations to configure it."
            )
        display = provider.replace("_", " ").title()
        raise RuntimeError(
            f"{display} API key not configured. "
            "Go to Settings > Integrations to set your API key."
        )

    # ── Default / fallback model selection ─────────────────────────

    def get_default_model(self, db: Session) -> str:
        """Return the default model for whatever is configured.

        Walks ``_PROVIDER_DEFAULTS`` in order and picks the first
        configured provider. If that provider has an explicit
        ``default_model`` in its IntegrationConfig, use it; otherwise
        use the hardcoded fallback.

        Last-ditch fallback: Sonnet 4.6. If nothing is configured the
        caller's first real call will raise a clean "not configured"
        error rather than timing out.
        """
        for provider, env_var, fallback_model in _PROVIDER_DEFAULTS:
            cfg = self._provider_cfg(db, provider)

            if provider == "ollama":
                if not (cfg and cfg.is_enabled):
                    continue
            elif provider == "vertex_ai":
                if not self._has_vertex_project(cfg):
                    continue
            else:
                if not self._has_api_key(cfg, env_var):
                    continue

            if cfg and cfg.config:
                explicit = cfg.config.get("default_model")
                if explicit:
                    return explicit
            return fallback_model

        return "claude-sonnet-4-6"

    def find_fallback_model(
        self,
        db: Session,
        *,
        exclude: set[str],
        tool_count: int = 0,
    ) -> Optional[tuple[str, str]]:
        """Find an alternative (model, provider) when the primary fails.

        Groq is skipped for high-tool-count agents — its on-demand tier
        has a ~12K TPM per-request limit and tool schemas alone exceed
        that for the copilot.
        """
        for provider, _env, fallback_model in _PROVIDER_DEFAULTS:
            if provider in exclude:
                continue
            if provider == "groq" and tool_count > 10:
                continue
            if self.is_provider_configured(db, provider):
                return fallback_model, provider
        return None

    def get_available_providers(self, db: Session) -> list[dict]:
        """Return every configured provider with its models — used by the UI."""
        info = {
            "anthropic": {
                "display": "Anthropic (Claude)",
                "models": ["claude-sonnet-4-6", "claude-haiku-4-5-20251001", "claude-opus-4-6"],
            },
            "groq": {
                "display": "Groq",
                "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "deepseek-r1-distill-llama-70b"],
            },
            "openai": {
                "display": "OpenAI",
                "models": ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3-mini"],
            },
            "google_gemini": {
                "display": "Google Gemini",
                "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
            },
            "ollama": {
                "display": "Ollama (Local)",
                "models": [],  # populated at runtime
            },
            "vertex_ai": {
                "display": "Google Vertex AI",
                "models": [
                    "vertex/gemini-2.5-flash",
                    "vertex/gemini-2.5-pro",
                    "vertex/gemini-2.0-flash",
                ],
            },
        }

        result = []
        for provider, meta in info.items():
            cfg = self._provider_cfg(db, provider)
            if provider == "ollama":
                if not (cfg and cfg.is_enabled):
                    continue
                models = self._list_ollama_models(cfg)
                result.append({"provider": provider, "display": meta["display"], "models": models, "configured": True})
            elif provider == "vertex_ai":
                if not self._has_vertex_project(cfg):
                    continue
                # When Vertex is up, Claude-on-Vertex is also available.
                models = list(meta["models"])
                models += ["vertex/claude-sonnet-4-5@20250929", "vertex/claude-haiku-4-5@20251001"]
                result.append({"provider": provider, "display": meta["display"], "models": models, "configured": True})
            else:
                env_var = _ENV_VAR_FOR_PROVIDER.get(provider)
                if not self._has_api_key(cfg, env_var):
                    continue
                result.append({"provider": provider, "display": meta["display"], "models": meta["models"], "configured": True})
        return result

    def _list_ollama_models(self, cfg: Optional[IntegrationConfig]) -> list[str]:
        """Probe the Ollama server for installed models. Best-effort — returns
        a small default list if the server is unreachable."""
        base_url = "http://localhost:11434"
        if cfg and cfg.config:
            base_url = cfg.config.get("base_url", base_url).rstrip("/")
        try:
            req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
            return [f"ollama/{m['name']}" for m in data.get("models", [])]
        except Exception:
            return ["ollama/llama3", "ollama/mistral", "ollama/codellama"]

    # ── Client factories ───────────────────────────────────────────

    def _cached(self, key: str, factory):
        if key not in self._client_cache:
            if len(self._client_cache) > 10:
                self._client_cache.clear()
            self._client_cache[key] = factory()
        return self._client_cache[key]

    def _resolve_api_key(self, db: Session, provider: str, env_var: str) -> str:
        cfg = self._provider_cfg(db, provider)
        key = None
        if cfg and cfg.config:
            key = cfg.config.get("api_key")
        if not key:
            key = os.environ.get(env_var)
        if not key:
            display = provider.replace("_", " ").title()
            raise RuntimeError(
                f"{display} API key not configured. "
                "Go to Settings > Integrations to set your API key."
            )
        return key

    def _resolve_vertex_project(self, db: Session) -> tuple[str, str]:
        cfg = self._provider_cfg(db, "vertex_ai")
        project = None
        location = "us-central1"
        if cfg and cfg.config:
            project = cfg.config.get("project_id") or None
            location = cfg.config.get("location") or "us-central1"
        if not project:
            project = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT")
        if not project:
            raise RuntimeError(
                "Vertex AI requires a GCP project. Set GOOGLE_CLOUD_PROJECT env var "
                "or configure it in Settings > Integrations."
            )
        return project, location

    def _resolve_claude_vertex_region(self, db: Session) -> str:
        """Pick the region for Claude-on-Vertex.

        Anthropic's Vertex deployment covers a narrower set of regions
        than Gemini (``us-east5``, ``europe-west1``, ``asia-southeast1``,
        plus some models in ``us-central1``). The Gemini ``location``
        on the IntegrationConfig row may not have Claude enabled, so we
        honour an explicit override first and fall back to ``global`` —
        Google's recommendation for Anthropic-on-Vertex, which routes
        to whichever backend has capacity.
        """
        cfg = self._provider_cfg(db, "vertex_ai")
        if cfg and cfg.config and cfg.config.get("claude_location"):
            return cfg.config["claude_location"]
        return os.environ.get("AGENT_ANTHROPIC_VERTEX_REGION") or "global"

    def get_anthropic_client(self, db: Session, model: str | None = None):
        """Return an Anthropic-compatible client for a Claude model.

        Preference order:
        1. Direct ``Anthropic`` client if ``ANTHROPIC_API_KEY`` (env or
           IntegrationConfig) is available.
        2. ``AnthropicVertex`` if Vertex AI is configured. GCP project
           pays; same wire protocol, so callers don't branch.
        3. Raise.

        Same client interface both ways — ``client.messages.create(...)``
        works identically — so the agent loops don't need to know which
        was picked.
        """
        # 1. Direct Anthropic key
        cfg = self._provider_cfg(db, "anthropic")
        api_key = None
        if cfg and cfg.config:
            api_key = cfg.config.get("api_key")
        if not api_key:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            from anthropic import Anthropic
            return self._cached(f"anthropic:{api_key[:12]}", lambda: Anthropic(api_key=api_key))

        # 2. Claude-on-Vertex
        if self._has_vertex_project(self._provider_cfg(db, "vertex_ai")):
            return self._get_anthropic_vertex_client(db)

        # 3. Nothing configured
        raise RuntimeError(
            "Anthropic API key not configured. "
            "Go to Settings > Integrations to set your API key, "
            "or configure Vertex AI to use Claude on GCP."
        )

    def _get_anthropic_vertex_client(self, db: Session):
        project, _gemini_location = self._resolve_vertex_project(db)
        region = self._resolve_claude_vertex_region(db)
        from anthropic import AnthropicVertex
        return self._cached(
            f"anthropic_vertex:{project}:{region}",
            lambda: AnthropicVertex(project_id=project, region=region),
        )

    def get_openai_client(self, db: Session):
        api_key = self._resolve_api_key(db, "openai", "OPENAI_API_KEY")
        from openai import OpenAI
        return self._cached(f"openai:{api_key[:12]}", lambda: OpenAI(api_key=api_key))

    def get_gemini_client(self, db: Session):
        api_key = self._resolve_api_key(db, "google_gemini", "GOOGLE_API_KEY")
        from google import genai
        return self._cached(f"gemini:{api_key[:12]}", lambda: genai.Client(api_key=api_key))

    def get_vertex_client(self, db: Session):
        project, location = self._resolve_vertex_project(db)
        from google import genai
        return self._cached(
            f"vertex:{project}:{location}",
            lambda: genai.Client(vertexai=True, project=project, location=location),
        )

    def get_groq_client(self, db: Session):
        api_key = self._resolve_api_key(db, "groq", "GROQ_API_KEY")
        from groq import Groq
        return self._cached(f"groq:{api_key[:12]}", lambda: Groq(api_key=api_key))

    def get_ollama_client(self, db: Session):
        cfg = self._provider_cfg(db, "ollama")
        base_url = "http://localhost:11434/v1"
        if cfg and cfg.config:
            base_url = cfg.config.get("base_url", base_url).rstrip("/")
            if not base_url.endswith("/v1"):
                base_url = base_url.rstrip("/") + "/v1"
        from openai import OpenAI
        return self._cached(
            f"ollama:{base_url}",
            lambda: OpenAI(base_url=base_url, api_key="ollama"),
        )

    def get_claude_client(self, db: Session, model: str):
        """Client for any Claude model, regardless of provider routing.

        Centralizes the Claude-on-Vertex decision so callers just say
        "I want to call Claude" without caring whether that's direct
        or via Vertex.
        """
        return self.get_anthropic_client(db, model)

    # ── Unified entrypoint for simple one-shot calls ──────────────

    def call(
        self,
        db: Session,
        *,
        system: str | None = None,
        user: str,
        max_tokens: int = 2048,
        model: str | None = None,
    ) -> tuple[str, str]:
        """Provider-agnostic single-turn call. Returns (text, model_id).

        ``system`` is optional — some extraction paths embed instructions
        in the user message and don't want a system prompt.

        Callers that need tool-use, streaming, or HITL should use the
        agent engine — this is the lightweight path for services like
        the pentest extractor, mapping inference, alert triage.
        """
        resolved_model = model or self.get_default_model(db)
        provider = self.detect_provider(resolved_model)

        logger.debug("LLMRouter.call: provider=%s model=%s", provider, resolved_model)

        if provider == "anthropic" or (provider == "vertex_ai" and self.is_claude_model(resolved_model)):
            client = self.get_anthropic_client(db, resolved_model)
            api_model = resolved_model.removeprefix("vertex/") if resolved_model.startswith("vertex/") else resolved_model
            kwargs: dict[str, Any] = {
                "model": api_model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": user}],
            }
            if system:
                kwargs["system"] = system
            resp = client.messages.create(**kwargs)
            return resp.content[0].text, resolved_model

        if provider in ("openai", "groq", "ollama"):
            if provider == "openai":
                client = self.get_openai_client(db)
            elif provider == "groq":
                client = self.get_groq_client(db)
            else:
                client = self.get_ollama_client(db)
            api_model = resolved_model.removeprefix("ollama/") if resolved_model.startswith("ollama/") else resolved_model
            messages: list[dict[str, Any]] = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": user})
            resp = client.chat.completions.create(
                model=api_model,
                max_tokens=max_tokens,
                messages=messages,
            )
            return resp.choices[0].message.content, resolved_model

        if provider in ("google_gemini", "vertex_ai"):
            from google.genai import types as genai_types
            if provider == "vertex_ai":
                client = self.get_vertex_client(db)
                api_model = resolved_model.removeprefix("vertex/")
            else:
                client = self.get_gemini_client(db)
                api_model = resolved_model
            config_kwargs: dict[str, Any] = {"max_output_tokens": max_tokens}
            if system:
                config_kwargs["system_instruction"] = system
            resp = client.models.generate_content(
                model=api_model,
                contents=user,
                config=genai_types.GenerateContentConfig(**config_kwargs),
            )
            return (resp.text or "").strip(), resolved_model

        raise RuntimeError(f"Unsupported provider for LLM call: {provider}")


# ── Module-level singleton ────────────────────────────────────────────

router = LLMRouter()
