"""Shared multi-provider LLM call helper.

Extracted from llm_vuln_validator._call_llm so other services (attack chain
narrator, validation agents, etc.) can reuse the same provider-selection
logic without copy-pasting.

Provider selection: tries Anthropic first (ANTHROPIC_API_KEY), falls back
to OpenAI (OPENAI_API_KEY). The model can be pinned via `model` param;
otherwise a sensible default is used per provider.

Kept synchronous on purpose — callers (post_ingest pipeline, correlator)
are sync code paths. Use httpx.Client with a generous timeout.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def call_llm(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 2048,
    model_env: str | None = None,
) -> str:
    """Multi-provider LLM call.

    Args:
        system_prompt: System instructions for the model.
        user_prompt: User message content.
        max_tokens: Max output tokens.
        model_env: Env var name to read per-feature model override (e.g.
            "LLM_VALIDATION_MODEL", "LLM_NARRATIVE_MODEL"). If set and
            present in the environment, that value overrides the default
            model for whichever provider is selected.

    Returns empty string if no provider is configured or on failure —
    callers should treat "" as a soft failure and fall back gracefully.
    """
    import httpx

    # Try Anthropic first
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        model = (model_env and os.environ.get(model_env)) or "claude-haiku-4-5-20251001"
        try:
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
        except Exception as e:
            logger.warning("Anthropic LLM call failed: %s", e)
            # fall through to OpenAI fallback

    # Fall back to OpenAI
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key:
        model = (model_env and os.environ.get(model_env)) or "gpt-4o-mini"
        try:
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
        except Exception as e:
            logger.warning("OpenAI LLM call failed: %s", e)

    logger.debug("No LLM provider configured (ANTHROPIC_API_KEY or OPENAI_API_KEY)")
    return ""
