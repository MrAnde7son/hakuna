"""Shared LLM dispatch helper for non-agent services.

Picks whichever provider is configured for the org (Anthropic, OpenAI, Gemini,
Vertex, Groq, Ollama) via `agents.agent_engine.get_default_model` and makes a
single-shot system+user prompt call. Returns `(response_text, model_id)`.

Used by services/mapping_inference and services/alert_triage. Agent-style
multi-turn work stays in `agents.agent_engine`; this wrapper is only for
one-shot analytical calls.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def call_llm(db: Session, system_prompt: str, user_prompt: str, *,
             max_tokens: int = 2048,
             model_override: Optional[str] = None) -> tuple[str, str]:
    """Call the org's configured LLM with a single system+user pair.

    Returns (response_text, model_id). Raises RuntimeError if no provider is
    configured. Never streams.
    """
    from agents.agent_engine import (
        get_default_model, detect_provider,
        _get_anthropic_client, _get_openai_client, _get_gemini_client,
        _get_vertex_client, _get_groq_client, _get_ollama_client,
    )

    model = model_override or get_default_model(db)
    provider = detect_provider(model)

    logger.debug("LLM dispatch: provider=%s model=%s", provider, model)

    if provider == "anthropic":
        client = _get_anthropic_client(db)
        resp = client.messages.create(
            model=model, max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return resp.content[0].text, model

    if provider in ("openai", "groq", "ollama"):
        if provider == "openai":
            client = _get_openai_client(db)
        elif provider == "groq":
            client = _get_groq_client(db)
        else:
            client = _get_ollama_client(db)
        api_model = model.replace("ollama/", "") if model.startswith("ollama/") else model
        resp = client.chat.completions.create(
            model=api_model, max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return resp.choices[0].message.content, model

    if provider in ("google_gemini", "vertex_ai"):
        # Gemini SDK doesn't have a distinct system role in generate_content;
        # prepend the system prompt to the user content.
        if provider == "vertex_ai":
            client = _get_vertex_client(db)
            api_model = model.replace("vertex/", "")
        else:
            client = _get_gemini_client(db)
            api_model = model
        combined = f"{system_prompt}\n\n{user_prompt}"
        resp = client.models.generate_content(
            model=api_model, contents=combined,
        )
        return resp.text, model

    raise RuntimeError(f"Unsupported provider for LLM dispatch: {provider}")
