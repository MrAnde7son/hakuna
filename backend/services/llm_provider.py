"""Graceful best-effort LLM call helper.

Thin wrapper around ``core.llm_router.router.call`` that:

- Returns ``""`` on any failure (rather than raising) — used by
  services that should degrade silently when the LLM is unavailable
  (llm_vuln_validator, attack_chain_narrator, js-endpoint extractor).
- Wraps the call in an ``llm_feedback`` span for telemetry.
- Honours a per-feature env-var model override (``model_env``) so ops
  can pin specific callers to a specific model without touching code.

Callers that want exceptions or don't need telemetry should use
``core.llm_router.router.call`` or ``services.llm_dispatch.call_llm``
directly.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from core.llm_router import router

logger = logging.getLogger(__name__)


def call_llm(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 2048,
    model_env: str | None = None,
    db=None,
    *,
    surface: str = "llm_provider",
    org_id: int | None = None,
    user_id: int | None = None,
    surface_ref_type: str | None = None,
    surface_ref_id: str | None = None,
) -> str:
    """Provider-agnostic LLM call — returns "" on any failure.

    Args:
        system_prompt: System instructions.
        user_prompt: User message content.
        max_tokens: Max output tokens.
        model_env: Env var name to read a per-feature model override
            (e.g. "LLM_VALIDATION_MODEL").
        db: SQLAlchemy session. Required — IntegrationConfig + Vertex
            project resolution happens against the DB.
        surface/org_id/user_id/surface_ref_*: telemetry fields routed
            to ``services.llm_feedback``.

    Returns empty string if no provider is configured or on failure.
    """
    from services import llm_feedback

    if db is None:
        logger.debug("call_llm invoked without db session — cannot resolve provider")
        return ""

    model_override: Optional[str] = None
    if model_env:
        model_override = os.environ.get(model_env) or None
    if not model_override:
        model_override = os.environ.get("HAKUNA_DEFAULT_MODEL") or None

    try:
        model = model_override or router.get_default_model(db)
        provider = router.detect_provider(model)
    except Exception as e:
        logger.debug("provider resolution failed: %s", e)
        return ""

    with llm_feedback.span(
        surface=surface,
        org_id=org_id,
        user_id=user_id,
        surface_ref_type=surface_ref_type,
        surface_ref_id=surface_ref_id,
        provider=provider,
        model=model,
        system_prompt=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    ):
        try:
            text, _ = router.call(
                db,
                system=system_prompt,
                user=user_prompt,
                max_tokens=max_tokens,
                model=model,
            )
            llm_feedback.record_response(text)
            return text
        except Exception as e:
            logger.warning("LLM call via %s failed: %s", provider, e)
            llm_feedback.record_error(e)
            return ""
