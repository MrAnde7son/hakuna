"""Single-turn LLM dispatch for non-agent services.

Thin forward to ``core.llm_router.router.call`` — kept as a separate
module so existing imports don't break. New code should call the router
directly.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from core.llm_router import router


def call_llm(
    db: Session,
    system_prompt: str,
    user_prompt: str,
    *,
    max_tokens: int = 2048,
    model_override: Optional[str] = None,
) -> tuple[str, str]:
    """Call the org's configured LLM with a single system+user pair.

    Returns (response_text, model_id). Raises RuntimeError if no
    provider is configured.
    """
    return router.call(
        db,
        system=system_prompt,
        user=user_prompt,
        max_tokens=max_tokens,
        model=model_override,
    )
