"""Embedding generation for LLM feedback-loop retrieval.

Thin wrapper over the OpenAI embeddings API (the most stable, cheapest
embeddings option across our LLM providers — we don't need to match the
chat provider). Falls back to None when no key is configured; callers
treat None as "retrieval disabled for this call."

Used by:
  - services.llm_feedback.retrieve_exemplars → embed the incoming query
  - services.llm_outcome_linker.backfill_embeddings → embed past logs

Not a fit for SQLite — retrieval skips embedding lookup there anyway.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_MODEL = os.environ.get("LLM_FEEDBACK_EMBEDDING_MODEL", "text-embedding-3-small")
_DIM = int(os.environ.get("LLM_FEEDBACK_EMBEDDING_DIM", "1024"))


def _resolve_api_key(db=None) -> Optional[str]:
    if db is not None:
        try:
            from models.models import IntegrationConfig
            cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == "openai").first()
            if cfg and cfg.config and cfg.config.get("api_key"):
                return cfg.config["api_key"]
        except Exception:
            pass
    return os.environ.get("OPENAI_API_KEY")


def embed_text(text: str, *, db=None) -> Optional[list[float]]:
    """Return an embedding vector for `text`, or None if unavailable.

    Uses OpenAI's text-embedding-3-small by default (1024d). Dimension
    is forced via the `dimensions` parameter so it matches the pgvector
    column width set in migration 041.
    """
    if not text:
        return None
    api_key = _resolve_api_key(db)
    if not api_key:
        return None

    import httpx
    try:
        with httpx.Client() as client:
            resp = client.post(
                "https://api.openai.com/v1/embeddings",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": _MODEL,
                    "input": text[:8000],  # model input cap — trim defensively
                    "dimensions": _DIM,
                },
                timeout=30.0,
            )
            resp.raise_for_status()
            return resp.json()["data"][0]["embedding"]
    except Exception as exc:
        logger.debug("embed_text failed: %s", exc)
        return None
