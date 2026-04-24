"""Fire-and-forget writer that streams LLM usage rows into BigQuery for COGS.

Every llm_feedback span, on successful flush to Postgres, also posts a
compact row to ``${COGS_BQ_DATASET}.${COGS_BQ_TABLE}``. Writes are best-effort
and run on a background thread — they never block or fail the caller, and
never raise.

Disable by unsetting ``COGS_BQ_DATASET``. The module also no-ops when the
``google-cloud-bigquery`` package is not installed, so dev environments
stay lean.

The BigQuery views in terraform/cogs.tf join these rows with
``cogs.llm_pricing`` (for $ per token) and with the detailed GCP billing
export (for per-service infra cost).
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

_DATASET = os.environ.get("COGS_BQ_DATASET") or None
_TABLE = os.environ.get("COGS_BQ_TABLE", "llm_usage")
_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT") or None

_client_lock = threading.Lock()
_client: Any = None
_client_disabled = False


def _get_client() -> Any:
    """Lazy-init a shared BigQuery client. Returns None if BQ is unavailable."""
    global _client, _client_disabled
    if _client_disabled:
        return None
    if _client is not None:
        return _client
    with _client_lock:
        if _client is not None:
            return _client
        if _client_disabled:
            return None
        try:
            from google.cloud import bigquery  # type: ignore
        except Exception:
            _client_disabled = True
            logger.debug("cogs_writer: google-cloud-bigquery not installed — COGS streaming disabled")
            return None
        try:
            _client = bigquery.Client(project=_PROJECT) if _PROJECT else bigquery.Client()
        except Exception as e:
            _client_disabled = True
            logger.warning("cogs_writer: could not init BigQuery client (%s) — COGS streaming disabled", e)
            return None
        return _client


def _table_ref() -> Optional[str]:
    if not (_DATASET and _TABLE and _PROJECT):
        return None
    return f"{_PROJECT}.{_DATASET}.{_TABLE}"


def enabled() -> bool:
    return _table_ref() is not None and _get_client() is not None


def post(
    *,
    interaction_id: Optional[int],
    org_id: int,
    user_id: Optional[int],
    surface: str,
    agent_id: Optional[int],
    agent_run_id: Optional[int],
    provider: Optional[str],
    model: Optional[str],
    input_tokens: Optional[int],
    output_tokens: Optional[int],
    latency_ms: Optional[int],
    status: Optional[str],
    created_at: datetime,
) -> None:
    """Enqueue one usage row. Non-blocking — returns immediately."""
    if not enabled():
        return
    row = {
        "interaction_id": interaction_id,
        "org_id": org_id,
        "user_id": user_id,
        "surface": surface,
        "agent_id": agent_id,
        "agent_run_id": agent_run_id,
        "provider": provider,
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_ms": latency_ms,
        "status": status,
        "created_at": created_at.isoformat(),
    }
    t = threading.Thread(target=_insert, args=(row,), daemon=True)
    t.start()


def _insert(row: dict) -> None:
    client = _get_client()
    ref = _table_ref()
    if client is None or ref is None:
        return
    try:
        errors = client.insert_rows_json(ref, [row])
        if errors:
            logger.warning("cogs_writer: BQ insert returned errors: %s", errors)
    except Exception:
        logger.exception("cogs_writer: BQ insert failed (non-fatal)")
