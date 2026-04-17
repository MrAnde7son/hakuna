"""LLM-based deep analysis of JS bundles.

Beyond endpoint extraction (handled by llm_js_endpoints), this module
asks the LLM to identify higher-order intelligence:

  - auth_flow         : type (jwt/session/oauth), login endpoint,
                        token storage location
  - role_logic        : role/permission patterns the bundle enforces
                        client-side (helpful for finding hidden admin paths)
  - hidden_routes     : routes only reachable via specific role/state checks
  - admin_endpoints   : endpoints gated behind admin/superuser checks
  - dangerous_sinks   : eval, innerHTML, document.write, dangerouslySet…

Cost discipline: a per-asset budget gates this hard.

  - Skipped entirely when ``criticality < min_criticality`` AND
    ``is_internet_facing`` is false.
  - Cached by sha256 of the joined JS corpus. If we already have an
    intelligence row whose content_hash matches, we return it without
    calling the LLM. The cache is invalidated when the JS changes.
  - Refresh window: even on cache miss, if a row was written within
    ``refresh_days``, we honor that and skip — protects against
    pathological JS that hashes differently every request.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.ingest.llm_js_endpoints import _call_llm

logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You are a security analyst extracting authentication and authorization intelligence from JavaScript bundles.

Analyze the JS code and return a JSON object with these keys:
  - auth_flow: {type: "jwt"|"session"|"oauth"|"custom"|"unknown",
                login_endpoint: str | null,
                token_storage: "localStorage"|"sessionStorage"|"cookie"|"memory"|null,
                refresh_endpoint: str | null}
  - role_logic: array of {role: str, indicators: array of str}
  - hidden_routes: array of paths that are gated behind role checks (admin-only, etc.)
  - admin_endpoints: array of {path: str, method: str | null, evidence: str}
  - dangerous_sinks: array of {sink: str, snippet: str (≤120 chars)}

When you cannot determine a value, use null or [] rather than guessing. No explanation text — JSON only."""


async def analyze_js_corpus(
    db: AsyncSession,
    asset_id: uuid.UUID,
    js_corpus: str,
    base_url: str,
    refresh_days: int = 7,
) -> dict | None:
    """Run deep LLM analysis over the joined JS corpus for one asset.

    Caches by content_hash; returns the cached intelligence dict on hit.
    Returns None when the LLM call fails or returns malformed JSON (the
    pipeline must continue without this signal).
    """
    if not js_corpus or len(js_corpus) < 1000:
        return None

    content_hash = hashlib.sha256(js_corpus.encode("utf-8", errors="replace")).hexdigest()

    cached = await _load_cached(db, asset_id, content_hash, refresh_days)
    if cached is not None:
        return cached

    # Truncate aggressively — the LLM only needs a representative sample.
    # 80KB covers a typical SPA's auth + routing logic; longer just costs
    # tokens without adding signal for these specific patterns.
    truncated = js_corpus[:80_000]

    try:
        response_text = await _call_llm(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=f"Base URL: {base_url}\n\nJS:\n{truncated}",
            max_tokens=3000,
        )
    except Exception as e:
        logger.warning("llm_js_deep: LLM call failed for asset %s: %s", asset_id, e)
        return None

    intelligence = _parse_response(response_text)
    if intelligence is None:
        return None

    await _store(db, asset_id, base_url, content_hash, intelligence)
    return intelligence


def _parse_response(text_body: str) -> dict | None:
    """Extract the JSON object from the LLM response.

    Handles three common LLM response shapes:
      - bare JSON object
      - JSON wrapped in ```json …``` fences
      - JSON preceded by a brief preamble we asked it not to include
    """
    if not text_body:
        return None
    body = text_body.strip()

    # Strip markdown fence
    if body.startswith("```"):
        body = body.split("\n", 1)[1] if "\n" in body else body[3:]
        if body.endswith("```"):
            body = body[:-3]
        body = body.strip()

    # Locate the first {…} block — sometimes the model adds prose before
    # the JSON despite the prompt asking it not to.
    if not body.startswith("{"):
        m = re.search(r"\{.*\}", body, re.DOTALL)
        if not m:
            return None
        body = m.group(0)

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None
    return data


async def _load_cached(
    db: AsyncSession,
    asset_id: uuid.UUID,
    content_hash: str,
    refresh_days: int,
) -> dict | None:
    """Cache hit when the same content was analyzed within refresh_days.

    Two-level check:
      1. content_hash equality (the JS hasn't changed at all)
      2. recency window (even if the hash differs, don't re-analyze
         within refresh_days — protects against responses that hash
         differently every request, e.g. inlined timestamps)
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=refresh_days)
    try:
        row = (await db.execute(
            text("""
                SELECT content_hash, intelligence, created_at
                FROM asset_js_artifacts
                WHERE asset_id = :asset_id
                  AND artifact_type = 'llm_intelligence'
                  AND js_url = 'asset:summary'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"asset_id": asset_id},
        )).fetchone()
    except Exception:
        return None

    if not row:
        return None

    # Same content → cache hit regardless of age.
    if row.content_hash == content_hash:
        return row.intelligence if isinstance(row.intelligence, dict) else None

    # Different content but recent → still skip (debounce window).
    created = row.created_at
    if created and created > cutoff:
        return row.intelligence if isinstance(row.intelligence, dict) else None

    return None


async def _store(
    db: AsyncSession,
    asset_id: uuid.UUID,
    base_url: str,
    content_hash: str,
    intelligence: dict,
) -> None:
    now = datetime.now(timezone.utc)
    try:
        await db.execute(
            text("""
                INSERT INTO asset_js_artifacts (
                    id, asset_id, artifact_type, js_url, content_hash,
                    intelligence, created_at
                )
                VALUES (
                    :id, :asset_id, 'llm_intelligence', 'asset:summary', :hash,
                    :intel, :now
                )
                ON CONFLICT (asset_id, artifact_type, js_url) DO UPDATE SET
                    content_hash = EXCLUDED.content_hash,
                    intelligence = EXCLUDED.intelligence,
                    created_at = EXCLUDED.created_at
            """),
            {
                "id": uuid.uuid4(),
                "asset_id": asset_id,
                "hash": content_hash,
                "intel": json.dumps(intelligence),
                "now": now,
            },
        )
        await db.commit()
    except Exception as e:
        logger.warning("llm_js_deep: store failed for asset %s: %s", asset_id, e)


def should_run_for_asset(criticality: int, is_internet_facing: bool, min_criticality: int) -> bool:
    """Cost gate — keep LLM spend on assets that warrant it.

    The bar is low (criticality >= 5 OR internet-facing) because the
    output is high-signal even on medium-risk assets. The whole feature
    is opt-in via ``LLM_JS_DEEP_ANALYSIS_ENABLED`` so operators choose
    when to pay for it at all.
    """
    return bool(is_internet_facing) or (int(criticality or 0) >= min_criticality)
