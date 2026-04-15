"""Fetch the resolved per-org findings-dedup rule from the backend.

Mirrors `backend/services/dedup.py`'s `findings` rule schema:

    {
      "enabled":     bool,
      "key_fields":  list[str],
      "strategy":    "keep_first" | "keep_last" | "merge",
      "scope":       str,
    }

The backend exposes this via:
    GET /api/internal/dedup/findings-rule?org_id=N
    Authorization: Bearer $HAKUNA_INTERNAL_TOKEN

We cache per-org rules in-memory with a short TTL so per-finding lookups don't
hammer the backend, and fall back to a safe default if the backend is
unreachable or unconfigured.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from scanner.vm.config import (
    BACKEND_URL,
    DEDUP_RULE_CACHE_TTL,
    INTERNAL_TOKEN,
)

logger = logging.getLogger(__name__)

# Default used when the backend is unreachable or unconfigured. Matches the
# backend's DEFAULT_CONFIG["findings"] block so behaviour is consistent in
# greenfield / offline deployments.
DEFAULT_RULE: dict[str, Any] = {
    "enabled": False,
    "key_fields": ["plugin_id", "asset_id", "port"],
    "strategy": "keep_last",
    "scope": "cross_scan",
}

# org_id -> (expires_at_monotonic, rule_dict)
_cache: dict[str, tuple[float, dict]] = {}


def _cache_key(org_id: Any) -> str:
    return str(org_id)


async def get_findings_rule(org_id: Any) -> dict:
    """Return the resolved findings-dedup rule for this org.

    Uses an in-memory TTL cache so repeated calls within a single scan don't
    re-hit the backend.
    """
    key = _cache_key(org_id)
    now = time.monotonic()
    cached = _cache.get(key)
    if cached and cached[0] > now:
        return cached[1]

    rule = await _fetch_from_backend(org_id)
    _cache[key] = (now + DEDUP_RULE_CACHE_TTL, rule)
    return rule


async def _fetch_from_backend(org_id: Any) -> dict:
    """Call the backend's internal endpoint. Returns DEFAULT_RULE on error.

    Never raises — the scanner should keep working even if the backend is
    temporarily down.
    """
    if not BACKEND_URL or not INTERNAL_TOKEN:
        logger.debug(
            "HAKUNA_BACKEND_URL / HAKUNA_INTERNAL_TOKEN not set — using default findings-dedup rule",
        )
        return dict(DEFAULT_RULE)

    url = f"{BACKEND_URL.rstrip('/')}/api/internal/dedup/findings-rule"
    headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, params={"org_id": str(org_id)}, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
            return {
                "enabled":    bool(payload.get("enabled", DEFAULT_RULE["enabled"])),
                "key_fields": list(payload.get("key_fields") or DEFAULT_RULE["key_fields"]),
                "strategy":   payload.get("strategy") or DEFAULT_RULE["strategy"],
                "scope":      payload.get("scope") or DEFAULT_RULE["scope"],
            }
    except Exception as exc:
        logger.warning(
            "Failed to fetch findings-dedup rule for org %s: %s — using default",
            org_id, exc,
        )
        return dict(DEFAULT_RULE)


def clear_cache() -> None:
    """Clear the in-memory cache — used by tests."""
    _cache.clear()
