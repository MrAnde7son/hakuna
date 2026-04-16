"""LLM-powered JavaScript endpoint extraction.

Analyzes JS bundles for hidden API endpoints using LLM with a
deterministic regex fallback when LLM is unavailable.
"""

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Regex patterns for deterministic fallback
_ENDPOINT_PATTERNS = [
    # fetch/axios/XHR calls
    re.compile(r"""(?:fetch|axios|XMLHttpRequest)\s*\(\s*[`"']([/][a-zA-Z0-9/_\-{}:.]+)[`"']"""),
    # String literals that look like API paths
    re.compile(r"""[`"'](\/api\/[a-zA-Z0-9/_\-{}:.]+)[`"']"""),
    re.compile(r"""[`"'](\/v[0-9]+\/[a-zA-Z0-9/_\-{}:.]+)[`"']"""),
    # Route definitions (React Router, Express, etc.)
    re.compile(r"""(?:path|route|url|endpoint)\s*[:=]\s*[`"']([/][a-zA-Z0-9/_\-{}:.]+)[`"']"""),
    # HTTP method calls
    re.compile(r"""\.(?:get|post|put|patch|delete)\s*\(\s*[`"']([/][a-zA-Z0-9/_\-{}:.]+)[`"']"""),
]

_METHOD_PATTERN = re.compile(
    r"""\.(?P<method>get|post|put|patch|delete)\s*\(\s*[`"'](?P<path>[/][a-zA-Z0-9/_\-{}:.]+)[`"']""",
    re.IGNORECASE,
)

# System prompt for LLM extraction
_SYSTEM_PROMPT = """You are a security analyst extracting API endpoints from JavaScript source code.

Analyze the JS code and extract all API endpoint paths. Look for:
- fetch() / axios / XHR calls
- REST API paths (/api/..., /v1/..., /graphql)
- WebSocket URLs
- Route definitions
- Hidden admin/debug endpoints

Respond ONLY with a JSON array. Each element:
{"path": "/api/v1/users", "method": "GET", "auth_required": true, "description": "User listing endpoint"}

If no endpoints found, return []. No explanation text."""


async def extract_endpoints_llm(js_content: str) -> list[dict]:
    """Use LLM to extract API endpoints from JS source code.

    Supports the same providers as the rest of the app (Anthropic, OpenAI)
    via the same httpx-based pattern used by scan_planner._call_llm.
    Provider/model is configured via LLM_JS_MODEL env var.

    Returns list of {"path", "method", "auth_required", "description"}.
    """
    # Truncate to stay within context limits
    truncated = js_content[:100_000]

    try:
        response_text = await _call_llm(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=truncated,
            max_tokens=4096,
        )
    except Exception as e:
        logger.warning("LLM JS extraction failed: %s", e)
        return []

    if not response_text:
        return []

    try:
        # Extract JSON array from response
        if response_text.strip().startswith("["):
            return json.loads(response_text.strip())

        match = re.search(r"\[.*\]", response_text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except (json.JSONDecodeError, ValueError):
        logger.debug("LLM JS extraction: could not parse JSON from response")

    return []


async def _call_llm(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 4096,
) -> str:
    """Multi-provider LLM call — same pattern as scan_planner._call_llm.

    Tries providers in order based on available API keys:
    1. Anthropic (ANTHROPIC_API_KEY)
    2. OpenAI (OPENAI_API_KEY)
    """
    import httpx

    # Try Anthropic first
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        model = os.environ.get("LLM_JS_MODEL", "claude-haiku-4-5-20251001")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
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

    # Fall back to OpenAI
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key:
        model = os.environ.get("LLM_JS_MODEL", "gpt-4o-mini")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
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

    logger.debug("No LLM API key configured (ANTHROPIC_API_KEY or OPENAI_API_KEY)")
    return ""


def extract_endpoints_regex(js_content: str) -> list[dict]:
    """Deterministic regex fallback for endpoint extraction.

    Returns list of {"path", "method"}.
    """
    endpoints: dict[str, str] = {}  # path -> method

    # First pass: extract method + path pairs
    for match in _METHOD_PATTERN.finditer(js_content):
        method = match.group("method").upper()
        path = match.group("path")
        if _is_valid_path(path):
            endpoints[path] = method

    # Second pass: extract paths from other patterns
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_content):
            path = match.group(1)
            if _is_valid_path(path) and path not in endpoints:
                endpoints[path] = "GET"  # default method

    return [{"path": p, "method": m} for p, m in endpoints.items()]


def _is_valid_path(path: str) -> bool:
    """Filter out false positive paths (CSS, images, etc.)."""
    if len(path) < 3 or len(path) > 200:
        return False
    # Skip static asset paths
    static_exts = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".ttf", ".map")
    if any(path.endswith(ext) for ext in static_exts):
        return False
    # Skip common JS framework internals
    if path.startswith("/.") or "/node_modules/" in path:
        return False
    return True


async def store_llm_js_endpoints(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    endpoints: list[dict],
) -> int:
    """Store LLM-extracted endpoints as AssetEndpoint records.

    Returns count of endpoints stored.
    """
    now = datetime.now(timezone.utc)
    stored = 0

    for ep in endpoints:
        path = ep.get("path", "")
        if not path or not _is_valid_path(path):
            continue

        method = ep.get("method", "GET").upper()
        url = path  # relative path — full URL not known

        endpoint_id = uuid.uuid4()
        await db.execute(
            text("""
                INSERT INTO asset_endpoints (id, asset_id, url, path, method, discovered_at, is_auth_page)
                VALUES (:id, :asset_id, :url, :path, :method, :now, false)
                ON CONFLICT DO NOTHING
            """),
            {
                "id": endpoint_id,
                "asset_id": asset_id,
                "url": url,
                "path": path,
                "method": method,
                "now": now,
            },
        )
        stored += 1

    await db.commit()
    return stored
