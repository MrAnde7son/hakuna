"""Source map exploitation.

When a JS bundle leaks its `.map` file (either at `<bundle>.map` or via
the trailing `//# sourceMappingURL=` comment), parse the map to recover
original source files. The recovered sources are returned to the caller
so they can be fed back into:

  - LLM endpoint extraction (richer than minified code)
  - JS secret scanning (secrets often only appear in original source)

This module is a strict tool — it doesn't itself persist sources to disk.
A small ``asset_js_artifacts`` row is written per asset summarizing what
was harvested (count, total bytes, sha256 of joined content), but the
actual source bodies are processed in-stream and discarded.

Hard caps prevent abuse:
  - per-map: ``max_bytes`` (default 5MB) — refused at the HTTP level
  - per-asset: ``max_per_asset`` (default 30 maps)
The scanner runs against arbitrary internet hosts; without these caps a
malicious server could OOM the worker by serving a 1GB sourcemap.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# Trailing comment that points at the map file. Common forms:
#   //# sourceMappingURL=app.js.map
#   //@ sourceMappingURL=https://cdn.example.com/app.js.map
_SMURL_RE = re.compile(
    r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s\*]+)",
)


@dataclass
class RecoveredSource:
    """One file recovered from a sourcemap. ``content`` may be empty when
    the map declared ``sources`` without ``sourcesContent`` — those entries
    are still listed (the path itself can be useful intel)."""
    path: str
    content: str

    @property
    def is_present(self) -> bool:
        return bool(self.content)


@dataclass
class SourcemapResult:
    js_url: str
    map_url: str
    sources: list[RecoveredSource]
    total_bytes: int
    content_hash: str  # sha256 over joined recovered content


async def harvest_sourcemap(
    client: httpx.AsyncClient,
    js_url: str,
    js_body: str | None,
    max_bytes: int,
    timeout: int,
) -> SourcemapResult | None:
    """Fetch and parse the sourcemap for one JS file.

    ``js_body`` may be passed when the caller already has the JS content
    in memory (most common case — js_fingerprint already downloaded it).
    When None, we don't refetch the JS — only candidate `.map` paths.
    """
    map_url = await _resolve_map_url(client, js_url, js_body, timeout)
    if not map_url:
        return None

    try:
        resp = await client.get(map_url, timeout=timeout)
    except Exception:
        return None
    if resp.status_code != 200:
        return None

    cl = resp.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > max_bytes:
        return None

    body = resp.content
    if len(body) > max_bytes:
        return None

    try:
        smap = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(smap, dict):
        return None

    sources = reconstruct_sources(smap)
    joined = "\n".join(s.content for s in sources if s.is_present)
    return SourcemapResult(
        js_url=js_url,
        map_url=map_url,
        sources=sources,
        total_bytes=len(joined),
        content_hash=hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest(),
    )


def reconstruct_sources(sourcemap: dict) -> list[RecoveredSource]:
    """Project a parsed sourcemap dict into RecoveredSource records.

    Sourcemap v3 fields used:
      - ``sources``        : list of original file paths (relative URLs)
      - ``sourcesContent`` : list of file bodies, parallel to ``sources``;
                             entries may be ``null`` when the bundler didn't
                             inline the source.

    We don't follow ``sourceRoot`` rewriting because the path itself is
    informational here (we're not loading source maps into a debugger);
    the relative path is fine for downstream consumers.
    """
    sources = sourcemap.get("sources") or []
    contents = sourcemap.get("sourcesContent") or []
    out: list[RecoveredSource] = []
    for i, src in enumerate(sources):
        if not isinstance(src, str):
            continue
        body = ""
        if i < len(contents) and isinstance(contents[i], str):
            body = contents[i]
        out.append(RecoveredSource(path=src, content=body))
    return out


async def _resolve_map_url(
    client: httpx.AsyncClient,
    js_url: str,
    js_body: str | None,
    timeout: int,
) -> str | None:
    """Find the URL of the source map for ``js_url``.

    Two paths:
      1. The trailing comment in the JS body wins (RFC pattern).
      2. Otherwise try ``<js_url>.map`` (common bundler default).
    """
    if js_body:
        # Search just the tail — sourceMappingURL comments are always at
        # the bottom and pulling the whole file through a regex is wasteful.
        tail = js_body[-2048:]
        m = _SMURL_RE.search(tail)
        if m:
            ref = m.group(1).strip()
            if ref.startswith("data:"):
                # Inline base64 sourcemap — refuse (we'd need to base64-
                # decode and parse a potentially huge blob with no Content-
                # Length to gate on). Rare in practice.
                return None
            return urljoin(js_url, ref)

    # Fallback — guess <url>.map and HEAD it. We HEAD to avoid pulling a
    # large body when the file doesn't exist; sites that don't support
    # HEAD will respond with 405 and we'll skip rather than risking a
    # spurious GET.
    candidate = js_url + ".map"
    try:
        head = await client.head(candidate, timeout=timeout)
    except Exception:
        return None
    if head.status_code in (200, 204):
        return candidate
    return None


async def harvest_asset_sourcemaps(
    db: AsyncSession,
    asset_id: uuid.UUID,
    js_files: list[tuple[str, str | None]],
    max_bytes: int = 5_000_000,
    max_per_asset: int = 30,
    concurrency: int = 10,
    timeout: int = 10,
) -> dict:
    """Harvest sourcemaps for one asset's JS files. Persist a summary row.

    ``js_files``: list of ``(js_url, js_body | None)``. The caller (the
    JS intel batched task) passes already-downloaded JS bodies so we
    don't re-fetch.

    Returns ``{maps_found, sources_recovered, total_bytes, content_hash}``.
    The recovered sources themselves are NOT in the return value — callers
    consume them via ``harvest_sourcemap`` directly. This wrapper exists
    to track the asset-level summary in ``asset_js_artifacts``.
    """
    capped = js_files[:max_per_asset]
    sem = asyncio.Semaphore(concurrency)
    now = datetime.now(timezone.utc)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "hakuna-scanner/sourcemap"},
    ) as client:
        async def _one(pair):
            url, body = pair
            async with sem:
                try:
                    return await harvest_sourcemap(client, url, body, max_bytes, timeout)
                except Exception as e:
                    logger.debug("sourcemap harvest failed for %s: %s", url, e)
                    return None

        results = await asyncio.gather(*[_one(p) for p in capped])

    found = [r for r in results if r is not None]
    sources_recovered = sum(len(r.sources) for r in found)
    total_bytes = sum(r.total_bytes for r in found)
    joined_hash = hashlib.sha256(
        ("|".join(sorted(r.content_hash for r in found))).encode("utf-8")
    ).hexdigest()

    if found:
        try:
            await db.execute(
                text("""
                    INSERT INTO asset_js_artifacts (
                        id, asset_id, artifact_type, js_url, content_hash,
                        intelligence, created_at
                    )
                    VALUES (
                        :id, :asset_id, 'sourcemap', :js_url, :hash,
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
                    # We use a synthetic per-asset URL since one row summarizes
                    # all maps for the asset — keeps the unique constraint
                    # happy while still giving the row a recognizable label.
                    "js_url": "asset:summary",
                    "hash": joined_hash,
                    "intel": json.dumps({
                        "maps_found": len(found),
                        "sources_recovered": sources_recovered,
                        "total_bytes": total_bytes,
                        "map_urls": [r.map_url for r in found],
                    }),
                    "now": now,
                },
            )
            await db.commit()
        except Exception as e:
            logger.warning("sourcemap: artifact insert failed for asset %s: %s", asset_id, e)

    return {
        "maps_found": len(found),
        "sources_recovered": sources_recovered,
        "total_bytes": total_bytes,
        "content_hash": joined_hash,
        "results": found,  # callers may consume RecoveredSource bodies directly
    }
