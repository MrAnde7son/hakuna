"""Async HTTP clients for GitHub REST + npm registry.

Respects GitHub's primary rate limit via X-RateLimit-Remaining and secondary
rate limit via Retry-After. Supports a token pool (round-robin) so callers
can stack PATs to multiply throughput. npm has no auth requirement for the
read endpoints we hit but we still back off on 429/5xx.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import os
import random
import time
from typing import Any, AsyncIterator

import aiohttp

logger = logging.getLogger(__name__)


GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
NPM_REGISTRY = "https://registry.npmjs.org"


class RateLimitedError(Exception):
    """Raised when every token in the pool is exhausted for the foreseeable
    future. Callers may re-raise or degrade (e.g., skip code search)."""


class GitHubClient:
    """Thin async GitHub REST client with token rotation + exponential backoff.

    Intentionally NOT PyGithub — the user spec pins aiohttp/asyncio for
    high-performance concurrent queries, and PyGithub is sync.
    """

    def __init__(
        self,
        tokens: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        max_retries: int = 5,
        base_backoff: float = 1.5,
    ):
        env_tokens = [t for t in (os.environ.get("GITHUB_TOKENS") or "").split(",") if t.strip()]
        if not tokens:
            single = os.environ.get("GITHUB_TOKEN")
            tokens = [single] if single else env_tokens
        self._tokens = [t.strip() for t in (tokens or []) if t and t.strip()]
        self._token_cycle = itertools.cycle(self._tokens) if self._tokens else None
        # Per-token cooldown map: token → epoch seconds when it's usable again.
        self._token_cooldown: dict[str, float] = {}
        self._session = session
        self._owns_session = session is None
        self.max_retries = max_retries
        self.base_backoff = base_backoff

    async def __aenter__(self) -> GitHubClient:
        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()

    def _pick_token(self) -> str | None:
        if not self._token_cycle:
            return None
        now = time.time()
        # Try up to len(tokens) tokens to find one off cooldown.
        for _ in range(len(self._tokens)):
            tok = next(self._token_cycle)
            if self._token_cooldown.get(tok, 0) <= now:
                return tok
        return None

    def _headers(self, token: str | None) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hakuna-easm/1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Core request method with rate-limit + backoff handling.

        Returns parsed JSON (or None for 204). Raises RateLimitedError only
        when all tokens are cooled down past our max backoff budget.
        """
        assert self._session is not None, "Use as async context manager"
        url = path if path.startswith("http") else f"{GITHUB_API}{path}"

        for attempt in range(self.max_retries):
            token = self._pick_token()
            if self._tokens and token is None:
                # Every token is cooling down — wait until the earliest is free.
                earliest = min(self._token_cooldown.values()) if self._token_cooldown else 0
                sleep_for = max(1.0, earliest - time.time())
                if sleep_for > 60:
                    raise RateLimitedError(
                        f"all {len(self._tokens)} GitHub tokens cooling down for {sleep_for:.0f}s"
                    )
                await asyncio.sleep(sleep_for)
                continue

            headers = self._headers(token)
            try:
                async with self._session.request(
                    method, url, params=params, json=json_body, headers=headers,
                ) as resp:
                    remaining = int(resp.headers.get("X-RateLimit-Remaining", "1") or 1)
                    reset = int(resp.headers.get("X-RateLimit-Reset", "0") or 0)

                    if resp.status == 403 and remaining == 0 and token:
                        # Primary rate limit hit — park this token.
                        cooldown_until = reset or (time.time() + 60)
                        self._token_cooldown[token] = cooldown_until
                        logger.warning(
                            "github token rate-limited until %d (%.0fs); rotating",
                            cooldown_until, max(0, cooldown_until - time.time()),
                        )
                        continue

                    if resp.status == 403 and "secondary rate limit" in (await resp.text()).lower():
                        # Secondary limit → respect Retry-After.
                        retry_after = float(resp.headers.get("Retry-After", "30"))
                        if token:
                            self._token_cooldown[token] = time.time() + retry_after
                        logger.warning("github secondary rate limit; sleeping %.1fs", retry_after)
                        await asyncio.sleep(retry_after)
                        continue

                    if resp.status == 429:
                        retry_after = float(resp.headers.get("Retry-After", "10"))
                        await asyncio.sleep(retry_after)
                        continue

                    if resp.status >= 500:
                        sleep_for = self._backoff(attempt)
                        await asyncio.sleep(sleep_for)
                        continue

                    if resp.status == 404:
                        return None

                    if resp.status >= 400:
                        text = (await resp.text())[:200]
                        logger.info("github %s %s → %d: %s", method, path, resp.status, text)
                        return None

                    if resp.status == 204 or resp.content_length == 0:
                        return None

                    return await resp.json()

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning("github %s %s transient error: %s", method, path, e)
                await asyncio.sleep(self._backoff(attempt))
                continue

        logger.error("github %s %s exhausted retries", method, path)
        return None

    def _backoff(self, attempt: int) -> float:
        # Full jitter exponential backoff.
        return random.uniform(0, self.base_backoff ** (attempt + 1))

    # ── Convenience endpoints ────────────────────────────────────

    async def search_users(self, query: str, per_page: int = 100) -> AsyncIterator[dict]:
        """Paginate GET /search/users."""
        page = 1
        while True:
            data = await self.request(
                "GET", "/search/users",
                params={"q": query, "per_page": per_page, "page": page},
            )
            if not data or not data.get("items"):
                return
            for item in data["items"]:
                yield item
            if len(data["items"]) < per_page or page >= 10:  # search caps at 1000 results
                return
            page += 1

    async def search_code(self, query: str, per_page: int = 100) -> AsyncIterator[dict]:
        """Paginate GET /search/code. Requires auth."""
        page = 1
        while True:
            data = await self.request(
                "GET", "/search/code",
                params={"q": query, "per_page": per_page, "page": page},
            )
            if not data or not data.get("items"):
                return
            for item in data["items"]:
                yield item
            if len(data["items"]) < per_page or page >= 10:
                return
            page += 1

    async def get_user(self, login: str) -> dict | None:
        return await self.request("GET", f"/users/{login}")  # type: ignore[return-value]

    async def get_org(self, login: str) -> dict | None:
        return await self.request("GET", f"/orgs/{login}")  # type: ignore[return-value]

    async def list_user_repos(self, login: str, per_page: int = 100) -> AsyncIterator[dict]:
        page = 1
        while True:
            data = await self.request(
                "GET", f"/users/{login}/repos",
                params={"per_page": per_page, "page": page, "type": "owner", "sort": "pushed"},
            )
            if not data:
                return
            for item in data:
                yield item
            if len(data) < per_page:
                return
            page += 1

    async def list_org_repos(self, login: str, per_page: int = 100) -> AsyncIterator[dict]:
        page = 1
        while True:
            data = await self.request(
                "GET", f"/orgs/{login}/repos",
                params={"per_page": per_page, "page": page, "type": "sources", "sort": "pushed"},
            )
            if not data:
                return
            for item in data:
                yield item
            if len(data) < per_page:
                return
            page += 1

    async def list_repo_contributors(
        self, owner: str, repo: str, per_page: int = 30,
    ) -> list[dict]:
        data = await self.request(
            "GET", f"/repos/{owner}/{repo}/contributors",
            params={"per_page": per_page, "anon": "false"},
        )
        return data if isinstance(data, list) else []

    async def get_file(self, owner: str, repo: str, path: str, ref: str | None = None) -> str | None:
        """Fetch a file from a public repo.

        Tries raw.githubusercontent.com first — it has no API rate limit and
        needs no token, so it's free to call. Falls back to the authenticated
        contents API only if the raw fetch misses (private repo, non-default
        branch we haven't guessed, etc.).
        """
        raw = await self.get_raw_file(owner, repo, path, ref=ref)
        if raw is not None:
            return raw

        import base64

        params: dict[str, Any] = {}
        if ref:
            params["ref"] = ref
        data = await self.request("GET", f"/repos/{owner}/{repo}/contents/{path}", params=params)
        if not data or not isinstance(data, dict):
            return None
        content = data.get("content")
        if not content:
            return None
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return None

    async def get_raw_file(
        self,
        owner: str,
        repo: str,
        path: str,
        *,
        ref: str | None = None,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        """Fetch a file via raw.githubusercontent.com.

        No API rate limit, no auth required for public repos. Tries HEAD
        (default branch) when ref is None — GitHub's raw host resolves that
        to the actual default without us needing a pre-query.

        Returns decoded text, or None on any non-200.
        """
        assert self._session is not None, "Use as async context manager"
        ref = ref or "HEAD"
        path = path.lstrip("/")
        url = f"{GITHUB_RAW}/{owner}/{repo}/{ref}/{path}"
        try:
            async with self._session.get(url, headers={"User-Agent": "hakuna-easm/1.0"}) as resp:
                if resp.status != 200:
                    return None
                data = await resp.content.read(max_bytes + 1)
                if len(data) > max_bytes:
                    logger.info("raw fetch %s/%s/%s truncated at %d bytes", owner, repo, path, max_bytes)
                    data = data[:max_bytes]
                return data.decode("utf-8", errors="replace")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug("raw fetch %s/%s/%s transient error: %s", owner, repo, path, e)
            return None

    async def raw_file_exists(
        self,
        owner: str,
        repo: str,
        path: str,
        *,
        ref: str | None = None,
    ) -> bool:
        """HEAD a raw URL — cheap existence probe that avoids downloading content."""
        assert self._session is not None, "Use as async context manager"
        ref = ref or "HEAD"
        path = path.lstrip("/")
        url = f"{GITHUB_RAW}/{owner}/{repo}/{ref}/{path}"
        try:
            async with self._session.head(
                url, headers={"User-Agent": "hakuna-easm/1.0"}, allow_redirects=True,
            ) as resp:
                return resp.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False


class NpmClient:
    """npm registry client. No auth required; much gentler rate limits than GitHub."""

    def __init__(
        self,
        session: aiohttp.ClientSession | None = None,
        max_retries: int = 4,
    ):
        self._session = session
        self._owns_session = session is None
        self.max_retries = max_retries

    async def __aenter__(self) -> NpmClient:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "hakuna-easm/1.0"},
            )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()

    async def request(self, path: str, params: dict | None = None) -> dict | list | None:
        assert self._session is not None
        url = path if path.startswith("http") else f"{NPM_REGISTRY}{path}"
        for attempt in range(self.max_retries):
            try:
                async with self._session.get(url, params=params) as resp:
                    if resp.status == 429:
                        retry_after = float(resp.headers.get("Retry-After", "5"))
                        await asyncio.sleep(retry_after)
                        continue
                    if resp.status >= 500:
                        await asyncio.sleep(random.uniform(0, 2 ** (attempt + 1)))
                        continue
                    if resp.status == 404:
                        return None
                    if resp.status >= 400:
                        return None
                    return await resp.json()
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning("npm %s transient error: %s", path, e)
                await asyncio.sleep(random.uniform(0, 2 ** (attempt + 1)))
        return None

    async def search_by_maintainer(self, domain: str, size: int = 250) -> list[dict]:
        """npm search supports 'maintainer:foo' — but there's no email filter,
        so we search the whole corpus for the domain string and filter client-side.
        Results have a 'package' dict with maintainer objects containing email.
        """
        data = await self.request(
            "/-/v1/search", params={"text": domain, "size": size, "from": 0},
        )
        if not data or "objects" not in data:
            return []
        return data["objects"]

    async def get_package(self, name: str) -> dict | None:
        # Package names can contain "/" for scoped packages — URL-encode the slash.
        encoded = name.replace("/", "%2F")
        return await self.request(f"/{encoded}")  # type: ignore[return-value]
