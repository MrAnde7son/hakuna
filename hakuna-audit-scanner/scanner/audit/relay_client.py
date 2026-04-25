"""HTTP client to a hakuna-relay-agent node.

Replaces the backend's ``services.relay_broker.RelayBroker`` —
specifically its ``send_task(agent_id, method, config, credentials,
params)`` interface. The relay-side method registry
(``hakuna-relay-agent/agent/method_registry.py``) is unchanged: an
``ssh_query`` method receives ``{config, credentials, params}`` and
returns a dict.

OSS deployments run a single relay node behind a fixed URL. Hakuna's
multi-tenant deployment uses a WebSocket fan-out broker — that path
stays in the backend's ``services.relay_broker`` and is wired in by
the backend's ``services.audit_runner`` when it dispatches a Celery
task; the OSS package never imports it.

Wire format (POST {RELAY_URL}/exec):

    request:
        {
            "method":      "ssh_query",
            "agent_id":    "relay-east-1",   # informational, single-node deployments ignore it
            "config":      {...},
            "credentials": {...},            # plaintext, never logged
            "params":      {...},
            "timeout_s":   60
        }

    response (HTTP 200):
        { "ok": true,  "result": {...} }
    response (HTTP 200, handler error):
        { "ok": false, "error": "...", "result": {...} }   # result is best-effort partial

A non-200 response or a connection error is raised as
``RelayDispatchError`` so the protocol-tool wrappers can convert it
into a structured tool result the LLM can reason about.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from scanner.audit.config import (
    HAKUNA_RELAY_TOKEN,
    HAKUNA_RELAY_URL,
    RELAY_TIMEOUT_SECONDS,
    RELAY_TRANSPORT,
)

logger = logging.getLogger(__name__)


class RelayDispatchError(RuntimeError):
    """Raised when the relay can't be reached or returns a non-200."""


class RelayClient:
    """Thin async HTTP client. One instance per worker process is fine —
    httpx.AsyncClient is reusable and pools connections."""

    def __init__(
        self,
        *,
        url: str | None = None,
        token: str | None = None,
        timeout_s: int | None = None,
    ):
        self._url = (url or HAKUNA_RELAY_URL or "").rstrip("/")
        self._token = token or HAKUNA_RELAY_TOKEN
        self._timeout = timeout_s or RELAY_TIMEOUT_SECONDS
        if not self._url:
            logger.warning(
                "relay_client: HAKUNA_RELAY_URL not set — every protocol "
                "tool will return a dispatch error until it is configured"
            )

    def is_connected(self, agent_id: str) -> bool:
        """HTTP transport has no persistent connection — always True iff
        a URL is configured. Kept for API-shape parity with the
        backend's WebSocket broker so protocol tools don't branch on
        transport."""
        return bool(self._url)

    async def send_task(
        self,
        *,
        agent_id: str | None,
        method: str,
        config: dict,
        credentials: dict,
        params: dict,
    ) -> dict:
        if not self._url:
            raise RelayDispatchError("HAKUNA_RELAY_URL is not set")

        body = {
            "agent_id": agent_id or "default",
            "method": method,
            "config": config,
            "credentials": credentials,
            "params": params,
            "timeout_s": self._timeout,
        }
        headers = {"content-type": "application/json"}
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"

        try:
            async with httpx.AsyncClient(timeout=self._timeout + 15) as client:
                resp = await client.post(f"{self._url}/exec", json=body, headers=headers)
        except httpx.HTTPError as e:
            raise RelayDispatchError(f"relay request failed: {e}") from e

        if resp.status_code >= 400:
            raise RelayDispatchError(
                f"relay returned HTTP {resp.status_code}: {resp.text[:300]}"
            )

        try:
            data = resp.json()
        except ValueError as e:
            raise RelayDispatchError(f"relay returned non-JSON body: {e}") from e

        if not data.get("ok", True):
            err = data.get("error") or "unknown relay handler error"
            partial = data.get("result") or {}
            return {"_relay_error": err, **partial}

        return data.get("result") or {}


# ── Module-level singleton ───────────────────────────────────────


_client: RelayClient | None = None


def get_relay_client() -> RelayClient:
    """Lazy singleton so unit tests can monkey-patch it without
    mutating module state at import time."""
    global _client
    if _client is None:
        if RELAY_TRANSPORT != "http":
            logger.warning(
                "relay_client: RELAY_TRANSPORT=%s but only 'http' is "
                "implemented in the OSS scanner. Falling back to http. "
                "WebSocket-broker dispatch lives in Hakuna's backend.",
                RELAY_TRANSPORT,
            )
        _client = RelayClient()
    return _client
