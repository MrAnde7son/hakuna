"""Pluggable relay transport — protocol-tool dispatchers go through here.

Two transports ship in this package:

  - ``HttpRelayTransport`` (default) — POSTs to a single
    ``hakuna-relay-agent`` node at ``HAKUNA_RELAY_URL``. Right answer
    for OSS deployments where one relay sits behind a fixed URL.
  - ``NullRelayTransport`` — every dispatch returns an error result.
    Used in unit tests and as the default when no URL is configured,
    so a mis-configured worker fails loudly per-call rather than at
    import.

The Hakuna multi-tenant deployment ships a third transport (in
``backend/services/audit_runner.py``) that adapts the existing
``services.relay_broker.RelayBroker`` (WebSocket fan-out) to this
interface. It's installed via ``set_transport(...)`` at backend
startup. The audit-scanner package never imports it.

Wire format (POST {RELAY_URL}/exec):

    request:
        {
            "method":      "ssh_query",
            "agent_id":    "relay-east-1",   # informational, single-node deployments ignore
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
from typing import Protocol

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


class RelayTransport(Protocol):
    """Single-method transport contract. Protocol tools call only
    ``send_task`` — they don't care which transport is plugged in."""

    def is_connected(self, agent_id: str | None) -> bool: ...

    async def send_task(
        self,
        *,
        agent_id: str | None,
        method: str,
        config: dict,
        credentials: dict,
        params: dict,
    ) -> dict: ...


# ── Null transport ───────────────────────────────────────────────


class NullRelayTransport:
    """Every dispatch returns a structured error. Lets unit tests run
    the engine without a relay, and lets a misconfigured worker fail
    visibly per-tool-call instead of crashing at import."""

    def is_connected(self, agent_id: str | None) -> bool:
        return False

    async def send_task(self, **kwargs) -> dict:
        raise RelayDispatchError(
            "no relay transport configured — set HAKUNA_RELAY_URL or call "
            "scanner.audit.relay_client.set_transport(...) at worker startup"
        )


# ── HTTP transport (OSS default) ─────────────────────────────────


class HttpRelayTransport:
    """Async HTTP client. One instance per worker process is fine —
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

    def is_connected(self, agent_id: str | None) -> bool:
        # HTTP transport has no persistent connection — "connected"
        # iff a URL is configured. Kept for API-shape parity with the
        # WebSocket broker so protocol tools don't branch on transport.
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


# ── Module-level swap point ──────────────────────────────────────


_transport: RelayTransport | None = None


def get_transport() -> RelayTransport:
    """Lazy singleton. First call resolves from env: HTTP if a URL is
    configured, else Null. Backend overrides via ``set_transport``
    before the worker accepts any task — that path uses the
    WebSocket-broker adapter so multi-tenant relays work."""
    global _transport
    if _transport is not None:
        return _transport

    if RELAY_TRANSPORT == "http" and HAKUNA_RELAY_URL:
        _transport = HttpRelayTransport()
    elif RELAY_TRANSPORT == "http":
        # HTTP requested but URL missing — return Null so individual
        # dispatch attempts surface a clear error rather than silently
        # connecting to nothing.
        logger.warning(
            "relay_client: RELAY_TRANSPORT=http but HAKUNA_RELAY_URL is empty — "
            "every dispatch will fail until configured or a custom transport is set"
        )
        _transport = NullRelayTransport()
    else:
        logger.warning(
            "relay_client: RELAY_TRANSPORT=%s is not implemented in OSS — "
            "use set_transport() at worker startup to plug in your own (e.g. "
            "the backend's WebSocket-broker adapter)",
            RELAY_TRANSPORT,
        )
        _transport = NullRelayTransport()

    return _transport


def set_transport(transport: RelayTransport) -> None:
    """Replace the active transport. Backend calls this once at worker
    startup. Test code uses it to swap in a mock."""
    global _transport
    _transport = transport
    logger.info("relay_client: transport set to %s", type(transport).__name__)


# ── Back-compat shim ─────────────────────────────────────────────
# Existing ssh_tools.py calls ``get_relay_client()`` — keep it as an
# alias for ``get_transport()`` so the protocol tool files don't have
# to change when the transport interface lands.


def get_relay_client() -> RelayTransport:
    return get_transport()
