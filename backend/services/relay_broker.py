"""Relay broker — manages WebSocket connections to on-prem relay agents and routes tasks.

Two flavors, same interface:

* ``RelayBroker``        — in-process, owns the websocket. Used by the backend
                           (uvicorn) where the ws endpoint runs.
* ``RemoteRelayBroker``  — HTTP stub that forwards to the backend's
                           ``/internal/relay/dispatch`` route. Used by
                           out-of-process callers (audit-worker Celery
                           processes) that can't hold the ws.

``get_relay_broker()`` picks the right one based on ``HAKUNA_PROCESS_ROLE``.
Call sites (``agents/tools/*_tools.py``, ``services/integrations.py``) never
know which they got.
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from typing import AsyncIterator, Optional

import httpx
from fastapi import WebSocket

logger = logging.getLogger(__name__)

# Task timeout (seconds)
TASK_TIMEOUT = 300


class RelayBroker:
    """Singleton that tracks connected relay agents and routes integration tasks to them."""

    def __init__(self):
        self._connections: dict[str, WebSocket] = {}     # agent_id → ws
        self._pending: dict[str, asyncio.Future] = {}    # task_id → future (for connect/push)
        self._streams: dict[str, asyncio.Queue] = {}     # task_id → record queue (for fetch_all)
        self._agent_info: dict[str, dict] = {}           # agent_id → metadata

    # ── Connection lifecycle ──

    async def register(self, agent_id: str, ws: WebSocket, info: dict = None):
        """Register a connected agent."""
        # Close existing connection if any
        if agent_id in self._connections:
            try:
                await self._connections[agent_id].close(code=4002, reason="Superseded by new connection")
            except Exception:
                pass
        self._connections[agent_id] = ws
        self._agent_info[agent_id] = info or {}
        logger.info("Relay agent %s connected", agent_id)

    async def unregister(self, agent_id: str):
        """Unregister a disconnected agent and fail any pending tasks."""
        self._connections.pop(agent_id, None)
        self._agent_info.pop(agent_id, None)

        # Fail any pending tasks for this agent
        failed_tasks = []
        for task_id, future in list(self._pending.items()):
            if not future.done():
                future.set_exception(ConnectionError(f"Relay agent {agent_id} disconnected"))
                failed_tasks.append(task_id)
        for task_id in failed_tasks:
            self._pending.pop(task_id, None)

        # Signal EOF on any active streams
        for task_id, queue in list(self._streams.items()):
            await queue.put(None)  # sentinel
        logger.info("Relay agent %s disconnected", agent_id)

    def is_connected(self, agent_id: str) -> bool:
        return agent_id in self._connections

    def connected_agents(self) -> list[str]:
        return list(self._connections.keys())

    # ── Task dispatch ──

    async def send_task(self, agent_id: str, method: str, config: dict,
                        credentials: Optional[dict] = None, params: dict = None,
                        payload: dict = None) -> dict:
        """Send a one-shot task (connect / push) and wait for the result."""
        ws = self._connections.get(agent_id)
        if not ws:
            raise ConnectionError(f"Relay agent {agent_id} is not connected")

        task_id = uuid.uuid4().hex
        future = asyncio.get_event_loop().create_future()
        self._pending[task_id] = future

        envelope = {
            "type": "task",
            "task_id": task_id,
            "method": method,
            "transport_config": config,
            "params": params or {},
        }
        if credentials:
            envelope["credentials"] = credentials
        if payload:
            envelope["payload"] = payload

        try:
            await ws.send_json(envelope)
            return await asyncio.wait_for(future, timeout=TASK_TIMEOUT)
        except asyncio.TimeoutError:
            self._pending.pop(task_id, None)
            raise TimeoutError(f"Relay agent {agent_id} did not respond within {TASK_TIMEOUT}s")
        except Exception:
            self._pending.pop(task_id, None)
            raise

    async def send_streaming_task(self, agent_id: str, config: dict,
                                  credentials: Optional[dict] = None,
                                  params: dict = None):
        """Send a fetch_all task and yield record batches as they stream back."""
        ws = self._connections.get(agent_id)
        if not ws:
            raise ConnectionError(f"Relay agent {agent_id} is not connected")

        task_id = uuid.uuid4().hex
        queue: asyncio.Queue = asyncio.Queue()
        self._streams[task_id] = queue

        envelope = {
            "type": "task",
            "task_id": task_id,
            "method": "fetch_all",
            "transport_config": config,
            "params": params or {},
        }
        if credentials:
            envelope["credentials"] = credentials

        try:
            await ws.send_json(envelope)

            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=TASK_TIMEOUT)
                except asyncio.TimeoutError:
                    raise TimeoutError(f"Relay agent {agent_id} timed out during streaming")

                if msg is None:  # sentinel = done or disconnected
                    break

                if msg.get("type") == "task_error":
                    raise RuntimeError(msg.get("error", "Relay agent reported an error"))

                if msg.get("type") == "records":
                    yield msg.get("batch", [])

                if msg.get("type") == "task_complete":
                    break
        finally:
            self._streams.pop(task_id, None)

    # ── Inbound message handling ──

    async def handle_agent_message(self, agent_id: str, msg: dict):
        """Route an inbound message from a relay agent to the right pending task."""
        msg_type = msg.get("type")
        task_id = msg.get("task_id")

        if msg_type == "pong":
            self._agent_info[agent_id] = {
                "version": msg.get("agent_version"),
                "uptime_s": msg.get("uptime_s"),
                "last_pong": datetime.utcnow().isoformat(),
            }
            return

        if not task_id:
            logger.warning("Relay agent %s sent message without task_id: %s", agent_id, msg_type)
            return

        # One-shot task responses (connect, push)
        if task_id in self._pending:
            future = self._pending.get(task_id)
            if future and not future.done():
                if msg_type == "task_complete":
                    future.set_result(msg.get("result", {}))
                elif msg_type == "task_error":
                    future.set_exception(RuntimeError(msg.get("error", "Unknown relay error")))
            if msg_type in ("task_complete", "task_error"):
                self._pending.pop(task_id, None)
            return

        # Streaming task responses (fetch_all)
        if task_id in self._streams:
            queue = self._streams[task_id]
            if msg_type in ("records", "task_complete", "task_error"):
                await queue.put(msg)
            return

        logger.debug("Relay message for unknown task %s (type=%s)", task_id, msg_type)

    # ── Health ──

    async def ping(self, agent_id: str):
        """Send a ping to an agent."""
        ws = self._connections.get(agent_id)
        if ws:
            await ws.send_json({"type": "ping"})


# ── Remote broker (for out-of-process callers) ──


class RemoteRelayBroker:
    """HTTP-backed stub that forwards dispatch requests to the backend.

    Mirrors the subset of ``RelayBroker`` that tools actually call
    (``is_connected``, ``send_task``, ``send_streaming_task``). The backend's
    ``/internal/relay/dispatch`` route runs the real ``RelayBroker.send_task``
    and returns the result, so errors and semantics match what in-process
    callers see. Exceptions are re-raised with the same types
    (``ConnectionError``, ``TimeoutError``) so tool error-handling doesn't
    need two code paths.
    """

    def __init__(self, base_url: str, token: str):
        if not base_url:
            raise RuntimeError("RemoteRelayBroker requires HAKUNA_BACKEND_URL")
        if not token:
            raise RuntimeError("RemoteRelayBroker requires INTERNAL_SHARED_SECRET")
        self._base = base_url.rstrip("/")
        self._headers = {"X-Internal-Token": token}
        # Per-call timeout: task budget + slack so the backend's HTTPException(504)
        # beats our own httpx.ReadTimeout.
        self._timeout = TASK_TIMEOUT + 10
        # Deliberately no long-lived AsyncClient: every tool dispatch wraps
        # `send_task` in a fresh `asyncio.run(...)` (see agents/tools/*._run_async),
        # and a client bound to an earlier event loop is unusable in the next one.
        # A short-lived client per call is fine — the request count is low and
        # localhost HTTP doesn't benefit meaningfully from connection pooling.

    # `is_connected` is called synchronously by every tool handler as a
    # pre-flight, so make it cheap in the happy path and *fail open* when it
    # can't get a clean answer. The reason: `send_task` already surfaces a
    # ConnectionError on a dead relay (via the backend's 502), so a false
    # "connected=true" here at worst defers the error by one HTTP call. A
    # false "connected=false" — which was happening when the backend was
    # slow to answer the 3s probe — short-circuits perfectly good tool runs.
    # Treat the probe as best-effort.
    def is_connected(self, agent_id: str) -> bool:
        try:
            r = httpx.get(
                f"{self._base}/internal/relay/{agent_id}/presence",
                headers=self._headers, timeout=10,
            )
            if r.status_code == 200:
                return bool(r.json().get("connected", False))
            # 401 / 503 / etc. are configuration errors, not connectivity;
            # assume the relay IS up and let send_task surface the real issue.
            logger.warning(
                "RemoteRelayBroker presence probe returned %s; assuming connected",
                r.status_code,
            )
            return True
        except httpx.HTTPError as e:
            logger.warning(
                "RemoteRelayBroker presence probe failed: %s; assuming connected",
                e,
            )
            return True

    async def send_task(
        self, agent_id: str, method: str, config: dict,
        credentials: Optional[dict] = None, params: Optional[dict] = None,
        payload: Optional[dict] = None,
    ) -> dict:
        body = {
            "agent_id": agent_id, "method": method, "config": config,
            "credentials": credentials, "params": params, "payload": payload,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout, headers=self._headers) as c:
                r = await c.post(f"{self._base}/internal/relay/dispatch", json=body)
        except httpx.ConnectError as e:
            raise ConnectionError(f"backend unreachable: {e}") from e
        except httpx.ReadTimeout as e:
            raise TimeoutError(f"backend read timeout: {e}") from e

        if r.status_code == 502:
            # Backend mapped broker ConnectionError → 502; re-raise as the
            # type tools already know how to handle.
            raise ConnectionError((r.json() or {}).get("detail", "relay not connected"))
        if r.status_code == 504:
            raise TimeoutError((r.json() or {}).get("detail", "relay timeout"))
        if r.status_code >= 400:
            detail = (r.json() or {}).get("detail", r.text[:200])
            raise RuntimeError(f"relay dispatch HTTP {r.status_code}: {detail}")
        return (r.json() or {}).get("result", {})

    async def send_streaming_task(
        self, agent_id: str, config: dict,
        credentials: Optional[dict] = None, params: Optional[dict] = None,
    ) -> AsyncIterator[list]:
        # Streaming (fetch_all) is not yet routed through the internal bridge.
        # Integration-builder syncs — the only caller today — run in-process in
        # the backend and hit `RelayBroker.send_streaming_task` directly.
        # Wire this endpoint when a worker-side caller actually needs it.
        raise NotImplementedError(
            "RemoteRelayBroker.send_streaming_task: workers don't stream yet. "
            "Add the SSE route + client if/when a worker-side integration sync appears."
        )



# ── Singleton (role-aware) ──

_local: Optional[RelayBroker] = None
_remote: Optional[RemoteRelayBroker] = None


def _role() -> str:
    return os.environ.get("HAKUNA_PROCESS_ROLE", "api").lower()


def get_relay_broker():
    """Return the right broker flavor for the current process.

    - ``HAKUNA_PROCESS_ROLE=worker`` (audit-worker / Celery) → RemoteRelayBroker
      (HTTP stub pointing at the backend).
    - Anything else (backend uvicorn, tests, CLI scripts) → in-process
      ``RelayBroker``.

    Callers never need to care which they got — the interface matches on the
    methods tools actually use.
    """
    global _local, _remote
    if _role() == "worker":
        if _remote is None:
            from core.auth import INTERNAL_SHARED_SECRET
            _remote = RemoteRelayBroker(
                base_url=os.environ.get("HAKUNA_BACKEND_URL", "http://backend:8000"),
                token=INTERNAL_SHARED_SECRET,
            )
        return _remote
    if _local is None:
        _local = RelayBroker()
    return _local


# Back-compat alias: earlier code expected `get_relay_broker` to be typed
# `-> RelayBroker`. Now it returns either flavor. Keep the old name working.
_broker = None
