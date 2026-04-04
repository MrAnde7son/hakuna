"""Relay broker — manages WebSocket connections to on-prem relay agents and routes tasks."""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional

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


# ── Singleton ──

_broker: Optional[RelayBroker] = None


def get_relay_broker() -> RelayBroker:
    global _broker
    if _broker is None:
        _broker = RelayBroker()
    return _broker
