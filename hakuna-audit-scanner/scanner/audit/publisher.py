"""Run-event publisher — streams ReAct loop events out of the worker.

The audit engine runs in a Celery worker process; the backend's
``GET /api/audits/runs/{run_id}/stream`` (SSE) endpoint runs in the
backend process. Per-iteration progress (``thinking`` → ``tool_call``
→ ``tool_result`` → ``text`` → ``done``) crosses the process boundary
via Redis pub-sub:

  - Engine publishes events to channel ``audit:run:{run_id}``.
  - Backend subscribes to that channel for the duration of the SSE
    connection and forwards each message to the client.

OSS standalone use: no backend, no SSE — wire the ``NullPublisher``
(default when ``REDIS_PUBSUB_URL`` is unset) and let the Celery result
payload carry the final transcript.

The ``RunPublisher`` protocol is async-publish only — subscribers live
elsewhere. Each event is a JSON dict with at minimum ``{"type": ...,
"run_id": ..., "ts": ...}``. The schema mirrors the backend's
``run_agent_streaming`` events so the frontend agent-run viewer can
consume both with no branching.

Event types the engine emits:

  - ``run_start``    — once at iteration 0, with provider/model/mission
  - ``thinking``     — once per iteration before the LLM call
  - ``tool_call``    — once per tool dispatched, with name + redacted input
  - ``tool_result``  — once per tool, with truncated result preview
  - ``text``         — assistant text blocks (may stream multiple per turn)
  - ``finding``      — emitted at every emit_finding call
  - ``run_end``      — once with stop_reason, iterations, duration
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class RunPublisher(Protocol):
    """Publish one event for ``run_id``. Implementations must be safe to
    call from a worker thread; engine wraps blocking calls accordingly."""

    def publish(self, run_id: str, event: dict) -> None: ...

    def close(self) -> None: ...


# ── Null impl (OSS standalone default) ───────────────────────────


class NullPublisher:
    """No-op — used when ``REDIS_PUBSUB_URL`` is not configured. Engine
    still invokes ``publish``; events vanish, transcript still arrives
    in the Celery result payload."""

    def publish(self, run_id: str, event: dict) -> None:
        return None

    def close(self) -> None:
        return None


# ── Redis impl ───────────────────────────────────────────────────


class RedisPublisher:
    """Publishes to ``audit:run:{run_id}``.

    Uses sync ``redis`` because the engine wraps publish calls with
    ``asyncio.to_thread`` already (and the publisher must work from
    the OpenAI/Anthropic SDK threadpool callbacks too — those run
    outside any event loop). Connection pool is shared across runs.
    """

    _CHANNEL_PREFIX = "audit:run:"

    def __init__(self, url: str):
        try:
            import redis  # type: ignore
        except ImportError as e:
            raise RuntimeError(f"redis package required for RedisPublisher: {e}")
        self._url = url
        self._client = redis.from_url(url, decode_responses=True)

    def publish(self, run_id: str, event: dict) -> None:
        channel = f"{self._CHANNEL_PREFIX}{run_id}"
        try:
            payload = json.dumps(event, default=str)
        except (TypeError, ValueError):
            logger.warning("publisher: event for %s not JSON-serialisable; dropping", run_id)
            return
        try:
            self._client.publish(channel, payload)
        except Exception:
            # Publishing must not fail the audit — log and continue. A
            # closed Redis or transient outage means the live viewer
            # loses some events; the Celery result still has the full
            # transcript.
            logger.exception("publisher: redis publish failed (run=%s)", run_id)

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass


# ── Factory ──────────────────────────────────────────────────────


def make_publisher(url: str | None = None) -> RunPublisher:
    """Return a RedisPublisher when a URL is provided, else NullPublisher.

    Resolution: explicit ``url`` arg > ``REDIS_PUBSUB_URL`` env >
    ``CELERY_BROKER_URL`` env (re-use the same Redis as Celery — fine
    for almost every deployment). Returning Null when nothing is set
    is the OSS-standalone path; warning is intentionally absent because
    no-streaming is a valid configuration.
    """
    candidate = url or os.environ.get("REDIS_PUBSUB_URL") or os.environ.get("CELERY_BROKER_URL")
    if not candidate or not candidate.startswith(("redis://", "rediss://")):
        return NullPublisher()
    try:
        return RedisPublisher(candidate)
    except Exception:
        logger.exception("publisher: failed to construct RedisPublisher; falling back to NullPublisher")
        return NullPublisher()


def event(event_type: str, run_id: str, **fields: Any) -> dict:
    """Helper — every event includes ``type``, ``run_id``, ``ts``."""
    return {
        "type": event_type,
        "run_id": run_id,
        "ts": datetime.utcnow().isoformat(),
        **fields,
    }
