"""Internal event bus — emit-site wrapper.

Single entry point for any code that wants to fire a system event
(``scan_complete``, ``asset_created``, ``validated_chain``, …). Calls
``agent_dispatcher.dispatch`` to wake the configured agent for the org;
that agent then reasons over the payload and posts a feed entry.

This is intentionally NOT a real pub/sub bus — it's a single-process
function dispatch that happens to be the right shape to swap in a real
bus later (Pub/Sub, Redis Streams, …) without changing emit-site code.

Emit sites should be cheap and non-blocking. ``emit`` returns
immediately after queuing the agent run on ``job_manager``; the agent
run executes in the background.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from services import agent_dispatcher

logger = logging.getLogger(__name__)


def emit(
    db: Session,
    *,
    event_type: str,
    org_id: int,
    payload: dict[str, Any] | None = None,
    dedup_key: Any = None,
) -> dict:
    """Fire ``event_type`` for ``org_id`` with the given payload.

    Returns the dispatcher's status dict — typically ``{"dispatched":
    True, ...}`` or ``{"dispatched": False, "reason": "no_agent"}``
    when the org hasn't opted in. The caller should treat both as
    success — "no agent configured" is the steady state for orgs that
    haven't enabled this event yet.

    ``dedup_key`` (optional): a stable id within the event — typically
    the primary entity (``scan_id``, ``asset_id``, ``finding_id``). When
    set, the dispatcher's debounce + rate-limit key on
    ``(agent, event_type, dedup_key)`` instead of just
    ``(agent, event_type)``, so two scans landing within the window
    each get their own narrator run. When ``None``, falls back to
    per-event-type debounce.

    Never raises: a bad emit must not break the pipeline path that
    triggered it. Errors are logged.
    """
    payload = payload or {}
    if not event_type:
        return {"dispatched": False, "reason": "missing_event_type"}
    if not org_id:
        return {"dispatched": False, "reason": "missing_org_id"}

    try:
        return agent_dispatcher.dispatch(
            db,
            event_type=event_type,
            org_id=org_id,
            payload=payload,
            dedup_key=dedup_key,
        )
    except Exception:
        logger.exception(
            "event_bus.emit: dispatcher raised for event=%s org=%d",
            event_type, org_id,
        )
        return {"dispatched": False, "reason": "dispatcher_error"}
