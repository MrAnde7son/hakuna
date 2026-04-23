"""Internal RPC: let out-of-process workers reach the relay websocket.

Audit workers (Celery) don't own the websocket to on-prem relay agents — the
websocket is accepted on the backend at `/ws/relay` and its Python-side object
lives in that process's `RelayBroker` singleton. Tools in `agents/tools/*` call
`broker.send_task(...)` expecting that local object to be present. For a worker
process the singleton is empty; every call would raise "relay not connected".

This router is the bridge. Workers POST here with a shared-secret header; the
backend runs the task through its in-process broker and returns the result.
Call sites don't know the difference — `services/relay_broker.get_relay_broker()`
returns either a local `RelayBroker` (backend) or a `RemoteRelayBroker` stub
(worker) that speaks to this router.

Scoped to process-to-process dispatch. Not exposed to the browser — the
`/internal/*` prefix is kept off any public gateway routing.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.auth import require_internal_token
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/relay", tags=["internal"])


class RelayDispatchRequest(BaseModel):
    agent_id: str
    method: str
    config: dict
    credentials: dict | None = None
    params: dict | None = None
    payload: dict | None = None


@router.post("/dispatch")
async def dispatch(
    body: RelayDispatchRequest,
    _: None = Depends(require_internal_token),
) -> dict[str, Any]:
    """One-shot relay task. Returns the task result on success.

    Translates broker exceptions to HTTP codes the client can cleanly map
    back to a raised `ConnectionError` / `TimeoutError` (the errors the
    in-process broker raises, so the worker-side stub can re-raise the
    same types and tools see identical behavior).
    """
    broker = get_relay_broker()
    try:
        result = await broker.send_task(
            body.agent_id, body.method, body.config,
            credentials=body.credentials,
            params=body.params,
            payload=body.payload,
        )
    except ConnectionError as e:
        raise HTTPException(502, str(e))
    except TimeoutError as e:
        raise HTTPException(504, str(e))
    except RuntimeError as e:
        # Agent reported a task_error (bad creds, target refused, op failed).
        # 422 lets RemoteRelayBroker re-raise as RuntimeError with the original
        # message, so worker-side tools see the same exception a local broker
        # would raise — not a generic 500.
        raise HTTPException(422, str(e))
    return {"result": result}


@router.get("/{agent_id}/presence")
async def presence(
    agent_id: str,
    _: None = Depends(require_internal_token),
) -> dict[str, bool]:
    """Cheap liveness probe. Workers use this for `broker.is_connected(...)`
    without round-tripping a full dispatch. Expected latency <5ms."""
    return {"connected": get_relay_broker().is_connected(agent_id)}
