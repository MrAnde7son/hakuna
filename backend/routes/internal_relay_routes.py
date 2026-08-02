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

import asyncio
import hmac
import logging
import os
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from pydantic import BaseModel
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from core.auth import require_internal_token
from core.database import SessionLocal, get_db
from models.models import Organization, RelayAgent
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/relay", tags=["internal"])
cloud_ws_router = APIRouter()


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


# ─────────────────────────────────────────────────────────────────
# Cloud relay (Hakuna-managed scanner running in GCP)
# ─────────────────────────────────────────────────────────────────
#
# The cloud scanner is a single multi-tenant container that holds one
# WebSocket per org and dispatches public-asset audits without needing a
# customer deployment. It authenticates with INTERNAL_SHARED_SECRET (the
# same shared secret the audit-worker uses for /internal/relay/dispatch)
# rather than per-org bearer tokens — the cloud relay runs inside the same
# trust boundary as the API.
#
# Flow:
#   1. Cloud relay polls GET /internal/cloud-relay/registrations.
#      Backend ensures every org has a relay_type='cloud_scanner' row,
#      returns the list of (agent_id, org_id, name).
#   2. For each agent_id, the cloud relay opens a WebSocket to
#      /ws/relay/cloud?agent_id=<id>&token=<INTERNAL_SHARED_SECRET>.
#   3. Backend validates the secret, looks up the agent, and registers it
#      with the in-process RelayBroker — same as a customer agent.
#
# When auto-trigger fires for an internet-facing asset, _pick_relay
# returns the cloud_scanner row and dispatch goes through the cloud
# relay's WebSocket. Customer-deployed agents continue to handle private
# assets unchanged.


class CloudRegistration(BaseModel):
    agent_id: str
    org_id: int
    name: str


def ensure_cloud_relay_for_org(db: Session, org: Organization) -> RelayAgent:
    """Idempotently create the cloud_scanner row for ``org``.

    One row per org. Token fields are set to a sentinel — the cloud relay
    authenticates via INTERNAL_SHARED_SECRET on /ws/relay/cloud, not a
    bearer token, so token_hash never gets verified for these rows.

    Called both by the cloud-relay registrations poll (production path,
    where the GCP container picks up the row and opens a WebSocket) and by
    the user-facing list_agents endpoint (so the row is visible in the UI
    even in environments where no cloud relay is deployed).
    """
    existing = (
        db.query(RelayAgent)
        .filter(RelayAgent.org_id == org.id, RelayAgent.relay_type == "cloud_scanner")
        .first()
    )
    if existing:
        return existing

    agent = RelayAgent(
        org_id=org.id,
        name="Hakuna Cloud Scanner",
        relay_type="cloud_scanner",
        token_hash="cloud-managed",   # never verified; see _ws_auth_check below
        token_prefix=None,
        credentials_mode="cloud_managed",
        labels={"managed_by": "hakuna"},
        created_by="system",
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    logger.info("auto-provisioned cloud_scanner relay for org %d (%s)", org.id, agent.id)
    return agent


@router.get("/cloud-relay/registrations")
async def cloud_relay_registrations(
    db: Session = Depends(get_db),
    _: None = Depends(require_internal_token),
) -> list[dict[str, Any]]:
    """Return cloud_scanner agent IDs for every org. Auto-provisions missing rows."""
    out: list[dict[str, Any]] = []
    for org in db.query(Organization).all():
        agent = ensure_cloud_relay_for_org(db, org)
        out.append({
            "agent_id": agent.id,
            "org_id": org.id,
            "name": agent.name,
        })
    return out


def _internal_secret() -> str:
    return os.environ.get("INTERNAL_SHARED_SECRET", "")


# Cloud Run kills the /ws/relay/cloud request at its 300s timeout, and the
# cloud-scanner reconnects within ~1s. Writing status='disconnected' immediately
# in the WS handler's finally block makes the UI flap to "Not deployed" during
# that gap. Defer the write — if last_seen_at advances past disconnect_at within
# the grace window, a reconnect happened (possibly on a different Cloud Run
# instance) and we skip the write.
_DISCONNECT_GRACE_SECONDS = 15


def _mark_disconnected_if_stale(agent_id: str, disconnect_at: datetime) -> None:
    db = SessionLocal()
    try:
        a = db.query(RelayAgent).filter(RelayAgent.id == agent_id).first()
        if a is None:
            return
        # last_seen_at is bumped on every message and on reconnect. If it has
        # advanced past our disconnect timestamp, the relay reconnected (here
        # or on another instance) — leave status alone.
        if a.last_seen_at and a.last_seen_at > disconnect_at:
            return
        a.status = "disconnected"
        a.last_seen_at = disconnect_at
        db.commit()
    except Exception:
        logger.exception("Failed to mark cloud_scanner %s disconnected", agent_id)
        db.rollback()
    finally:
        db.close()


async def _delayed_disconnect_status(agent_id: str, disconnect_at: datetime) -> None:
    try:
        await asyncio.sleep(_DISCONNECT_GRACE_SECONDS)
    except asyncio.CancelledError:
        return
    await asyncio.to_thread(_mark_disconnected_if_stale, agent_id, disconnect_at)


@cloud_ws_router.websocket("/ws/relay/cloud")
async def cloud_relay_websocket(ws: WebSocket, db: Session = Depends(get_db)):
    """WebSocket endpoint for the Hakuna-managed cloud scanner.

    Authenticates via the same INTERNAL_SHARED_SECRET used for
    /internal/relay/* — the cloud relay runs in the same trust boundary as
    the API, so it doesn't need per-agent bearer tokens. The agent_id is
    passed as a query param and must reference a relay_type='cloud_scanner'
    row.
    """
    token = ws.query_params.get("token", "")
    agent_id = ws.query_params.get("agent_id", "")

    secret = _internal_secret()
    if not secret or not token or not hmac.compare_digest(token, secret):
        await ws.accept()
        await ws.send_json({"type": "error", "message": "Unauthorized"})
        await ws.close(code=4001, reason="Unauthorized")
        return

    agent = db.query(RelayAgent).filter(
        RelayAgent.id == agent_id,
        RelayAgent.relay_type == "cloud_scanner",
    ).first()
    if not agent:
        await ws.accept()
        await ws.send_json({"type": "error", "message": "Unknown cloud_scanner agent"})
        await ws.close(code=4004, reason="Unknown agent")
        return

    await ws.accept()

    agent.status = "connected"
    agent.last_seen_at = datetime.utcnow()
    agent.ip_address = ws.client.host if ws.client else None
    db.commit()

    broker = get_relay_broker()
    await broker.register(agent.id, ws, info={
        "org_id": agent.org_id,
        "name": agent.name,
        "relay_type": "cloud_scanner",
    })

    await ws.send_json({
        "type": "welcome",
        "agent_id": agent.id,
        "agent_name": agent.name,
        "credentials_mode": agent.credentials_mode,
        "allowed_hosts": agent.allowed_hosts or [],
    })

    try:
        from fastapi import WebSocketDisconnect
        while True:
            msg = await ws.receive_json()
            await broker.handle_agent_message(agent.id, msg)
            agent.last_seen_at = datetime.utcnow()
            if msg.get("type") == "pong":
                v = msg.get("agent_version")
                if isinstance(v, str) and v:
                    agent.agent_version = v
            db.commit()
    except WebSocketDisconnect:
        logger.info("Cloud relay agent %s disconnected", agent.id)
    except OperationalError:
        # DB session is held open for this connection's whole lifetime (up to
        # Cloud Run's 300s timeout); a server-closed idle connection here just
        # means the underlying socket died before the client did. Expected,
        # not an app error — pool_pre_ping can't catch this because the
        # session was already checked out. See incident 2026-08-02.
        db.rollback()
        logger.info("Cloud relay agent %s: DB connection dropped mid-session", agent.id)
    except Exception:
        logger.exception("Cloud relay WebSocket error for agent %s", agent.id)
    finally:
        await broker.unregister(agent.id)
        disconnect_at = datetime.utcnow()
        asyncio.create_task(_delayed_disconnect_status(agent.id, disconnect_at))
