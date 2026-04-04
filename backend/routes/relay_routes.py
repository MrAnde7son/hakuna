"""
Relay agent routes — REST API for agent management + WebSocket endpoint.
Prefix: /api/relay-agents
"""
import logging
import secrets
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, require_auth
from models.models import RelayAgent, Integration
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/relay-agents", tags=["relay-agents"])
ws_router = APIRouter()

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

TOKEN_PREFIX = "hka_"


# ─────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────

class CreateAgentRequest(BaseModel):
    name: str
    allowed_hosts: List[str] = []
    credentials_mode: str = "agent_local"
    labels: dict = {}

class UpdateAgentRequest(BaseModel):
    name: Optional[str] = None
    allowed_hosts: Optional[List[str]] = None
    credentials_mode: Optional[str] = None
    labels: Optional[dict] = None

class AgentResponse(BaseModel):
    id: str
    name: str
    status: str
    last_seen_at: Optional[str] = None
    agent_version: Optional[str] = None
    ip_address: Optional[str] = None
    allowed_hosts: list = []
    credentials_mode: str = "agent_local"
    labels: dict = {}
    token_prefix: Optional[str] = None
    created_at: Optional[str] = None
    integration_count: int = 0


def _agent_to_dict(agent: RelayAgent, integration_count: int = 0) -> dict:
    return {
        "id": agent.id,
        "name": agent.name,
        "status": agent.status or "disconnected",
        "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        "agent_version": agent.agent_version,
        "ip_address": agent.ip_address,
        "allowed_hosts": agent.allowed_hosts or [],
        "credentials_mode": agent.credentials_mode or "agent_local",
        "labels": agent.labels or {},
        "token_prefix": agent.token_prefix,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
        "integration_count": integration_count,
    }


# ─────────────────────────────────────────────────────────
# REST Endpoints
# ─────────────────────────────────────────────────────────

@router.get("")
async def list_agents(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """List all relay agents for the current org."""
    org_id = current_user.org_id
    agents = db.query(RelayAgent).filter(RelayAgent.org_id == org_id).order_by(RelayAgent.created_at.desc()).all()

    broker = get_relay_broker()
    results = []
    for agent in agents:
        # Update live status from broker
        if broker.is_connected(agent.id) and agent.status != "connected":
            agent.status = "connected"
        elif not broker.is_connected(agent.id) and agent.status == "connected":
            agent.status = "disconnected"

        count = db.query(Integration).filter(Integration.relay_agent_id == agent.id).count()
        results.append(_agent_to_dict(agent, integration_count=count))

    db.commit()
    return results


@router.post("")
async def create_agent(
    body: CreateAgentRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Create a new relay agent and return the one-time token."""
    org_id = current_user.org_id

    # Generate a secure token
    raw_token = TOKEN_PREFIX + secrets.token_urlsafe(48)
    token_hash = _pwd_ctx.hash(raw_token)
    token_prefix = raw_token[:12] + "..."

    agent = RelayAgent(
        org_id=org_id,
        name=body.name,
        token_hash=token_hash,
        token_prefix=token_prefix,
        allowed_hosts=body.allowed_hosts,
        credentials_mode=body.credentials_mode,
        labels=body.labels,
        created_by=str(current_user.id),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    return {
        **_agent_to_dict(agent),
        "token": raw_token,  # Only returned once at creation
    }


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    org_id = current_user.org_id
    agent = db.query(RelayAgent).filter(
        RelayAgent.id == agent_id, RelayAgent.org_id == org_id
    ).first()
    if not agent:
        raise HTTPException(404, "Relay agent not found")

    broker = get_relay_broker()
    agent.status = "connected" if broker.is_connected(agent.id) else "disconnected"
    db.commit()

    count = db.query(Integration).filter(Integration.relay_agent_id == agent.id).count()
    return _agent_to_dict(agent, integration_count=count)


@router.put("/{agent_id}")
async def update_agent(
    agent_id: str,
    body: UpdateAgentRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    org_id = current_user.org_id
    agent = db.query(RelayAgent).filter(
        RelayAgent.id == agent_id, RelayAgent.org_id == org_id
    ).first()
    if not agent:
        raise HTTPException(404, "Relay agent not found")

    if body.name is not None:
        agent.name = body.name
    if body.allowed_hosts is not None:
        agent.allowed_hosts = body.allowed_hosts
    if body.credentials_mode is not None:
        agent.credentials_mode = body.credentials_mode
    if body.labels is not None:
        agent.labels = body.labels
    db.commit()
    db.refresh(agent)

    count = db.query(Integration).filter(Integration.relay_agent_id == agent.id).count()
    return _agent_to_dict(agent, integration_count=count)


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    org_id = current_user.org_id
    agent = db.query(RelayAgent).filter(
        RelayAgent.id == agent_id, RelayAgent.org_id == org_id
    ).first()
    if not agent:
        raise HTTPException(404, "Relay agent not found")

    # Check for linked integrations
    linked = db.query(Integration).filter(Integration.relay_agent_id == agent_id).count()
    if linked > 0:
        raise HTTPException(409, f"Agent is used by {linked} integration(s). Remove them first.")

    # Disconnect if connected
    broker = get_relay_broker()
    if broker.is_connected(agent_id):
        await broker.unregister(agent_id)

    db.delete(agent)
    db.commit()
    return {"ok": True}


@router.post("/{agent_id}/rotate-token")
async def rotate_token(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Generate a new token for an agent (invalidates the old one)."""
    org_id = current_user.org_id
    agent = db.query(RelayAgent).filter(
        RelayAgent.id == agent_id, RelayAgent.org_id == org_id
    ).first()
    if not agent:
        raise HTTPException(404, "Relay agent not found")

    raw_token = TOKEN_PREFIX + secrets.token_urlsafe(48)
    agent.token_hash = _pwd_ctx.hash(raw_token)
    agent.token_prefix = raw_token[:12] + "..."

    # Disconnect existing connection (old token is now invalid)
    broker = get_relay_broker()
    if broker.is_connected(agent_id):
        await broker.unregister(agent_id)
    agent.status = "disconnected"

    db.commit()
    return {
        "token": raw_token,
        "token_prefix": agent.token_prefix,
    }


@router.get("/{agent_id}/setup")
async def get_setup_instructions(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Return setup instructions for deploying the relay agent."""
    org_id = current_user.org_id
    agent = db.query(RelayAgent).filter(
        RelayAgent.id == agent_id, RelayAgent.org_id == org_id
    ).first()
    if not agent:
        raise HTTPException(404, "Relay agent not found")

    # Build the docker run command
    docker_cmd = (
        "docker run -d --restart=unless-stopped \\\n"
        "  --name hakuna-relay-agent \\\n"
        "  -e HAKUNA_AGENT_TOKEN=<your-agent-token> \\\n"
        "  -e HAKUNA_CLOUD_URL=wss://<your-hakuna-host>/ws/relay \\\n"
        "  hakuna/relay-agent:latest"
    )

    # Build docker-compose example
    compose_yaml = (
        "version: '3.8'\n"
        "services:\n"
        "  hakuna-relay:\n"
        "    image: hakuna/relay-agent:latest\n"
        "    restart: unless-stopped\n"
        "    environment:\n"
        "      HAKUNA_AGENT_TOKEN: <your-agent-token>\n"
        "      HAKUNA_CLOUD_URL: wss://<your-hakuna-host>/ws/relay\n"
        "      # Add on-prem service credentials below:\n"
        "      # JIRA_BASE_URL: http://jira.internal:8080\n"
        "      # JIRA_USERNAME: svc-hakuna\n"
        "      # JIRA_PASSWORD: secret\n"
    )

    # Agent env vars reference
    env_vars = [
        {"name": "HAKUNA_AGENT_TOKEN", "required": True, "description": "Authentication token (from agent creation)"},
        {"name": "HAKUNA_CLOUD_URL", "required": True, "description": "WebSocket URL of your Hakuna instance"},
        {"name": "HAKUNA_LOG_LEVEL", "required": False, "description": "Logging level (DEBUG, INFO, WARNING). Default: INFO"},
        {"name": "HAKUNA_RECONNECT_MAX", "required": False, "description": "Max reconnect delay in seconds. Default: 60"},
    ]

    # Per-product credential env vars
    product_env_examples = [
        {"product": "Jira Server/DC", "vars": [
            {"name": "JIRA_BASE_URL", "example": "http://jira.internal:8080"},
            {"name": "JIRA_USERNAME", "example": "svc-hakuna"},
            {"name": "JIRA_PASSWORD", "example": "<password>"},
        ]},
        {"product": "ServiceNow", "vars": [
            {"name": "SERVICENOW_BASE_URL", "example": "https://yourcompany.service-now.com"},
            {"name": "SERVICENOW_USERNAME", "example": "svc-hakuna"},
            {"name": "SERVICENOW_PASSWORD", "example": "<password>"},
        ]},
        {"product": "CrowdStrike (GovCloud)", "vars": [
            {"name": "CROWDSTRIKE_BASE_URL", "example": "https://api.laggar.gcw.crowdstrike.com"},
            {"name": "CROWDSTRIKE_CLIENT_ID", "example": "<client-id>"},
            {"name": "CROWDSTRIKE_CLIENT_SECRET", "example": "<client-secret>"},
        ]},
    ]

    return {
        "agent_id": agent.id,
        "agent_name": agent.name,
        "credentials_mode": agent.credentials_mode,
        "docker_run": docker_cmd,
        "docker_compose": compose_yaml,
        "env_vars": env_vars,
        "product_examples": product_env_examples,
        "steps": [
            "1. Copy the agent token from above (shown only once at creation).",
            "2. Deploy the relay agent container in your network using Docker or Docker Compose.",
            "3. Set HAKUNA_AGENT_TOKEN and HAKUNA_CLOUD_URL environment variables.",
            "4. If using agent-local credentials, add the on-prem product credentials as environment variables.",
            "5. Start the container. It will connect to Hakuna automatically.",
            "6. Verify the agent shows as 'Connected' in the Hakuna dashboard.",
            "7. Create an integration in the Integration Builder and select this relay agent.",
        ],
    }


# ─────────────────────────────────────────────────────────
# WebSocket Endpoint
# ─────────────────────────────────────────────────────────

def _authenticate_agent(db: Session, token: str) -> Optional[RelayAgent]:
    """Verify an agent token against stored hashes."""
    if not token or not token.startswith(TOKEN_PREFIX):
        return None

    # Query all agents and check hashes (bcrypt is slow per-check but agents are few)
    agents = db.query(RelayAgent).all()
    for agent in agents:
        if _pwd_ctx.verify(token, agent.token_hash):
            return agent
    return None


@ws_router.websocket("/ws/relay")
async def relay_websocket(ws: WebSocket, db: Session = Depends(get_db)):
    """WebSocket endpoint for relay agent connections.

    Agents authenticate via the Authorization header or the first message.
    """
    # Try auth from query param (WebSocket clients can't always set headers)
    token = ws.query_params.get("token", "")
    if not token:
        # Try Authorization header
        auth_header = ws.headers.get("authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()

    agent = _authenticate_agent(db, token)
    if not agent:
        await ws.accept()
        await ws.send_json({"type": "error", "message": "Invalid agent token"})
        await ws.close(code=4001, reason="Unauthorized")
        return

    await ws.accept()

    # Update agent metadata
    agent.status = "connected"
    agent.last_seen_at = datetime.utcnow()
    agent.ip_address = ws.client.host if ws.client else None
    db.commit()

    broker = get_relay_broker()
    await broker.register(agent.id, ws, info={
        "org_id": agent.org_id,
        "name": agent.name,
    })

    # Send welcome message
    await ws.send_json({
        "type": "welcome",
        "agent_id": agent.id,
        "agent_name": agent.name,
        "credentials_mode": agent.credentials_mode,
        "allowed_hosts": agent.allowed_hosts or [],
    })

    try:
        while True:
            msg = await ws.receive_json()
            await broker.handle_agent_message(agent.id, msg)

            # Update last_seen
            agent.last_seen_at = datetime.utcnow()
            if msg.get("type") == "pong":
                agent.agent_version = msg.get("agent_version")
            db.commit()
    except WebSocketDisconnect:
        logger.info("Relay agent %s (%s) disconnected", agent.name, agent.id)
    except Exception as e:
        logger.exception("Relay WebSocket error for agent %s", agent.id)
    finally:
        await broker.unregister(agent.id)
        agent.status = "disconnected"
        agent.last_seen_at = datetime.utcnow()
        db.commit()
