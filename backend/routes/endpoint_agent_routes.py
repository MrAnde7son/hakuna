"""Endpoint agent routes — host-resident live vulnerability detection & response.

Prefix: /api/endpoint-agents

Two audiences share this router:

* Management endpoints (JWT auth) — create/list agents, queue response
  actions, inspect findings. Used by the Hakuna UI.
* Agent endpoints (token auth via the `X-Agent-Token` header) — enroll,
  check in with host inventory, report action results. Used by the
  installed agent itself.
"""

import hashlib
import logging
import os
import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.auth import get_current_user, get_accessible_org_ids, resolve_active_org_id
from core.database import get_db
from core.time_utils import iso_utc
from models.models import EndpointAgent, EndpointAgentAction, Finding
from services import endpoint_detection

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/endpoint-agents", tags=["endpoint-agents"])

TOKEN_PREFIX = "hke_"
AGENT_VERSION = "1.0.0"
VALID_ACTION_TYPES = {"kill_process", "quarantine_file", "apply_patch", "isolate_host"}


def _public_base_url() -> str:
    return os.environ.get("HAKUNA_PUBLIC_URL", "http://localhost:8000").rstrip("/")


def _hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────

class CreateAgentRequest(BaseModel):
    name: str
    auto_respond: bool = False
    checkin_interval: int = 300
    labels: dict = {}


class UpdateAgentRequest(BaseModel):
    name: Optional[str] = None
    auto_respond: Optional[bool] = None
    checkin_interval: Optional[int] = None


class EnrollRequest(BaseModel):
    hostname: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None


class CheckinRequest(BaseModel):
    hostname: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None
    agent_version: Optional[str] = None
    public: bool = False
    software: List[dict] = []
    processes: List[dict] = []
    listening_ports: List[dict] = []
    security_controls: List[dict] = []


class QueueActionRequest(BaseModel):
    action_type: str
    params: dict = {}
    finding_id: Optional[int] = None
    reason: Optional[str] = None


class ActionResultRequest(BaseModel):
    status: str           # completed | failed
    result: dict = {}


# ─────────────────────────────────────────────────────────
# Serializers
# ─────────────────────────────────────────────────────────

def _agent_to_dict(agent: EndpointAgent, *, action_counts: dict = None) -> dict:
    return {
        "id": agent.id,
        "name": agent.name,
        "status": agent.status or "pending",
        "hostname": agent.hostname,
        "platform": agent.platform,
        "os_version": agent.os_version,
        "ip_address": agent.ip_address,
        "agent_version": agent.agent_version,
        "asset_id": agent.asset_id,
        "auto_respond": bool(agent.auto_respond),
        "checkin_interval": agent.checkin_interval or 300,
        "last_checkin_at": iso_utc(agent.last_checkin_at),
        "token_prefix": agent.token_prefix,
        "labels": agent.labels or {},
        "created_at": iso_utc(agent.created_at),
        "pending_actions": (action_counts or {}).get("pending", 0),
    }


def _action_to_dict(action: EndpointAgentAction) -> dict:
    return {
        "id": action.id,
        "agent_id": action.agent_id,
        "finding_id": action.finding_id,
        "action_type": action.action_type,
        "params": action.params or {},
        "status": action.status,
        "result": action.result or {},
        "reason": action.reason,
        "origin": action.origin,
        "created_at": iso_utc(action.created_at),
        "dispatched_at": iso_utc(action.dispatched_at),
        "completed_at": iso_utc(action.completed_at),
    }


def _finding_to_dict(f: Finding) -> dict:
    refs = f.references or {}
    return {
        "id": f.id,
        "cve": (f.cves or [None])[0],
        "plugin_name": f.plugin_name,
        "plugin_family": f.plugin_family,
        "severity": f.severity,
        "severity_label": f.severity_label,
        "cvss3_score": f.cvss3_score,
        "priority_score": f.priority_score,
        "is_kev": f.is_kev,
        "epss_score": f.epss_score,
        "exploit_available": f.exploit_available,
        "trending_in_news": f.trending_in_news,
        "description": f.description,
        "solution": f.solution,
        "plugin_output": f.plugin_output,
        "workflow_status": f.workflow_status,
        "ctx_reachability": f.ctx_reachability,
        "ctx_exploitability": f.ctx_exploitability,
        "endpoint_context": refs.get("endpoint_context", {}),
        "ai_threat_signal": refs.get("ai_threat_signal"),
        "first_seen": iso_utc(f.first_seen),
        "last_seen": iso_utc(f.last_seen),
    }


# ─────────────────────────────────────────────────────────
# Agent-facing endpoints (token auth) — declared before /{agent_id}
# ─────────────────────────────────────────────────────────

def _resolve_agent_by_token(db: Session, token: Optional[str]) -> EndpointAgent:
    if not token:
        raise HTTPException(401, "Missing X-Agent-Token header")
    agent = db.query(EndpointAgent).filter(
        EndpointAgent.token_hash == _hash_token(token.strip())
    ).first()
    if not agent:
        raise HTTPException(401, "Invalid agent token")
    if agent.status == "disabled":
        raise HTTPException(403, "Agent is disabled")
    return agent


@router.post("/enroll")
async def enroll_agent(
    body: EnrollRequest,
    db: Session = Depends(get_db),
    x_agent_token: Optional[str] = Header(None),
):
    """First contact from a freshly installed agent — records host facts and
    flips the agent from `pending` to `active`."""
    agent = _resolve_agent_by_token(db, x_agent_token)
    agent.hostname = body.hostname or agent.hostname
    agent.platform = body.platform or agent.platform
    agent.os_version = body.os_version or agent.os_version
    agent.agent_version = body.agent_version or AGENT_VERSION
    if agent.status == "pending":
        agent.status = "active"
    db.commit()
    return {
        "agent_id": agent.id,
        "name": agent.name,
        "checkin_interval": agent.checkin_interval or 300,
        "auto_respond": bool(agent.auto_respond),
    }


@router.post("/checkin")
async def agent_checkin(
    body: CheckinRequest,
    db: Session = Depends(get_db),
    x_agent_token: Optional[str] = Header(None),
):
    """Periodic check-in — submit host inventory, receive detection results
    and any queued host response actions."""
    agent = _resolve_agent_by_token(db, x_agent_token)
    agent.hostname = body.hostname or agent.hostname
    agent.platform = body.platform or agent.platform
    agent.os_version = body.os_version or agent.os_version
    agent.ip_address = body.ip_address or agent.ip_address
    agent.agent_version = body.agent_version or agent.agent_version or AGENT_VERSION
    db.flush()

    try:
        result = endpoint_detection.process_checkin(db, agent, body.model_dump())
    except Exception:
        db.rollback()
        logger.exception("Endpoint check-in failed for agent %s", agent.id)
        raise HTTPException(500, "Check-in processing failed")
    return result


@router.post("/actions/{action_id}/result")
async def report_action_result(
    action_id: str,
    body: ActionResultRequest,
    db: Session = Depends(get_db),
    x_agent_token: Optional[str] = Header(None),
):
    """Agent reports the outcome of a host response action."""
    agent = _resolve_agent_by_token(db, x_agent_token)
    action = db.query(EndpointAgentAction).filter(
        EndpointAgentAction.id == action_id,
        EndpointAgentAction.agent_id == agent.id,
    ).first()
    if not action:
        raise HTTPException(404, "Action not found")

    status = body.status if body.status in ("completed", "failed") else "failed"
    action.status = status
    action.result = body.result or {}
    from datetime import datetime
    action.completed_at = datetime.utcnow()

    # If a remediation action succeeded, mark the linked finding resolved.
    if status == "completed" and action.finding_id and action.action_type in (
        "apply_patch", "quarantine_file"
    ):
        finding = db.get(Finding, action.finding_id)
        if finding and finding.workflow_status != "resolved":
            finding.workflow_status = "resolved"
            finding.resolved_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "action": _action_to_dict(action)}


# ─────────────────────────────────────────────────────────
# Management endpoints (JWT auth)
# ─────────────────────────────────────────────────────────

@router.get("")
async def list_agents(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(EndpointAgent)
    if org_ids is not None:
        q = q.filter(EndpointAgent.org_id.in_(org_ids))
    agents = q.order_by(EndpointAgent.created_at.desc()).all()

    out = []
    for agent in agents:
        pending = db.query(EndpointAgentAction).filter(
            EndpointAgentAction.agent_id == agent.id,
            EndpointAgentAction.status.in_(["pending", "dispatched"]),
        ).count()
        out.append(_agent_to_dict(agent, action_counts={"pending": pending}))
    return out


@router.post("")
async def create_agent(
    body: CreateAgentRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Register a new endpoint agent. Returns the token *once* — it is stored
    only as a hash."""
    org_id = resolve_active_org_id(current_user, org_ids)

    raw_token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    agent = EndpointAgent(
        org_id=org_id,
        name=body.name,
        token_hash=_hash_token(raw_token),
        token_prefix=raw_token[:12] + "...",
        status="pending",
        auto_respond=body.auto_respond,
        checkin_interval=max(30, body.checkin_interval or 300),
        labels=body.labels or {},
        created_by=str(current_user.id),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    base = _public_base_url()
    install_command = (
        f"HAKUNA_URL={base} HAKUNA_AGENT_TOKEN={raw_token} "
        f"python3 hakuna_agent.py --demo"
    )
    return {
        **_agent_to_dict(agent),
        "token": raw_token,
        "install_command": install_command,
    }


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    agent = _get_owned_agent(db, agent_id, org_ids)
    actions = db.query(EndpointAgentAction).filter(
        EndpointAgentAction.agent_id == agent.id
    ).order_by(EndpointAgentAction.created_at.desc()).limit(50).all()

    findings = []
    if agent.asset_id:
        findings = db.query(Finding).filter(
            Finding.asset_id == agent.asset_id,
            Finding.source_type == endpoint_detection.SOURCE,
        ).order_by(Finding.priority_score.desc()).all()

    return {
        **_agent_to_dict(agent),
        "actions": [_action_to_dict(a) for a in actions],
        "findings": [_finding_to_dict(f) for f in findings],
    }


@router.patch("/{agent_id}")
async def update_agent(
    agent_id: str,
    body: UpdateAgentRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    agent = _get_owned_agent(db, agent_id, org_ids)
    if body.name is not None:
        agent.name = body.name
    if body.auto_respond is not None:
        agent.auto_respond = body.auto_respond
    if body.checkin_interval is not None:
        agent.checkin_interval = max(30, body.checkin_interval)
    db.commit()
    return _agent_to_dict(agent)


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    agent = _get_owned_agent(db, agent_id, org_ids)
    db.delete(agent)
    db.commit()
    return {"ok": True}


@router.get("/{agent_id}/findings")
async def list_agent_findings(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    agent = _get_owned_agent(db, agent_id, org_ids)
    if not agent.asset_id:
        return []
    findings = db.query(Finding).filter(
        Finding.asset_id == agent.asset_id,
        Finding.source_type == endpoint_detection.SOURCE,
    ).order_by(Finding.priority_score.desc()).all()
    return [_finding_to_dict(f) for f in findings]


@router.post("/{agent_id}/actions")
async def queue_action(
    agent_id: str,
    body: QueueActionRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Queue a host response action for the agent to execute on next check-in."""
    agent = _get_owned_agent(db, agent_id, org_ids)
    if body.action_type not in VALID_ACTION_TYPES:
        raise HTTPException(
            400, f"Invalid action_type. Allowed: {sorted(VALID_ACTION_TYPES)}"
        )
    action = EndpointAgentAction(
        org_id=agent.org_id,
        agent_id=agent.id,
        finding_id=body.finding_id,
        action_type=body.action_type,
        params=body.params or {},
        reason=body.reason,
        origin="manual",
        created_by=str(current_user.id),
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return _action_to_dict(action)


@router.post("/{agent_id}/findings/{finding_id}/edr-detection")
async def create_finding_edr_detection(
    agent_id: str,
    finding_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Close the loop — turn a finding into an EDR detection rule."""
    agent = _get_owned_agent(db, agent_id, org_ids)
    finding = db.query(Finding).filter(
        Finding.id == finding_id, Finding.asset_id == agent.asset_id
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found for this agent")

    rule = endpoint_detection.create_edr_detection(
        db, agent.org_id, finding, origin="manual"
    )
    db.commit()
    return {
        "detection_rule_id": rule.id,
        "name": rule.name,
        "severity": rule.severity,
        "push_connector": endpoint_detection.EDR_PUSH_CONNECTOR,
    }


def _get_owned_agent(db: Session, agent_id: str,
                     org_ids: Optional[List[int]]) -> EndpointAgent:
    q = db.query(EndpointAgent).filter(EndpointAgent.id == agent_id)
    if org_ids is not None:
        q = q.filter(EndpointAgent.org_id.in_(org_ids))
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Endpoint agent not found")
    return agent
