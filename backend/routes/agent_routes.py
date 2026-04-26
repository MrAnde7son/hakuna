"""
Mini Agent API routes — CRUD for agents, run endpoint, templates, streaming, schedules.
"""
import json
import asyncio
import os
from typing import Optional, List, Dict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Header, Request, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db, SessionLocal
from core.limiter import limiter
from core.time_utils import iso_utc
from models.models import Agent, AgentRun, AgentSchedule, AgentDocument, AgentApproval, LLMInteraction, User
from core.auth import get_current_user, get_accessible_org_ids, apply_org_filter
from agents.agent_tools import get_tool_catalog
from agents.agent_engine import run_agent, run_agent_streaming, update_agent_memory, resume_agent_run
from agents.agent_pipeline import get_available_pipelines, PIPELINE_REGISTRY
from agents.agent_prompts import ENHANCED_PROMPTS

from hakuna.routing.model_router import SONNET as _DEFAULT_MODEL
from agents.agent_engine import get_default_model, get_available_providers

router = APIRouter(prefix="/api/agents", tags=["agents"])


# ── Pydantic schemas ─────────────────────────────────────────────────

class AgentCreate(BaseModel):
    name: str
    description: Optional[str] = None
    system_prompt: str
    tools: List[str] = []
    guardrails: Dict = {}
    model: Optional[str] = None  # resolved at creation time from configured provider

class AgentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    system_prompt: Optional[str] = None
    tools: Optional[List[str]] = None
    guardrails: Optional[Dict] = None
    model: Optional[str] = None
    memory: Optional[Dict] = None

class AgentRunRequest(BaseModel):
    input: str


# ── Tool catalog ─────────────────────────────────────────────────────

@router.get("/tool-catalog")
def tool_catalog():
    """List all available tools agents can use."""
    return get_tool_catalog()


@router.get("/available-models")
def available_models(db: Session = Depends(get_db)):
    """Return providers and models that have API keys configured."""
    providers = get_available_providers(db)
    default = get_default_model(db)
    return {"providers": providers, "default_model": default}


# ── Agent CRUD ───────────────────────────────────────────────────────

@router.get("")
def list_agents(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = db.query(Agent).filter(Agent.name != "__copilot__").order_by(Agent.updated_at.desc())
    q = apply_org_filter(q, Agent, org_ids)
    # Scratch agents are spawned per-(asset, mission) by the audit runner and
    # are scan-internal; their traces surface from the Scan detail panel, not
    # the Agents list. Filter in Python so we don't need dialect-specific
    # JSON operators (tests run on SQLite, prod on Postgres).
    agents = [
        a for a in q.all()
        if not (isinstance(a.guardrails, dict) and a.guardrails.get("scratch") is True)
    ]
    agent_ids = [a.id for a in agents]

    # Gather last run per agent (status + timestamp + run_count)
    from sqlalchemy import func, case
    last_runs = {}
    run_counts = {}
    if agent_ids:
        # Latest run per agent
        subq = (
            db.query(AgentRun.agent_id, func.max(AgentRun.id).label("max_id"))
            .filter(AgentRun.agent_id.in_(agent_ids))
            .group_by(AgentRun.agent_id)
            .subquery()
        )
        latest = (
            db.query(AgentRun)
            .join(subq, AgentRun.id == subq.c.max_id)
            .all()
        )
        for r in latest:
            last_runs[r.agent_id] = {
                "status": r.status,
                "created_at": iso_utc(r.created_at),
                "input": (r.input or "")[:100],
            }
        # Run count per agent
        counts = (
            db.query(AgentRun.agent_id, func.count(AgentRun.id))
            .filter(AgentRun.agent_id.in_(agent_ids))
            .group_by(AgentRun.agent_id)
            .all()
        )
        run_counts = {aid: cnt for aid, cnt in counts}

    # Active schedules per agent
    schedule_map = {}
    if agent_ids:
        scheds = (
            db.query(AgentSchedule)
            .filter(AgentSchedule.agent_id.in_(agent_ids), AgentSchedule.is_enabled == True)
            .all()
        )
        for s in scheds:
            schedule_map.setdefault(s.agent_id, []).append({
                "cron_expression": s.cron_expression,
                "next_run_at": iso_utc(s.next_run_at),
            })

    result = []
    for a in agents:
        d = _agent_to_dict(a)
        d["last_run"] = last_runs.get(a.id)
        d["run_count"] = run_counts.get(a.id, 0)
        d["schedules"] = schedule_map.get(a.id, [])
        result.append(d)
    return result


@router.post("")
def create_agent(body: AgentCreate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user), x_org_context: Optional[str] = Header(None, alias="X-Org-Context")):
    effective_org_id = int(x_org_context) if x_org_context else (user.org_id if user else None)
    resolved_model = body.model or get_default_model(db)
    agent = Agent(
        org_id=effective_org_id,
        name=body.name,
        description=body.description,
        system_prompt=body.system_prompt,
        tools=body.tools,
        guardrails=body.guardrails,
        model=resolved_model,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return _agent_to_dict(agent)


# ── Pipelines (multi-stage agent workflows) ──────────────────────────

@router.get("/pipelines")
def list_pipelines():
    """List available multi-stage agent pipelines."""
    return get_available_pipelines()


class PipelineRunRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    input: str
    model_overrides: Dict[str, str] = {}


@router.post("/pipelines/{pipeline_id}/run")
@limiter.limit("10/minute")
def run_pipeline(pipeline_id: str, body: PipelineRunRequest, request: Request, db: Session = Depends(get_db)):
    """Execute a multi-stage agent pipeline."""
    factory = PIPELINE_REGISTRY.get(pipeline_id)
    if not factory:
        raise HTTPException(404, f"Pipeline '{pipeline_id}' not found")

    pipeline = factory()
    results = pipeline.execute(db, body.input, body.model_overrides or None)

    return {
        "pipeline": pipeline_id,
        "stages": [r.to_dict() for r in results],
        "success": all(r.success for r in results),
        "final_output": results[-1].output if results and results[-1].success else None,
    }


# ── Templates (must be before /{agent_id} to avoid route conflicts) ──

@router.get("/templates")
def list_templates():
    """List available agent templates."""
    return AGENT_TEMPLATES


@router.post("/from-template")
def create_from_template(body: dict, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user), x_org_context: Optional[str] = Header(None, alias="X-Org-Context")):
    """Create an agent from a template."""
    template_id = body.get("template_id")
    template = next((t for t in AGENT_TEMPLATES if t["id"] == template_id), None)
    if not template:
        raise HTTPException(404, f"Template '{template_id}' not found")

    effective_org_id = int(x_org_context) if x_org_context else (user.org_id if user else None)
    agent = Agent(
        org_id=effective_org_id,
        name=body.get("name", template["name"]),
        description=template["description"],
        system_prompt=template["system_prompt"],
        tools=template["tools"],
        guardrails=body.get("guardrails", template["guardrails"]),
        model=body.get("model") or get_default_model(db),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return _agent_to_dict(agent)


# ── Export / Import (must be before /{agent_id}) ─────────────────────

@router.get("/export/{agent_id}")
def export_agent(agent_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Export an agent as a shareable JSON config."""
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    return {
        "_format": "hakuna-agent-v1",
        "name": agent.name,
        "description": agent.description,
        "system_prompt": agent.system_prompt,
        "tools": agent.tools,
        "guardrails": agent.guardrails,
        "model": agent.model,
        "memory": agent.memory,
    }


@router.post("/import")
def import_agent(body: dict, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user), x_org_context: Optional[str] = Header(None, alias="X-Org-Context")):
    """Import an agent from a JSON config."""
    name = body.get("name")
    system_prompt = body.get("system_prompt")
    if not name or not system_prompt:
        raise HTTPException(400, "Agent config must include 'name' and 'system_prompt'")

    effective_org_id = int(x_org_context) if x_org_context else (user.org_id if user else None)
    agent = Agent(
        org_id=effective_org_id,
        name=body.get("name"),
        description=body.get("description"),
        system_prompt=body.get("system_prompt"),
        tools=body.get("tools", []),
        guardrails=body.get("guardrails", {}),
        model=body.get("model") or get_default_model(db),
        memory=body.get("memory", {}),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return _agent_to_dict(agent)


# ── Agent Schedules (must be before /{agent_id}) ─────────────────────

class ScheduleCreate(BaseModel):
    agent_id: int
    cron_expression: str  # e.g. "0 8 * * 1-5" = weekdays 8 AM
    input: str
    is_enabled: bool = True

class ScheduleUpdate(BaseModel):
    cron_expression: Optional[str] = None
    input: Optional[str] = None
    is_enabled: Optional[bool] = None


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """List all agent schedules (scoped to accessible agents)."""
    q = db.query(AgentSchedule).join(Agent, Agent.id == AgentSchedule.agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    schedules = q.order_by(AgentSchedule.created_at.desc()).all()
    return [_schedule_to_dict(s) for s in schedules]


@router.post("/schedules")
def create_schedule(body: ScheduleCreate, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Create a new agent schedule."""
    q = db.query(Agent).filter(Agent.id == body.agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")

    schedule = AgentSchedule(
        agent_id=body.agent_id,
        cron_expression=body.cron_expression,
        input_template=body.input,
        is_enabled=body.is_enabled,
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    # Notify scheduler to pick up new job
    from agents.agent_scheduler import sync_schedules
    sync_schedules()

    return _schedule_to_dict(schedule)


@router.patch("/schedules/{schedule_id}")
def update_schedule(schedule_id: int, body: ScheduleUpdate, db: Session = Depends(get_db)):
    """Update an agent schedule."""
    schedule = db.query(AgentSchedule).filter(AgentSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(schedule, field, val)
    db.commit()
    db.refresh(schedule)

    from agents.agent_scheduler import sync_schedules
    sync_schedules()

    return _schedule_to_dict(schedule)


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db)):
    """Delete an agent schedule."""
    schedule = db.query(AgentSchedule).filter(AgentSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    db.delete(schedule)
    db.commit()

    from agents.agent_scheduler import sync_schedules
    sync_schedules()

    return {"ok": True}


# ── Agent Documents (RAG context) ─────────────────────────────────────

ALLOWED_DOC_TYPES = {
    ".txt", ".md", ".csv", ".json", ".xml", ".html", ".htm",
    ".log", ".yaml", ".yml", ".nessus", ".pdf", ".py", ".js", ".ts",
    ".conf", ".cfg", ".ini", ".toml",
}
MAX_DOC_SIZE = 10 * 1024 * 1024  # 10 MB
CHUNK_SIZE = 1500  # chars per chunk
CHUNK_OVERLAP = 200  # overlap between chunks


def _chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> List[str]:
    """Split text into overlapping chunks for retrieval."""
    if len(text) <= chunk_size:
        return [text]
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        if chunk.strip():
            chunks.append(chunk)
        start = end - overlap
    return chunks


def _extract_text(content: bytes, filename: str) -> str:
    """Extract plain text from uploaded file content."""
    ext = os.path.splitext(filename)[1].lower()
    # For binary formats we could add specialized extraction later
    # For now, decode as UTF-8 with fallback
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return content.decode("latin-1")


@router.get("/documents/{agent_id}")
def list_agent_documents(agent_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """List all documents attached to an agent."""
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    docs = db.query(AgentDocument).filter(AgentDocument.agent_id == agent_id).order_by(AgentDocument.created_at.desc()).all()
    return [_doc_to_dict(d) for d in docs]


@router.post("/documents/{agent_id}")
async def upload_agent_document(agent_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Upload a file as RAG context for an agent."""
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")

    # Validate extension
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_DOC_TYPES:
        raise HTTPException(400, f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_DOC_TYPES))}")

    # Read file
    content = await file.read()
    if len(content) > MAX_DOC_SIZE:
        raise HTTPException(400, f"File too large ({len(content)} bytes). Max: {MAX_DOC_SIZE} bytes")

    # Extract text and chunk
    text = _extract_text(content, file.filename)
    chunks = _chunk_text(text)

    doc = AgentDocument(
        agent_id=agent_id,
        filename=file.filename,
        content_type=file.content_type,
        size_bytes=len(content),
        chunks=chunks,
        chunk_count=len(chunks),
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    return _doc_to_dict(doc)


@router.delete("/documents/{agent_id}/{doc_id}")
def delete_agent_document(agent_id: int, doc_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Delete a document from an agent."""
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    if not q.first():
        raise HTTPException(404, "Agent not found")
    doc = db.query(AgentDocument).filter(AgentDocument.id == doc_id, AgentDocument.agent_id == agent_id).first()
    if not doc:
        raise HTTPException(404, "Document not found")
    db.delete(doc)
    db.commit()
    return {"ok": True}


def _doc_to_dict(d: AgentDocument):
    return {
        "id": d.id,
        "agent_id": d.agent_id,
        "filename": d.filename,
        "content_type": d.content_type,
        "size_bytes": d.size_bytes,
        "chunk_count": d.chunk_count,
        "created_at": iso_utc(d.created_at),
    }


# ── Approval queue (HITL) — must be before /{agent_id} ──────────────

class ApprovalDecide(BaseModel):
    decision: str          # "approved" | "rejected"
    reason: Optional[str] = None


@router.get("/approvals")
def list_approvals(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """List approval requests, optionally filtered by status (pending/approved/rejected/expired)."""
    q = (
        db.query(AgentApproval)
        .join(Agent, Agent.id == AgentApproval.agent_id)
    )
    q = apply_org_filter(q, Agent, org_ids)
    if status:
        q = q.filter(AgentApproval.status == status)
    approvals = q.order_by(AgentApproval.requested_at.desc()).limit(200).all()
    return [_approval_to_dict(a) for a in approvals]


@router.get("/approvals/{approval_id}")
def get_approval(
    approval_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Get a single approval request."""
    q = (
        db.query(AgentApproval)
        .join(Agent, Agent.id == AgentApproval.agent_id)
        .filter(AgentApproval.id == approval_id)
    )
    q = apply_org_filter(q, Agent, org_ids)
    approval = q.first()
    if not approval:
        raise HTTPException(404, "Approval not found")
    return _approval_to_dict(approval, include_snapshot=True)


@router.post("/approvals/{approval_id}/decide")
def decide_approval(
    approval_id: int,
    body: ApprovalDecide,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Approve or reject a pending tool call. Resumes the agent run."""
    if body.decision not in ("approved", "rejected"):
        raise HTTPException(400, "decision must be 'approved' or 'rejected'")

    q = (
        db.query(AgentApproval)
        .join(Agent, Agent.id == AgentApproval.agent_id)
        .filter(AgentApproval.id == approval_id, AgentApproval.status == "pending")
    )
    q = apply_org_filter(q, Agent, org_ids)
    approval = q.first()
    if not approval:
        raise HTTPException(404, "Pending approval not found")

    run = resume_agent_run(
        run_id=approval.agent_run_id,
        decision=body.decision,
        reason=body.reason,
        decider_id=current_user.id if current_user else None,
        db=db,
    )
    return {"ok": True, "run": _run_to_dict(run)}


# ── Agent by ID (parameterized routes last) ──────────────────────────

@router.get("/{agent_id}")
def get_agent(agent_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    return _agent_to_dict(agent)


@router.patch("/{agent_id}")
def update_agent(agent_id: int, body: AgentUpdate, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(agent, field, val)
    db.commit()
    db.refresh(agent)
    return _agent_to_dict(agent)


@router.delete("/{agent_id}")
def delete_agent(agent_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    # AgentSchedule and AgentApproval FKs are not configured with cascade,
    # so clear them explicitly before deleting the agent.
    db.query(AgentApproval).filter(AgentApproval.agent_id == agent_id).delete(synchronize_session=False)
    db.query(AgentSchedule).filter(AgentSchedule.agent_id == agent_id).delete(synchronize_session=False)
    # llm_interactions is an audit log that should outlive the agent — NULL
    # the FKs so cascading the agent (and its runs) doesn't trip the FK.
    run_id_subq = db.query(AgentRun.id).filter(AgentRun.agent_id == agent_id).subquery()
    db.query(LLMInteraction).filter(
        (LLMInteraction.agent_id == agent_id) | (LLMInteraction.agent_run_id.in_(run_id_subq))
    ).update({"agent_id": None, "agent_run_id": None}, synchronize_session=False)
    db.delete(agent)
    db.commit()
    return {"ok": True}


# ── Run agent ────────────────────────────────────────────────────────

@router.post("/{agent_id}/run", status_code=202)
@limiter.limit("10/minute")
def run_agent_endpoint(agent_id: int, body: AgentRunRequest, request: Request, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    from services.job_manager import dispatch

    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")

    user_input = body.input

    def _run():
        bg_db = SessionLocal()
        try:
            ag = bg_db.query(Agent).filter(Agent.id == agent_id).first()
            result = run_agent(ag, user_input, bg_db)
            return _run_to_dict(result)
        finally:
            bg_db.close()

    job = dispatch(f"agent_run_{agent_id}", _run)
    return {"job_id": job.id, "status": job.status.value, "poll_url": f"/api/jobs/{job.id}/status"}


# ── Streaming run (SSE) ──────────────────────────────────────────────

@router.post("/{agent_id}/run/stream")
@limiter.limit("10/minute")
async def run_agent_stream(agent_id: int, body: AgentRunRequest, request: Request, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Run an agent with Server-Sent Events streaming."""
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")

    # Snapshot agent data before entering the generator (avoids detached instance)
    agent_data = {
        "id": agent.id, "system_prompt": agent.system_prompt,
        "tools": agent.tools, "guardrails": agent.guardrails,
        "memory": agent.memory, "model": agent.model, "name": agent.name,
    }
    user_input = body.input

    async def event_stream():
        # Use a fresh DB session for the background work
        stream_db = SessionLocal()
        try:
            ag = stream_db.query(Agent).filter(Agent.id == agent_data["id"]).first()
            for event in run_agent_streaming(ag, user_input, stream_db):
                yield f"data: {json.dumps(event)}\n\n"
                await asyncio.sleep(0)  # yield control
            yield "data: [DONE]\n\n"
        finally:
            stream_db.close()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Run history ──────────────────────────────────────────────────────

@router.get("/{agent_id}/runs")
def list_runs(agent_id: int, limit: int = 20, db: Session = Depends(get_db)):
    runs = (
        db.query(AgentRun)
        .filter(AgentRun.agent_id == agent_id)
        .order_by(AgentRun.created_at.desc())
        .limit(limit)
        .all()
    )
    # Auto-expire stale "running" runs (stuck due to disconnected streams)
    stale_cutoff = datetime.utcnow() - timedelta(minutes=10)
    for r in runs:
        if r.status == "running" and r.created_at and r.created_at < stale_cutoff:
            r.status = "failed"
            r.error = "Run timed out (stream disconnected)"
            r.finished_at = datetime.utcnow()
    db.commit()
    return [_run_to_dict(r, include_trace=False) for r in runs]


@router.get("/{agent_id}/runs/{run_id}")
def get_run(agent_id: int, run_id: int, db: Session = Depends(get_db)):
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.agent_id == agent_id).first()
    if not run:
        raise HTTPException(404, "Run not found")
    return _run_to_dict(run)


@router.get("/{agent_id}/runs/{run_id}/approvals")
def list_run_approvals(agent_id: int, run_id: int, db: Session = Depends(get_db)):
    """List all approval requests for a specific run."""
    approvals = (
        db.query(AgentApproval)
        .filter(AgentApproval.agent_run_id == run_id, AgentApproval.agent_id == agent_id)
        .order_by(AgentApproval.requested_at.asc())
        .all()
    )
    return [_approval_to_dict(a) for a in approvals]


# ── Helpers ──────────────────────────────────────────────────────────

def _agent_to_dict(a: Agent):
    return {
        "id": a.id, "name": a.name, "description": a.description,
        "system_prompt": a.system_prompt, "tools": a.tools,
        "guardrails": a.guardrails, "memory": a.memory,
        "model": a.model,
        "document_count": len(a.documents) if a.documents else 0,
        "created_at": iso_utc(a.created_at),
        "updated_at": iso_utc(a.updated_at),
    }


def _run_to_dict(r: AgentRun, include_trace: bool = True):
    d = {
        "id": r.id, "agent_id": r.agent_id, "input": r.input,
        "output": r.output, "status": r.status, "error": r.error,
        "steps_used": r.steps_used,
        "created_at": iso_utc(r.created_at),
        "finished_at": iso_utc(r.finished_at),
    }
    if include_trace:
        d["trace"] = r.trace
    return d


# ── Agent Templates ──────────────────────────────────────────────────

AGENT_TEMPLATES = [
    {
        "id": "daily_triage",
        "name": "Daily Triage Report",
        "description": "Morning triage: top risks, SLA breaches, new criticals, and quick wins for today.",
        "icon": "clipboard",
        "system_prompt": ENHANCED_PROMPTS["daily_triage"],
        "tools": [
            "get_sla_status", "get_top_risky_assets", "get_regression_findings",
            "get_quick_wins", "get_plugin_family_stats", "get_scan_summary",
            "get_exploit_findings", "list_scans",
            "query_findings", "get_finding_detail", "get_asset_profile",
            "get_blast_radius", "get_workflow_status_summary",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
        "suggested_input": "Run the daily triage for the latest scan.",
    },
    {
        "id": "patch_tuesday",
        "name": "Patch Tuesday Prep",
        "description": "Analyze missing patches, group by KB, identify impacted assets and prioritize patching order.",
        "icon": "calendar",
        "system_prompt": ENHANCED_PROMPTS["patch_tuesday"],
        "tools": [
            "get_missing_patches", "get_exploit_findings", "get_os_breakdown",
            "get_remediation_grouping", "get_internet_facing_risk", "query_assets",
            "query_findings", "get_finding_detail", "get_asset_profile",
            "get_installed_software", "get_inventory_services",
            "list_scans", "get_scan_summary", "get_owner_workload",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
        "suggested_input": "Prepare the patch Tuesday plan for the latest scan.",
    },
    {
        "id": "executive_summary",
        "name": "Executive Summary",
        "description": "Generate a non-technical executive summary with risk posture, trends, and key metrics.",
        "icon": "briefcase",
        "system_prompt": ENHANCED_PROMPTS["executive_summary"],
        "tools": [
            "get_scan_summary", "get_sla_status", "get_top_risky_assets",
            "get_plugin_family_stats", "compare_scans", "get_owner_workload",
            "get_workflow_status_summary", "get_quick_wins", "get_exploit_findings",
            "get_internet_facing_risk", "build_report",
            "list_scans",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 10, "read_only": True},
        "suggested_input": "Generate the executive summary for our latest scan results.",
    },
    {
        "id": "sla_watchdog",
        "name": "SLA Watchdog",
        "description": "Monitor SLA deadlines, alert on breaches, and suggest escalation actions.",
        "icon": "alarm",
        "system_prompt": ENHANCED_PROMPTS["sla_watchdog"],
        "tools": [
            "get_sla_status", "get_sla_config", "get_owner_workload", "query_findings",
            "get_finding_detail", "get_asset_profile",
            "get_top_risky_assets", "list_scans", "get_scan_summary",
            "send_slack_message", "send_teams_message", "send_email_alert",
            "send_webhook", "create_jira_ticket", "create_servicenow_ticket",
            "update_finding_status",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
        "suggested_input": "Check SLA compliance and report any breaches or at-risk findings.",
    },
    {
        "id": "attack_surface",
        "name": "Attack Surface Mapper",
        "description": "Map the attack surface: internet-facing hosts, admin accounts, open shares, weak certs.",
        "icon": "radar",
        "system_prompt": ENHANCED_PROMPTS["attack_surface"],
        "tools": [
            "analyze_attack_surface", "get_blast_radius",
            "get_internet_facing_risk", "get_inventory_users", "get_inventory_services",
            "get_writeable_shares", "get_certificates", "get_network_connections",
            "get_security_controls", "get_top_risky_assets",
            "query_assets", "query_findings", "get_asset_profile",
            "trigger_easm_scan", "check_easm_scan_status", "list_easm_domains",
            "list_scans", "get_scan_summary",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": True},
        "suggested_input": "Map the full attack surface for the latest scan.",
    },
    {
        "id": "ticket_creator",
        "name": "Auto-Ticket Creator",
        "description": "Analyze critical findings and automatically create Jira/ServiceNow tickets with proper priority.",
        "icon": "ticket",
        "system_prompt": ENHANCED_PROMPTS["ticket_creator"],
        "tools": [
            "get_exploit_findings", "query_findings", "get_remediation_grouping",
            "get_internet_facing_risk", "get_finding_detail", "get_asset_profile",
            "get_blast_radius", "get_sla_status", "list_scans", "get_scan_summary",
            "create_jira_ticket", "create_servicenow_ticket",
            "list_integrations", "call_integration_push", "send_webhook",
            "update_finding_status",
            "create_tag", "bulk_tag_findings", "list_tags",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": False},
        "suggested_input": "Create Jira tickets for all critical findings with known exploits.",
    },
    {
        "id": "campaign_builder",
        "name": "Remediation Campaign Builder",
        "description": "Build targeted remediation campaigns based on risk criteria and assign to teams.",
        "icon": "target",
        "system_prompt": ENHANCED_PROMPTS["campaign_builder"],
        "tools": [
            "get_scan_summary", "query_findings", "query_assets", "get_exploit_findings",
            "get_remediation_grouping", "get_plugin_family_stats", "get_owner_workload",
            "get_finding_detail", "get_asset_profile",
            "create_campaign", "list_campaigns", "get_campaign",
            "create_campaign_workflow", "list_workflows", "list_workflow_templates",
            "create_tag", "tag_assets", "bulk_tag_findings",
            "list_tags", "list_scans",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": False},
        "suggested_input": "Build a remediation campaign for the most critical issues in the latest scan.",
    },
    {
        "id": "threat_intel",
        "name": "Threat Intelligence Analyst",
        "description": "Correlate threat intel with your scan data — identify active threat groups, trending CVEs, and campaigns targeting your environment.",
        "icon": "radar",
        "system_prompt": ENHANCED_PROMPTS["threat_intel"],
        "tools": [
            "get_threat_groups", "get_threat_cves", "get_threat_campaigns",
            "get_ttps", "correlate_cves_with_findings",
            "get_scan_summary", "query_findings", "get_exploit_findings",
            "get_finding_detail", "get_asset_profile", "get_blast_radius",
            "get_internet_facing_risk", "get_top_risky_assets",
            "search_web", "fetch_url", "search_documents",
            "list_scans",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": True},
        "suggested_input": "Give me a threat intel briefing — which active threat groups and campaigns are relevant to our latest scan?",
    },
    {
        "id": "auto_tagger",
        "name": "Auto-Tagger",
        "description": "Automatically classify assets and findings with meaningful tags — environment, role, owner, risk type — using pattern detection and auto-tag rules.",
        "icon": "tag",
        "system_prompt": ENHANCED_PROMPTS["auto_tagger"],
        "tools": [
            "list_scans", "get_scan_summary", "get_os_breakdown", "get_plugin_family_stats",
            "list_tags", "get_tag_stats", "create_tag", "manage_tag",
            "suggest_tagging_schema",
            "run_auto_tag_rules", "create_auto_tag_rule", "manage_auto_tag_rule",
            "list_ownership_rules", "run_ownership_rules",
            "query_assets", "query_findings",
            "tag_assets", "bulk_tag_findings",
            "get_asset_profile", "get_finding_detail",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 20, "read_only": False},
        "suggested_input": "Automatically tag all assets and critical findings in the latest scan.",
    },
    {
        "id": "scan_coverage_auditor",
        "name": "Scan Coverage Auditor",
        "description": "Identify assets not scanned recently, credential failures, scan gaps, and orphaned assets.",
        "icon": "shield",
        "system_prompt": ENHANCED_PROMPTS["scan_coverage_auditor"],
        "tools": [
            "list_scans", "get_scan_summary", "query_assets", "compare_scans",
            "query_findings", "get_os_breakdown", "get_asset_profile",
            "get_internet_facing_risk",
            "list_integrations", "get_integration_runs",
            "trigger_easm_scan", "check_easm_scan_status", "list_easm_domains",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
        "suggested_input": "Audit scan coverage — which assets haven't been scanned recently and where are the credential failures?",
    },
    {
        "id": "regression_detector",
        "name": "Regression Detector",
        "description": "Find vulnerabilities that were remediated but reappeared — detect config drift and failed patching.",
        "icon": "alert",
        "system_prompt": ENHANCED_PROMPTS["regression_detector"],
        "tools": [
            "list_scans", "get_scan_summary", "get_regression_findings",
            "compare_scans", "get_asset_profile", "get_finding_detail",
            "query_findings", "get_plugin_family_stats",
            "get_blast_radius", "get_owner_workload",
            "update_finding_status",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
        "suggested_input": "Show me findings that were fixed but came back in the latest scan.",
    },
    {
        "id": "exception_reviewer",
        "name": "Exception / Risk Acceptance Reviewer",
        "description": "Audit expiring risk acceptances, false positives, and exception hygiene across the program.",
        "icon": "file",
        "system_prompt": ENHANCED_PROMPTS["exception_reviewer"],
        "tools": [
            "list_scans", "get_scan_summary", "query_findings",
            "get_workflow_status_summary", "get_finding_detail",
            "get_asset_profile", "get_sla_status",
            "list_exceptions", "manage_exception", "create_exception",
            "get_blast_radius", "update_finding_status",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": False},
        "suggested_input": "Which risk acceptances expire in the next 14 days and what's the residual risk?",
    },
    {
        "id": "owner_accountability",
        "name": "Asset Owner Accountability Report",
        "description": "Per-team scorecards: open vulns, SLA compliance, resolution rates, and remediation velocity.",
        "icon": "brain",
        "system_prompt": ENHANCED_PROMPTS["owner_accountability"],
        "tools": [
            "list_scans", "get_scan_summary", "get_owner_workload",
            "get_sla_status", "get_sla_config", "get_workflow_status_summary",
            "query_findings", "get_finding_detail", "get_regression_findings",
            "list_ownership_rules", "manage_ownership_rule", "run_ownership_rules",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
        "suggested_input": "Give me a scorecard for each team showing their open criticals, overdue SLAs, and mean-time-to-remediate.",
    },
    {
        "id": "zero_day_check",
        "name": "Zero-Day Exposure Check",
        "description": "Rapidly assess exposure when a new CVE or zero-day drops — blast radius, affected assets, and action plan.",
        "icon": "zap",
        "system_prompt": ENHANCED_PROMPTS["zero_day_check"],
        "tools": [
            "list_scans", "get_scan_summary", "query_findings", "query_assets",
            "get_threat_cves", "correlate_cves_with_findings",
            "get_exploit_findings", "get_finding_detail", "get_asset_profile",
            "get_network_connections", "get_inventory_users",
            "get_installed_software", "get_inventory_services",
            "get_threat_campaigns", "get_threat_groups", "get_ttps",
            "get_internet_facing_risk", "get_blast_radius",
            "search_web", "fetch_url",
            "send_slack_message", "send_teams_message", "send_email_alert",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": True},
        "suggested_input": "CVE-2024-XXXX just dropped — how exposed are we?",
    },
    {
        "id": "change_validator",
        "name": "Change Window Validator",
        "description": "Compare pre and post change-window scans to confirm patches landed and detect regressions.",
        "icon": "check",
        "system_prompt": ENHANCED_PROMPTS["change_validator"],
        "tools": [
            "list_scans", "get_scan_summary", "compare_scans",
            "get_missing_patches", "get_installed_software",
            "query_findings", "get_finding_detail",
            "get_asset_profile", "get_regression_findings", "get_blast_radius",
            "update_finding_status",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
        "suggested_input": "Compare pre and post change-window scans and confirm which patches were successfully applied.",
    },
    {
        "id": "noise_reducer",
        "name": "Noise Reducer / Tuning Advisor",
        "description": "Identify low-value findings generating the most noise and recommend scan tuning to improve signal.",
        "icon": "settings",
        "system_prompt": ENHANCED_PROMPTS["noise_reducer"],
        "tools": [
            "list_scans", "get_scan_summary", "get_plugin_family_stats",
            "query_findings", "query_assets", "get_finding_detail", "get_remediation_grouping",
            "get_tag_stats",
            "get_dedup_config", "update_dedup_config", "run_dedup",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": False},
        "suggested_input": "Which low-value findings are creating the most noise across our scans?",
    },
    {
        "id": "asset_classifier",
        "name": "Asset Classifier",
        "description": "Analyze all assets in a scan, build a tagging taxonomy (OS, environment, network segment, role), and tag every asset.",
        "icon": "tag",
        "system_prompt": ENHANCED_PROMPTS["asset_classifier"],
        "tools": [
            "list_scans", "get_scan_summary", "get_os_breakdown",
            "query_assets", "get_asset_profile",
            "list_tags", "get_tag_stats", "create_tag", "manage_tag",
            "tag_assets", "suggest_tagging_schema",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 20, "read_only": False},
        "suggested_input": "Classify every asset in the latest scan with OS, environment, network segment, and role tags.",
    },
    {
        "id": "auto_tag_rule_builder",
        "name": "Auto-Tag Rule Builder",
        "description": "Analyze scan data, identify repeating patterns, and build persistent auto-tag rules that classify future uploads automatically.",
        "icon": "tag",
        "system_prompt": ENHANCED_PROMPTS["auto_tag_rule_builder"],
        "tools": [
            "list_scans", "get_scan_summary", "get_os_breakdown", "get_plugin_family_stats",
            "query_assets", "query_findings", "get_asset_profile",
            "list_tags", "get_tag_stats", "create_tag", "manage_tag",
            "tag_assets", "bulk_tag_findings",
            "create_auto_tag_rule", "manage_auto_tag_rule", "run_auto_tag_rules",
            "suggest_tagging_schema",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 20, "read_only": False},
        "suggested_input": "Analyze the latest scan and propose auto-tag rules that will classify future uploads.",
    },
    {
        "id": "escalation_detective",
        "name": "Escalation Detective",
        "description": "Investigate why specific vulnerabilities persistently fail remediation — chronic offenders, regressions, owner gaps, and root causes.",
        "icon": "brain",
        "system_prompt": ENHANCED_PROMPTS["escalation_detective"],
        "tools": [
            "list_scans", "get_scan_summary", "compare_scans",
            "get_sla_status", "get_sla_config",
            "query_findings", "get_finding_detail", "get_regression_findings",
            "get_owner_workload", "get_top_risky_assets", "get_asset_profile",
            "get_workflow_status_summary", "get_plugin_family_stats",
            "list_ownership_rules",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": True},
        "suggested_input": "Investigate why the same critical findings keep failing remediation across recent scans.",
    },
    {
        "id": "compliance_auditor",
        "name": "Compliance Auditor",
        "description": "Pre-audit assessment mapping current VM posture to compliance controls (PCI-DSS, SOC2, NIST CSF, CIS) and identifying gaps.",
        "icon": "shield",
        "system_prompt": ENHANCED_PROMPTS["compliance_auditor"],
        "tools": [
            "list_scans", "get_scan_summary", "compare_scans",
            "query_assets", "query_findings", "get_finding_detail",
            "get_sla_status", "get_sla_config",
            "list_exceptions", "get_workflow_status_summary",
            "get_regression_findings", "get_plugin_family_stats",
            "list_custom_roles", "list_ownership_rules",
            "build_report",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": True},
        "suggested_input": "Run a pre-audit compliance assessment against PCI-DSS and NIST CSF for the latest scan.",
    },
    {
        "id": "dedup_analyst",
        "name": "Dedup Analyst",
        "description": "Identify and resolve duplicate or overlapping findings across scans — same CVE via multiple plugins, superseded patches, and cross-scan overlap.",
        "icon": "settings",
        "system_prompt": ENHANCED_PROMPTS["dedup_analyst"],
        "tools": [
            "list_scans", "get_scan_summary", "compare_scans",
            "query_findings", "get_finding_detail", "get_plugin_family_stats",
            "get_dedup_config", "update_dedup_config", "run_dedup",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": False},
        "suggested_input": "Analyze the latest scans for duplicate findings and propose dedup rules.",
    },
    {
        "id": "soc_triage",
        "name": "SOC Triage Analyst",
        "description": "Investigate SIEM alerts — correlate events with vulnerability exposure, assess asset risk, and make triage decisions.",
        "icon": "alert",
        "system_prompt": ENHANCED_PROMPTS["soc_triage"],
        "tools": [
            "query_events", "get_event_context", "list_alerts", "get_alert_with_events",
            "triage_alert", "update_alert_status", "get_exposure_context",
            "query_findings", "get_finding_detail", "get_asset_profile",
            "get_blast_radius", "get_internet_facing_risk",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": False},
        "suggested_input": "Triage all open SIEM alerts — investigate events, check asset exposure, and recommend actions.",
    },
    {
        "id": "detection_engineer",
        "name": "Detection Engineer",
        "description": "Create and tune detection rules, analyze false positive rates, and build suppression rules to reduce alert fatigue.",
        "icon": "settings",
        "system_prompt": ENHANCED_PROMPTS["detection_engineer"],
        "tools": [
            "query_events", "list_alerts", "get_alert_with_events",
            "run_detection_rule_now", "get_exposure_context",
            "query_assets", "query_findings", "get_asset_profile",
            "get_internet_facing_risk", "get_top_risky_assets",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 15, "read_only": True},
        "suggested_input": "Analyze recent SIEM events and suggest new detection rules for suspicious patterns.",
    },
    {
        "id": "validator_agent",
        "name": "Vulnerability Validator",
        "description": "Autonomous validator for high/critical findings. Runs safe probes to confirm or refute exploitability, then requests a human approval before writing the verdict.",
        "icon": "shield-check",
        "system_prompt": ENHANCED_PROMPTS["validator_agent"],
        "tools": [
            # Probes
            "probe_url_status", "probe_tcp_connect",
            "fetch_response_headers", "check_response_body",
            # Verdict writer (HITL-gated)
            "update_finding_validation",
            # Read-only context
            "get_finding_detail", "get_asset_profile",
            "get_threat_cves", "list_exceptions",
            "fetch_url", "search_web",
            # Memory + clarification
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {
            "max_steps": 10,
            "read_only": False,  # must write the verdict
            "autonomy_level": "conservative",  # HITL required on update_finding_validation
        },
        "suggested_input": "Validate finding {finding_id} — determine whether it's truly exploitable and record your verdict.",
    },
]


# ── Protocol Audit templates (auto-expanded from AUDITS registry) ────
#
# One template per (protocol, mission) tuple. Kept after the hand-written
# entries above so the static validator_agent etc. remain the source of truth
# for their shape; protocol audits are a uniform family so we generate them.
def _build_protocol_audit_templates() -> list[dict]:
    from agents.audit_registry import AUDITS

    out: list[dict] = []
    for proto, audit in AUDITS.items():
        for mission in audit.missions:
            prompt = ENHANCED_PROMPTS.get(mission.prompt_key)
            if not prompt:
                continue
            out.append({
                "id": f"{proto}_audit_{mission.key}",
                "name": f"{audit.label} — {mission.label}",
                "description": mission.description,
                "icon": "shield-alert",
                "system_prompt": prompt,
                "tools": list(audit.tool_names),
                "guardrails": {
                    "max_steps": mission.suggested_budget,
                    "read_only": False,           # emit_finding writes Finding rows
                    "autonomy_level": "autonomous",  # read-only probes; no HITL needed
                },
                "suggested_input": (
                    f"Audit asset {{asset_id}} for {mission.label.lower()} exposures via {proto.upper()}."
                ),
                "hidden": True,  # not user-browsable; kicked off via /api/audits/run
            })
    return out


AGENT_TEMPLATES.extend(_build_protocol_audit_templates())


def _schedule_to_dict(s: AgentSchedule):
    return {
        "id": s.id, "agent_id": s.agent_id,
        "cron_expression": s.cron_expression, "input": s.input_template,
        "is_enabled": s.is_enabled,
        "last_run_at": iso_utc(s.last_run_at),
        "next_run_at": iso_utc(s.next_run_at),
        "created_at": iso_utc(s.created_at),
    }


def _approval_to_dict(a: AgentApproval, include_snapshot: bool = False):
    d = {
        "id": a.id,
        "agent_run_id": a.agent_run_id,
        "agent_id": a.agent_id,
        "tool_name": a.tool_name,
        "tool_input": a.tool_input,
        "provider": a.provider,
        "model_name": a.model_name,
        "current_step": a.current_step,
        "status": a.status,
        "requested_at": iso_utc(a.requested_at),
        "decided_at": iso_utc(a.decided_at),
        "decided_by": a.decided_by,
        "rejection_reason": a.rejection_reason,
    }
    if include_snapshot:
        d["assistant_content"] = a.assistant_content
    return d
