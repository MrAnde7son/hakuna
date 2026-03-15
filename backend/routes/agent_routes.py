"""
Mini Agent API routes — CRUD for agents, run endpoint, templates, streaming, schedules.
"""
import json
import asyncio
import os
import sys
from typing import Optional, List, Dict
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Header, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db, SessionLocal
from models.models import Agent, AgentRun, AgentSchedule, AgentDocument, User
from core.auth import get_current_user, get_accessible_org_ids, apply_org_filter
from agents.agent_tools import get_tool_catalog
from agents.agent_engine import run_agent, run_agent_streaming, update_agent_memory
from agents.agent_pipeline import get_available_pipelines, PIPELINE_REGISTRY
from agents.agent_prompts import ENHANCED_PROMPTS

# Add repo root to path so hakuna package is importable from backend/
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

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
    q = db.query(Agent).order_by(Agent.updated_at.desc())
    q = apply_org_filter(q, Agent, org_ids)
    return [_agent_to_dict(a) for a in q.all()]


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
def run_pipeline(pipeline_id: str, body: PipelineRunRequest, db: Session = Depends(get_db)):
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
        "_format": "nessus-remediation-agent-v1",
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
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


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
    db.delete(agent)
    db.commit()
    return {"ok": True}


# ── Run agent ────────────────────────────────────────────────────────

@router.post("/{agent_id}/run")
def run_agent_endpoint(agent_id: int, body: AgentRunRequest, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = db.query(Agent).filter(Agent.id == agent_id)
    q = apply_org_filter(q, Agent, org_ids)
    agent = q.first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    result = run_agent(agent, body.input, db)
    return _run_to_dict(result)


# ── Streaming run (SSE) ──────────────────────────────────────────────

@router.post("/{agent_id}/run/stream")
async def run_agent_stream(agent_id: int, body: AgentRunRequest, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
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
    return [_run_to_dict(r, include_trace=False) for r in runs]


@router.get("/{agent_id}/runs/{run_id}")
def get_run(agent_id: int, run_id: int, db: Session = Depends(get_db)):
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.agent_id == agent_id).first()
    if not run:
        raise HTTPException(404, "Run not found")
    return _run_to_dict(run)


# ── Helpers ──────────────────────────────────────────────────────────

def _agent_to_dict(a: Agent):
    return {
        "id": a.id, "name": a.name, "description": a.description,
        "system_prompt": a.system_prompt, "tools": a.tools,
        "guardrails": a.guardrails, "memory": a.memory,
        "model": a.model,
        "document_count": len(a.documents) if a.documents else 0,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


def _run_to_dict(r: AgentRun, include_trace: bool = True):
    d = {
        "id": r.id, "agent_id": r.agent_id, "input": r.input,
        "output": r.output, "status": r.status, "error": r.error,
        "steps_used": r.steps_used,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
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
            "list_scans", "get_scan_summary",
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
            "list_scans", "request_clarification",
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
            "get_sla_status", "get_owner_workload", "query_findings",
            "get_top_risky_assets", "list_scans",
            "send_slack_message", "send_teams_message", "send_email_alert",
            "create_jira_ticket",
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
            "get_internet_facing_risk", "get_inventory_users", "get_writeable_shares",
            "get_certificates", "get_network_connections", "get_security_controls",
            "get_top_risky_assets", "list_scans", "get_scan_summary",
            "request_clarification",
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
            "create_jira_ticket", "create_servicenow_ticket",
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
            "get_scan_summary", "query_findings", "get_exploit_findings",
            "get_remediation_grouping", "get_plugin_family_stats", "get_owner_workload",
            "create_campaign", "create_tag", "tag_assets", "bulk_tag_findings",
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
            "get_finding_detail", "get_asset_profile", "list_scans",
            "request_clarification",
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
            "list_scans", "get_scan_summary", "list_tags", "create_tag",
            "run_auto_tag_rules", "query_assets", "query_findings",
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
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
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
            "get_sla_status", "get_workflow_status_summary",
            "query_findings", "get_regression_findings",
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
            "list_scans", "get_scan_summary", "query_findings",
            "get_threat_cves", "correlate_cves_with_findings",
            "get_exploit_findings", "get_asset_profile",
            "get_network_connections", "get_inventory_users",
            "get_threat_campaigns", "get_threat_groups", "get_ttps",
            "get_internet_facing_risk",
            "request_clarification",
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
            "get_missing_patches", "query_findings", "get_finding_detail",
            "get_asset_profile", "get_regression_findings",
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
            "query_findings", "get_finding_detail", "get_remediation_grouping",
            "read_scratchpad", "write_scratchpad", "request_clarification",
        ],
        "guardrails": {"max_steps": 12, "read_only": True},
        "suggested_input": "Which low-value findings are creating the most noise across our scans?",
    },
]


def _schedule_to_dict(s: AgentSchedule):
    return {
        "id": s.id, "agent_id": s.agent_id,
        "cron_expression": s.cron_expression, "input": s.input_template,
        "is_enabled": s.is_enabled,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
