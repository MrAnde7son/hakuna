"""
Security Copilot API routes — conversational agent with access to all tools.

The copilot auto-provisions a hidden agent per org with all tools enabled,
then reuses the existing agent engine for streaming execution.
"""
import json
import asyncio
import logging
from typing import Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Header, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db, SessionLocal
from core.auth import get_current_user, get_accessible_org_ids, apply_org_filter
from core.time_utils import iso_utc
from models.models import Agent, CopilotAttachment, CopilotConversation, User
from agents.agent_tools import TOOL_REGISTRY
from agents.tool_categories import select_tools_for_message
from agents.agent_engine import (
    run_agent_streaming, get_default_model, get_available_providers,
)
from core.llm_router import router as llm_router
from agents.copilot_prompt import COPILOT_SYSTEM_PROMPT
from models.models import Organization

router = APIRouter(prefix="/api/copilot", tags=["copilot"])

COPILOT_AGENT_NAME = "__copilot__"
MAX_CONTEXT_TURNS = 10  # Last N exchanges to include as conversation context

# Copilot requires a model with reliable structured tool-use (not text-based).
# Groq/Llama generates <function=name>{args}</function> text instead of proper
# tool_use blocks, and tries to nest tool references inside parameters —
# fundamentally incompatible with multi-step agentic workflows.
# Ollama models vary in tool-use quality — we include it as a last resort.
_COPILOT_MODEL_PREFERENCE = [
    ("anthropic", "claude-sonnet-4-6"),
    ("openai", "gpt-4o"),
    ("google_gemini", "gemini-2.5-flash"),
    ("vertex_ai", "vertex/gemini-2.5-flash"),
    ("ollama", None),  # model resolved dynamically from Ollama config
]


# ── Pydantic schemas ─────────────────────────────────────────────────

class MessageRequest(BaseModel):
    message: str
    context: Optional[str] = None
    attachment_ids: Optional[List[int]] = None  # files uploaded via /attachments


# ── Helpers ──────────────────────────────────────────────────────────

def _pick_copilot_model(db: Session) -> str:
    """Pick the best model for the copilot based on available providers.

    The copilot requires structured tool-use (Anthropic, OpenAI, Gemini, or Vertex AI).
    Groq/Llama is excluded — it generates text-based function calls that break
    multi-step agentic workflows. Ollama is a last resort (tool-use quality varies).
    """
    available_providers = get_available_providers(db)
    available_map = {p["provider"]: p for p in available_providers}
    for provider, model in _COPILOT_MODEL_PREFERENCE:
        if provider in available_map:
            if model is not None:
                return model
            # Ollama: pick default_model from config, or first available model
            from models.models import IntegrationConfig
            cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == "ollama").first()
            if cfg and cfg.config and cfg.config.get("default_model"):
                m = cfg.config["default_model"]
                return m if m.startswith("ollama/") else f"ollama/{m}"
            models = available_map[provider].get("models", [])
            return models[0] if models else None
    return None


def _get_or_create_copilot_agent(db: Session, org_id: Optional[int]) -> Agent:
    """Get or create the hidden copilot agent for this org."""
    best_model = _pick_copilot_model(db)
    if not best_model:
        raise HTTPException(
            400,
            "Security Copilot requires a provider with structured tool-use: "
            "Anthropic, OpenAI, Google Gemini, Vertex AI, or Ollama. "
            "Groq is not supported for agentic workflows. "
            "Go to Settings > Integrations to configure a provider."
        )

    q = db.query(Agent).filter(Agent.name == COPILOT_AGENT_NAME)
    if org_id:
        q = q.filter(Agent.org_id == org_id)
    agent = q.first()

    all_tools = list(TOOL_REGISTRY.keys())

    # Read org autonomy level from org settings
    autonomy_level = "conservative"
    if org_id:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if org and org.settings:
            autonomy_level = org.settings.get("copilot_autonomy", "conservative")

    guardrails = {"max_steps": 25, "approval_mode": "hitl", "autonomy_level": autonomy_level}

    if agent:
        changed = False
        if set(agent.tools or []) != set(all_tools):
            agent.tools = all_tools
            changed = True
        if agent.model != best_model:
            agent.model = best_model
            changed = True
        current_autonomy = (agent.guardrails or {}).get("autonomy_level", "conservative")
        if current_autonomy != autonomy_level:
            agent.guardrails = {**(agent.guardrails or {}), "autonomy_level": autonomy_level}
            changed = True
        if changed:
            db.commit()
        return agent

    agent = Agent(
        org_id=org_id,
        name=COPILOT_AGENT_NAME,
        description="Security Copilot — conversational vulnerability management assistant",
        system_prompt=COPILOT_SYSTEM_PROMPT,
        tools=all_tools,
        guardrails=guardrails,
        model=best_model,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent


def _conversation_to_dict(c: CopilotConversation) -> dict:
    return {
        "id": c.id,
        "title": c.title,
        "message_count": len(c.messages) if c.messages else 0,
        "created_at": iso_utc(c.created_at),
        "updated_at": iso_utc(c.updated_at),
    }


def _build_native_history(messages: list) -> Optional[list]:
    """Convert stored conversation messages to native user/assistant turns.

    Returns a list of {role, content} dicts suitable for passing as
    conversation_messages to the agent engine, or None if empty.
    Truncates long assistant messages and limits to the last MAX_CONTEXT_TURNS
    exchanges to keep context manageable.
    """
    if not messages:
        return None

    recent = messages[-MAX_CONTEXT_TURNS * 2:]
    native = []
    for msg in recent:
        role = msg.get("role", "user")
        if role not in ("user", "assistant"):
            continue
        content = msg.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        if not content:
            continue
        # Truncate long assistant responses in history
        if role == "assistant" and len(content) > 1500:
            content = content[:1500] + "..."
        native.append({"role": role, "content": content})

    return native if native else None


def _build_contextual_input(messages: list, new_message: str) -> str:
    """Build a user input string that includes conversation history for context."""
    if not messages:
        return new_message

    # Take last N turns for context
    recent = messages[-MAX_CONTEXT_TURNS * 2:]  # *2 for user+assistant pairs

    history_parts = []
    for msg in recent:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, list):
            # Extract text from structured content blocks
            content = " ".join(
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        if content:
            label = "User" if role == "user" else "Assistant"
            # Truncate long assistant responses in history
            if role == "assistant" and len(content) > 1500:
                content = content[:1500] + "..."
            history_parts.append(f"[{label}]: {content}")

    if not history_parts:
        return new_message

    history = "\n".join(history_parts)
    return f"""<conversation_history>
{history}
</conversation_history>

<current_message>
{new_message}
</current_message>"""


# ── Conversation CRUD ────────────────────────────────────────────────

@router.get("/conversations")
def list_conversations(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
):
    """List the current user's copilot conversations."""
    q = db.query(CopilotConversation).filter(
        CopilotConversation.user_id == current_user.id
    ).order_by(CopilotConversation.updated_at.desc())
    return [_conversation_to_dict(c) for c in q.limit(50).all()]


@router.post("/conversations")
def create_conversation(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Create a new copilot conversation."""
    effective_org_id = int(x_org_context) if x_org_context else (current_user.org_id if current_user else None)
    conv = CopilotConversation(
        org_id=effective_org_id,
        user_id=current_user.id,
        title="New conversation",
        messages=[],
    )
    db.add(conv)
    db.commit()
    db.refresh(conv)
    return _conversation_to_dict(conv)


@router.get("/conversations/{conversation_id}")
def get_conversation(
    conversation_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
):
    """Get a conversation with full message history."""
    conv = db.query(CopilotConversation).filter(
        CopilotConversation.id == conversation_id,
        CopilotConversation.user_id == current_user.id,
    ).first()
    if not conv:
        raise HTTPException(404, "Conversation not found")
    return {
        **_conversation_to_dict(conv),
        "messages": conv.messages or [],
    }


@router.delete("/conversations/{conversation_id}")
def delete_conversation(
    conversation_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
):
    """Delete a conversation."""
    conv = db.query(CopilotConversation).filter(
        CopilotConversation.id == conversation_id,
        CopilotConversation.user_id == current_user.id,
    ).first()
    if not conv:
        raise HTTPException(404, "Conversation not found")
    db.delete(conv)
    db.commit()
    return {"ok": True}


# ── Chat attachments ────────────────────────────────────────────────

# Same cap as `/api/upload` so a copilot upload can drive the same ingest path.
COPILOT_ATTACHMENT_MAX_BYTES = 200 * 1024 * 1024  # 200 MB


@router.post("/conversations/{conversation_id}/attachments")
async def upload_attachment(
    conversation_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Stage a file the user dropped into the chat. Returns an attachment_id
    that subsequent tool calls (e.g. `upload_scan`) can resolve to the bytes."""
    conv = db.query(CopilotConversation).filter(
        CopilotConversation.id == conversation_id,
        CopilotConversation.user_id == current_user.id,
    ).first()
    if not conv:
        raise HTTPException(404, "Conversation not found")

    # Stream into a bounded buffer.
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > COPILOT_ATTACHMENT_MAX_BYTES:
            raise HTTPException(
                413,
                f"Attachment too large (max {COPILOT_ATTACHMENT_MAX_BYTES // (1024 * 1024)} MB)",
            )
        chunks.append(chunk)
    content = b"".join(chunks)
    del chunks

    if not content:
        raise HTTPException(400, "Attachment is empty")

    effective_org_id = int(x_org_context) if x_org_context else (current_user.org_id if current_user else None)
    att = CopilotAttachment(
        org_id=effective_org_id,
        user_id=current_user.id,
        conversation_id=conv.id,
        filename=file.filename or "attachment",
        content_type=file.content_type,
        size_bytes=total,
        content=content,
    )
    db.add(att)
    db.commit()
    db.refresh(att)
    return {
        "id": att.id,
        "filename": att.filename,
        "size_bytes": att.size_bytes,
        "content_type": att.content_type,
    }


@router.delete("/conversations/{conversation_id}/attachments/{attachment_id}")
def delete_attachment(
    conversation_id: int,
    attachment_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
):
    """Discard an unsent attachment (user removed it before hitting send)."""
    att = db.query(CopilotAttachment).filter(
        CopilotAttachment.id == attachment_id,
        CopilotAttachment.user_id == current_user.id,
        CopilotAttachment.conversation_id == conversation_id,
    ).first()
    if not att:
        raise HTTPException(404, "Attachment not found")
    db.delete(att)
    db.commit()
    return {"ok": True}


def _attachment_hint(db: Session, user_id: int, attachment_ids: list[int]) -> Optional[str]:
    """Render attachment metadata into a hint block the LLM sees so it knows
    to call the appropriate tool (upload_scan, etc.) with the attachment_id."""
    if not attachment_ids:
        return None
    rows = db.query(CopilotAttachment).filter(
        CopilotAttachment.id.in_(attachment_ids),
        CopilotAttachment.user_id == user_id,
    ).all()
    if not rows:
        return None
    lines = []
    for a in rows:
        size_mb = (a.size_bytes or 0) / (1024 * 1024)
        lines.append(
            f"- attachment_id={a.id} filename={a.filename!r} "
            f"size={size_mb:.2f}MB content_type={a.content_type or 'unknown'}"
        )
    return (
        "<attachments>\n"
        "The user attached the following file(s) to this message. "
        "If a file looks like a vulnerability scan (Nessus .nessus, Qualys XML, "
        "Rapid7, OpenVAS), call `upload_scan` with the attachment_id to ingest it. "
        "Confirm with the user before processing if intent is unclear.\n"
        + "\n".join(lines)
        + "\n</attachments>"
    )


# ── Send message (streaming) ────────────────────────────────────────

@router.post("/conversations/{conversation_id}/message")
async def send_message(
    conversation_id: int,
    body: MessageRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Send a message to the copilot and stream the response via SSE."""
    conv = db.query(CopilotConversation).filter(
        CopilotConversation.id == conversation_id,
        CopilotConversation.user_id == current_user.id,
    ).first()
    if not conv:
        raise HTTPException(404, "Conversation not found")

    effective_org_id = int(x_org_context) if x_org_context else (current_user.org_id if current_user else None)
    copilot_agent = _get_or_create_copilot_agent(db, effective_org_id)

    # Append user message to conversation (store clean message without context metadata)
    user_msg = {"role": "user", "content": body.message, "timestamp": iso_utc(datetime.utcnow())}
    messages = list(conv.messages or [])
    messages.append(user_msg)
    conv.messages = messages
    conv.updated_at = datetime.utcnow()

    # Auto-title from first message
    if conv.title == "New conversation":
        conv.title = body.message[:80].strip()

    db.commit()

    # Prepend page context (if provided) to the LLM input only, not stored in history
    user_input = (body.context + "\n\n" + body.message) if body.context else body.message

    # Surface attached files to the LLM so it can call upload_scan / etc.
    att_hint = _attachment_hint(db, current_user.id, body.attachment_ids or [])
    if att_hint:
        user_input = att_hint + "\n\n" + user_input
    agent_id = copilot_agent.id
    conv_id = conv.id
    user_id = current_user.id

    # Dynamic tool selection: pick only relevant tools instead of all ~111
    selected_tools = select_tools_for_message(body.message, messages[:-1])

    # Build native multi-turn history for provider-level prompt caching.
    # Prior messages are sent as separate user/assistant turns instead of being
    # baked into the user_input string, so providers can cache the prefix.
    history = messages[:-1]  # exclude the just-appended current user msg
    native_history = _build_native_history(history)

    async def event_stream():
        stream_db = SessionLocal()
        try:
            ag = stream_db.query(Agent).filter(Agent.id == agent_id).first()
            ag.tools = selected_tools  # in-memory override, not persisted
            text_accum = ""
            for event in run_agent_streaming(ag, user_input, stream_db,
                                             conversation_messages=native_history):
                if event.get("type") == "text":
                    text_accum += event.get("text", "")
                yield f"data: {json.dumps(event)}\n\n"
                await asyncio.sleep(0)

            # Persist assistant response to conversation
            if text_accum:
                c = stream_db.query(CopilotConversation).filter(
                    CopilotConversation.id == conv_id
                ).first()
                if c:
                    msgs = list(c.messages or [])
                    msgs.append({
                        "role": "assistant",
                        "content": text_accum,
                        "timestamp": iso_utc(datetime.utcnow()),
                    })
                    c.messages = msgs
                    c.updated_at = datetime.utcnow()
                    stream_db.commit()

                    # Generate context-aware follow-up recommendations.
                    # Run on every exchange so the assistant's own posed questions
                    # ("Would you like me to …?") get surfaced as buttons.
                    try:
                        recs = _generate_recommendations(stream_db, ag.model, msgs)
                    except Exception as e:
                        logger.warning(f"Recommendation generation failed: {e}")
                        recs = []
                    # Fall back to static prompts only if generation failed entirely.
                    if not recs and len(msgs) <= 2:
                        recs = [
                            {"text": p["text"][:80], "icon": p["icon"]}
                            for p in SUGGESTED_PROMPTS[:3]
                        ]
                    if recs:
                        yield f"data: {json.dumps({'type': 'recommendations', 'recommendations': recs})}\n\n"
                        await asyncio.sleep(0)

            yield "data: [DONE]\n\n"
        finally:
            stream_db.close()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Context-aware follow-up recommendations ─────────────────────────

_RECOMMENDATION_PROMPT = """Based on the conversation below, suggest exactly 3 short follow-up questions the user might want to ask next.

PRIORITY RULE — align with the assistant's last message:
If the assistant's most recent message ends with its own suggestions, offers, or questions (e.g. "Would you like me to …?", a bulleted list of next steps, "I can also …"), your 3 suggestions MUST be the user-facing reply to those offers. Rewrite each offer as a first-person user request ("Yes, create the campaign", "Open the Jira tickets", "Show more detail on asset X"). Do NOT invent unrelated new topics when the assistant already proposed concrete next steps.

Otherwise, the questions should be:
- Directly relevant to what was just discussed
- Actionable (lead to a useful next step)
- Diverse (cover different angles — e.g. drill down, take action, explore related)

All suggestions must be:
- Short (under 60 characters each)
- ONLY questions the agent can actually answer using the capabilities listed below

Agent capabilities (only suggest questions that use these):
- Query/filter findings by severity, status, port, plugin, asset, CVE, tags, SLA, exploit status, campaign membership
- Query/filter assets by IP, hostname, OS, criticality, tags, last scan date, internet-facing
- List scans, compare scans, get scan summaries
- Get finding details, asset profiles
- List campaigns and get campaign details with completion %, per-owner progress
- Risk analysis: top risky assets, exploit findings, quick wins, regressions, SLA breaches
- Remediation grouping, internet-facing risk, owner workload
- Inventory: users, services, network connections, patches, software, certificates, shares, OS breakdown
- Threat intel: threat groups, CVEs, campaigns, TTPs, CVE-finding correlation
- Tag statistics: asset/finding counts per tag, severity breakdown by tag
- Agent management: list agents, get agent run output, create agents, schedule agents
- Workflow inspection: list workflows, get workflow details/execution logs
- Actions: create campaigns, create tickets (Jira/ServiceNow), send notifications (Slack/Teams/Email), tag assets/findings, run auto-tag rules
- Integration status: list integrations, trigger fetch/push syncs
- Plugin family statistics
- Settings: dedup config (view/update/run), risk scoring (view/update weights, criticality rules, recalculate), SLA (view/update deadlines, recalculate), exceptions (list/create/update/delete), ownership rules (list/create/update/delete/run), RBAC roles (list/create/update), integration builder (list/enable/disable/run/history), scan management (delete/rename)
- Attack surface analysis: combine internet-facing assets, network connections, privileged users, and exploits into attack path narratives
- Tagging strategy: suggest organized tagging schemas based on asset metadata
- Agent recommendations: analyze data and recommend pre-built agent templates to deploy
- Report/dashboard building: create saved report templates with configurable widgets

Do NOT suggest questions about: time-series trends over arbitrary periods, prediction/forecasting, creating workflows, user permissions/activity, or health checks on API keys.

Respond ONLY with a JSON array of 3 strings. No other text.

Example: ["Create a campaign for these findings?", "Which assets are most affected?", "Show exploit details for the top CVE"]"""

_RECOMMENDATION_ICONS = ["zap", "target", "clipboard"]


def _generate_recommendations(db: Session, model: str, messages: list) -> list:
    """Generate 3 context-aware follow-up recommendations using a fast LLM call."""
    if not messages or len(messages) < 2:
        return []

    # Build a compact conversation summary (last 3 exchanges max)
    recent = messages[-6:]
    summary_parts = []
    for msg in recent:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        if content:
            label = "User" if role == "user" else "Assistant"
            # Keep content brief
            if len(content) > 500:
                content = content[:500] + "..."
            summary_parts.append(f"{label}: {content}")

    if not summary_parts:
        return []

    conversation_text = "\n".join(summary_parts)
    full_prompt = f"{_RECOMMENDATION_PROMPT}\n\nConversation:\n{conversation_text}"

    try:
        text, _ = llm_router.call(
            db,
            user=full_prompt,
            max_tokens=200,
            model=model,
        )
        text = (text or "").strip()
        if not text:
            return []

        # Parse JSON array from response (handle markdown code blocks)
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        recommendations = json.loads(text)
        if isinstance(recommendations, list) and len(recommendations) >= 1:
            return [
                {"text": str(q)[:80], "icon": _RECOMMENDATION_ICONS[i % 3]}
                for i, q in enumerate(recommendations[:3])
            ]
    except Exception as e:
        logger.warning(f"Failed to generate recommendations: {e}")

    return []


# ── Suggested prompts ────────────────────────────────────────────────

SUGGESTED_PROMPTS = [
    {"text": "Analyze my attack surface and prioritize the biggest risks", "icon": "shield-alert"},
    {"text": "Find critical gaps, create a campaign, assign owners, and open tickets", "icon": "zap"},
    {"text": "Check SLA breaches, escalate overdue items, and notify owners", "icon": "alarm"},
    {"text": "Suggest a tagging strategy and organize my assets", "icon": "tags"},
    {"text": "Find internet-facing risks, open Jira tickets, and alert the team on Slack", "icon": "globe"},
    {"text": "Recommend agents I should deploy to automate my VM program", "icon": "bot"},
    {"text": "Build an executive risk dashboard I can share with leadership", "icon": "layout-dashboard"},
    {"text": "Analyze my latest scan, find regressions, and create a fix campaign", "icon": "clipboard"},
]


@router.get("/suggested-prompts")
def suggested_prompts():
    """Return suggested prompts for the copilot."""
    return SUGGESTED_PROMPTS


# ── Autonomy level management ─────────────────────────────────────

VALID_AUTONOMY_LEVELS = {"conservative", "standard", "autonomous"}

AUTONOMY_DESCRIPTIONS = {
    "conservative": "Approve every write action (default). Safest option — the copilot asks before creating tickets, tags, campaigns, or sending notifications.",
    "standard": "Auto-approve low-risk actions (tagging, status updates, reports). Still requires approval for tickets, notifications, campaigns, and external integrations.",
    "autonomous": "Auto-approve all internal actions. Only requires approval for external-facing actions (Jira, ServiceNow, Slack, Teams, Email, webhooks).",
}


@router.get("/autonomy")
def get_autonomy_level(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Get the current copilot autonomy level for this org."""
    effective_org_id = int(x_org_context) if x_org_context else (current_user.org_id if current_user else None)
    level = "conservative"
    if effective_org_id:
        org = db.query(Organization).filter(Organization.id == effective_org_id).first()
        if org and org.settings:
            level = org.settings.get("copilot_autonomy", "conservative")
    return {
        "level": level,
        "description": AUTONOMY_DESCRIPTIONS.get(level, ""),
        "available_levels": [
            {"level": k, "description": v} for k, v in AUTONOMY_DESCRIPTIONS.items()
        ],
    }


class AutonomyRequest(BaseModel):
    level: str


@router.put("/autonomy")
def set_autonomy_level(
    body: AutonomyRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Set the copilot autonomy level for this org. Requires admin role."""
    if current_user.role not in ("superadmin", "org_admin"):
        raise HTTPException(403, "Only admins can change the copilot autonomy level")
    if body.level not in VALID_AUTONOMY_LEVELS:
        raise HTTPException(400, f"Invalid autonomy level. Must be one of: {VALID_AUTONOMY_LEVELS}")

    effective_org_id = int(x_org_context) if x_org_context else (current_user.org_id if current_user else None)
    if not effective_org_id:
        # Superadmin with "All Organizations" — fall back to home org
        effective_org_id = current_user.org_id if current_user else None
    if not effective_org_id:
        raise HTTPException(400, "Organization context required — select a specific org")

    org = db.query(Organization).filter(Organization.id == effective_org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    settings = dict(org.settings or {})
    settings["copilot_autonomy"] = body.level
    org.settings = settings
    db.commit()

    return {
        "level": body.level,
        "description": AUTONOMY_DESCRIPTIONS[body.level],
        "message": f"Copilot autonomy set to '{body.level}'. Changes take effect on next conversation message.",
    }
