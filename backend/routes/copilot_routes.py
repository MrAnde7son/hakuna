"""
Security Copilot API routes — conversational agent with access to all tools.

The copilot auto-provisions a hidden agent per org with all tools enabled,
then reuses the existing agent engine for streaming execution.
"""
import json
import asyncio
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db, SessionLocal
from core.auth import get_current_user, get_accessible_org_ids, apply_org_filter
from core.subscription import require_pro
from models.models import Agent, CopilotConversation, User
from agents.agent_tools import TOOL_REGISTRY
from agents.agent_engine import run_agent_streaming, get_default_model, get_available_providers
from agents.copilot_prompt import COPILOT_SYSTEM_PROMPT

router = APIRouter(prefix="/api/copilot", tags=["copilot"], dependencies=[Depends(require_pro)])

COPILOT_AGENT_NAME = "__copilot__"
MAX_CONTEXT_TURNS = 10  # Last N exchanges to include as conversation context

# Copilot requires a model with reliable structured tool-use (not text-based).
# Groq/Llama generates <function=name>{args}</function> text instead of proper
# tool_use blocks, and tries to nest tool references inside parameters —
# fundamentally incompatible with multi-step agentic workflows.
_COPILOT_MODEL_PREFERENCE = [
    ("anthropic", "claude-sonnet-4-6"),
    ("openai", "gpt-4o"),
    ("google_gemini", "gemini-2.5-flash"),
]


# ── Pydantic schemas ─────────────────────────────────────────────────

class MessageRequest(BaseModel):
    message: str


# ── Helpers ──────────────────────────────────────────────────────────

def _pick_copilot_model(db: Session) -> str:
    """Pick the best model for the copilot based on available providers.

    The copilot requires structured tool-use (Anthropic, OpenAI, or Gemini).
    Groq/Llama is excluded — it generates text-based function calls that break
    multi-step agentic workflows.
    """
    available = {p["provider"] for p in get_available_providers(db)}
    for provider, model in _COPILOT_MODEL_PREFERENCE:
        if provider in available:
            return model
    return None


def _get_or_create_copilot_agent(db: Session, org_id: Optional[int]) -> Agent:
    """Get or create the hidden copilot agent for this org."""
    best_model = _pick_copilot_model(db)
    if not best_model:
        raise HTTPException(
            400,
            "Security Copilot requires an Anthropic, OpenAI, or Google Gemini API key. "
            "Groq is not supported for agentic workflows. "
            "Go to Settings > Integrations to configure a provider."
        )

    q = db.query(Agent).filter(Agent.name == COPILOT_AGENT_NAME)
    if org_id:
        q = q.filter(Agent.org_id == org_id)
    agent = q.first()

    all_tools = list(TOOL_REGISTRY.keys())

    if agent:
        changed = False
        if set(agent.tools or []) != set(all_tools):
            agent.tools = all_tools
            changed = True
        if agent.model != best_model:
            agent.model = best_model
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
        guardrails={"max_steps": 25, "approval_mode": "hitl"},
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
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


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

    # Append user message to conversation
    user_msg = {"role": "user", "content": body.message, "timestamp": datetime.utcnow().isoformat()}
    messages = list(conv.messages or [])
    messages.append(user_msg)
    conv.messages = messages
    conv.updated_at = datetime.utcnow()

    # Auto-title from first message
    if conv.title == "New conversation":
        conv.title = body.message[:80].strip()

    db.commit()

    # Build contextual input with conversation history
    user_input = _build_contextual_input(messages[:-1], body.message)
    agent_id = copilot_agent.id
    conv_id = conv.id
    user_id = current_user.id

    async def event_stream():
        stream_db = SessionLocal()
        try:
            ag = stream_db.query(Agent).filter(Agent.id == agent_id).first()
            text_accum = ""
            for event in run_agent_streaming(ag, user_input, stream_db):
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
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    c.messages = msgs
                    c.updated_at = datetime.utcnow()
                    stream_db.commit()

            yield "data: [DONE]\n\n"
        finally:
            stream_db.close()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Suggested prompts ────────────────────────────────────────────────

SUGGESTED_PROMPTS = [
    {"text": "Find the riskiest gaps and triage them", "icon": "shield-alert"},
    {"text": "Check SLA breaches and escalate overdue findings", "icon": "alarm"},
    {"text": "Find quick wins and create a campaign to fix them", "icon": "zap"},
    {"text": "Analyze my latest scan and summarize what changed", "icon": "clipboard"},
    {"text": "Find internet-facing assets with critical vulns and open tickets", "icon": "globe"},
    {"text": "Identify exploitable findings and assign to owners", "icon": "bug"},
    {"text": "Build a remediation campaign for the top 10 risks", "icon": "target"},
    {"text": "Generate an executive summary and send it to Slack", "icon": "briefcase"},
]


@router.get("/suggested-prompts")
def suggested_prompts():
    """Return suggested prompts for the copilot."""
    return SUGGESTED_PROMPTS
