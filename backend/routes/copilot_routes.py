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

from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db, SessionLocal
from core.auth import get_current_user, get_accessible_org_ids, apply_org_filter
from core.subscription import require_pro
from models.models import Agent, CopilotConversation, User
from agents.agent_tools import TOOL_REGISTRY
from agents.agent_engine import (
    run_agent_streaming, get_default_model, get_available_providers,
    PROVIDER_FOR_MODEL, _get_anthropic_client, _get_openai_client,
    _get_gemini_client, _get_ollama_client, _get_vertex_client,
)
from agents.copilot_prompt import COPILOT_SYSTEM_PROMPT

router = APIRouter(prefix="/api/copilot", tags=["copilot"], dependencies=[Depends(require_pro)])

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

                    # Generate context-aware follow-up recommendations
                    try:
                        recs = _generate_recommendations(stream_db, ag.model, msgs)
                        if recs:
                            yield f"data: {json.dumps({'type': 'recommendations', 'recommendations': recs})}\n\n"
                            await asyncio.sleep(0)
                    except Exception as e:
                        logger.warning(f"Recommendation generation failed: {e}")

            yield "data: [DONE]\n\n"
        finally:
            stream_db.close()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Context-aware follow-up recommendations ─────────────────────────

_RECOMMENDATION_PROMPT = """Based on the conversation below, suggest exactly 3 short follow-up questions the user might want to ask next. The questions should be:
- Directly relevant to what was just discussed
- Actionable (lead to a useful next step)
- Diverse (cover different angles — e.g. drill down, take action, explore related)
- Short (under 60 characters each)
- ONLY suggest questions the agent can actually answer using the capabilities listed below

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

    provider = PROVIDER_FOR_MODEL.get(model, "")

    try:
        if provider == "anthropic":
            client = _get_anthropic_client(db)
            resp = client.messages.create(
                model=model,
                max_tokens=200,
                messages=[{"role": "user", "content": full_prompt}],
            )
            text = resp.content[0].text.strip()
        elif provider == "openai":
            client = _get_openai_client(db)
            resp = client.chat.completions.create(
                model=model,
                max_tokens=200,
                messages=[{"role": "user", "content": full_prompt}],
            )
            text = resp.choices[0].message.content.strip()
        elif provider == "google_gemini":
            client = _get_gemini_client(db)
            resp = client.models.generate_content(
                model=f"models/{model}",
                contents=full_prompt,
                config={"max_output_tokens": 200},
            )
            text = resp.text.strip()
        elif provider == "vertex_ai":
            client = _get_vertex_client(db)
            base_model = model.replace("vertex/", "")
            resp = client.models.generate_content(
                model=f"models/{base_model}",
                contents=full_prompt,
                config={"max_output_tokens": 200},
            )
            text = resp.text.strip()
        elif model and model.startswith("ollama/"):
            client = _get_ollama_client(db)
            resp = client.chat.completions.create(
                model=model.replace("ollama/", ""),
                max_tokens=200,
                messages=[{"role": "user", "content": full_prompt}],
            )
            text = resp.choices[0].message.content.strip()
        else:
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
