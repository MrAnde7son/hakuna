"""``request_clarification`` — graceful fallback for the LLM.

Returns a structured ``clarification_needed`` payload. In the Hakuna
backend this hooks into the agent-approval flow (the engine pauses
the run, frontend renders an approval card, user replies, engine
resumes). In OSS standalone, the request is published as an event
and recorded in steps but the run continues — there is no human in
the loop to wait for.

Phase 2 will add real pause-and-resume by writing a ``ClarificationRequest``
row, breaking out of the loop with ``stop_reason="awaiting_clarification"``,
and accepting a ``resume_audit_run`` Celery task that injects the user's
reply as a tool_result block. For phase 1 the tool is a no-op signal so
the protocol palettes can declare it without breaking.
"""

from __future__ import annotations

from scanner.audit.agent_context import AuditContext
from scanner.audit.audit_engine import agent_tool
from scanner.audit.publisher import event as _ev


@agent_tool(
    "request_clarification",
    "When you cannot determine which action to take or which tool to use, "
    "call this to surface a structured clarification request. Do NOT "
    "guess or hallucinate an action — ask for clarification instead. The "
    "OSS scanner records the request and continues; the Hakuna backend "
    "pauses the run and awaits a human reply.",
    {
        "question": {
            "type": "string",
            "description": "The specific question you need answered",
        },
        "options": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Possible options the user can choose from (if applicable)",
        },
        "context": {
            "type": "string",
            "description": "Brief context about what you were trying to do when you got stuck",
        },
    },
)
def request_clarification(ctx: AuditContext, params: dict) -> dict:
    payload = {
        "type": "clarification_needed",
        "question": params.get("question") or "I need more information to proceed.",
        "options": params.get("options") or [],
        "context": params.get("context") or "",
    }
    # Surface for live viewers; backend's approval-flow listener picks
    # this up and renders the approval card.
    ctx.publisher.publish(ctx.run_id, _ev("clarification", ctx.run_id, **payload))
    return payload
