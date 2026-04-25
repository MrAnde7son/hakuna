"""Scratchpad tools — persistent per-agent state across runs.

Wraps the file-based scratchpad in ``scanner.audit.agent_context``.
The backend's version of these tools sits in ``agent_tools.py`` and
reads/writes the same file path; we re-expose them with the
audit-scanner's tool registry so any audit can declare them in its
``tool_names`` palette.

``agent_id`` defaults to ``ctx.agent_id`` (the run id in OSS standalone
runs; the persistent ``Agent.id`` when the backend dispatches). LLM
input does not carry an agent id — the engine doesn't expose one.
"""

from __future__ import annotations

import logging

from scanner.audit.agent_context import (
    AuditContext,
    clear_scratchpad,
    read_scratchpad,
    write_scratchpad,
)
from scanner.audit.audit_engine import agent_tool

logger = logging.getLogger(__name__)


@agent_tool(
    "read_scratchpad",
    "Read your persistent scratchpad state from a previous run. Call this "
    "at the START of a multi-step workflow to resume where you left off. "
    "Returns a JSON object with your saved state, or {} if empty.",
    {},
)
def read_scratchpad_tool(ctx: AuditContext, params: dict) -> dict:
    return read_scratchpad(ctx.agent_id)


@agent_tool(
    "write_scratchpad",
    "Save a key-value pair to your persistent scratchpad. Use this to "
    "track intermediate state across runs: campaign progress, pending "
    "items, analysis checkpoints. Call this DURING your workflow to "
    "checkpoint progress, not just at the end.",
    {
        "key": {
            "type": "string",
            "description": "State key (e.g. 'cve_candidates', 'last_orient_iter')",
        },
        "value": {
            "type": "object",
            "description": "Value to store (any JSON-serialisable object)",
        },
    },
)
def write_scratchpad_tool(ctx: AuditContext, params: dict) -> dict:
    key = params.get("key")
    if not key:
        return {"error": "key is required"}
    value = params.get("value")
    state = write_scratchpad(ctx.agent_id, key, value)
    return {"saved": True, "keys": list(state.keys())}


@agent_tool(
    "clear_scratchpad",
    "Clear your entire scratchpad state. Use this when starting a fresh "
    "workflow or when previous state is stale.",
    {},
)
def clear_scratchpad_tool(ctx: AuditContext, params: dict) -> dict:
    clear_scratchpad(ctx.agent_id)
    return {"cleared": True}
