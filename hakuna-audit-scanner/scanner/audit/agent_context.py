"""Agent context — scratchpad + tool-output compression.

Trimmed port of ``backend/agents/agent_context.py``. Drops the
``AgentHandoff`` machinery and the ``AgentDocument`` (RAG) integration
because neither is needed by a single-asset protocol audit run; the
backend keeps both for the workflow / pipeline layer.

Scratchpad files live under ``config.SCRATCHPAD_DIR`` (overridable via
env so multi-replica workers can share a volume).
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Optional

from scanner.audit.config import SCRATCHPAD_DIR

logger = logging.getLogger(__name__)


# ── Scratchpad ───────────────────────────────────────────────────


def _scratchpad_path(agent_id: int | str) -> str:
    os.makedirs(SCRATCHPAD_DIR, exist_ok=True)
    return os.path.join(SCRATCHPAD_DIR, f"agent_{agent_id}_state.json")


def read_scratchpad(agent_id: int | str) -> dict:
    """Read the full scratchpad for an agent. Returns {} if none exists."""
    path = _scratchpad_path(agent_id)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def write_scratchpad(agent_id: int | str, key: str, value: Any) -> dict:
    """Write a key-value pair to the agent's scratchpad. Returns updated state."""
    state = read_scratchpad(agent_id)
    state[key] = value
    state["_last_updated"] = datetime.utcnow().isoformat()
    path = _scratchpad_path(agent_id)
    with open(path, "w") as f:
        json.dump(state, f, indent=2, default=str)
    return state


def clear_scratchpad(agent_id: int | str) -> dict:
    path = _scratchpad_path(agent_id)
    if os.path.exists(path):
        os.remove(path)
    return {}


# ── Tool-output compression ──────────────────────────────────────
# Same heuristics as the backend version — keep cost-relevant fields,
# drop verbose blobs, truncate long lists. The protocol-tool palette
# returns dicts with ``users``/``listeners``/``packages`` arrays that
# would balloon context without this.


def compress_tool_result(tool_name: str, result: Any, max_items: int = 30) -> Any:
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            cleaned = re.sub(r"<[^>]+>", "", result)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()
            return cleaned[:3000]

    if isinstance(result, list):
        truncated = result[:max_items]
        if len(result) > max_items:
            truncated.append({"_truncated": True, "_total": len(result), "_showing": max_items})
        return truncated

    if isinstance(result, dict):
        compressed = {}
        for k, v in result.items():
            if isinstance(v, list) and len(v) > max_items:
                compressed[k] = compress_tool_result(tool_name, v, max_items)
            elif isinstance(v, str) and len(v) > 1000:
                compressed[k] = v[:1000] + "..."
            else:
                compressed[k] = v
        return compressed

    return result


# ── Run-time context object ──────────────────────────────────────


class AuditContext:
    """Mutable per-run state passed into every tool dispatch.

    The protocol tools (``ssh_tools.py`` etc.) read ``relay_agent_id``,
    ``credential_id``, and ``credentials`` off this object instead of
    reaching into the backend's ``services.credential_manager``. The
    audit worker resolves credentials once per run and hands the
    plaintext dict in here — same pattern the VM scanner uses with
    ``ScanCredentials``.

    ``findings`` is the accumulator the ``emit_finding`` tool appends
    to; the worker returns this list in the Celery result payload.
    """

    def __init__(
        self,
        *,
        run_id: str,
        agent_id: int | str,
        org_id: str | int | None,
        asset: dict,
        target: str,
        target_port: int | None,
        relay_agent_id: str | None,
        credential_id: str | None,
        credentials: dict,
        protocol: str,
        mission_key: str,
    ):
        self.run_id = run_id
        self.agent_id = agent_id
        self.org_id = org_id
        self.asset = asset
        self.target = target
        self.target_port = target_port
        self.relay_agent_id = relay_agent_id
        self.credential_id = credential_id
        self.credentials = credentials
        self.protocol = protocol
        self.mission_key = mission_key
        self.findings: list[dict] = []
        self.steps: list[dict] = []

    def emit_finding(self, finding: dict) -> None:
        """Append a finding dict to the run accumulator. Called by the
        ``emit_finding`` tool — backend ingest reads ``findings`` off
        the Celery result, identical to the nuclei_worker shape."""
        self.findings.append(finding)


def build_context_section(agent_id: int | str, agent_memory: Optional[dict] = None) -> str:
    """System-prompt suffix with persistent memory + scratchpad state.

    Drops the ``AgentDocument`` / RAG section the backend version
    appends — knowledge-base documents live in the backend, not in the
    OSS scanner.
    """
    sections = []

    if agent_memory:
        sections.append(
            "## Persistent Memory\n" + json.dumps(agent_memory, indent=2, default=str)
        )

    scratchpad = read_scratchpad(agent_id)
    if scratchpad:
        sections.append(
            "## Scratchpad (your working state from previous runs)\n"
            "Use write_scratchpad to update this state as you work.\n"
            + json.dumps(scratchpad, indent=2, default=str)
        )

    if not sections:
        return ""

    return "\n\n---\n\n" + "\n\n".join(sections)
