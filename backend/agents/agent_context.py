"""
Agent Context Management — scratchpad, structured handoffs, and output compression.

Provides:
- Scratchpad: persistent per-agent key-value store for campaign state, intermediate results
- Handoff: typed inter-agent data transfer objects
- Compression: strip noise from tool outputs before passing to LLM context
"""
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Scratchpad (persistent per-agent state) ───────────────────────────

SCRATCHPAD_DIR = os.path.join(os.path.dirname(__file__), "agent_scratchpads")


def _scratchpad_path(agent_id: int) -> str:
    os.makedirs(SCRATCHPAD_DIR, exist_ok=True)
    return os.path.join(SCRATCHPAD_DIR, f"agent_{agent_id}_state.json")


def read_scratchpad(agent_id: int) -> dict:
    """Read the full scratchpad for an agent. Returns {} if none exists."""
    path = _scratchpad_path(agent_id)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def write_scratchpad(agent_id: int, key: str, value: Any) -> dict:
    """Write a key-value pair to the agent's scratchpad. Returns updated state."""
    state = read_scratchpad(agent_id)
    state[key] = value
    state["_last_updated"] = datetime.utcnow().isoformat()
    path = _scratchpad_path(agent_id)
    with open(path, "w") as f:
        json.dump(state, f, indent=2, default=str)
    return state


def clear_scratchpad(agent_id: int) -> dict:
    """Clear the entire scratchpad for an agent."""
    path = _scratchpad_path(agent_id)
    if os.path.exists(path):
        os.remove(path)
    return {}


# ── Structured Handoff Objects ────────────────────────────────────────

class AgentHandoff:
    """Typed data transfer object between agents in a pipeline.

    Ensures all inter-agent communication uses structured JSON
    rather than plain text summaries.
    """

    def __init__(
        self,
        source_agent: str,
        target_agent: str,
        handoff_type: str,
        payload: dict,
        metadata: Optional[dict] = None,
    ):
        self.source_agent = source_agent
        self.target_agent = target_agent
        self.handoff_type = handoff_type
        self.payload = payload
        self.metadata = metadata or {}
        self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "handoff": {
                "source": self.source_agent,
                "target": self.target_agent,
                "type": self.handoff_type,
                "created_at": self.created_at,
                "metadata": self.metadata,
            },
            "payload": self.payload,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict) -> "AgentHandoff":
        h = data.get("handoff", {})
        return cls(
            source_agent=h.get("source", "unknown"),
            target_agent=h.get("target", "unknown"),
            handoff_type=h.get("type", "generic"),
            payload=data.get("payload", {}),
            metadata=h.get("metadata", {}),
        )


# Predefined handoff types with expected payload schemas
HANDOFF_SCHEMAS = {
    "normalized_findings": {
        "description": "Normalized finding data from ingest/normalization agent",
        "required_fields": ["findings", "scan_id", "asset_count"],
    },
    "risk_scores": {
        "description": "Risk-scored findings from the risk model agent",
        "required_fields": ["scored_findings", "scoring_model", "timestamp"],
    },
    "remediation_plan": {
        "description": "Structured remediation plan from the planner agent",
        "required_fields": ["plan_id", "actions", "priority_order", "estimated_effort"],
    },
    "triage_result": {
        "description": "Triage decisions from the triage agent",
        "required_fields": ["decisions", "rationale", "escalations"],
    },
    "ticket_batch": {
        "description": "Batch of tickets to create from the ticket agent",
        "required_fields": ["tickets", "ticketing_system", "requires_confirmation"],
    },
}


def validate_handoff(handoff: AgentHandoff) -> List[str]:
    """Validate a handoff against its schema. Returns list of errors (empty = valid)."""
    schema = HANDOFF_SCHEMAS.get(handoff.handoff_type)
    if not schema:
        return []  # Unknown types are allowed (no validation)
    errors = []
    for field in schema.get("required_fields", []):
        if field not in handoff.payload:
            errors.append(f"Missing required field '{field}' for handoff type '{handoff.handoff_type}'")
    return errors


# ── Tool Output Compression ──────────────────────────────────────────

def compress_finding_output(finding: dict) -> dict:
    """Strip verbose fields from a finding dict before passing to LLM.

    Retains: id, plugin_id, plugin_name, severity, cvss3, vpr, priority_score,
             cves, solution (truncated), effort, asset_id, exploit flags.
    Strips: full description, raw plugin_output, lengthy synopsis.
    """
    compressed = {}
    # Always keep these core fields
    keep_fields = {
        "id", "plugin_id", "plugin_name", "severity", "severity_label",
        "cvss3", "vpr", "priority_score", "effort", "effort_level",
        "asset_id", "cves", "exploit_available", "exploit_maturity",
        "is_kev", "ransomware_linked", "zero_day", "epss_score", "epss",
        "sla_status", "sla_due_date", "workflow_status", "is_regression",
        "times_seen", "owner_suggestion", "port", "protocol",
    }
    for k, v in finding.items():
        if k in keep_fields:
            compressed[k] = v

    # Truncate solution to 200 chars
    if "solution" in finding:
        sol = finding["solution"] or ""
        compressed["solution"] = sol[:200] + ("..." if len(sol) > 200 else "")

    return compressed


def compress_asset_output(asset: dict) -> dict:
    """Strip verbose fields from an asset dict."""
    keep_fields = {
        "id", "ip", "hostname", "fqdn", "os", "criticality", "risk_score",
        "critical_count", "high_count", "medium_count", "low_count",
        "is_internet_facing", "environment", "environment_tag",
        "inferred_primary_user", "inferred_team",
    }
    return {k: v for k, v in asset.items() if k in keep_fields}


def compress_tool_result(tool_name: str, result: Any, max_items: int = 30) -> Any:
    """Compress a tool result before injecting into LLM context.

    - Truncates lists to max_items
    - Compresses finding/asset dicts
    - Strips raw XML/HTML noise
    """
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            # Strip XML/HTML tags from raw strings
            cleaned = re.sub(r'<[^>]+>', '', result)
            # Collapse whitespace
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            return cleaned[:3000]

    if isinstance(result, list):
        # Truncate long lists
        truncated = result[:max_items]
        if len(result) > max_items:
            truncated.append({"_truncated": True, "_total": len(result), "_showing": max_items})

        # Compress individual items if they look like findings or assets
        compressed = []
        for item in truncated:
            if isinstance(item, dict):
                if "plugin_id" in item or "plugin_name" in item:
                    compressed.append(compress_finding_output(item))
                elif "risk_score" in item and "ip" in item:
                    compressed.append(compress_asset_output(item))
                else:
                    compressed.append(item)
            else:
                compressed.append(item)
        return compressed

    if isinstance(result, dict):
        # Compress nested lists within dicts (e.g., {"findings": [...], "summary": {...}})
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


# ── Scratchpad injection into system prompt ──────────────────────────

def _get_document_summary(agent_id: int) -> Optional[str]:
    """Return a summary of uploaded documents for the agent's system prompt."""
    try:
        from core.database import SessionLocal
        from models.models import AgentDocument
        db = SessionLocal()
        try:
            docs = db.query(AgentDocument).filter(AgentDocument.agent_id == agent_id).all()
            if not docs:
                return None
            lines = [f"- {d.filename} ({d.chunk_count} chunks, {d.size_bytes:,} bytes)" for d in docs]
            return (
                "## Knowledge Base Documents\n"
                "The following documents have been uploaded as reference material. "
                "Use the `search_documents` tool to retrieve relevant content from them.\n"
                + "\n".join(lines)
            )
        finally:
            db.close()
    except Exception:
        logger.exception("Failed to load document summary for agent %s", agent_id)
        return None


_ORG_MEMORY_BUDGET_BYTES = 2048
_ORG_MEMORY_PER_NAMESPACE = 10


def _build_org_memory_section(org_id: int, namespaces: List[str]) -> Optional[str]:
    """Render up to ~2KB of recent active facts across the requested namespaces.

    Truncates oldest first so the most recent learnings always survive the
    budget. Returns None when no facts are available — caller should skip
    the section entirely in that case.
    """
    if not namespaces:
        return None
    try:
        from core.database import SessionLocal
        from services.org_memory import recall as recall_facts
        db = SessionLocal()
        try:
            collected: list[tuple[str, dict]] = []
            for ns in namespaces:
                facts = recall_facts(db, org_id, ns, limit=_ORG_MEMORY_PER_NAMESPACE)
                for f in facts:
                    collected.append((ns, f))
            if not collected:
                return None
            # `recall` returns newest first per namespace, so the *end* of
            # `collected` holds the oldest entries; pop those first when over
            # budget.
            lines = [
                "## Org Memory",
                "Shared org-level knowledge captured by other agents and analysts.",
                "Use `recall_org_memory` to read more, `remember_org_memory` to add new facts.",
            ]
            rendered: list[str] = []
            for ns, f in collected:
                key = f.get("key")
                value = f.get("value")
                conf = f.get("confidence")
                rendered.append(
                    f"- [{ns}] {key} (confidence={conf}): {json.dumps(value, default=str)}"
                )
            body = "\n".join(lines + rendered)
            while len(body.encode("utf-8")) > _ORG_MEMORY_BUDGET_BYTES and rendered:
                rendered.pop()  # drop oldest (end of list)
                body = "\n".join(lines + rendered + ["- (older facts truncated)"])
            return body
        finally:
            db.close()
    except Exception:
        logger.exception("Failed to build org memory section for org %s", org_id)
        return None


def build_context_section(
    agent_id: int,
    agent_memory: Optional[dict] = None,
    org_id: Optional[int] = None,
    org_memory_namespaces: Optional[List[str]] = None,
) -> str:
    """Build the context section to append to an agent's system prompt.

    Includes:
    - Persistent memory (from agent.memory)
    - Scratchpad state (from file)
    - Knowledge base document listing (RAG)
    - Org Memory (cross-agent, opt-in via org_memory_namespaces)
    """
    sections = []

    if agent_memory:
        sections.append(
            "## Persistent Memory\n"
            + json.dumps(agent_memory, indent=2, default=str)
        )

    scratchpad = read_scratchpad(agent_id)
    if scratchpad:
        sections.append(
            "## Scratchpad (your working state from previous runs)\n"
            "Use write_scratchpad to update this state as you work.\n"
            + json.dumps(scratchpad, indent=2, default=str)
        )

    doc_summary = _get_document_summary(agent_id)
    if doc_summary:
        sections.append(doc_summary)

    if org_id is not None and org_memory_namespaces:
        org_section = _build_org_memory_section(org_id, org_memory_namespaces)
        if org_section:
            sections.append(org_section)

    if not sections:
        return ""

    return "\n\n---\n\n" + "\n\n".join(sections)
