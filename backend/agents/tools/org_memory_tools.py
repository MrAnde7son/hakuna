"""Org-scoped, agent-shared memory tools.

These let any agent in the org read and write the shared knowledge layer in
`services/org_memory.py`. Distinct from `read_scratchpad`/`write_scratchpad`
(per-agent state) — facts persisted here are visible to every agent in the
same organization on subsequent runs.

`recall_org_memory` is read-only and never approval-gated.
`remember_org_memory` is a low-risk write that is not gated at any
autonomy level — see ``agents.action_registry`` for the unified gate.
"""
from __future__ import annotations

import logging
from typing import Any

from agents.agent_tools import agent_tool
from services import org_memory

logger = logging.getLogger(__name__)


@agent_tool(
    "recall_org_memory",
    "Read facts from the org-shared memory layer — knowledge captured by "
    "other agents (and analysts) about how this customer triages: priority "
    "rules, owner conventions, business context, asset criticality cues. "
    "WHEN TO CALL: Before making a triage decision, check whether the org "
    "has already taught us a rule that applies. Pass a `namespace` (e.g. "
    "'priority_rules', 'owner_hints', 'business_context') and optionally a "
    "specific `key`.",
    {
        "namespace": {"type": "string", "description": "Memory namespace, e.g. 'priority_rules', 'owner_hints', 'business_context'"},
        "key":       {"type": "string", "description": "Optional exact key. If omitted, returns the whole namespace (newest first)."},
    },
)
def recall_org_memory_tool(db, params: dict) -> dict:
    namespace = (params.get("namespace") or "").strip()
    key = params.get("key")
    if isinstance(key, str):
        key = key.strip() or None
    org_id = params.get("_org_id")

    if not namespace:
        return {"error": "namespace is required"}
    if not org_id:
        return {"error": "org context not available"}

    facts = org_memory.recall(db, org_id=org_id, namespace=namespace, key=key)
    return {"namespace": namespace, "key": key, "facts": facts, "count": len(facts)}


@agent_tool(
    "remember_org_memory",
    "Persist a new fact into the org-shared memory layer so other agents "
    "(and your own future runs) can use it. Append-only — passing a key "
    "that already exists supersedes the previous value (history is "
    "preserved). "
    "WHEN TO CALL: When the user explicitly teaches a rule ('always treat "
    "PCI-tagged assets as critical'), or when you discover a stable "
    "pattern across runs. Include `evidence` so a reviewer can audit "
    "where the fact came from.",
    {
        "namespace":  {"type": "string", "description": "Memory namespace, e.g. 'priority_rules', 'owner_hints', 'business_context'"},
        "key":        {"type": "string", "description": "Stable identifier within the namespace, e.g. 'pci_assets_priority'"},
        "value":      {"description": "JSON-serializable fact body. Can be string, number, list, or dict."},
        "evidence":   {"type": "object", "description": "Optional audit trail: where this fact came from (user_msg, finding_id, run_id, etc.)"},
        "confidence": {"type": "number", "description": "Subjective confidence 0-1, default 0.8"},
    },
)
def remember_org_memory_tool(db, params: dict) -> dict:
    namespace = (params.get("namespace") or "").strip()
    key = (params.get("key") or "").strip()
    value: Any = params.get("value")
    evidence = params.get("evidence")
    confidence = params.get("confidence", 0.8)
    org_id = params.get("_org_id")
    source_agent_id = params.get("_agent_id")
    source_run_id = params.get("_agent_run_id")

    if not namespace or not key:
        return {"error": "namespace and key are required"}
    if value is None:
        return {"error": "value is required"}
    if not org_id:
        return {"error": "org context not available"}

    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.8
    confidence = max(0.0, min(1.0, confidence))

    fact = org_memory.remember(
        db,
        org_id=org_id,
        namespace=namespace,
        key=key,
        value=value,
        evidence=evidence if isinstance(evidence, dict) else None,
        confidence=confidence,
        source_agent_id=source_agent_id,
        source_run_id=source_run_id,
    )
    return {
        "id": fact.id,
        "namespace": namespace,
        "key": key,
        "confidence": confidence,
        "status": "remembered",
    }
