"""
LLM-driven workflow generation.

Given a natural-language description ("when a KEV finding lands on a domain
controller, ticket the AD team in ServiceNow"), produce a workflow DAG that
matches the on-disk node catalog. Output is always created as `status="draft"`
so an LLM hallucination cannot fire real Slack/Jira side-effects.

Validation pass:
    - Every node_subtype must exist in NODE_CATALOG.
    - Every edge endpoint must reference a known node_id.
    - Exactly one trigger node (relaxed: at least one).
    - Unknown config keys are surfaced as warnings, not errors — the workflow
      engine treats unknown keys as no-ops, so these are safe to ship.

The LLM is asked to return JSON only. We extract via a tolerant parser that
handles ```json fences and stripped prose, then validate.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from sqlalchemy.orm import Session

from core.llm_router import router as llm_router
from services.workflow_catalog import NODE_CATALOG, WORKFLOW_TEMPLATES

logger = logging.getLogger(__name__)


def _build_catalog_summary() -> str:
    """Compact catalog representation for the LLM prompt — subtype, label, description, config keys."""
    out: list[str] = []
    for category, defs in NODE_CATALOG.items():
        out.append(f"\n## {category} (node_type={category[:-1]})")
        for d in defs:
            keys = list((d.get("config_schema") or {}).keys())
            keys_str = f"  config keys: [{', '.join(keys)}]" if keys else "  config keys: []"
            out.append(f"- {d['subtype']}: {d.get('description', d.get('label', ''))}\n{keys_str}")
    return "\n".join(out)


def _few_shot_examples() -> str:
    """Pull 2 templates as concrete examples so the LLM matches the exact JSON shape."""
    chosen = [t for t in WORKFLOW_TEMPLATES if t["id"] in ("critical_triage", "exploit_response")]
    return "\n\n".join(json.dumps({
        "name": t["name"], "description": t["description"],
        "nodes": t["nodes"], "edges": t["edges"],
    }, indent=2) for t in chosen)


SYSTEM_PROMPT = """You design vulnerability-management workflow DAGs for the Hakuna platform.

A workflow is a directed graph: trigger nodes feed filter nodes feed action nodes.
Output a JSON object with this exact shape — no prose, no markdown fences:

{
  "name": "<short title>",
  "description": "<one sentence>",
  "nodes": [
    {"node_id": "<unique string>", "node_type": "trigger|filter|action",
     "node_subtype": "<from catalog>", "label": "<short>", "config": {...},
     "position_x": <int>, "position_y": <int>}
  ],
  "edges": [
    {"edge_id": "<unique>", "source_node_id": "<id>", "target_node_id": "<id>",
     "source_handle": "output", "target_handle": "input"}
  ]
}

Rules:
- Use only node_subtype values from the catalog below.
- Every workflow must have at least one trigger node.
- Wire trigger → filter(s) → action(s) with edges. Actions must be reachable.
- Position nodes left-to-right: triggers x=60, filters x=360, actions x=660+.
  Vertical spacing 200px between siblings.
- For unknown config values (e.g. exact integration ID), use sensible defaults
  or empty strings — the human reviewer will fill them in.
- If the user asks for something the catalog can't express, pick the closest
  available subtype rather than inventing one.

# Node catalog
{catalog_summary}

# Examples
{examples}
"""


def _extract_json(text: str) -> dict | None:
    """Pull a JSON object out of LLM output. Tolerant of code fences and prose."""
    if not text:
        return None
    # Strip markdown fences if present
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    # Otherwise grab the first balanced {...}
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _valid_subtypes() -> dict[str, str]:
    """Map subtype → category (triggers/filters/actions) for validation."""
    out: dict[str, str] = {}
    for category, defs in NODE_CATALOG.items():
        # category is plural — strip trailing 's' to align with node_type singular
        node_type = category[:-1] if category.endswith("s") else category
        for d in defs:
            out[d["subtype"]] = node_type
    return out


def _validate_workflow(wf: dict) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors block creation; warnings are surfaced to UI."""
    errors: list[str] = []
    warnings: list[str] = []

    nodes = wf.get("nodes") or []
    edges = wf.get("edges") or []
    if not isinstance(nodes, list) or not nodes:
        errors.append("Workflow must have at least one node.")
        return errors, warnings
    if not isinstance(edges, list):
        errors.append("Workflow edges must be a list.")
        return errors, warnings

    valid_subtypes = _valid_subtypes()
    node_ids: set[str] = set()
    has_trigger = False

    for i, n in enumerate(nodes):
        nid = n.get("node_id")
        if not nid or nid in node_ids:
            errors.append(f"Node {i}: missing or duplicate node_id ({nid!r}).")
            continue
        node_ids.add(nid)

        sub = n.get("node_subtype")
        ntype = n.get("node_type")
        if sub not in valid_subtypes:
            errors.append(f"Node {nid}: unknown node_subtype {sub!r}.")
            continue
        expected_type = valid_subtypes[sub]
        if ntype != expected_type:
            warnings.append(
                f"Node {nid}: node_type was {ntype!r}, corrected to {expected_type!r}."
            )
            n["node_type"] = expected_type
        if expected_type == "trigger":
            has_trigger = True

        # Surface unknown config keys as warnings (engine ignores them safely)
        cat_def = next(
            (d for cat in NODE_CATALOG.values() for d in cat if d["subtype"] == sub),
            None,
        )
        if cat_def:
            known_keys = set((cat_def.get("config_schema") or {}).keys())
            cfg = n.get("config") or {}
            for k in cfg:
                if known_keys and k not in known_keys:
                    warnings.append(f"Node {nid}: unknown config key {k!r} (will be ignored).")

    if not has_trigger:
        errors.append("Workflow must have at least one trigger node.")

    edge_ids: set[str] = set()
    for i, e in enumerate(edges):
        eid = e.get("edge_id")
        if not eid or eid in edge_ids:
            errors.append(f"Edge {i}: missing or duplicate edge_id ({eid!r}).")
            continue
        edge_ids.add(eid)
        if e.get("source_node_id") not in node_ids:
            errors.append(f"Edge {eid}: source_node_id references unknown node.")
        if e.get("target_node_id") not in node_ids:
            errors.append(f"Edge {eid}: target_node_id references unknown node.")

    return errors, warnings


def generate_workflow(db: Session, description: str, model: str | None = None) -> dict:
    """Call the LLM to produce a workflow JSON for the given description.

    Returns:
        {
          "name": str, "description": str,
          "nodes": [...], "edges": [...],
          "warnings": [str],     # non-blocking
          "model": str,           # which model produced this
          "original_prompt": str,
        }

    Raises:
        ValueError on validation errors (caller surfaces to UI).
    """
    if not description or not description.strip():
        raise ValueError("Description is required")

    system_prompt = SYSTEM_PROMPT.replace(
        "{catalog_summary}", _build_catalog_summary()
    ).replace("{examples}", _few_shot_examples())

    user_prompt = (
        f"Generate a workflow for: {description.strip()}\n\n"
        "Return JSON only. No commentary."
    )

    text, used_model = llm_router.call(
        db, system=system_prompt, user=user_prompt, max_tokens=4096, model=model,
    )

    parsed = _extract_json(text)
    if parsed is None:
        logger.warning("workflow_generator: failed to parse LLM output: %s", text[:500])
        raise ValueError("LLM did not return parseable JSON. Try rephrasing or pick a template.")

    errors, warnings = _validate_workflow(parsed)
    if errors:
        raise ValueError("Generated workflow failed validation: " + "; ".join(errors))

    return {
        "name": parsed.get("name") or "AI-generated workflow",
        "description": parsed.get("description") or description.strip(),
        "nodes": parsed.get("nodes") or [],
        "edges": parsed.get("edges") or [],
        "warnings": warnings,
        "model": used_model,
        "original_prompt": description.strip(),
    }
