"""`emit_edge` — write a typed edge to the unified asset graph.

Companion to `emit_finding`: where `emit_finding` records that an
exposure exists, `emit_edge` records *what the exposure enables in the
attack graph*. The Cross-Scan Chain Coordinator (Phase 3+) walks these
edges to validate multi-hop chains.

Agents may only emit a closed subset of edge types
(`AGENT_EMITTABLE_EDGE_TYPES`): coercion reachability, identity edges,
local privilege escalation, DCSync. Infrastructure edges
(`resolves_to`, etc.) and exploit anchors (`cve_on_asset`) are written
by their respective producers — agents calling those types get a
silent drop with a warning log, no finding pollution.

The agent prompt's READ-ONLY / one-host rules still apply; emitting
an edge is a claim about something the tools observed, not a license
to walk to other hosts.
"""

from __future__ import annotations

import logging
from typing import Any

from agents.agent_tools import agent_tool
from models.asset_edges import AGENT_EMITTABLE_EDGE_TYPES, CONFIDENCE_LEVELS
from services.asset_edges import upsert_edge

logger = logging.getLogger(__name__)


@agent_tool(
    "emit_edge",
    "Record an attack-graph edge that this audit observed. Use this when "
    "you've proven a *capability* in the graph that's distinct from the "
    "finding itself — e.g. a coercion pipe is reachable, a domain user can "
    "log into this host, this account can DCSync. The Coordinator chains "
    "these into multi-hop kill paths. "
    "Edge types you can emit: "
    "`asset_to_asset_coerce` (PrinterBug/PetitPotam/DFSCoerce/WebDAV reachable — "
    "set src_asset_id=this host, leave dst_asset_id null, put pipe name in "
    "properties.pipe), "
    "`user_to_asset` / `asset_to_asset_auth` (an identity can authenticate to a "
    "host), "
    "`local_root` (same-host privesc proven — src=dst=this host, "
    "properties.method describes how), "
    "`principal_to_domain` (DCSync rights or equivalent — properties.principal "
    "carries the SID/name). "
    "WHEN TO CALL: alongside `emit_finding`, after you've confirmed the "
    "capability with a tool call. Pass `enabled_by_finding_id` if you just "
    "emitted a finding that justifies this edge.",
    {
        "edge_type":             {"type": "string", "description": "asset_to_asset_coerce | user_to_asset | asset_to_asset_auth | local_root | principal_to_domain | authenticates_via"},
        "src_asset_id":          {"type": "integer", "description": "Source asset id. Required for most edges; the audit's own host."},
        "dst_asset_id":          {"type": "integer", "description": "Destination asset id. Optional — leave null for `asset_to_asset_coerce` (relay target unknown) and `principal_to_domain` (domain pseudo-sink)."},
        "weight":                {"type": "number", "description": "Edge weight 0.0–1.0 (default 1.0)"},
        "confidence":            {"type": "string", "description": "confirmed | high | medium | low (default high)"},
        "properties":            {"type": "object", "description": "Edge metadata: {pipe: 'spoolss'} for coerce, {method: 'sudo_no_passwd'} for local_root, {principal: 'svc-backup'} for principal_to_domain"},
        "evidence":              {"type": "object", "description": "Free-form observation evidence — tool calls and their outputs that justify the edge"},
        "enabled_by_finding_id": {"type": "integer", "description": "Finding id (from a recent emit_finding) that this edge backs"},
    },
)
def emit_edge_tool(db, params: dict[str, Any]) -> dict:
    edge_type = (params.get("edge_type") or "").strip().lower()
    src_asset_id = params.get("src_asset_id")
    dst_asset_id = params.get("dst_asset_id")
    weight = params.get("weight")
    confidence = (params.get("confidence") or "high").strip().lower()
    properties = params.get("properties") or {}
    evidence = params.get("evidence") or {}
    enabled_by = params.get("enabled_by_finding_id")
    org_id = params.get("_org_id")

    if not edge_type:
        return {"error": "edge_type is required"}
    if edge_type not in AGENT_EMITTABLE_EDGE_TYPES:
        return {
            "error": f"edge_type {edge_type!r} is not emittable by audit agents",
            "allowed_types": sorted(AGENT_EMITTABLE_EDGE_TYPES),
        }
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "high"
    if not org_id:
        return {"error": "internal: _org_id missing from agent context"}
    if src_asset_id is None and dst_asset_id is None:
        return {"error": "at least one of src_asset_id or dst_asset_id is required"}

    try:
        weight_f = 1.0 if weight is None else float(weight)
    except (TypeError, ValueError):
        weight_f = 1.0

    # Stamp agent provenance into source_detail so a chain reviewer can
    # navigate back to the run that wrote the edge.
    source_detail: dict[str, Any] = {"evidence": evidence} if evidence else {}
    if params.get("_agent_id"):
        source_detail["agent_id"] = params["_agent_id"]
    if params.get("_agent_run_id"):
        source_detail["agent_run_id"] = params["_agent_run_id"]

    edge = upsert_edge(
        db,
        org_id=int(org_id),
        edge_type=edge_type,
        source_system="audit_agent",
        src_asset_id=int(src_asset_id) if src_asset_id is not None else None,
        dst_asset_id=int(dst_asset_id) if dst_asset_id is not None else None,
        weight=weight_f,
        confidence=confidence,
        properties=properties if isinstance(properties, dict) else {},
        enabled_by_finding_id=int(enabled_by) if enabled_by is not None else None,
        source_detail=source_detail,
    )
    if edge is None:
        return {"error": "upsert_edge rejected the parameters"}

    logger.info(
        "emit_edge: type=%s src=%s dst=%s confidence=%s → edge_id=%s",
        edge_type, src_asset_id, dst_asset_id, confidence, edge.id,
    )
    return {
        "edge_id": edge.id,
        "edge_type": edge_type,
        "src_asset_id": edge.source_asset_id,
        "dst_asset_id": edge.target_asset_id,
        "confidence": edge.confidence,
        "status": "emitted",
    }
