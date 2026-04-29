"""`emit_lead` — record an observation the agent didn't pursue.

Companion to `emit_finding` and `emit_edge`. Where `emit_finding`
records that an exposure exists and `emit_edge` records what the
exposure enables, `emit_lead` records *something the agent saw but
didn't have budget to chase*. The Cross-Scan Chain Coordinator
(`services.chain_coordinator`, `lead_followup` pattern) consumes open
leads on the next tick and dispatches the suggested probe — so the
audit gets the next-hop visibility without ever relaxing the agent's
read-only / one-host rules.

Use sparingly. A lead should be specific (asset hint + protocol) and
actionable, not "you should look at the network." Examples:

  * SMB audit: "lsarpc reachable on three other hosts in DOMAIN.LOCAL"
    → one lead per host, suggested_protocol="ldap", reason explains the
    DC suspicion.
  * SSH audit: "this account also appears in /etc/passwd on host_B
    (NFS shared) — credential reuse plausible" → one lead with
    suggested_protocol="ssh", reason describes the shared-creds context.
  * LDAP audit: "the writable SPN on this host suggests RBCD takeover
    against host_X" → suggested_protocol="ldap" again, reason names
    the target.

Leads do not bypass per-asset cooldowns or the org-level enable
switches; the Coordinator gates dispatch the same way as any other
hypothesis.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from agents.agent_tools import agent_tool
from models.models import AgentLead, Asset, Scan
from sqlalchemy import or_

logger = logging.getLogger(__name__)


# Closed set of protocols a lead can suggest. Mirrors the audit registry
# but enumerated here so a buggy / hallucinated protocol string lands as
# a tool error, not a row that the Coordinator will silently drop.
_SUGGESTABLE_PROTOCOLS: frozenset[str] = frozenset({
    "smb", "ssh", "wmi", "ldap", "snmp", "winrm",
    "exposed_datastore", "exposed_ai_service",
    "exposed_anon_protocol", "ipmi_bmc", "netbios_local",
})


@agent_tool(
    "emit_lead",
    "Record an observation that points at a follow-up scan you did NOT "
    "perform. Use this when the audit ran out of budget but you saw "
    "something the Coordinator should chase on a future tick — e.g. "
    "another DC in the same domain, a credential that probably reuses "
    "on a neighbor, an SPN that hints at RBCD against a tier-0 host. "
    "Pass `target_asset_id` if you have one (preferred) or "
    "`target_asset_hint` (hostname/fqdn/ip) if you only know the name. "
    "`suggested_protocol` must be one of: smb, ssh, wmi, ldap, snmp, "
    "winrm, exposed_datastore, exposed_ai_service, exposed_anon_protocol, "
    "ipmi_bmc, netbios_local. WHEN TO CALL: at end-of-budget, alongside "
    "Tier-2/3 emits — never as a substitute for a finding the agent "
    "could have confirmed in-budget.",
    {
        "reason":             {"type": "string",  "description": "What you saw and why a follow-up is warranted (1–3 sentences)"},
        "suggested_protocol": {"type": "string",  "description": "Protocol the Coordinator should dispatch (see allowed set in description)"},
        "suggested_mission":  {"type": "string",  "description": "Mission within the protocol (default 'exposure_audit')"},
        "target_asset_id":    {"type": "integer", "description": "Resolved backend asset id, when known"},
        "target_asset_hint":  {"type": "string",  "description": "Hostname / fqdn / ip when asset id is not known"},
        "properties":         {"type": "object",  "description": "Free-form metadata (e.g. {dc_name, domain, spn})"},
    },
)
def emit_lead_tool(db, params: dict[str, Any]) -> dict:
    org_id = params.get("_org_id")
    reason = (params.get("reason") or "").strip()
    protocol = (params.get("suggested_protocol") or "").strip().lower()
    mission = (params.get("suggested_mission") or "exposure_audit").strip().lower()
    target_asset_id = params.get("target_asset_id")
    target_asset_hint = (params.get("target_asset_hint") or "").strip() or None
    properties = params.get("properties") or {}

    if not org_id:
        return {"error": "internal: _org_id missing from agent context"}
    if not reason:
        return {"error": "reason is required"}
    if protocol not in _SUGGESTABLE_PROTOCOLS:
        return {
            "error": f"suggested_protocol {protocol!r} is not allowed",
            "allowed_protocols": sorted(_SUGGESTABLE_PROTOCOLS),
        }
    if target_asset_id is None and not target_asset_hint:
        return {"error": "either target_asset_id or target_asset_hint is required"}

    # Resolve target_asset_id from hint when caller passed only the hint.
    # Same scope rule as the rest of the agent — the asset must be in
    # this org. Hint match: case-insensitive on hostname/fqdn/ip.
    if target_asset_id is None and target_asset_hint:
        hint = target_asset_hint.strip().lower()
        candidate = (
            db.query(Asset)
            .join(Scan, Asset.scan_id == Scan.id)
            .filter(Scan.org_id == int(org_id))
            .filter(or_(
                Asset.hostname.ilike(hint),
                Asset.fqdn.ilike(hint),
                Asset.ip == hint,
            ))
            .first()
        )
        if candidate is not None:
            target_asset_id = candidate.id

    # Dedup against an existing open lead with the same (org, asset, protocol,
    # mission) tuple — same observation across two runs should bump
    # `updated_at`, not multiply rows.
    existing = (
        db.query(AgentLead)
        .filter(
            AgentLead.org_id == int(org_id),
            AgentLead.suggested_protocol == protocol,
            AgentLead.suggested_mission == mission,
            AgentLead.status == "open",
        )
    )
    if target_asset_id is not None:
        existing = existing.filter(AgentLead.target_asset_id == int(target_asset_id))
    elif target_asset_hint:
        existing = existing.filter(AgentLead.target_asset_hint == target_asset_hint)
    found = existing.first()

    now = datetime.utcnow()
    if found is not None:
        found.updated_at = now
        if reason and reason != found.reason:
            found.reason = reason
        if isinstance(properties, dict) and properties:
            merged = dict(found.properties or {})
            merged.update(properties)
            found.properties = merged
        return {
            "lead_id": found.id,
            "status": found.status,
            "deduped": True,
        }

    lead = AgentLead(
        org_id=int(org_id),
        agent_run_id=int(params["_agent_run_id"]) if params.get("_agent_run_id") else None,
        target_asset_id=int(target_asset_id) if target_asset_id is not None else None,
        target_asset_hint=target_asset_hint,
        reason=reason,
        suggested_protocol=protocol,
        suggested_mission=mission,
        properties=properties if isinstance(properties, dict) else {},
        status="open",
        created_at=now,
        updated_at=now,
    )
    db.add(lead)
    db.flush()

    logger.info(
        "emit_lead: org=%s asset=%s protocol=%s mission=%s → lead_id=%s",
        org_id, target_asset_id, protocol, mission, lead.id,
    )
    return {
        "lead_id": lead.id,
        "status": "open",
        "target_asset_id": lead.target_asset_id,
        "suggested_protocol": protocol,
        "suggested_mission": mission,
    }
