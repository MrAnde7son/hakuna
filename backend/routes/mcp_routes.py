"""MCP (Model Context Protocol) server.

Exposes Hakuna read APIs as MCP tools so customers can connect their own
agents (Claude Desktop, Cursor, in-house agents) to query findings, assets,
and campaigns.

Write tools route through ``agents.action_registry``: HARD_WRITE / EXTERNAL
calls create an ``AgentApproval`` row with ``source='mcp_external'`` and
return ``{"status":"pending_approval","approval_id":N}`` to the caller.
SOFT_WRITE calls auto-execute at the default ``standard`` autonomy.

Transport: Streamable HTTP — single POST /api/mcp endpoint speaking
JSON-RPC 2.0. Auth reuses the existing JWT bearer + X-Org-Context model.

Client config example::

    {
      "mcpServers": {
        "hakuna": {
          "url": "https://hakuna.example.com/api/mcp",
          "headers": {
            "Authorization": "Bearer <jwt>",
            "X-Org-Context": "<org_id>"
          }
        }
      }
    }
"""
import json
import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from agents import action_registry
from agents.action_registry import RiskTier, requires_approval
from core.auth import get_accessible_org_ids, require_auth
from core.database import get_db
from models.models import (
    AgentApproval,
    Asset,
    Campaign,
    CampaignFinding,
    Finding,
    FindingException,
    OrgActionGrant,
    Scan,
    User,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["mcp"])

SERVER_NAME = "hakuna-mcp"
SERVER_VERSION = "1.1.0"
SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}
DEFAULT_PROTOCOL_VERSION = "2025-06-18"


# ── External-action registry entries ──────────────────────────────────
#
# Two of the six write tools (``update_finding_status``, ``create_campaign``)
# already have ActionSpecs registered by ``agents.agent_tools``; we reuse
# those rather than declaring a parallel set. The remaining four are
# MCP-only — register them here so the gate has a tier for them.

action_registry.register_action(
    "assign_owner",
    RiskTier.SOFT_WRITE,
    scopes=["assets:write"],
    description="Set the business owner for an asset by email.",
)
action_registry.register_action(
    "request_exception",
    RiskTier.HARD_WRITE,
    scopes=["findings:write"],
    description="Request a finding exception (accepted risk) with justification and TTL.",
)
action_registry.register_action(
    "trigger_scan",
    RiskTier.HARD_WRITE,
    scopes=["scans:run"],
    description="Queue a scan run against a list of asset IDs.",
)
action_registry.register_action(
    "add_finding_comment",
    RiskTier.SOFT_WRITE,
    scopes=["findings:write"],
    description="Append a comment to a finding's workflow notes.",
)


# ── Tool registry ─────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_findings",
        "description": (
            "List vulnerability findings in the user's accessible orgs. "
            "Filter by severity, KEV status, or free-text search across plugin "
            "name, synopsis, and CVE. Returns up to `limit` rows ordered by "
            "priority_score desc."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Substring match across plugin_name, synopsis, cves"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter by severity label",
                },
                "kev_only": {"type": "boolean", "description": "Only CISA KEV-listed findings"},
                "exploit_available": {"type": "boolean", "description": "Only findings with public exploits"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_finding",
        "description": "Fetch a single finding by ID with full detail (description, solution, CVEs, plugin output).",
        "inputSchema": {
            "type": "object",
            "properties": {"finding_id": {"type": "integer"}},
            "required": ["finding_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_assets",
        "description": (
            "List assets (hosts, web apps, cloud instances, etc.) in the user's "
            "accessible orgs. Filter by asset_type, criticality floor, or free-text "
            "search across hostname/ip/fqdn."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string"},
                "asset_type": {"type": "string", "description": "e.g. host, web_app, ai_agent, mcp_server"},
                "criticality_min": {"type": "integer", "minimum": 1, "maximum": 10},
                "internet_facing_only": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_asset",
        "description": "Fetch a single asset by ID with full detail and finding counts.",
        "inputSchema": {
            "type": "object",
            "properties": {"asset_id": {"type": "integer"}},
            "required": ["asset_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_campaigns",
        "description": "List remediation campaigns with status and finding counts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["draft", "active", "completed", "paused"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
            },
            "additionalProperties": False,
        },
    },
    # ── Write tools ──────────────────────────────────────────
    {
        "name": "update_finding_status",
        "description": (
            "Move a finding to a new workflow status. Routes through the action "
            "registry — SOFT_WRITE, auto-approves at standard autonomy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "status": {
                    "type": "string",
                    "enum": ["open", "in_progress", "resolved", "accepted_risk", "false_positive"],
                },
                "comment": {"type": "string", "description": "Optional note recorded in workflow_notes."},
            },
            "required": ["finding_id", "status"],
            "additionalProperties": False,
        },
    },
    {
        "name": "create_campaign",
        "description": (
            "Create a remediation campaign seeded with the given findings. "
            "HARD_WRITE — requires approval at standard autonomy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
                "finding_ids": {"type": "array", "items": {"type": "integer"}},
                "owner_id": {"type": "integer", "description": "Optional: campaign owner user id."},
            },
            "required": ["name", "finding_ids"],
            "additionalProperties": False,
        },
    },
    {
        "name": "assign_owner",
        "description": (
            "Set the asset's business owner email and resolve to a User if one "
            "matches. SOFT_WRITE — auto-approves at standard autonomy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_id": {"type": "integer"},
                "owner_email": {"type": "string", "format": "email"},
            },
            "required": ["asset_id", "owner_email"],
            "additionalProperties": False,
        },
    },
    {
        "name": "request_exception",
        "description": (
            "Request an accepted-risk exception for a finding. Creates a "
            "FindingException scoped by plugin_id and asset_ip. HARD_WRITE — "
            "requires approval at standard autonomy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "justification": {"type": "string", "minLength": 10},
                "expires_at": {"type": "string", "format": "date", "description": "ISO date (YYYY-MM-DD)"},
            },
            "required": ["finding_id", "justification", "expires_at"],
            "additionalProperties": False,
        },
    },
    {
        "name": "trigger_scan",
        "description": (
            "Queue a scan run against the given asset IDs. HARD_WRITE — "
            "requires approval at standard autonomy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_ids": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
                "scan_type": {"type": "string", "enum": ["nuclei", "easm", "credentialed"], "default": "nuclei"},
            },
            "required": ["asset_ids"],
            "additionalProperties": False,
        },
    },
    {
        "name": "add_finding_comment",
        "description": (
            "Append a comment to a finding's workflow_notes. SOFT_WRITE — "
            "auto-approves at standard autonomy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "comment": {"type": "string", "minLength": 1},
            },
            "required": ["finding_id", "comment"],
            "additionalProperties": False,
        },
    },
]

SEVERITY_LABEL_TO_INT = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ToolError(Exception):
    """Raised by a tool to surface a clean error in the tool result."""


# ── Read-tool implementations ─────────────────────────────


def _serialize_finding(f: Finding, *, summary: bool = False) -> dict[str, Any]:
    base = {
        "id": f.id,
        "asset_id": f.asset_id,
        "scan_id": f.scan_id,
        "plugin_id": f.plugin_id,
        "plugin_name": f.plugin_name,
        "severity": f.severity,
        "severity_label": f.severity_label,
        "cvss3_score": f.cvss3_score,
        "vpr_score": f.vpr_score,
        "priority_score": f.priority_score,
        "cves": f.cves or [],
        "is_kev": f.is_kev,
        "exploit_available": f.exploit_available,
        "epss_score": f.epss_score,
        "synopsis": f.synopsis,
    }
    if not summary:
        base.update({
            "description": f.description,
            "solution": f.solution,
            "plugin_output": f.plugin_output,
            "port": f.port,
            "protocol": f.protocol,
            "cwe_ids": f.cwe_ids or [],
            "matched_ttps": f.matched_ttps or [],
            "ssvc_decision": f.ssvc_decision,
            "exploit_maturity_level": f.exploit_maturity_level,
        })
    return base


def _serialize_asset(a: Asset, *, summary: bool = False) -> dict[str, Any]:
    base = {
        "id": a.id,
        "scan_id": a.scan_id,
        "asset_type": a.asset_type,
        "hostname": a.hostname,
        "ip": a.ip,
        "fqdn": a.fqdn,
        "os": a.os,
        "criticality": a.criticality,
        "environment_tag": a.environment_tag,
        "is_internet_facing": a.is_internet_facing,
        "risk_score": a.risk_score,
        "critical_count": a.critical_count,
        "high_count": a.high_count,
    }
    if not summary:
        base.update({
            "asset_identity": a.asset_identity or {},
            "asset_attributes": a.asset_attributes or {},
            "device_type": a.device_type,
            "business_context": a.business_context,
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "asset_status": a.asset_status,
            "medium_count": a.medium_count,
            "low_count": a.low_count,
        })
    return base


def _tool_list_findings(args: dict, db: Session, org_ids: Optional[list[int]], **_) -> dict:
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))

    if sev := args.get("severity"):
        sev_int = SEVERITY_LABEL_TO_INT.get(sev.lower())
        if sev_int is not None:
            q = q.filter(Finding.severity == sev_int)
    if args.get("kev_only"):
        q = q.filter(Finding.is_kev.is_(True))
    if args.get("exploit_available"):
        q = q.filter(Finding.exploit_available.is_(True))
    if search := args.get("search"):
        like = f"%{search}%"
        q = q.filter(
            (Finding.plugin_name.ilike(like))
            | (Finding.synopsis.ilike(like))
        )

    limit = min(int(args.get("limit", 50)), 200)
    rows = q.order_by(Finding.priority_score.desc()).limit(limit).all()
    return {"count": len(rows), "findings": [_serialize_finding(f, summary=True) for f in rows]}


def _tool_get_finding(args: dict, db: Session, org_ids: Optional[list[int]], **_) -> dict:
    fid = int(args["finding_id"])
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == fid)
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))
    f = q.first()
    if not f:
        raise ToolError(f"Finding {fid} not found or not accessible")
    return _serialize_finding(f, summary=False)


def _tool_list_assets(args: dict, db: Session, org_ids: Optional[list[int]], **_) -> dict:
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))

    if asset_type := args.get("asset_type"):
        q = q.filter(Asset.asset_type == asset_type)
    if (cm := args.get("criticality_min")) is not None:
        q = q.filter(Asset.criticality >= int(cm))
    if args.get("internet_facing_only"):
        q = q.filter(Asset.is_internet_facing.is_(True))
    if search := args.get("search"):
        like = f"%{search}%"
        q = q.filter(
            (Asset.hostname.ilike(like))
            | (Asset.ip.ilike(like))
            | (Asset.fqdn.ilike(like))
        )

    limit = min(int(args.get("limit", 50)), 200)
    rows = q.order_by(Asset.risk_score.desc()).limit(limit).all()
    return {"count": len(rows), "assets": [_serialize_asset(a, summary=True) for a in rows]}


def _tool_get_asset(args: dict, db: Session, org_ids: Optional[list[int]], **_) -> dict:
    aid = int(args["asset_id"])
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == aid)
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))
    a = q.first()
    if not a:
        raise ToolError(f"Asset {aid} not found or not accessible")
    return _serialize_asset(a, summary=False)


def _tool_list_campaigns(args: dict, db: Session, org_ids: Optional[list[int]], **_) -> dict:
    q = db.query(Campaign)
    if org_ids is not None:
        q = q.filter(Campaign.org_id.in_(org_ids))
    if status := args.get("status"):
        q = q.filter(Campaign.status == status)
    limit = min(int(args.get("limit", 50)), 200)
    rows = q.order_by(Campaign.updated_at.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "campaigns": [
            {
                "id": c.id,
                "name": c.name,
                "status": c.status,
                "description": c.description,
                "finding_count": c.finding_count,
                "last_run_at": c.last_run_at.isoformat() if c.last_run_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            }
            for c in rows
        ],
    }


# ── Write-tool implementations ────────────────────────────


def _resolve_finding(db: Session, finding_id: int, org_ids: Optional[list[int]]) -> Finding:
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == finding_id)
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))
    f = q.first()
    if not f:
        raise ToolError(f"Finding {finding_id} not found or not accessible")
    return f


def _tool_update_finding_status(args: dict, db: Session, org_ids: Optional[list[int]], *, user: User, org_id: int, **_) -> dict:
    f = _resolve_finding(db, int(args["finding_id"]), org_ids)
    new_status = args["status"]
    before = f.workflow_status
    f.workflow_status = new_status
    f.status_changed_at = datetime.utcnow()
    if comment := args.get("comment"):
        f.workflow_notes = (f.workflow_notes + "\n\n" if f.workflow_notes else "") + (
            f"[mcp_external by {user.email} @ {datetime.utcnow().isoformat()}]\n{comment}"
        )
    db.commit()
    return {"finding_id": f.id, "before": before, "after": new_status}


def _tool_create_campaign(args: dict, db: Session, org_ids: Optional[list[int]], *, user: User, org_id: int, **_) -> dict:
    finding_ids = list(args.get("finding_ids") or [])
    if not finding_ids:
        raise ToolError("finding_ids must contain at least one id")

    findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.id.in_(finding_ids))
    )
    if org_ids is not None:
        findings = findings.filter(Scan.org_id.in_(org_ids))
    findings = findings.all()
    if len(findings) != len(set(finding_ids)):
        raise ToolError("One or more finding_ids not found or not accessible")

    campaign = Campaign(
        org_id=org_id,
        name=args["name"],
        description=args.get("description") or "",
        status="draft",
        owner_id=args.get("owner_id") or user.id,
        finding_count=len(findings),
    )
    db.add(campaign)
    db.flush()
    for f in findings:
        db.add(CampaignFinding(campaign_id=campaign.id, finding_id=f.id))
    db.commit()
    return {
        "campaign_id": campaign.id,
        "name": campaign.name,
        "status": campaign.status,
        "finding_count": campaign.finding_count,
    }


def _tool_assign_owner(args: dict, db: Session, org_ids: Optional[list[int]], *, user: User, org_id: int, **_) -> dict:
    aid = int(args["asset_id"])
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == aid)
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))
    a = q.first()
    if not a:
        raise ToolError(f"Asset {aid} not found or not accessible")

    email = args["owner_email"].strip().lower()
    before = a.business_context or ""
    # Asset doesn't carry a direct owner_id column — record on business_context
    # (an existing free-form field) and surface the resolved user if matched.
    matched = (
        db.query(User)
        .filter(User.email == email, User.org_id == org_id)
        .first()
    )
    a.business_context = f"owner:{email}" + (f" (user_id={matched.id})" if matched else "")
    db.commit()
    return {
        "asset_id": a.id,
        "before": before,
        "after": a.business_context,
        "matched_user_id": matched.id if matched else None,
    }


def _tool_request_exception(args: dict, db: Session, org_ids: Optional[list[int]], *, user: User, org_id: int, **_) -> dict:
    f = _resolve_finding(db, int(args["finding_id"]), org_ids)
    try:
        expires = datetime.strptime(args["expires_at"], "%Y-%m-%d")
    except ValueError as e:
        raise ToolError(f"expires_at must be YYYY-MM-DD: {e}")

    asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
    exc = FindingException(
        org_id=org_id,
        plugin_id=f.plugin_id,
        plugin_name=f.plugin_name,
        asset_ip=asset.ip if asset else None,
        exception_type="accepted_risk",
        reason=args["justification"],
        approved_by=user.email,
        expires_at=expires,
        is_active=True,
    )
    db.add(exc)
    db.commit()
    return {
        "exception_id": exc.id,
        "finding_id": f.id,
        "expires_at": exc.expires_at.isoformat() if exc.expires_at else None,
    }


def _tool_trigger_scan(args: dict, db: Session, org_ids: Optional[list[int]], *, user: User, org_id: int, **_) -> dict:
    asset_ids = list(args.get("asset_ids") or [])
    if not asset_ids:
        raise ToolError("asset_ids must contain at least one id")

    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id.in_(asset_ids))
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))
    accessible = {a.id for a in q.all()}
    missing = set(asset_ids) - accessible
    if missing:
        raise ToolError(f"Assets not found or not accessible: {sorted(missing)}")

    scan_type = args.get("scan_type") or "nuclei"
    # Queue is service-specific; we record a queued Scan placeholder so the
    # caller has a handle to look up later. The actual scan worker picks this up.
    queued = Scan(
        org_id=org_id,
        filename=f"mcp_external/{scan_type}/{datetime.utcnow().isoformat()}",
        status="queued",
    )
    db.add(queued)
    db.commit()
    return {
        "scan_id": queued.id,
        "scan_type": scan_type,
        "asset_ids": sorted(accessible),
        "status": queued.status,
    }


def _tool_add_finding_comment(args: dict, db: Session, org_ids: Optional[list[int]], *, user: User, org_id: int, **_) -> dict:
    f = _resolve_finding(db, int(args["finding_id"]), org_ids)
    comment = args["comment"]
    stamp = f"[mcp_external by {user.email} @ {datetime.utcnow().isoformat()}]"
    new_notes = (f.workflow_notes + "\n\n" if f.workflow_notes else "") + f"{stamp}\n{comment}"
    f.workflow_notes = new_notes
    db.commit()
    return {"finding_id": f.id, "comment_appended": True}


TOOL_HANDLERS = {
    "list_findings": _tool_list_findings,
    "get_finding": _tool_get_finding,
    "list_assets": _tool_list_assets,
    "get_asset": _tool_get_asset,
    "list_campaigns": _tool_list_campaigns,
    "update_finding_status": _tool_update_finding_status,
    "create_campaign": _tool_create_campaign,
    "assign_owner": _tool_assign_owner,
    "request_exception": _tool_request_exception,
    "trigger_scan": _tool_trigger_scan,
    "add_finding_comment": _tool_add_finding_comment,
}


# ── Approval gate ──────────────────────────────────────────


def _has_active_org_grant(db: Session, org_id: Optional[int], action_name: str) -> bool:
    """True if the org has a non-expired ``org_for_24h`` grant for this action."""
    if org_id is None:
        return False
    now = datetime.utcnow()
    return (
        db.query(OrgActionGrant)
        .filter(
            OrgActionGrant.org_id == org_id,
            OrgActionGrant.action_name == action_name,
            OrgActionGrant.expires_at > now,
        )
        .first()
        is not None
    )


def _create_mcp_approval(
    db: Session,
    *,
    org_id: Optional[int],
    user: User,
    action_name: str,
    args: dict,
) -> AgentApproval:
    approval = AgentApproval(
        org_id=org_id,
        agent_run_id=None,
        agent_id=None,
        source="mcp_external",
        tool_name=action_name,
        tool_input=args,
        status="pending",
        # Snapshot fields stay empty — there's no agent loop to resume.
        messages_snapshot=[],
        assistant_content=[],
        provider=None,
        model_name=None,
        current_step=0,
        tool_use_id=None,
        # Record the requesting principal in decided_by? No — that's the
        # decider. Stash it in tool_input under a private key for audit.
    )
    approval.tool_input = {**args, "_principal_user_id": user.id, "_principal_email": user.email}
    db.add(approval)
    db.flush()

    # Surface in the org's notification bell so analysts see it without
    # having to live on the Approval Queue page.
    if org_id:
        try:
            from services.notifications import create_notification
            create_notification(
                db,
                org_id,
                "approval_required",
                f"External MCP caller: {action_name} needs approval",
                body=f"Requested by {user.email}",
                link=f"/agents?approvals=1",
                entity_type="agent_approval",
                entity_id=approval.id,
                metadata={
                    "source": "mcp_external",
                    "tool_name": action_name,
                    "principal_email": user.email,
                },
            )
        except Exception:  # pragma: no cover — defensive
            logger.exception("failed to emit MCP approval_required notification")

    db.commit()
    db.refresh(approval)
    return approval


# ── JSON-RPC dispatch ─────────────────────────────────────


def _jsonrpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> dict:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _handle_initialize(params: dict) -> dict:
    client_version = params.get("protocolVersion", DEFAULT_PROTOCOL_VERSION)
    negotiated = client_version if client_version in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
    return {
        "protocolVersion": negotiated,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def _resolve_active_org(org_ids: Optional[list[int]], user: User) -> Optional[int]:
    """The org context in which to attribute the call. ``X-Org-Context``
    narrows accessible to a single id; superadmins with no header get None
    and can't issue write tools."""
    if org_ids is not None and len(org_ids) == 1:
        return org_ids[0]
    return user.org_id


def _handle_tools_call(
    params: dict,
    db: Session,
    org_ids: Optional[list[int]],
    user: User,
) -> dict:
    name = params.get("name")
    args = params.get("arguments") or {}
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return {
            "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
            "isError": True,
        }

    spec = action_registry.get_action(name)
    is_write = spec is not None and spec.risk_tier != RiskTier.READ

    if is_write:
        org_id = _resolve_active_org(org_ids, user)
        if org_id is None:
            return {
                "content": [{"type": "text", "text": "Write tools require an X-Org-Context header."}],
                "isError": True,
            }

        granted = _has_active_org_grant(db, org_id, name)
        if not granted and requires_approval(name, "standard"):
            try:
                approval = _create_mcp_approval(
                    db, org_id=org_id, user=user, action_name=name, args=args,
                )
            except Exception:
                logger.exception("failed to record MCP approval row for %s", name)
                return {
                    "content": [{"type": "text", "text": "Failed to enqueue approval"}],
                    "isError": True,
                }
            payload = {"status": "pending_approval", "approval_id": approval.id, "tool": name}
            return {
                "content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload,
                "isError": False,
            }

    try:
        kwargs = {"user": user, "org_id": _resolve_active_org(org_ids, user)} if is_write else {}
        result = handler(args, db, org_ids, **kwargs)
        return {
            "content": [{"type": "text", "text": json.dumps(result, default=str)}],
            "structuredContent": result,
            "isError": False,
        }
    except ToolError as e:
        return {"content": [{"type": "text", "text": str(e)}], "isError": True}
    except Exception as e:
        logger.exception("MCP tool %s failed", name)
        return {
            "content": [{"type": "text", "text": f"Tool execution failed: {e}"}],
            "isError": True,
        }


def _dispatch(message: dict, db: Session, org_ids: Optional[list[int]], user: User) -> Optional[dict]:
    """Handle one JSON-RPC message. Returns the response dict, or None for notifications."""
    method = message.get("method")
    params = message.get("params") or {}
    req_id = message.get("id")
    is_notification = req_id is None

    try:
        if method == "initialize":
            return _jsonrpc_result(req_id, _handle_initialize(params))
        if method in ("notifications/initialized", "notifications/cancelled", "notifications/roots/list_changed"):
            return None
        if method == "ping":
            return _jsonrpc_result(req_id, {})
        if method == "tools/list":
            return _jsonrpc_result(req_id, {"tools": TOOLS})
        if method == "tools/call":
            return _jsonrpc_result(req_id, _handle_tools_call(params, db, org_ids, user))
        if is_notification:
            return None
        return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")
    except Exception as e:
        logger.exception("MCP dispatch failed for method %s", method)
        if is_notification:
            return None
        return _jsonrpc_error(req_id, -32603, "Internal error", str(e))


# ── HTTP endpoint ─────────────────────────────────────────


@router.post("/api/mcp")
async def mcp_endpoint(
    request: Request,
    user: User = Depends(require_auth),
    org_ids: Optional[list[int]] = Depends(get_accessible_org_ids),
    db: Session = Depends(get_db),
):
    """Streamable HTTP transport for MCP. Accepts a single JSON-RPC request or
    a batch. Always responds with application/json (no SSE streaming for the
    current tool set)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            _jsonrpc_error(None, -32700, "Parse error"), status_code=400
        )

    if isinstance(body, list):
        responses = [r for r in (_dispatch(m, db, org_ids, user) for m in body) if r is not None]
        if not responses:
            return JSONResponse(content=None, status_code=202)
        return JSONResponse(responses)

    if not isinstance(body, dict):
        return JSONResponse(_jsonrpc_error(None, -32600, "Invalid Request"), status_code=400)

    response = _dispatch(body, db, org_ids, user)
    if response is None:
        return JSONResponse(content=None, status_code=202)
    return JSONResponse(response)


@router.get("/api/mcp")
async def mcp_endpoint_get(user: User = Depends(require_auth)):
    """GET on the MCP endpoint is reserved for SSE streaming in the spec; we
    don't currently push server-initiated messages, so just describe the server."""
    return {
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "protocolVersions": sorted(SUPPORTED_PROTOCOL_VERSIONS),
        "transport": "streamable-http",
        "tools": [t["name"] for t in TOOLS],
    }
