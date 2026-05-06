"""MCP (Model Context Protocol) server.

Exposes Hakuna read APIs as MCP tools so customers can connect their own
agents (Claude Desktop, Cursor, in-house agents) to query findings, assets,
and campaigns.

Transport: Streamable HTTP — single POST /api/mcp endpoint speaking
JSON-RPC 2.0. Auth reuses the existing JWT bearer + X-Org-Context model.

Client config example:
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
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from core.auth import get_accessible_org_ids, require_auth
from core.database import get_db
from models.models import Asset, Campaign, Finding, Scan, User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["mcp"])

SERVER_NAME = "hakuna-mcp"
SERVER_VERSION = "1.0.0"
SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}
DEFAULT_PROTOCOL_VERSION = "2025-06-18"


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
]

SEVERITY_LABEL_TO_INT = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Tool implementations ──────────────────────────────────

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


def _tool_list_findings(args: dict, db: Session, org_ids: Optional[list[int]]) -> dict:
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


def _tool_get_finding(args: dict, db: Session, org_ids: Optional[list[int]]) -> dict:
    fid = int(args["finding_id"])
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == fid)
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))
    f = q.first()
    if not f:
        raise ToolError(f"Finding {fid} not found or not accessible")
    return _serialize_finding(f, summary=False)


def _tool_list_assets(args: dict, db: Session, org_ids: Optional[list[int]]) -> dict:
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


def _tool_get_asset(args: dict, db: Session, org_ids: Optional[list[int]]) -> dict:
    aid = int(args["asset_id"])
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == aid)
    if org_ids is not None:
        q = q.filter(Scan.org_id.in_(org_ids))
    a = q.first()
    if not a:
        raise ToolError(f"Asset {aid} not found or not accessible")
    return _serialize_asset(a, summary=False)


def _tool_list_campaigns(args: dict, db: Session, org_ids: Optional[list[int]]) -> dict:
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


TOOL_HANDLERS = {
    "list_findings": _tool_list_findings,
    "get_finding": _tool_get_finding,
    "list_assets": _tool_list_assets,
    "get_asset": _tool_get_asset,
    "list_campaigns": _tool_list_campaigns,
}


class ToolError(Exception):
    """Raised by a tool to surface a clean error in the tool result."""


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


def _handle_tools_call(params: dict, db: Session, org_ids: Optional[list[int]]) -> dict:
    name = params.get("name")
    args = params.get("arguments") or {}
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return {
            "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
            "isError": True,
        }
    try:
        result = handler(args, db, org_ids)
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


def _dispatch(message: dict, db: Session, org_ids: Optional[list[int]]) -> Optional[dict]:
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
            return _jsonrpc_result(req_id, _handle_tools_call(params, db, org_ids))
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
    current read-only tool set)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            _jsonrpc_error(None, -32700, "Parse error"), status_code=400
        )

    if isinstance(body, list):
        responses = [r for r in (_dispatch(m, db, org_ids) for m in body) if r is not None]
        if not responses:
            return JSONResponse(content=None, status_code=202)
        return JSONResponse(responses)

    if not isinstance(body, dict):
        return JSONResponse(_jsonrpc_error(None, -32600, "Invalid Request"), status_code=400)

    response = _dispatch(body, db, org_ids)
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
