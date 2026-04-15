"""
Mini Agent Tool Registry — defines tools available to user-built agents.

Each tool is a function that receives (db, params) and returns a JSON-serializable result.
Tools are registered with a decorator and exposed via TOOL_REGISTRY.
"""
import json
import logging
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import func, case, distinct, or_
from models.models import (
    Asset, Finding, Scan, User, Organization,
    InventoryUser, InventoryGroup, InventoryService, InventoryNetConn,
    InventoryPatch, InventoryLoggedOn, InventoryScheduledTask,
    InventorySoftware, InventorySecurityControl, InventoryCertificate,
    InventoryShare, InventoryComputer, InventoryDatabaseInstance,
    InventoryCredential, InventoryDomainTrust,
    AssetRelationship, FirewallPolicy,
    Tag, TagAssignment, SLAConfig, FindingException, FindingTicket,
    ScanComparison, Campaign, CampaignFinding,
    IntegrationConfig, AutoTagRule, OwnershipRule,
    Integration, IntegrationRun,
    Workflow, WorkflowNode, WorkflowEdge, WorkflowExecution, WorkflowExecutionLog,
    Agent, AgentRun, AgentSchedule,
    CustomRole, ExternalTagSource,
)
from services.ownership_inference import resolve_finding_owner
from models.threat_intel_models import (
    ThreatGroup, ThreatGroupTTP, TTP, ThreatCVE, ThreatCampaign,
)

logger = logging.getLogger(__name__)

TOOL_REGISTRY = {}


def agent_tool(name: str, description: str, parameters: dict):
    """Decorator to register a tool for mini agents."""
    def decorator(fn):
        TOOL_REGISTRY[name] = {
            "fn": fn,
            "name": name,
            "description": description,
            "parameters": parameters,
        }
        return fn
    return decorator


def get_tool_catalog():
    """Return list of tool definitions (without fn) for the frontend."""
    return [
        {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}
        for t in TOOL_REGISTRY.values()
    ]


def get_claude_tool_schemas(tool_names: list):
    """Return Anthropic tool-use schemas for selected tools."""
    schemas = []
    for name in tool_names:
        t = TOOL_REGISTRY.get(name)
        if t:
            schemas.append({
                "name": t["name"],
                "description": t["description"],
                "input_schema": {
                    "type": "object",
                    "properties": t["parameters"],
                },
            })
    return schemas


def get_openai_tool_schemas(tool_names: list):
    """Return OpenAI-compatible tool schemas (works for OpenAI and Groq)."""
    schemas = []
    for name in tool_names:
        t = TOOL_REGISTRY.get(name)
        if t:
            schemas.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": {
                        "type": "object",
                        "properties": t["parameters"],
                    },
                },
            })
    return schemas


# ── Tools ────────────────────────────────────────────────────────────

@agent_tool(
    "query_findings",
    "Search and filter findings with the same options available in the Findings Explorer UI. "
    "Returns up to 50 results sorted by priority score. "
    "WHEN TO CALL: When you need to find specific findings matching criteria. Use this instead of requesting bulk scan dumps.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "asset_id": {"type": "integer", "description": "Filter by asset ID"},
        "severity_min": {"type": "integer", "description": "Minimum severity (0=Info..4=Critical)"},
        "severity": {"type": "integer", "description": "Exact severity (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)"},
        "plugin_family": {"type": "string", "description": "Filter by plugin family substring"},
        "cve": {"type": "string", "description": "Search for a specific CVE ID"},
        "keyword": {"type": "string", "description": "Search plugin name, synopsis, or description"},
        "status": {"type": "string", "description": "Filter by status: 'open' (default), 'resolved', 'all'"},
        "workflow_status": {"type": "string", "description": "Filter by workflow status: 'open', 'accepted_risk', 'false_positive', 'compensating_control', or 'excepted' (combines risk/fp/control)"},
        "exploit": {"type": "boolean", "description": "Filter findings with known exploits"},
        "is_kev": {"type": "boolean", "description": "Filter CISA Known Exploited Vulnerabilities"},
        "ransomware_linked": {"type": "boolean", "description": "Filter ransomware-linked findings"},
        "trending_in_news": {"type": "boolean", "description": "Filter findings trending in news"},
        "has_ttps": {"type": "boolean", "description": "Filter findings with MITRE ATT&CK TTP mappings"},
        "tactic": {"type": "string", "description": "Filter by MITRE ATT&CK tactic name"},
        "technique_id": {"type": "string", "description": "Filter by MITRE ATT&CK technique ID (e.g. T1059)"},
        "effort_level": {"type": "string", "description": "Filter by remediation effort: 'quick_win', 'medium', 'complex'"},
        "sla_status": {"type": "string", "description": "Filter by SLA status: 'on_track', 'at_risk', 'breached', 'resolved', 'n/a'"},
        "port": {"type": "string", "description": "Filter by port number"},
        "source": {"type": "string", "description": "Filter by scanner source (e.g. 'nessus', 'qualys')"},
        "has_exception": {"type": "boolean", "description": "Filter findings that have an active exception/waiver"},
        "has_ticket": {"type": "boolean", "description": "Filter findings with linked tickets"},
        "ticket_status": {"type": "string", "description": "Filter by ticket status: 'open', 'in_progress', 'resolved'"},
        "control_status": {"type": "string", "description": "Filter by control mitigation: 'mitigated', 'partially_mitigated', 'not_mitigated'"},
        "product": {"type": "string", "description": "Filter by SBOM product name"},
        "cpe": {"type": "string", "description": "Filter by CPE string"},
        "min_priority": {"type": "number", "description": "Minimum priority score (0-10)"},
        "min_epss": {"type": "number", "description": "Minimum EPSS score (0-1)"},
        "auto_resolved": {"type": "boolean", "description": "Filter auto-resolved findings (fixed in a later scan)"},
        "not_in_campaign": {"type": "boolean", "description": "If true, only return findings NOT assigned to any campaign"},
        "tags": {"type": "string", "description": "Comma-separated tag filters (e.g. 'env:production,team:devops')"},
        "tag_logic": {"type": "string", "description": "Tag filter logic: 'AND' (default) or 'OR'"},
        "sort_by": {"type": "string", "description": "Sort field (default: 'priority_score'). Options: severity, plugin_name, cvss3_score, effort_level, sla_status, first_seen, last_seen"},
        "order": {"type": "string", "description": "Sort order: 'desc' (default) or 'asc'"},
        "limit": {"type": "integer", "description": "Max results (default 50, max 200)"},
    },
)
def query_findings(db: Session, params: dict):
    q = db.query(Finding)
    if params.get("_org_id"):
        q = q.join(Scan, Finding.scan_id == Scan.id).filter(Scan.org_id == params["_org_id"])
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    if params.get("asset_id"):
        q = q.filter(Finding.asset_id == params["asset_id"])

    # Severity filters
    if params.get("severity") is not None:
        q = q.filter(Finding.severity == params["severity"])
    elif params.get("severity_min") is not None:
        q = q.filter(Finding.severity >= params["severity_min"])

    # Status / workflow status
    wf_status = params.get("workflow_status")
    if wf_status:
        if wf_status == "excepted":
            q = q.filter(Finding.workflow_status.in_(["accepted_risk", "false_positive", "compensating_control"]))
        else:
            q = q.filter(Finding.workflow_status == wf_status)
    else:
        status = params.get("status", "open")
        if status == "open":
            q = q.filter(
                (Finding.workflow_status == None)
                | (~Finding.workflow_status.in_(["resolved", "accepted_risk", "false_positive"]))
            )
        elif status == "resolved":
            q = q.filter(Finding.workflow_status == "resolved")

    # Text filters
    if params.get("plugin_family"):
        q = q.filter(Finding.plugin_family.ilike(f"%{params['plugin_family']}%"))
    if params.get("cve"):
        q = q.filter(Finding.cves.contains(params["cve"]))
    if params.get("keyword"):
        kw = f"%{params['keyword']}%"
        q = q.filter(
            (Finding.plugin_name.ilike(kw))
            | (Finding.synopsis.ilike(kw))
            | (Finding.description.ilike(kw))
        )
    if params.get("port"):
        q = q.filter(Finding.port == str(params["port"]))

    # Exploit & threat intel filters
    if params.get("exploit") is not None:
        q = q.filter(Finding.exploit_available == params["exploit"])
    if params.get("is_kev") is not None:
        q = q.filter(Finding.is_kev == params["is_kev"])
    if params.get("ransomware_linked") is not None:
        q = q.filter(Finding.ransomware_linked == params["ransomware_linked"])
    if params.get("trending_in_news") is not None:
        q = q.filter(Finding.trending_in_news == params["trending_in_news"])

    # MITRE ATT&CK filters
    if params.get("has_ttps") is not None:
        if params["has_ttps"]:
            q = q.filter(Finding.matched_ttps != None, Finding.matched_ttps != "[]")
        else:
            q = q.filter((Finding.matched_ttps == None) | (Finding.matched_ttps == "[]"))
    if params.get("tactic"):
        q = q.filter(Finding.matched_ttps.contains(params["tactic"]))
    if params.get("technique_id"):
        q = q.filter(Finding.matched_ttps.contains(params["technique_id"]))

    # Prioritization & effort filters
    if params.get("effort_level"):
        q = q.filter(Finding.effort_level == params["effort_level"])
    if params.get("sla_status"):
        q = q.filter(Finding.sla_status == params["sla_status"])
    if params.get("min_priority") is not None:
        q = q.filter(Finding.priority_score >= params["min_priority"])
    if params.get("min_epss") is not None:
        q = q.filter(Finding.epss_score >= params["min_epss"])

    # Source filter
    if params.get("source"):
        q = q.filter(Finding.source_type == params["source"])

    # Control status
    if params.get("control_status"):
        q = q.filter(Finding.control_mitigation_status == params["control_status"])

    # Auto-resolved
    if params.get("auto_resolved") is not None:
        q = q.filter(Finding.auto_resolved == params["auto_resolved"])

    # Exception filter
    if params.get("has_exception") is not None:
        exception_finding_ids = db.query(FindingException.finding_id).filter(
            FindingException.status == "approved"
        ).subquery()
        if params["has_exception"]:
            q = q.filter(Finding.id.in_(exception_finding_ids))
        else:
            q = q.filter(~Finding.id.in_(exception_finding_ids))

    # Ticket filter (tickets are in FindingTicket table)
    if params.get("has_ticket") is not None or params.get("ticket_status"):
        ticket_q = db.query(FindingTicket.finding_id)
        if params.get("ticket_status"):
            ticket_q = ticket_q.filter(FindingTicket.mapped_status == params["ticket_status"])
        ticket_sub = ticket_q.subquery()
        if params.get("has_ticket") is False:
            q = q.filter(~Finding.id.in_(ticket_sub))
        else:
            q = q.filter(Finding.id.in_(ticket_sub))

    # Campaign membership filter
    if params.get("not_in_campaign"):
        campaign_finding_ids = db.query(CampaignFinding.finding_id).subquery()
        q = q.filter(~Finding.id.in_(campaign_finding_ids))

    # SBOM filters
    if params.get("product"):
        q = q.filter(Finding.plugin_name.ilike(f"%{params['product']}%"))
    if params.get("cpe"):
        q = q.join(Asset, Finding.asset_id == Asset.id).filter(
            Asset.cpe.contains(params["cpe"])
        )

    # Tag filter
    if params.get("tags"):
        tag_values = [t.strip() for t in params["tags"].split(",") if t.strip()]
        tag_logic = params.get("tag_logic", "AND").upper()
        # Find asset IDs that have the requested tags
        tag_q = db.query(TagAssignment.asset_id)
        tag_ids = []
        for tv in tag_values:
            if ":" in tv:
                cat, val = tv.split(":", 1)
                matching = db.query(Tag.id).filter(Tag.category == cat, Tag.value == val).all()
            else:
                matching = db.query(Tag.id).filter(Tag.value == tv).all()
            tag_ids.extend([m[0] for m in matching])
        if tag_ids:
            if tag_logic == "AND":
                for tid in set(tag_ids):
                    sub = db.query(TagAssignment.asset_id).filter(TagAssignment.tag_id == tid).subquery()
                    q = q.filter(Finding.asset_id.in_(sub))
            else:
                sub = db.query(TagAssignment.asset_id).filter(TagAssignment.tag_id.in_(tag_ids)).subquery()
                q = q.filter(Finding.asset_id.in_(sub))

    # Sorting
    sort_field = params.get("sort_by", "priority_score")
    sort_order = params.get("order", "desc")
    sort_col = getattr(Finding, sort_field, Finding.priority_score)
    q = q.order_by(sort_col.desc() if sort_order == "desc" else sort_col.asc())

    limit = min(params.get("limit", 50), 200)
    rows = q.limit(limit).all()
    results = []
    for f in rows:
        asset = f.asset if f.asset_id else None
        owner = resolve_finding_owner(f, asset, db)
        results.append({
            "id": f.id, "plugin_id": f.plugin_id, "plugin_name": f.plugin_name,
            "severity": f.severity, "severity_label": f.severity_label,
            "cvss3": f.cvss3_score, "vpr": f.vpr_score,
            "priority_score": f.priority_score, "effort": f.effort_level,
            "asset_id": f.asset_id, "cves": f.cves,
            "port": f.port, "sla_status": f.sla_status,
            "exploit_available": f.exploit_available, "is_kev": f.is_kev,
            "workflow_status": f.workflow_status,
            "workflow_assigned_to": f.workflow_assigned_to,
            "owner_name": owner.get("owner_name"),
            "owner_role": owner.get("owner_role"),
            "owner_team": owner.get("owner_team"),
            "ownership_source": owner.get("source"),
            "solution": (f.solution or "")[:500],
        })
    return results


@agent_tool(
    "query_assets",
    "Search and filter assets with the same options available in the Asset Inventory UI. "
    "Returns up to 50 results sorted by risk score. "
    "WHEN TO CALL: When you need to find specific assets or get asset details for a filtered set.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "ip": {"type": "string", "description": "Filter by IP substring"},
        "hostname": {"type": "string", "description": "Filter by hostname substring"},
        "fqdn": {"type": "string", "description": "Filter by FQDN substring"},
        "os": {"type": "string", "description": "Filter by OS substring"},
        "keyword": {"type": "string", "description": "Search across hostname, IP, FQDN, and OS"},
        "min_criticality": {"type": "integer", "description": "Minimum criticality (1-10)"},
        "criticality": {"type": "integer", "description": "Exact criticality value (1-10)"},
        "environment": {"type": "string", "description": "Environment filter: 'internet', 'external', 'dmz', 'internal', 'cloud', 'development', 'production', 'staging', 'ot'"},
        "min_risk": {"type": "number", "description": "Minimum risk score (0-10)"},
        "max_risk": {"type": "number", "description": "Maximum risk score (0-10)"},
        "min_critical": {"type": "integer", "description": "Minimum number of critical findings"},
        "min_high": {"type": "integer", "description": "Minimum number of high findings"},
        "has_findings": {"type": "boolean", "description": "Filter assets that have any findings"},
        "server_role": {"type": "string", "description": "Filter by server role: 'web_server', 'dns_server', 'mail_server', 'database', 'ftp_server'"},
        "source": {"type": "string", "description": "Filter by scanner source system"},
        "min_sources": {"type": "integer", "description": "Minimum number of source systems that detected this asset"},
        "asset_status": {"type": "string", "description": "Lifecycle status: 'active' or 'stale'"},
        "is_internet_facing": {"type": "boolean", "description": "Filter internet-facing assets"},
        "device_type": {"type": "string", "description": "Filter by device type: 'server', 'workstation', 'router', 'switch', 'firewall', 'printer', etc."},
        "tags": {"type": "string", "description": "Comma-separated tag filters (e.g. 'env:production,team:devops')"},
        "tag_logic": {"type": "string", "description": "Tag filter logic: 'AND' (default) or 'OR'"},
        "last_seen_before": {"type": "string", "description": "Filter assets not scanned since this date (ISO format, e.g. '2026-03-01'). Useful for finding stale assets."},
        "last_seen_after": {"type": "string", "description": "Filter assets scanned after this date (ISO format, e.g. '2026-03-01')"},
        "sort_by": {"type": "string", "description": "Sort field (default: 'risk_score'). Options: hostname, ip, criticality, critical_count, os, environment_tag, first_seen, last_seen"},
        "order": {"type": "string", "description": "Sort order: 'desc' (default) or 'asc'"},
        "limit": {"type": "integer", "description": "Max results (default 50, max 200)"},
    },
)
def query_assets(db: Session, params: dict):
    q = db.query(Asset)
    if params.get("_org_id"):
        q = q.join(Scan, Asset.scan_id == Scan.id).filter(Scan.org_id == params["_org_id"])
    if params.get("scan_id"):
        q = q.filter(Asset.scan_id == params["scan_id"])

    # Text search (keyword searches across multiple fields)
    if params.get("keyword"):
        kw = f"%{params['keyword']}%"
        q = q.filter(
            (Asset.hostname.ilike(kw))
            | (Asset.ip.ilike(kw))
            | (Asset.fqdn.ilike(kw))
            | (Asset.os.ilike(kw))
        )
    if params.get("ip"):
        q = q.filter(Asset.ip.ilike(f"%{params['ip']}%"))
    if params.get("hostname"):
        q = q.filter(Asset.hostname.ilike(f"%{params['hostname']}%"))
    if params.get("fqdn"):
        q = q.filter(Asset.fqdn.ilike(f"%{params['fqdn']}%"))
    if params.get("os"):
        q = q.filter(Asset.os.ilike(f"%{params['os']}%"))

    # Criticality
    if params.get("criticality") is not None:
        q = q.filter(Asset.criticality == params["criticality"])
    elif params.get("min_criticality"):
        q = q.filter(Asset.criticality >= params["min_criticality"])

    # Environment
    if params.get("environment"):
        q = q.filter(Asset.environment_tag == params["environment"])

    # Risk score range
    if params.get("min_risk") is not None:
        q = q.filter(Asset.risk_score >= params["min_risk"])
    if params.get("max_risk") is not None:
        q = q.filter(Asset.risk_score <= params["max_risk"])

    # Finding count filters
    if params.get("min_critical") is not None:
        q = q.filter(Asset.critical_count >= params["min_critical"])
    if params.get("min_high") is not None:
        q = q.filter(Asset.high_count >= params["min_high"])
    if params.get("has_findings") is not None:
        if params["has_findings"]:
            q = q.filter(
                (Asset.critical_count > 0) | (Asset.high_count > 0)
                | (Asset.medium_count > 0) | (Asset.low_count > 0)
            )
        else:
            q = q.filter(
                Asset.critical_count == 0, Asset.high_count == 0,
                Asset.medium_count == 0, Asset.low_count == 0
            )

    # Server role / device type
    if params.get("server_role"):
        q = q.filter(Asset.business_context.ilike(f"%{params['server_role']}%"))
    if params.get("device_type"):
        q = q.filter(Asset.device_type == params["device_type"])

    # Source filter
    if params.get("source"):
        q = q.filter(Asset.source_systems.contains(params["source"]))
    if params.get("min_sources") is not None:
        # Filter assets seen by at least N sources
        q = q.filter(Asset.times_seen >= params["min_sources"])

    # Lifecycle
    if params.get("asset_status"):
        q = q.filter(Asset.asset_status == params["asset_status"])

    # Internet-facing
    if params.get("is_internet_facing") is not None:
        q = q.filter(Asset.is_internet_facing == params["is_internet_facing"])

    # Last seen date filters
    if params.get("last_seen_before"):
        try:
            cutoff = datetime.fromisoformat(params["last_seen_before"])
            q = q.filter(Asset.last_seen < cutoff)
        except (ValueError, TypeError):
            pass
    if params.get("last_seen_after"):
        try:
            cutoff = datetime.fromisoformat(params["last_seen_after"])
            q = q.filter(Asset.last_seen >= cutoff)
        except (ValueError, TypeError):
            pass

    # Tag filter
    if params.get("tags"):
        tag_values = [t.strip() for t in params["tags"].split(",") if t.strip()]
        tag_logic = params.get("tag_logic", "AND").upper()
        tag_ids = []
        for tv in tag_values:
            if ":" in tv:
                cat, val = tv.split(":", 1)
                matching = db.query(Tag.id).filter(Tag.category == cat, Tag.value == val).all()
            else:
                matching = db.query(Tag.id).filter(Tag.value == tv).all()
            tag_ids.extend([m[0] for m in matching])
        if tag_ids:
            if tag_logic == "AND":
                for tid in set(tag_ids):
                    sub = db.query(TagAssignment.asset_id).filter(TagAssignment.tag_id == tid).subquery()
                    q = q.filter(Asset.id.in_(sub))
            else:
                sub = db.query(TagAssignment.asset_id).filter(TagAssignment.tag_id.in_(tag_ids)).subquery()
                q = q.filter(Asset.id.in_(sub))

    # Sorting
    sort_field = params.get("sort_by", "risk_score")
    sort_order = params.get("order", "desc")
    sort_col = getattr(Asset, sort_field, Asset.risk_score)
    q = q.order_by(sort_col.desc() if sort_order == "desc" else sort_col.asc())

    limit = min(params.get("limit", 50), 200)
    rows = q.limit(limit).all()
    return [
        {
            "id": a.id, "ip": a.ip, "hostname": a.hostname, "fqdn": a.fqdn,
            "os": a.os, "criticality": a.criticality, "risk_score": a.risk_score,
            "environment": a.environment_tag, "device_type": a.device_type,
            "asset_status": a.asset_status,
            "is_internet_facing": a.is_internet_facing,
            "critical_count": a.critical_count, "high_count": a.high_count,
            "medium_count": a.medium_count, "low_count": a.low_count,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        }
        for a in rows
    ]


@agent_tool(
    "get_scan_summary",
    "Get a high-level summary of a scan: asset count, finding counts by severity, top plugin families. "
    "WHEN TO CALL: As the FIRST tool call in most workflows to understand the scan landscape before drilling down.",
    {
        "scan_id": {"type": "integer", "description": "Scan ID to summarize (required)"},
    },
)
def get_scan_summary(db: Session, params: dict):
    scan_id = params.get("scan_id")
    if not scan_id:
        return {"error": "scan_id is required"}
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": f"Scan {scan_id} not found"}
    asset_count = db.query(func.count(Asset.id)).filter(Asset.scan_id == scan_id).scalar()
    sev_counts = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
        .all()
    )
    sev_map = {s: c for s, c in sev_counts}
    top_families = (
        db.query(Finding.plugin_family, func.count(Finding.id).label("cnt"))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.plugin_family)
        .order_by(func.count(Finding.id).desc())
        .limit(10)
        .all()
    )
    return {
        "scan_id": scan_id, "scan_name": scan.scan_name, "scan_date": scan.scan_date,
        "assets": asset_count,
        "critical": sev_map.get(4, 0), "high": sev_map.get(3, 0),
        "medium": sev_map.get(2, 0), "low": sev_map.get(1, 0), "info": sev_map.get(0, 0),
        "top_families": [{"family": f, "count": c} for f, c in top_families],
    }


@agent_tool(
    "get_inventory_users",
    "List domain/local users from inventory. Useful for finding admins, kerberoastable accounts, etc.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "is_domain_admin": {"type": "boolean", "description": "Filter domain admins only"},
        "is_privileged": {"type": "boolean", "description": "Filter privileged users"},
        "search": {"type": "string", "description": "Search username or domain"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_inventory_users(db: Session, params: dict):
    q = db.query(InventoryUser)
    if params.get("scan_id"):
        q = q.filter(InventoryUser.scan_id == params["scan_id"])
    if params.get("is_domain_admin"):
        q = q.filter(InventoryUser.is_domain_admin == True)
    if params.get("is_privileged"):
        q = q.filter(InventoryUser.is_privileged == True)
    if params.get("search"):
        kw = f"%{params['search']}%"
        q = q.filter((InventoryUser.username.ilike(kw)) | (InventoryUser.domain.ilike(kw)))
    limit = min(params.get("limit", 50), 200)
    rows = q.limit(limit).all()
    return [
        {
            "id": u.id, "username": u.username, "domain": u.domain,
            "user_type": u.user_type, "is_local_admin": u.is_local_admin,
            "is_domain_admin": u.is_domain_admin, "is_privileged": u.is_privileged,
            "spns": u.spns, "member_of": u.member_of,
        }
        for u in rows
    ]


@agent_tool(
    "get_inventory_services",
    "List running services on assets. Useful for attack surface mapping.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "asset_id": {"type": "integer", "description": "Filter by asset ID"},
        "search": {"type": "string", "description": "Search service name"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_inventory_services(db: Session, params: dict):
    q = db.query(InventoryService)
    if params.get("scan_id"):
        q = q.filter(InventoryService.scan_id == params["scan_id"])
    if params.get("asset_id"):
        q = q.filter(InventoryService.asset_id == params["asset_id"])
    if params.get("search"):
        q = q.filter(InventoryService.service_name.ilike(f"%{params['search']}%"))
    limit = min(params.get("limit", 50), 200)
    rows = q.limit(limit).all()
    return [
        {"id": s.id, "service_name": s.service_name, "display_name": s.display_name, "is_running": s.is_running}
        for s in rows
    ]


@agent_tool(
    "get_network_connections",
    "List network connections from inventory. Useful for lateral movement analysis.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "asset_id": {"type": "integer", "description": "Filter by asset ID"},
        "state": {"type": "string", "description": "Filter by state (ESTABLISHED, LISTEN, etc.)"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_network_connections(db: Session, params: dict):
    q = db.query(InventoryNetConn)
    if params.get("scan_id"):
        q = q.filter(InventoryNetConn.scan_id == params["scan_id"])
    if params.get("asset_id"):
        q = q.filter(InventoryNetConn.asset_id == params["asset_id"])
    if params.get("state"):
        q = q.filter(InventoryNetConn.state.ilike(f"%{params['state']}%"))
    limit = min(params.get("limit", 50), 200)
    rows = q.limit(limit).all()
    return [
        {
            "id": n.id, "proto": n.proto, "state": n.state,
            "local_addr": n.local_addr, "local_port": n.local_port,
            "remote_addr": n.remote_addr, "remote_port": n.remote_port,
        }
        for n in rows
    ]


@agent_tool(
    "get_missing_patches",
    "List missing patches/KBs from inventory. Useful for patch gap analysis.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "asset_id": {"type": "integer", "description": "Filter by asset ID"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_missing_patches(db: Session, params: dict):
    q = db.query(InventoryPatch)
    if params.get("scan_id"):
        q = q.filter(InventoryPatch.scan_id == params["scan_id"])
    if params.get("asset_id"):
        q = q.filter(InventoryPatch.asset_id == params["asset_id"])
    limit = min(params.get("limit", 50), 200)
    rows = q.order_by(InventoryPatch.vuln_count.desc()).limit(limit).all()
    return [
        {"id": p.id, "kb_id": p.kb_id, "vuln_count": p.vuln_count, "description": p.description, "cves": p.cves}
        for p in rows
    ]


@agent_tool(
    "tag_assets",
    "Apply a tag to a list of assets by ID. Requires write permission (read_only guardrail must be off).",
    {
        "tag_id": {"type": "integer", "description": "Tag ID to apply"},
        "asset_ids": {"type": "array", "items": {"type": "integer"}, "description": "List of asset IDs"},
    },
)
def tag_assets(db: Session, params: dict):
    tag_id = params.get("tag_id")
    asset_ids = params.get("asset_ids", [])
    if not tag_id or not asset_ids:
        return {"error": "tag_id and asset_ids are required"}
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        return {"error": f"Tag {tag_id} not found"}
    capped_ids = asset_ids[:100]  # cap at 100
    valid_ids = set(
        r[0] for r in db.query(Asset.id).filter(Asset.id.in_(capped_ids)).all()
    )
    created = 0
    for aid in capped_ids:
        if aid not in valid_ids:
            continue
        exists = db.query(TagAssignment).filter(
            TagAssignment.tag_id == tag_id,
            TagAssignment.asset_id == aid,
        ).first()
        if not exists:
            db.add(TagAssignment(tag_id=tag_id, asset_id=aid, assigned_by="rule:agent"))
            created += 1
    db.commit()
    return {"tagged": created, "tag": f"{tag.category}:{tag.value}"}


@agent_tool(
    "list_tags",
    "List all available tags. Useful before tagging assets.",
    {},
)
def list_tags(db: Session, params: dict):
    tags = db.query(Tag).order_by(Tag.category, Tag.value).all()
    return [
        {"id": t.id, "category": t.category, "value": t.value, "color": t.color}
        for t in tags
    ]


@agent_tool(
    "get_tag_stats",
    "Get tag distribution statistics: how many assets and findings each tag covers, "
    "plus severity breakdown per tag. "
    "WHEN TO CALL: When the user asks about tag usage, distribution, or which tags have the most critical findings.",
    {
        "scan_id": {"type": "integer", "description": "Optional: filter to a specific scan"},
        "limit": {"type": "integer", "description": "Max tags to return (default 30)"},
    },
)
def get_tag_stats(db: Session, params: dict):
    org_id = params.get("_org_id")
    org_ids = params.get("_org_ids", [org_id] if org_id else [])

    # Get all tags with their assignment counts
    tags = db.query(Tag).all()
    results = []
    for tag in tags:
        # Count assets with this tag
        asset_q = db.query(func.count(distinct(TagAssignment.asset_id))).filter(
            TagAssignment.tag_id == tag.id
        )
        asset_count = asset_q.scalar() or 0
        if asset_count == 0:
            continue

        # Count findings on tagged assets, with severity breakdown
        tagged_assets = db.query(TagAssignment.asset_id).filter(TagAssignment.tag_id == tag.id).subquery()
        finding_q = db.query(
            func.count(Finding.id),
            func.sum(case((Finding.severity == 4, 1), else_=0)),
            func.sum(case((Finding.severity == 3, 1), else_=0)),
            func.sum(case((Finding.severity == 2, 1), else_=0)),
        ).filter(Finding.asset_id.in_(tagged_assets))

        if params.get("scan_id"):
            finding_q = finding_q.filter(Finding.scan_id == params["scan_id"])

        row = finding_q.one()
        results.append({
            "tag_id": tag.id,
            "category": tag.category,
            "value": tag.value,
            "color": tag.color,
            "asset_count": asset_count,
            "finding_count": row[0] or 0,
            "critical_count": row[1] or 0,
            "high_count": row[2] or 0,
            "medium_count": row[3] or 0,
        })

    results.sort(key=lambda x: x["critical_count"], reverse=True)
    limit = min(params.get("limit", 30), 100)
    return results[:limit]


@agent_tool(
    "list_scans",
    "List all available scans with basic info.",
    {},
)
def list_scans(db: Session, params: dict):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [
        {"id": s.id, "filename": s.filename, "scan_name": s.scan_name, "scan_date": s.scan_date}
        for s in scans
    ]


# ── VM Analyst Day-to-Day Tools ──────────────────────────────────────

@agent_tool(
    "get_top_risky_assets",
    "Rank assets by risk score, showing the riskiest hosts with their severity breakdown. Essential for daily triage.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "limit": {"type": "integer", "description": "How many assets to return (default 20)"},
        "min_critical": {"type": "integer", "description": "Only assets with at least N critical findings"},
    },
)
def get_top_risky_assets(db: Session, params: dict):
    q = db.query(Asset)
    if params.get("scan_id"):
        q = q.filter(Asset.scan_id == params["scan_id"])
    if params.get("min_critical"):
        q = q.filter(Asset.critical_count >= params["min_critical"])
    limit = min(params.get("limit", 20), 100)
    rows = q.order_by(Asset.risk_score.desc()).limit(limit).all()
    return [
        {
            "id": a.id, "ip": a.ip, "hostname": a.hostname, "os": a.os,
            "risk_score": a.risk_score, "criticality": a.criticality,
            "critical": a.critical_count, "high": a.high_count,
            "medium": a.medium_count, "low": a.low_count,
            "is_internet_facing": a.is_internet_facing,
            "inferred_primary_user": a.inferred_primary_user,
            "environment": a.environment_tag,
        }
        for a in rows
    ]


@agent_tool(
    "get_sla_status",
    "Check SLA compliance: which findings are on track, at risk, or breached. Critical for daily stand-ups.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "status_filter": {"type": "string", "description": "Filter: breached, at_risk, on_track, or all (default all)"},
        "severity_min": {"type": "integer", "description": "Minimum severity to check (default 1=Low)"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_sla_status(db: Session, params: dict):
    q = db.query(Finding).filter(Finding.sla_status.isnot(None), Finding.sla_status != "n/a")
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    if params.get("status_filter") and params["status_filter"] != "all":
        q = q.filter(Finding.sla_status == params["status_filter"])
    sev_min = params.get("severity_min", 1)
    q = q.filter(Finding.severity >= sev_min)
    limit = min(params.get("limit", 50), 200)
    rows = q.order_by(Finding.sla_due_date).limit(limit).all()

    # Also compute summary counts
    summary_q = db.query(Finding.sla_status, func.count(Finding.id)).filter(
        Finding.sla_status.isnot(None), Finding.sla_status != "n/a",
        Finding.severity >= sev_min,
    )
    if params.get("scan_id"):
        summary_q = summary_q.filter(Finding.scan_id == params["scan_id"])
    summary = {s: c for s, c in summary_q.group_by(Finding.sla_status).all()}

    return {
        "summary": summary,
        "findings": [
            {
                "id": f.id, "plugin_name": f.plugin_name, "severity": f.severity,
                "sla_status": f.sla_status,
                "sla_due_date": f.sla_due_date.isoformat() if f.sla_due_date else None,
                "asset_id": f.asset_id, "priority_score": f.priority_score,
                "workflow_status": f.workflow_status,
            }
            for f in rows
        ],
    }


@agent_tool(
    "get_remediation_grouping",
    "Group findings by solution text to identify 'bang-for-buck' patches — one fix that resolves many findings.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "severity_min": {"type": "integer", "description": "Minimum severity (default 3=High)"},
        "limit": {"type": "integer", "description": "Top N solution groups (default 15)"},
    },
)
def get_remediation_grouping(db: Session, params: dict):
    sev_min = params.get("severity_min", 3)
    q = (
        db.query(
            Finding.solution,
            func.count(Finding.id).label("finding_count"),
            func.count(distinct(Finding.asset_id)).label("asset_count"),
            func.max(Finding.severity).label("max_severity"),
            func.avg(Finding.priority_score).label("avg_priority"),
        )
        .filter(Finding.severity >= sev_min, Finding.solution.isnot(None), Finding.solution != "")
    )
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    rows = (
        q.group_by(Finding.solution)
        .order_by(func.count(Finding.id).desc())
        .limit(min(params.get("limit", 15), 50))
        .all()
    )
    return [
        {
            "solution": (r.solution or "")[:300],
            "finding_count": r.finding_count,
            "asset_count": r.asset_count,
            "max_severity": r.max_severity,
            "avg_priority": round(r.avg_priority, 1) if r.avg_priority else 0,
        }
        for r in rows
    ]


@agent_tool(
    "get_exploit_findings",
    "List findings with known exploits, KEV entries, or ransomware links. The highest-urgency items.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "exploit_type": {"type": "string", "description": "Filter: exploit_available, kev, ransomware, zero_day, or all (default all)"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_exploit_findings(db: Session, params: dict):
    q = db.query(Finding)
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    etype = params.get("exploit_type", "all")
    if etype == "exploit_available":
        q = q.filter(Finding.exploit_available == True)
    elif etype == "kev":
        q = q.filter(Finding.is_kev == True)
    elif etype == "ransomware":
        q = q.filter(Finding.ransomware_linked == True)
    elif etype == "zero_day":
        q = q.filter(Finding.zero_day == True)
    else:
        q = q.filter(
            (Finding.exploit_available == True)
            | (Finding.is_kev == True)
            | (Finding.ransomware_linked == True)
            | (Finding.zero_day == True)
        )
    limit = min(params.get("limit", 50), 200)
    rows = q.order_by(Finding.priority_score.desc()).limit(limit).all()
    return [
        {
            "id": f.id, "plugin_id": f.plugin_id, "plugin_name": f.plugin_name,
            "severity": f.severity, "priority_score": f.priority_score,
            "exploit_available": f.exploit_available, "exploit_maturity": f.exploit_maturity,
            "is_kev": f.is_kev, "ransomware_linked": f.ransomware_linked,
            "zero_day": f.zero_day, "epss_score": f.epss_score,
            "cves": f.cves, "asset_id": f.asset_id,
            "solution": (f.solution or "")[:300],
        }
        for f in rows
    ]


@agent_tool(
    "get_os_breakdown",
    "Break down assets by operating system. Useful for patch Tuesday planning and EOL tracking.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
    },
)
def get_os_breakdown(db: Session, params: dict):
    q = db.query(
        Asset.os,
        func.count(Asset.id).label("count"),
        func.avg(Asset.risk_score).label("avg_risk"),
        func.sum(Asset.critical_count).label("total_critical"),
        func.sum(Asset.high_count).label("total_high"),
    )
    if params.get("scan_id"):
        q = q.filter(Asset.scan_id == params["scan_id"])
    rows = q.filter(Asset.os.isnot(None)).group_by(Asset.os).order_by(func.count(Asset.id).desc()).all()
    return [
        {
            "os": r.os, "asset_count": r.count,
            "avg_risk": round(r.avg_risk, 1) if r.avg_risk else 0,
            "total_critical": r.total_critical or 0,
            "total_high": r.total_high or 0,
        }
        for r in rows
    ]


@agent_tool(
    "get_finding_detail",
    "Get full details for a specific finding by ID — description, plugin output, solution, CVEs, scores. "
    "WHEN TO CALL: When you need the full context of a specific finding (e.g., to write a ticket description or assess a remediation).",
    {
        "finding_id": {"type": "integer", "description": "Finding ID (required)"},
    },
)
def get_finding_detail(db: Session, params: dict):
    fid = params.get("finding_id")
    if not fid:
        return {"error": "finding_id is required"}
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        return {"error": f"Finding {fid} not found"}
    asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
    return {
        "id": f.id, "plugin_id": f.plugin_id, "plugin_name": f.plugin_name,
        "plugin_family": f.plugin_family, "severity": f.severity,
        "cvss2": f.cvss2_score, "cvss3": f.cvss3_score, "vpr": f.vpr_score,
        "epss": f.epss_score, "is_kev": f.is_kev,
        "exploit_available": f.exploit_available, "exploit_maturity": f.exploit_maturity,
        "cves": f.cves, "synopsis": f.synopsis,
        "description": (f.description or "")[:2000],
        "solution": f.solution,
        "plugin_output": (f.plugin_output or "")[:2000],
        "port": f.port, "protocol": f.protocol,
        "priority_score": f.priority_score, "effort_level": f.effort_level,
        "owner_suggestion": f.owner_suggestion,
        "sla_status": f.sla_status,
        "sla_due_date": f.sla_due_date.isoformat() if f.sla_due_date else None,
        "workflow_status": f.workflow_status,
        "workflow_assigned_to": f.workflow_assigned_to,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "times_seen": f.times_seen,
        "is_regression": f.is_regression,
        "asset_ip": asset.ip if asset else None,
        "asset_hostname": asset.hostname if asset else None,
        "asset_os": asset.os if asset else None,
    }


@agent_tool(
    "get_asset_profile",
    "Get a full profile of an asset: vulns, installed software, services, logged-on users, security controls. "
    "WHEN TO CALL: When you need to assess an asset's full attack surface or understand what's running on a host.",
    {
        "asset_id": {"type": "integer", "description": "Asset ID (required)"},
    },
)
def get_asset_profile(db: Session, params: dict):
    aid = params.get("asset_id")
    if not aid:
        return {"error": "asset_id is required"}
    a = db.query(Asset).filter(Asset.id == aid).first()
    if not a:
        return {"error": f"Asset {aid} not found"}

    sev_counts = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.asset_id == aid)
        .group_by(Finding.severity).all()
    )
    top_findings = (
        db.query(Finding)
        .filter(Finding.asset_id == aid, Finding.severity >= 3)
        .order_by(Finding.priority_score.desc()).limit(10).all()
    )
    services = db.query(InventoryService).filter(InventoryService.asset_id == aid).limit(30).all()
    logged_on = db.query(InventoryLoggedOn).filter(InventoryLoggedOn.asset_id == aid).all()
    controls = db.query(InventorySecurityControl).filter(InventorySecurityControl.asset_id == aid).all()
    software_count = db.query(func.count(InventorySoftware.id)).filter(InventorySoftware.asset_id == aid).scalar()

    return {
        "asset": {
            "id": a.id, "ip": a.ip, "hostname": a.hostname, "fqdn": a.fqdn,
            "os": a.os, "criticality": a.criticality, "risk_score": a.risk_score,
            "environment": a.environment_tag, "is_internet_facing": a.is_internet_facing,
            "inferred_primary_user": a.inferred_primary_user,
            "inferred_team": a.inferred_team,
        },
        "severity_counts": {s: c for s, c in sev_counts},
        "top_findings": [
            {"id": f.id, "plugin_name": f.plugin_name, "severity": f.severity,
             "priority_score": f.priority_score, "cves": f.cves, "solution": (f.solution or "")[:200]}
            for f in top_findings
        ],
        "services": [{"name": s.service_name, "running": s.is_running} for s in services],
        "logged_on_users": [{"username": u.username, "domain": u.domain} for u in logged_on],
        "security_controls": [
            {"type": c.control_type, "product": c.product_name, "enabled": c.is_enabled, "up_to_date": c.is_up_to_date}
            for c in controls
        ],
        "installed_software_count": software_count,
    }


@agent_tool(
    "get_regression_findings",
    "Find findings that were previously fixed but reappeared (regressions). Key for accountability.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "severity_min": {"type": "integer", "description": "Minimum severity (default 1)"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_regression_findings(db: Session, params: dict):
    q = db.query(Finding).filter(Finding.is_regression == True)
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    sev_min = params.get("severity_min", 1)
    q = q.filter(Finding.severity >= sev_min)
    limit = min(params.get("limit", 50), 200)
    rows = q.order_by(Finding.priority_score.desc()).limit(limit).all()
    return [
        {
            "id": f.id, "plugin_name": f.plugin_name, "severity": f.severity,
            "priority_score": f.priority_score, "times_seen": f.times_seen,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "asset_id": f.asset_id, "cves": f.cves,
        }
        for f in rows
    ]


@agent_tool(
    "get_quick_wins",
    "List low-effort, high-impact findings (quick wins). Perfect for sprint planning.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "severity_min": {"type": "integer", "description": "Minimum severity (default 2=Medium)"},
        "limit": {"type": "integer", "description": "Max results (default 30)"},
    },
)
def get_quick_wins(db: Session, params: dict):
    q = db.query(Finding).filter(Finding.effort_level == "quick_win")
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    sev_min = params.get("severity_min", 2)
    q = q.filter(Finding.severity >= sev_min)
    limit = min(params.get("limit", 30), 100)
    rows = q.order_by(Finding.priority_score.desc()).limit(limit).all()
    return [
        {
            "id": f.id, "plugin_name": f.plugin_name, "severity": f.severity,
            "priority_score": f.priority_score, "effort": f.effort_level,
            "solution": (f.solution or "")[:300],
            "asset_id": f.asset_id, "cves": f.cves,
            "owner_suggestion": f.owner_suggestion,
        }
        for f in rows
    ]


@agent_tool(
    "get_plugin_family_stats",
    "Break down findings by plugin family with severity distribution. Useful for team routing (Windows, Network, Web Apps, etc.).",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
    },
)
def get_plugin_family_stats(db: Session, params: dict):
    q = db.query(
        Finding.plugin_family,
        func.count(Finding.id).label("total"),
        func.sum(case((Finding.severity == 4, 1), else_=0)).label("critical"),
        func.sum(case((Finding.severity == 3, 1), else_=0)).label("high"),
        func.sum(case((Finding.severity == 2, 1), else_=0)).label("medium"),
        func.count(distinct(Finding.asset_id)).label("affected_assets"),
    )
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    rows = (
        q.filter(Finding.plugin_family.isnot(None))
        .group_by(Finding.plugin_family)
        .order_by(func.count(Finding.id).desc())
        .limit(30).all()
    )
    return [
        {
            "family": r.plugin_family, "total": r.total,
            "critical": r.critical, "high": r.high, "medium": r.medium,
            "affected_assets": r.affected_assets,
        }
        for r in rows
    ]


@agent_tool(
    "get_certificates",
    "List SSL/TLS certificates — find expiring, self-signed, or weak certs.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "asset_id": {"type": "integer", "description": "Filter by asset ID"},
        "expiring_within_days": {"type": "integer", "description": "Only certs expiring within N days"},
        "self_signed_only": {"type": "boolean", "description": "Only self-signed certificates"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_certificates(db: Session, params: dict):
    q = db.query(InventoryCertificate)
    if params.get("scan_id"):
        q = q.filter(InventoryCertificate.scan_id == params["scan_id"])
    if params.get("asset_id"):
        q = q.filter(InventoryCertificate.asset_id == params["asset_id"])
    if params.get("self_signed_only"):
        q = q.filter(InventoryCertificate.is_self_signed == True)
    limit = min(params.get("limit", 50), 200)
    rows = q.order_by(InventoryCertificate.not_after).limit(limit).all()

    from datetime import datetime, timedelta
    threshold = None
    if params.get("expiring_within_days"):
        threshold = datetime.utcnow() + timedelta(days=params["expiring_within_days"])

    results = []
    for c in rows:
        if threshold and c.not_after:
            try:
                exp = datetime.fromisoformat(str(c.not_after).replace("Z", "+00:00").replace("+00:00", ""))
                if exp > threshold:
                    continue
            except (ValueError, TypeError):
                pass
        results.append({
            "id": c.id, "subject_cn": c.subject_cn, "issuer_cn": c.issuer_cn,
            "not_before": str(c.not_before) if c.not_before else None,
            "not_after": str(c.not_after) if c.not_after else None,
            "is_self_signed": c.is_self_signed, "key_size": c.key_size,
            "sig_algo": c.sig_algo, "asset_id": c.asset_id,
        })
    return results


@agent_tool(
    "get_installed_software",
    "Search installed software across assets. Useful for finding vulnerable software versions or shadow IT.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "asset_id": {"type": "integer", "description": "Filter by specific asset"},
        "search": {"type": "string", "description": "Search software name (e.g. 'Java', 'Chrome', 'Apache')"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_installed_software(db: Session, params: dict):
    q = db.query(InventorySoftware)
    if params.get("scan_id"):
        q = q.filter(InventorySoftware.scan_id == params["scan_id"])
    if params.get("asset_id"):
        q = q.filter(InventorySoftware.asset_id == params["asset_id"])
    if params.get("search"):
        q = q.filter(InventorySoftware.name.ilike(f"%{params['search']}%"))
    limit = min(params.get("limit", 50), 200)
    rows = q.order_by(InventorySoftware.name).limit(limit).all()
    return [
        {"id": s.id, "name": s.name, "version": s.version, "vendor": s.vendor, "asset_id": s.asset_id}
        for s in rows
    ]


@agent_tool(
    "get_writeable_shares",
    "List writeable SMB shares — a common lateral movement vector.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def get_writeable_shares(db: Session, params: dict):
    q = db.query(InventoryShare).filter(InventoryShare.is_writeable == True)
    if params.get("scan_id"):
        q = q.filter(InventoryShare.scan_id == params["scan_id"])
    limit = min(params.get("limit", 50), 200)
    rows = q.limit(limit).all()
    return [
        {
            "id": s.id, "share_name": s.share_name, "share_type": s.share_type,
            "path": s.path, "comment": s.comment, "asset_id": s.asset_id,
            "acl": s.acl,
        }
        for s in rows
    ]


@agent_tool(
    "get_workflow_status_summary",
    "Summarize finding workflow statuses (open, in_progress, resolved, etc.) for tracking remediation progress.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "severity_min": {"type": "integer", "description": "Minimum severity (default 1)"},
    },
)
def get_workflow_status_summary(db: Session, params: dict):
    q = db.query(
        Finding.workflow_status,
        Finding.severity,
        func.count(Finding.id),
    )
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    sev_min = params.get("severity_min", 1)
    q = q.filter(Finding.severity >= sev_min)
    rows = q.group_by(Finding.workflow_status, Finding.severity).all()

    result = {}
    for status, sev, count in rows:
        status = status or "open"
        if status not in result:
            result[status] = {"total": 0, "by_severity": {}}
        result[status]["total"] += count
        sev_label = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}.get(sev, "info")
        result[status]["by_severity"][sev_label] = result[status]["by_severity"].get(sev_label, 0) + count
    return result


@agent_tool(
    "get_owner_workload",
    "Show how many findings are assigned to each owner/team. Helps balance workload across teams.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
    },
)
def get_owner_workload(db: Session, params: dict):
    q = db.query(
        Finding.owner_suggestion,
        func.count(Finding.id).label("total"),
        func.sum(case((Finding.severity == 4, 1), else_=0)).label("critical"),
        func.sum(case((Finding.severity == 3, 1), else_=0)).label("high"),
        func.sum(case((Finding.workflow_status == "open", 1), else_=0)).label("open"),
        func.sum(case((Finding.workflow_status == "in_progress", 1), else_=0)).label("in_progress"),
    )
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    q = q.filter(Finding.severity >= 1)  # skip info
    rows = q.group_by(Finding.owner_suggestion).all()
    return [
        {
            "owner": r.owner_suggestion or "Unassigned",
            "total": r.total, "critical": r.critical, "high": r.high,
            "open": r.open, "in_progress": r.in_progress,
        }
        for r in rows
    ]


@agent_tool(
    "compare_scans",
    "Compare two scans to find new, fixed, and recurring findings. Essential for showing progress.",
    {
        "base_scan_id": {"type": "integer", "description": "Older/baseline scan ID (required)"},
        "compare_scan_id": {"type": "integer", "description": "Newer scan ID to compare (required)"},
    },
)
def compare_scans(db: Session, params: dict):
    base_id = params.get("base_scan_id")
    cmp_id = params.get("compare_scan_id")
    if not base_id or not cmp_id:
        return {"error": "Both base_scan_id and compare_scan_id are required"}

    # Check for cached comparison
    cached = db.query(ScanComparison).filter_by(base_scan_id=base_id, compare_scan_id=cmp_id).first()
    if cached:
        return {
            "new_count": cached.new_count, "fixed_count": cached.fixed_count,
            "recurring_count": cached.recurring_count,
            "new_by_severity": cached.new_by_severity,
            "fixed_by_severity": cached.fixed_by_severity,
            "new_findings": (cached.new_findings or [])[:30],
            "fixed_findings": (cached.fixed_findings or [])[:30],
        }

    # Compute on the fly
    base_set = set(
        db.query(Finding.plugin_id, Asset.ip)
        .join(Asset).filter(Finding.scan_id == base_id).all()
    )
    cmp_set = set(
        db.query(Finding.plugin_id, Asset.ip)
        .join(Asset).filter(Finding.scan_id == cmp_id).all()
    )
    new_keys = cmp_set - base_set
    fixed_keys = base_set - cmp_set
    recurring_keys = base_set & cmp_set
    return {
        "new_count": len(new_keys), "fixed_count": len(fixed_keys),
        "recurring_count": len(recurring_keys),
        "sample_new": [{"plugin_id": p, "ip": ip} for p, ip in list(new_keys)[:20]],
        "sample_fixed": [{"plugin_id": p, "ip": ip} for p, ip in list(fixed_keys)[:20]],
    }


@agent_tool(
    "get_internet_facing_risk",
    "List internet-facing assets with their critical/high findings. Top priority for any VM program.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "limit": {"type": "integer", "description": "Max results (default 20)"},
    },
)
def get_internet_facing_risk(db: Session, params: dict):
    q = db.query(Asset).filter(Asset.is_internet_facing == True)
    if params.get("scan_id"):
        q = q.filter(Asset.scan_id == params["scan_id"])
    limit = min(params.get("limit", 20), 100)
    rows = q.order_by(Asset.risk_score.desc()).limit(limit).all()
    results = []
    for a in rows:
        exploitable = (
            db.query(func.count(Finding.id))
            .filter(Finding.asset_id == a.id, Finding.exploit_available == True)
            .scalar()
        )
        results.append({
            "id": a.id, "ip": a.ip, "hostname": a.hostname, "os": a.os,
            "risk_score": a.risk_score,
            "critical": a.critical_count, "high": a.high_count,
            "exploitable_findings": exploitable,
        })
    return results


@agent_tool(
    "update_finding_status",
    "Update the workflow status of one or more findings (open/in_progress/resolved/accepted_risk/false_positive). Requires write permission. "
    "WHEN TO CALL: After analyzing findings and determining the appropriate status change, with user confirmation.",
    {
        "finding_ids": {"type": "array", "items": {"type": "integer"}, "description": "List of finding IDs to update"},
        "status": {"type": "string", "description": "New status: open, in_progress, resolved, accepted_risk, false_positive"},
        "assigned_to": {"type": "string", "description": "Optional: assign to a person/team"},
        "notes": {"type": "string", "description": "Optional: add a note"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def update_finding_status(db: Session, params: dict):
    fids = params.get("finding_ids", [])
    new_status = params.get("status")
    if not fids or not new_status:
        return {"error": "finding_ids and status are required"}
    valid = {"open", "in_progress", "resolved", "accepted_risk", "false_positive"}
    if new_status not in valid:
        return {"error": f"Invalid status. Must be one of: {valid}"}
    from datetime import datetime
    updated = 0
    for fid in fids[:100]:
        f = db.query(Finding).filter(Finding.id == fid).first()
        if f:
            f.workflow_status = new_status
            f.status_changed_at = datetime.utcnow()
            if params.get("assigned_to"):
                f.workflow_assigned_to = params["assigned_to"]
            if params.get("notes"):
                f.workflow_notes = params["notes"]
            updated += 1
    db.commit()
    return {"updated": updated}


@agent_tool(
    "get_security_controls",
    "List security controls (AV, EDR, firewall, encryption) across assets. Find gaps in coverage.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "control_type": {"type": "string", "description": "Filter: av, edr, firewall, backup, encryption"},
        "disabled_only": {"type": "boolean", "description": "Only show disabled/outdated controls"},
    },
)
def get_security_controls(db: Session, params: dict):
    q = db.query(InventorySecurityControl)
    if params.get("scan_id"):
        q = q.filter(InventorySecurityControl.scan_id == params["scan_id"])
    if params.get("control_type"):
        q = q.filter(InventorySecurityControl.control_type == params["control_type"])
    if params.get("disabled_only"):
        q = q.filter((InventorySecurityControl.is_enabled == False) | (InventorySecurityControl.is_up_to_date == False))
    rows = q.limit(100).all()
    return [
        {
            "id": c.id, "control_type": c.control_type, "product": c.product_name,
            "vendor": c.vendor, "enabled": c.is_enabled, "up_to_date": c.is_up_to_date,
            "asset_id": c.asset_id,
        }
        for c in rows
    ]


# ── Action Tools (write operations) ──────────────────────────────────

@agent_tool(
    "create_jira_ticket",
    "Create a Jira ticket for findings. Requires Jira integration configured in Settings. Write operation. "
    "WHEN TO CALL: After you have identified findings that need ticketing and confirmed the action with the user. "
    "NEVER call this without setting confirmed=true after user approval.",
    {
        "title": {"type": "string", "description": "Ticket title/summary"},
        "description": {"type": "string", "description": "Ticket body/description"},
        "project": {"type": "string", "description": "Jira project key (e.g. SEC). Uses default if omitted."},
        "priority": {"type": "string", "description": "Priority: highest, high, medium, low, lowest"},
        "labels": {"type": "string", "description": "Comma-separated labels"},
        "finding_ids": {"type": "array", "description": "List of finding IDs to reference in the ticket"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def create_jira_ticket(db: Session, params: dict):
    import services.integrations as integ
    cfg = integ.get_integration_config(db, "jira")
    if not cfg:
        return {"error": "Jira integration not configured. Go to Settings > Integrations."}

    # Build items from finding IDs if provided
    items = []
    if params.get("finding_ids"):
        findings = db.query(Finding).filter(Finding.id.in_(params["finding_ids"])).all()
        for f in findings:
            asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
            sev_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
            items.append({
                "finding_id": f.id, "plugin_name": f.plugin_name, "plugin_id": f.plugin_id,
                "severity_label": sev_map.get(f.severity, "?"), "severity": f.severity,
                "asset_ip": asset.ip if asset else "", "asset_hostname": asset.hostname if asset else "",
                "solution": f.solution or "",
            })

    config = {
        "title_template": params.get("title", "Agent-created ticket"),
        "description_template": params.get("description", "Created by agent"),
        "group_by": "one_for_all",
    }
    if params.get("project"):
        config["project"] = params["project"]
    if params.get("priority"):
        config["priority"] = params["priority"]
    if params.get("labels"):
        config["labels"] = params["labels"]

    result = integ.create_jira_ticket(db, config, items or [{"finding_id": 0}])
    return result


@agent_tool(
    "create_servicenow_ticket",
    "Create a ServiceNow incident. Requires ServiceNow integration configured in Settings. Write operation. "
    "WHEN TO CALL: After identifying findings needing an incident and confirming with the user.",
    {
        "title": {"type": "string", "description": "Short description of the incident"},
        "description": {"type": "string", "description": "Full description"},
        "urgency": {"type": "string", "description": "Urgency: 1 (high), 2 (medium), 3 (low)"},
        "impact": {"type": "string", "description": "Impact: 1 (high), 2 (medium), 3 (low)"},
        "assignment_group": {"type": "string", "description": "Assignment group name"},
        "finding_ids": {"type": "array", "description": "List of finding IDs to reference"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def create_servicenow_ticket(db: Session, params: dict):
    import services.integrations as integ
    cfg = integ.get_integration_config(db, "servicenow")
    if not cfg:
        return {"error": "ServiceNow integration not configured. Go to Settings > Integrations."}

    items = _build_finding_items(db, params.get("finding_ids", []))
    config = {
        "title_template": params.get("title", "Agent-created incident"),
        "description_template": params.get("description", "Created by agent"),
        "group_by": "one_for_all",
    }
    if params.get("urgency"):
        config["urgency"] = params["urgency"]
    if params.get("impact"):
        config["impact"] = params["impact"]
    if params.get("assignment_group"):
        config["assignment_group"] = params["assignment_group"]

    result = integ.create_servicenow_ticket(db, config, items or [{"finding_id": 0}])
    return result


@agent_tool(
    "send_slack_message",
    "Send a Slack message via webhook. Requires Slack integration configured in Settings. Write operation. "
    "WHEN TO CALL: After composing the alert message and confirming with the user that sending is appropriate.",
    {
        "message": {"type": "string", "description": "The message text to send"},
        "channel": {"type": "string", "description": "Override channel (e.g. #security-alerts)"},
        "include_summary": {"type": "boolean", "description": "Include severity breakdown if finding_ids provided"},
        "finding_ids": {"type": "array", "description": "List of finding IDs to summarize"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def send_slack_message(db: Session, params: dict):
    import services.integrations as integ
    cfg = integ.get_integration_config(db, "slack")
    if not cfg:
        return {"error": "Slack integration not configured. Go to Settings > Integrations."}

    items = _build_finding_items(db, params.get("finding_ids", []))
    config = {
        "message_template": params.get("message", "Agent notification"),
        "include_summary": params.get("include_summary", False),
    }
    if params.get("channel"):
        config["channel"] = params["channel"]

    result = integ.send_slack_notification(db, config, items)
    return result


@agent_tool(
    "send_teams_message",
    "Send a Microsoft Teams message via webhook. Requires Teams integration configured in Settings. Write operation. "
    "WHEN TO CALL: After composing the alert message and confirming with the user that sending is appropriate.",
    {
        "message": {"type": "string", "description": "The message text to send"},
        "include_summary": {"type": "boolean", "description": "Include severity breakdown if finding_ids provided"},
        "finding_ids": {"type": "array", "description": "List of finding IDs to summarize"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def send_teams_message(db: Session, params: dict):
    import services.integrations as integ
    cfg = integ.get_integration_config(db, "teams")
    if not cfg:
        return {"error": "Teams integration not configured. Go to Settings > Integrations."}

    items = _build_finding_items(db, params.get("finding_ids", []))
    config = {
        "message_template": params.get("message", "Agent notification"),
        "include_summary": params.get("include_summary", False),
    }

    result = integ.send_teams_notification(db, config, items)
    return result


@agent_tool(
    "send_email_alert",
    "Send an email notification. Requires Email (SMTP) integration configured in Settings. Write operation. "
    "WHEN TO CALL: After composing the email and confirming with the user that sending is appropriate.",
    {
        "to": {"type": "string", "description": "Recipient email address(es), comma-separated"},
        "subject": {"type": "string", "description": "Email subject line"},
        "body": {"type": "string", "description": "Email body text"},
        "include_findings_table": {"type": "boolean", "description": "Append findings summary table"},
        "finding_ids": {"type": "array", "description": "List of finding IDs to include"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def send_email_alert(db: Session, params: dict):
    import services.integrations as integ
    cfg = integ.get_integration_config(db, "email")
    if not cfg:
        return {"error": "Email (SMTP) integration not configured. Go to Settings > Integrations."}

    items = _build_finding_items(db, params.get("finding_ids", []))
    config = {
        "to": params.get("to", ""),
        "subject": params.get("subject", "Agent Alert"),
        "body_template": params.get("body", "Agent notification"),
        "include_findings_table": params.get("include_findings_table", False),
    }

    result = integ.send_email(db, config, items)
    return result


@agent_tool(
    "create_campaign",
    "Create a remediation campaign to track a group of findings. Write operation. "
    "WHEN TO CALL: After scoping the campaign, identifying findings to include, and confirming with the user.",
    {
        "name": {"type": "string", "description": "Campaign name"},
        "description": {"type": "string", "description": "Campaign description/goal"},
        "scan_id": {"type": "integer", "description": "Scope to specific scan (optional)"},
        "finding_ids": {"type": "array", "description": "List of finding IDs to include"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def create_campaign(db: Session, params: dict):
    name = params.get("name")
    if not name:
        return {"error": "Campaign name is required"}

    campaign = Campaign(
        org_id=params.get("_org_id"),
        name=name,
        description=params.get("description", ""),
        scan_id=params.get("scan_id"),
        status="active",
    )
    db.add(campaign)
    db.flush()

    added = 0
    for fid in (params.get("finding_ids") or []):
        cf = CampaignFinding(campaign_id=campaign.id, finding_id=fid, status="open")
        db.add(cf)
        added += 1
    db.commit()
    return {"campaign_id": campaign.id, "name": campaign.name, "findings_added": added}


@agent_tool(
    "list_campaigns",
    "List remediation campaigns with their status, owner, and finding counts. "
    "WHEN TO CALL: When you need to see existing campaigns, check campaign progress, or find campaigns for a specific scan.",
    {
        "scan_id": {"type": "integer", "description": "Filter campaigns by scan ID (optional)"},
        "status": {"type": "string", "description": "Filter by status: draft, active, completed, paused (optional)"},
        "limit": {"type": "integer", "description": "Max results (default 50, max 200)"},
    },
)
def list_campaigns(db: Session, params: dict):
    org_id = params.get("_org_id")
    org_ids = params.get("_org_ids", [org_id] if org_id else [])
    q = db.query(Campaign).filter(Campaign.org_id.in_(org_ids))

    if params.get("scan_id"):
        q = q.filter((Campaign.scan_id == params["scan_id"]) | (Campaign.scan_id == None))
    if params.get("status"):
        q = q.filter(Campaign.status == params["status"])

    limit = min(params.get("limit", 50), 200)
    campaigns = q.order_by(Campaign.created_at.desc()).limit(limit).all()

    owner_ids = {c.owner_id for c in campaigns if c.owner_id}
    owners = {u.id: u for u in db.query(User).filter(User.id.in_(owner_ids)).all()} if owner_ids else {}

    return [
        {
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "status": c.status,
            "scan_id": c.scan_id,
            "finding_count": c.finding_count,
            "owner_id": c.owner_id,
            "owner_name": (owners[c.owner_id].display_name or owners[c.owner_id].email) if c.owner_id and c.owner_id in owners else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "last_run_at": c.last_run_at.isoformat() if c.last_run_at else None,
        }
        for c in campaigns
    ]


@agent_tool(
    "get_campaign",
    "Get detailed campaign information including findings grouped by owner with ownership resolution. "
    "WHEN TO CALL: When you need to see who owns findings in a campaign, check remediation progress by owner, or review campaign details.",
    {
        "campaign_id": {"type": "integer", "description": "Campaign ID to retrieve"},
    },
)
def get_campaign(db: Session, params: dict):
    campaign_id = params.get("campaign_id")
    if not campaign_id:
        return {"error": "campaign_id is required"}

    org_id = params.get("_org_id")
    org_ids = params.get("_org_ids", [org_id] if org_id else [])
    campaign = db.query(Campaign).filter(
        Campaign.id == campaign_id,
        Campaign.org_id.in_(org_ids),
    ).first()
    if not campaign:
        return {"error": "Campaign not found"}

    owner = db.query(User).filter(User.id == campaign.owner_id).first() if campaign.owner_id else None

    # Build findings with ownership resolution
    status_counts = {"open": 0, "in_progress": 0, "resolved": 0, "wont_fix": 0}
    owner_groups = {}
    for cf in campaign.findings:
        f = cf.finding
        if f is None:
            continue
        asset = f.asset if f else None
        s = cf.status or "open"
        status_counts[s] = status_counts.get(s, 0) + 1

        # Resolve ownership: campaign override > full resolution chain
        if cf.owner_role:
            owner_key = cf.owner_role
            o_name = cf.owner_name or cf.owner_role
            o_role = cf.owner_role
            o_team = cf.team
        elif f:
            resolved = resolve_finding_owner(f, asset, db)
            o_role = resolved.get("owner_role") or "Unassigned"
            o_name = resolved.get("owner_name") or o_role
            owner_key = o_role
            o_team = resolved.get("owner_team")
        else:
            owner_key = "Unassigned"
            o_name = "Unassigned"
            o_role = "Unassigned"
            o_team = None

        if owner_key not in owner_groups:
            owner_groups[owner_key] = {
                "owner_name": o_name, "owner_role": o_role, "team": o_team,
                "findings": [], "open": 0, "resolved": 0,
            }
        grp = owner_groups[owner_key]
        grp["findings"].append({
            "id": f.id, "plugin_name": f.plugin_name, "severity": f.severity,
            "priority_score": f.priority_score, "campaign_status": cf.status,
            "workflow_status": f.workflow_status,
        })
        if s == "resolved":
            grp["resolved"] += 1
        elif s == "open":
            grp["open"] += 1

    total_findings = sum(len(g["findings"]) for g in owner_groups.values())
    resolved_count = status_counts.get("resolved", 0)
    completion_pct = round(resolved_count / total_findings * 100, 1) if total_findings > 0 else 0

    # Per-owner progress summary (without individual findings for overview)
    owner_progress = [
        {
            "owner_name": g["owner_name"], "owner_role": g["owner_role"], "team": g["team"],
            "total": len(g["findings"]), "open": g["open"], "resolved": g["resolved"],
            "completion_pct": round(g["resolved"] / len(g["findings"]) * 100, 1) if g["findings"] else 0,
        }
        for g in owner_groups.values()
    ]

    return {
        "id": campaign.id,
        "name": campaign.name,
        "description": campaign.description,
        "status": campaign.status,
        "scan_id": campaign.scan_id,
        "owner_name": (owner.display_name or owner.email) if owner else None,
        "finding_count": total_findings,
        "completion_pct": completion_pct,
        "status_counts": status_counts,
        "owner_progress": owner_progress,
        "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
        "last_run_at": campaign.last_run_at.isoformat() if campaign.last_run_at else None,
        "owner_groups": list(owner_groups.values()),
    }


@agent_tool(
    "create_exception",
    "Create a finding exception (accepted risk, false positive, or compensating control). Write operation. "
    "WHEN TO CALL: After evaluating the finding and determining an exception is warranted, with user confirmation.",
    {
        "plugin_id": {"type": "string", "description": "Plugin ID to create exception for"},
        "asset_ip": {"type": "string", "description": "Scope to specific asset IP (omit for all assets)"},
        "exception_type": {"type": "string", "description": "Type: accepted_risk, false_positive, compensating_control"},
        "reason": {"type": "string", "description": "Justification/reason for the exception"},
        "compensating_control_detail": {"type": "string", "description": "Details of compensating control (if applicable)"},
        "expiration_date": {"type": "string", "description": "Exception expiry date (YYYY-MM-DD)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def create_exception(db: Session, params: dict):
    plugin_id = params.get("plugin_id")
    if not plugin_id:
        return {"error": "plugin_id is required"}

    exc = FindingException(
        org_id=params.get("_org_id"),
        plugin_id=plugin_id,
        asset_ip=params.get("asset_ip"),
        exception_type=params.get("exception_type", "accepted_risk"),
        reason=params.get("reason", "Created by agent"),
        compensating_control_detail=params.get("compensating_control_detail"),
        is_active=True,
    )
    if params.get("expiration_date"):
        try:
            exc.expires_at = datetime.strptime(params["expiration_date"], "%Y-%m-%d")
        except ValueError:
            pass
    db.add(exc)
    db.commit()
    return {"exception_id": exc.id, "plugin_id": plugin_id, "type": exc.exception_type}


@agent_tool(
    "create_tag",
    "Create a new tag for organizing assets and findings. Write operation.",
    {
        "category": {"type": "string", "description": "Tag category (e.g. env, net, team, priority)"},
        "value": {"type": "string", "description": "Tag value (e.g. production, dmz, infra-team)"},
        "color": {"type": "string", "description": "Hex color code (e.g. #3b82f6)"},
    },
)
def create_tag(db: Session, params: dict):
    category = params.get("category")
    value = params.get("value")
    if not category or not value:
        return {"error": "Both category and value are required"}

    existing = db.query(Tag).filter(Tag.category == category, Tag.value == value).first()
    if existing:
        return {"tag_id": existing.id, "already_exists": True, "label": f"{category}:{value}"}

    tag = Tag(org_id=params.get("_org_id"), category=category, value=value, color=params.get("color", "#6b7280"))
    db.add(tag)
    db.commit()
    return {"tag_id": tag.id, "label": f"{category}:{value}"}


@agent_tool(
    "bulk_tag_findings",
    "Apply a tag to multiple findings by ID. Write operation.",
    {
        "tag_id": {"type": "integer", "description": "Tag ID to apply"},
        "finding_ids": {"type": "array", "description": "List of finding IDs to tag"},
    },
)
def bulk_tag_findings(db: Session, params: dict):
    tag_id = params.get("tag_id")
    finding_ids = params.get("finding_ids", [])
    if not tag_id or not finding_ids:
        return {"error": "tag_id and finding_ids are required"}

    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        return {"error": f"Tag {tag_id} not found"}

    added = 0
    for fid in finding_ids:
        exists = db.query(TagAssignment).filter(
            TagAssignment.tag_id == tag_id,
            TagAssignment.finding_id == fid,
        ).first()
        if not exists:
            db.add(TagAssignment(tag_id=tag_id, finding_id=fid))
            added += 1
    db.commit()
    return {"tagged": added, "tag": f"{tag.category}:{tag.value}"}


@agent_tool(
    "create_auto_tag_rule",
    "Create a persistent auto-tag rule that automatically applies a tag to assets or findings on every future scan upload. Write operation.",
    {
        "name": {"type": "string", "description": "Rule name (e.g. 'Tag Windows Servers')"},
        "tag_id": {"type": "integer", "description": "ID of the tag to apply when conditions match"},
        "target_type": {"type": "string", "description": "What to tag: 'asset', 'finding', or 'both'"},
        "conditions": {"type": "array", "description": "List of condition objects, e.g. [{\"field\": \"os\", \"operator\": \"contains\", \"value\": \"Windows Server\"}]"},
        "condition_logic": {"type": "string", "description": "How to combine conditions: 'AND' or 'OR' (default: AND)"},
        "description": {"type": "string", "description": "Optional description of what this rule does"},
    },
)
def create_auto_tag_rule(db: Session, params: dict):
    tag_id = params.get("tag_id")
    name = params.get("name")
    conditions = params.get("conditions", [])
    if not name:
        return {"error": "name is required"}
    if not tag_id:
        return {"error": "tag_id is required"}
    if not conditions:
        return {"error": "conditions are required"}

    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        return {"error": f"Tag {tag_id} not found"}

    rule = AutoTagRule(
        org_id=params.get("_org_id"),
        name=name,
        description=params.get("description"),
        tag_id=tag_id,
        target_type=params.get("target_type", "asset"),
        conditions=conditions,
        condition_logic=params.get("condition_logic", "AND"),
        is_enabled=True,
    )
    db.add(rule)
    db.commit()
    return {"rule_id": rule.id, "name": name, "tag": f"{tag.category}:{tag.value}", "conditions_count": len(conditions)}


@agent_tool(
    "run_auto_tag_rules",
    "Execute all auto-tag rules for a scan. Automatically classifies assets/findings based on rules. Write operation.",
    {
        "scan_id": {"type": "integer", "description": "Scan ID to run auto-tag rules against"},
    },
)
def run_auto_tag_rules(db: Session, params: dict):
    scan_id = params.get("scan_id")
    if not scan_id:
        return {"error": "scan_id is required"}

    import services.tags as tag_engine
    results = tag_engine.run_all_auto_tag_rules(db, scan_id)
    return {"scan_id": scan_id, "rules_executed": len(results), "results": dict(list(results.items())[:20])}


@agent_tool(
    "send_webhook",
    "Send data to an arbitrary webhook URL. Useful for custom integrations. Write operation. "
    "WHEN TO CALL: After preparing the payload and confirming with the user.",
    {
        "url": {"type": "string", "description": "Webhook URL to POST to"},
        "payload": {"type": "object", "description": "JSON payload to send"},
        "method": {"type": "string", "description": "HTTP method (default: POST)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def send_webhook_tool(db: Session, params: dict):
    url = params.get("url")
    if not url:
        return {"error": "url is required"}

    import services.integrations as integ
    config = {
        "url": url,
        "method": params.get("method", "POST"),
        "include_findings": True,
    }
    payload = params.get("payload", {})
    result = integ.send_webhook(config, [payload] if payload else [])
    return result


# ── Helper for building finding items for integration connectors ──────

def _build_finding_items(db: Session, finding_ids: list) -> list:
    """Build integration-compatible item dicts from finding IDs."""
    if not finding_ids:
        return []
    findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
    sev_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    items = []
    for f in findings:
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        items.append({
            "finding_id": f.id, "plugin_name": f.plugin_name, "plugin_id": f.plugin_id,
            "severity_label": sev_map.get(f.severity, "?"), "severity": f.severity,
            "asset_ip": asset.ip if asset else "", "asset_hostname": asset.hostname if asset else "",
            "solution": f.solution or "", "cvss3_score": f.cvss3_score, "vpr_score": f.vpr_score,
            "priority_score": f.priority_score,
        })
    return items


# ── Threat Intelligence Tools ─────────────────────────────────────────

@agent_tool(
    "get_threat_groups",
    "List known threat groups (APTs, ransomware gangs). Filter by motivation, country, or ransomware status.",
    {
        "motivation": {"type": "string", "description": "Filter: espionage, financial, destruction, hacktivism"},
        "country": {"type": "string", "description": "Filter by country of origin"},
        "is_ransomware": {"type": "boolean", "description": "Only show ransomware groups"},
        "is_nation_state": {"type": "boolean", "description": "Only show nation-state actors"},
        "search": {"type": "string", "description": "Search by name or alias"},
        "limit": {"type": "integer", "description": "Max results (default 25)"},
    },
)
def get_threat_groups(db: Session, params: dict):
    q = db.query(ThreatGroup)
    if params.get("motivation"):
        q = q.filter(ThreatGroup.motivation == params["motivation"])
    if params.get("country"):
        q = q.filter(ThreatGroup.country.ilike(f"%{params['country']}%"))
    if params.get("is_ransomware"):
        q = q.filter(ThreatGroup.is_ransomware == True)
    if params.get("is_nation_state"):
        q = q.filter(ThreatGroup.is_nation_state == True)
    if params.get("search"):
        term = f"%{params['search']}%"
        q = q.filter(ThreatGroup.name.ilike(term))
    rows = q.limit(params.get("limit", 25)).all()
    return [
        {
            "id": g.id, "mitre_id": g.mitre_id, "name": g.name,
            "aliases": g.aliases, "country": g.country,
            "motivation": g.motivation, "is_ransomware": g.is_ransomware,
            "is_nation_state": g.is_nation_state,
            "target_sectors": g.target_sectors, "target_countries": g.target_countries,
            "first_seen": g.first_seen, "last_seen": g.last_seen,
        }
        for g in rows
    ]


@agent_tool(
    "get_threat_cves",
    "Search CVEs in the threat intel database. Find KEV entries, trending CVEs, those with public exploits.",
    {
        "cve_id": {"type": "string", "description": "Specific CVE ID (e.g. CVE-2024-1234)"},
        "in_kev": {"type": "boolean", "description": "Only CISA KEV entries"},
        "has_public_exploit": {"type": "boolean", "description": "Only CVEs with public exploits"},
        "trending_in_news": {"type": "boolean", "description": "Only CVEs trending in security news"},
        "min_epss": {"type": "number", "description": "Minimum EPSS score (0-1)"},
        "min_cvss": {"type": "number", "description": "Minimum CVSS3 score"},
        "search": {"type": "string", "description": "Search in description or affected products"},
        "limit": {"type": "integer", "description": "Max results (default 30)"},
    },
)
def get_threat_cves(db: Session, params: dict):
    q = db.query(ThreatCVE)
    if params.get("cve_id"):
        q = q.filter(ThreatCVE.cve_id == params["cve_id"].upper())
    if params.get("in_kev"):
        q = q.filter(ThreatCVE.in_kev == True)
    if params.get("has_public_exploit"):
        q = q.filter(ThreatCVE.has_public_exploit == True)
    if params.get("trending_in_news"):
        q = q.filter(ThreatCVE.trending_in_news == True)
    if params.get("min_epss"):
        q = q.filter(ThreatCVE.epss_score >= params["min_epss"])
    if params.get("min_cvss"):
        q = q.filter(ThreatCVE.cvss3_score >= params["min_cvss"])
    if params.get("search"):
        term = f"%{params['search']}%"
        q = q.filter(ThreatCVE.description.ilike(term))

    q = q.order_by(ThreatCVE.epss_score.desc().nullslast())
    rows = q.limit(params.get("limit", 30)).all()
    return [
        {
            "cve_id": c.cve_id, "description": (c.description or "")[:300],
            "cvss3": c.cvss3_score, "cvss4": c.cvss4_score,
            "epss": c.epss_score, "epss_pct": c.epss_percentile,
            "in_kev": c.in_kev, "kev_due": c.kev_due_date,
            "kev_ransomware": c.kev_ransomware_use,
            "has_exploit": c.has_public_exploit,
            "trending": c.trending_in_news,
            "published": c.published_date,
            "affected_products": c.affected_products[:5] if c.affected_products else [],
        }
        for c in rows
    ]


@agent_tool(
    "get_threat_campaigns",
    "List known threat campaigns — active attack operations by threat groups.",
    {
        "is_active": {"type": "boolean", "description": "Only show active campaigns"},
        "severity": {"type": "string", "description": "Filter: critical, high, medium, low"},
        "search": {"type": "string", "description": "Search by name or description"},
        "limit": {"type": "integer", "description": "Max results (default 20)"},
    },
)
def get_threat_campaigns(db: Session, params: dict):
    q = db.query(ThreatCampaign)
    if params.get("is_active") is not None:
        q = q.filter(ThreatCampaign.is_active == params["is_active"])
    if params.get("severity"):
        q = q.filter(ThreatCampaign.severity == params["severity"])
    if params.get("search"):
        term = f"%{params['search']}%"
        q = q.filter(ThreatCampaign.name.ilike(term) | ThreatCampaign.description.ilike(term))
    rows = q.order_by(ThreatCampaign.created_at.desc()).limit(params.get("limit", 20)).all()
    return [
        {
            "id": c.id, "name": c.name, "severity": c.severity,
            "is_active": c.is_active, "description": (c.description or "")[:300],
            "threat_group_id": c.threat_group_id,
            "target_sectors": c.target_sectors, "target_countries": c.target_countries,
            "cve_ids": c.cve_ids, "ttp_ids": c.ttp_ids,
            "malware_used": c.malware_used,
            "first_seen": c.first_seen, "last_seen": c.last_seen,
        }
        for c in rows
    ]


@agent_tool(
    "get_ttps",
    "List MITRE ATT&CK TTPs (tactics, techniques, procedures). Map to threat groups.",
    {
        "tactic": {"type": "string", "description": "Filter by tactic: initial-access, execution, persistence, etc."},
        "search": {"type": "string", "description": "Search by technique name or ID"},
        "group_id": {"type": "integer", "description": "Only TTPs used by this threat group ID"},
        "limit": {"type": "integer", "description": "Max results (default 30)"},
    },
)
def get_ttps(db: Session, params: dict):
    q = db.query(TTP)
    if params.get("tactic"):
        q = q.filter(TTP.tactic == params["tactic"])
    if params.get("search"):
        term = f"%{params['search']}%"
        q = q.filter(TTP.name.ilike(term) | TTP.technique_id.ilike(term))
    if params.get("group_id"):
        q = q.join(ThreatGroupTTP).filter(ThreatGroupTTP.group_id == params["group_id"])
    rows = q.limit(params.get("limit", 30)).all()
    return [
        {
            "id": t.id, "technique_id": t.technique_id, "name": t.name,
            "tactic": t.tactic, "description": (t.description or "")[:200],
            "platforms": t.platforms, "is_subtechnique": t.is_subtechnique,
        }
        for t in rows
    ]


@agent_tool(
    "correlate_cves_with_findings",
    "Cross-reference threat intel CVEs with your scan findings. Find which CVEs from intel are present in your environment.",
    {
        "scan_id": {"type": "integer", "description": "Scope to specific scan"},
        "in_kev_only": {"type": "boolean", "description": "Only match CISA KEV CVEs"},
        "trending_only": {"type": "boolean", "description": "Only match trending/newsworthy CVEs"},
        "min_epss": {"type": "number", "description": "Minimum EPSS score for CVEs to match"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def correlate_cves_with_findings(db: Session, params: dict):
    """Find threat-intel CVEs that exist in scan findings."""
    # Get relevant threat CVEs
    cve_q = db.query(ThreatCVE)
    if params.get("in_kev_only"):
        cve_q = cve_q.filter(ThreatCVE.in_kev == True)
    if params.get("trending_only"):
        cve_q = cve_q.filter(ThreatCVE.trending_in_news == True)
    if params.get("min_epss"):
        cve_q = cve_q.filter(ThreatCVE.epss_score >= params["min_epss"])
    threat_cves = {c.cve_id: c for c in cve_q.all()}

    if not threat_cves:
        return {"matches": 0, "results": [], "note": "No threat CVEs match the filter criteria."}

    # Find findings with matching CVEs
    fq = db.query(Finding).filter(Finding.cves.isnot(None))
    if params.get("scan_id"):
        fq = fq.filter(Finding.scan_id == params["scan_id"])
    findings = fq.limit(5000).all()

    matches = []
    seen = set()
    for f in findings:
        for cve_id in (f.cves or []):
            if cve_id in threat_cves and cve_id not in seen:
                tc = threat_cves[cve_id]
                asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
                matches.append({
                    "cve_id": cve_id,
                    "finding_id": f.id,
                    "plugin_name": f.plugin_name,
                    "severity": f.severity,
                    "asset_ip": asset.ip if asset else "",
                    "asset_hostname": asset.hostname if asset else "",
                    "epss": tc.epss_score,
                    "in_kev": tc.in_kev,
                    "has_exploit": tc.has_public_exploit,
                    "trending": tc.trending_in_news,
                    "kev_due": tc.kev_due_date,
                })
                seen.add(cve_id)
            if len(matches) >= params.get("limit", 50):
                break

    matches.sort(key=lambda x: (x.get("epss") or 0), reverse=True)
    return {"matches": len(matches), "results": matches}


# ── Scratchpad Tools (persistent agent working state) ─────────────────

@agent_tool(
    "read_scratchpad",
    "Read your persistent scratchpad state from a previous run. Call this at the START of a multi-step workflow "
    "to resume where you left off. Returns a JSON object with your saved state, or {} if empty.",
    {},
)
def read_scratchpad_tool(db: Session, params: dict):
    from agents.agent_context import read_scratchpad
    # agent_id is injected by the engine via params["_agent_id"]
    agent_id = params.get("_agent_id")
    if not agent_id:
        return {"error": "No agent context available"}
    return read_scratchpad(agent_id)


@agent_tool(
    "write_scratchpad",
    "Save a key-value pair to your persistent scratchpad. Use this to track intermediate state across runs: "
    "campaign progress, pending tickets, open items, analysis checkpoints. "
    "Call this DURING your workflow to checkpoint progress, not just at the end.",
    {
        "key": {"type": "string", "description": "State key (e.g. 'campaign_progress', 'pending_patches', 'last_triage_date')"},
        "value": {"type": "object", "description": "Value to store (any JSON-serializable object)"},
    },
)
def write_scratchpad_tool(db: Session, params: dict):
    from agents.agent_context import write_scratchpad
    agent_id = params.get("_agent_id")
    if not agent_id:
        return {"error": "No agent context available"}
    key = params.get("key")
    value = params.get("value")
    if not key:
        return {"error": "key is required"}
    state = write_scratchpad(agent_id, key, value)
    return {"saved": True, "keys": list(state.keys())}


@agent_tool(
    "clear_scratchpad",
    "Clear your entire scratchpad state. Use this when starting a fresh workflow or when previous state is stale.",
    {},
)
def clear_scratchpad_tool(db: Session, params: dict):
    from agents.agent_context import clear_scratchpad
    agent_id = params.get("_agent_id")
    if not agent_id:
        return {"error": "No agent context available"}
    clear_scratchpad(agent_id)
    return {"cleared": True}


# ── Request Clarification Tool (graceful fallback) ────────────────────

@agent_tool(
    "request_clarification",
    "When you cannot determine which action to take or which tool to use, call this tool to return a structured "
    "clarification request to the user. Do NOT guess or hallucinate an action — ask for clarification instead.",
    {
        "question": {"type": "string", "description": "The specific question you need answered"},
        "options": {"type": "array", "items": {"type": "string"}, "description": "Possible options the user can choose from (if applicable)"},
        "context": {"type": "string", "description": "Brief context about what you were trying to do when you got stuck"},
    },
)
def request_clarification(db: Session, params: dict):
    return {
        "type": "clarification_needed",
        "question": params.get("question", "I need more information to proceed."),
        "options": params.get("options", []),
        "context": params.get("context", ""),
    }


# ── RAG Document Search Tool ──────────────────────────────────────────

@agent_tool(
    "search_documents",
    "Search the knowledge base documents uploaded to this agent for relevant information. "
    "Returns matching text chunks. Use this tool when the user asks about information that may "
    "be in the uploaded documents or when you need reference material.",
    {
        "query": {"type": "string", "description": "The search query — keywords or a question to search for in the documents"},
        "max_results": {"type": "integer", "description": "Maximum number of chunks to return (default 5)"},
    },
)
def search_documents(db: Session, params: dict):
    from models.models import AgentDocument
    agent_id = params.get("_agent_id")
    if not agent_id:
        return {"error": "No agent context available"}

    query = (params.get("query") or "").lower().strip()
    max_results = min(params.get("max_results", 5), 15)

    if not query:
        return {"error": "Query is required"}

    docs = db.query(AgentDocument).filter(AgentDocument.agent_id == agent_id).all()
    if not docs:
        return {"results": [], "message": "No documents uploaded to this agent."}

    # Simple keyword-based retrieval: score each chunk by keyword overlap
    query_terms = set(query.split())
    scored = []
    for doc in docs:
        for i, chunk in enumerate(doc.chunks or []):
            chunk_lower = chunk.lower()
            # Score: count how many query terms appear in the chunk
            score = sum(1 for term in query_terms if term in chunk_lower)
            # Boost exact phrase match
            if query in chunk_lower:
                score += len(query_terms) * 2
            if score > 0:
                scored.append({
                    "score": score,
                    "filename": doc.filename,
                    "chunk_index": i,
                    "text": chunk,
                })

    # Sort by score descending
    scored.sort(key=lambda x: x["score"], reverse=True)
    results = scored[:max_results]

    # Strip internal score from output
    for r in results:
        del r["score"]

    return {
        "results": results,
        "total_matches": len(scored),
        "documents_searched": len(docs),
    }


# ---------------------------------------------------------------------------
# Integration tools — let agents use configured integrations
# ---------------------------------------------------------------------------


@agent_tool(
    "list_integrations",
    "List all configured integrations for the current organization, showing name, direction, entity, "
    "transport type, status, and last run info. "
    "WHEN TO CALL: When you need to discover what external systems are connected (Jira, ServiceNow, "
    "SIEM, CMDB, etc.) before fetching or pushing data through them.",
    {},
)
def list_integrations(db: Session, params: dict):
    rows = db.query(Integration).filter(Integration.enabled == True).all()
    return [
        {
            "id": i.id,
            "name": i.name,
            "direction": i.direction,
            "entity": i.entity,
            "transport_type": i.transport_type,
            "template_id": i.template_id,
            "enabled": i.enabled,
            "last_run_status": i.last_run_status,
            "last_run_at": str(i.last_run_at) if i.last_run_at else None,
            "last_run_records": i.last_run_records,
        }
        for i in rows
    ]


@agent_tool(
    "call_integration_fetch",
    "Trigger a pull integration to fetch data from an external system (e.g. import assets from a CMDB, "
    "pull tickets from Jira). The integration must already be configured and enabled. Returns the run "
    "result with record counts. "
    "WHEN TO CALL: When you need fresh data from an external system that has a configured pull integration.",
    {
        "integration_id": {"type": "integer", "description": "ID of the integration to run (from list_integrations)"},
        "confirmed": {"type": "boolean", "description": "Must be true to execute — confirm with the user first"},
    },
)
def call_integration_fetch(db: Session, params: dict):
    import asyncio
    from services.run_engine import execute

    integration_id = params.get("integration_id")
    if not integration_id:
        return {"error": "integration_id is required"}

    integration = db.query(Integration).filter(
        Integration.id == integration_id,
        Integration.enabled == True,
    ).first()
    if not integration:
        return {"error": f"Integration {integration_id} not found or disabled"}
    if integration.direction != "pull":
        return {"error": f"Integration '{integration.name}' is a {integration.direction} integration, not pull. Use call_integration_push for push integrations."}

    try:
        run_id = asyncio.get_event_loop().run_until_complete(
            execute(db, integration_id, triggered_by="agent")
        )
    except RuntimeError:
        # No running event loop — create one
        run_id = asyncio.run(execute(db, integration_id, triggered_by="agent"))

    run = db.query(IntegrationRun).filter(IntegrationRun.id == run_id).first()
    if not run:
        return {"error": "Run completed but record not found"}

    return {
        "run_id": run.id,
        "status": run.status,
        "records_fetched": run.records_fetched,
        "records_inserted": run.records_inserted,
        "records_updated": run.records_updated,
        "records_skipped": run.records_skipped,
        "error_message": run.error_message,
        "duration_ms": run.duration_ms,
    }


@agent_tool(
    "call_integration_push",
    "Trigger a push integration to send data to an external system (e.g. push findings to Jira, "
    "send alerts to a SIEM, create tickets in ServiceNow). The integration must already be configured "
    "and enabled. Returns the run result with success/error counts. "
    "WHEN TO CALL: When you need to push findings or data to an external system that has a configured push integration.",
    {
        "integration_id": {"type": "integer", "description": "ID of the integration to run (from list_integrations)"},
        "confirmed": {"type": "boolean", "description": "Must be true to execute — confirm with the user first"},
    },
)
def call_integration_push(db: Session, params: dict):
    import asyncio
    from services.run_engine import execute

    integration_id = params.get("integration_id")
    if not integration_id:
        return {"error": "integration_id is required"}

    integration = db.query(Integration).filter(
        Integration.id == integration_id,
        Integration.enabled == True,
    ).first()
    if not integration:
        return {"error": f"Integration {integration_id} not found or disabled"}
    if integration.direction != "push":
        return {"error": f"Integration '{integration.name}' is a {integration.direction} integration, not push. Use call_integration_fetch for pull integrations."}

    try:
        run_id = asyncio.get_event_loop().run_until_complete(
            execute(db, integration_id, triggered_by="agent")
        )
    except RuntimeError:
        run_id = asyncio.run(execute(db, integration_id, triggered_by="agent"))

    run = db.query(IntegrationRun).filter(IntegrationRun.id == run_id).first()
    if not run:
        return {"error": "Run completed but record not found"}

    return {
        "run_id": run.id,
        "status": run.status,
        "records_fetched": run.records_fetched,
        "records_inserted": run.records_inserted,
        "records_updated": run.records_updated,
        "records_skipped": run.records_skipped,
        "error_message": run.error_message,
        "duration_ms": run.duration_ms,
    }


# ── Workflow tools ───────────────────────────────────────────────────

@agent_tool(
    "list_workflows",
    "List all automation workflows with their status, trigger type, and run count. "
    "WHEN TO CALL: When the user asks about workflows, automation, or what's configured.",
    {
        "status": {"type": "string", "description": "Filter by status: draft, active, paused (optional)"},
    },
)
def list_workflows_tool(db: Session, params: dict):
    q = db.query(Workflow)
    if params.get("_org_id"):
        q = q.filter(Workflow.org_id == params["_org_id"])
    if params.get("status"):
        q = q.filter(Workflow.status == params["status"])
    rows = q.order_by(Workflow.updated_at.desc()).limit(50).all()
    results = []
    for w in rows:
        trigger_node = db.query(WorkflowNode).filter(
            WorkflowNode.workflow_id == w.id, WorkflowNode.node_type == "trigger"
        ).first()
        results.append({
            "id": w.id, "name": w.name, "description": w.description,
            "status": w.status, "is_enabled": w.is_enabled,
            "trigger_type": trigger_node.node_subtype if trigger_node else None,
            "node_count": db.query(WorkflowNode).filter(WorkflowNode.workflow_id == w.id).count(),
            "run_count": w.run_count, "last_run_at": w.last_run_at.isoformat() if w.last_run_at else None,
            "campaign_id": w.campaign_id,
        })
    return results


@agent_tool(
    "get_workflow_detail",
    "Get full details of a specific workflow including all nodes (triggers, conditions, actions), "
    "edges (connections between nodes), and recent execution history. "
    "WHEN TO CALL: When the user asks to explain a workflow, asks what a workflow does, "
    "or is viewing a workflow detail page.",
    {
        "workflow_id": {"type": "integer", "description": "Workflow ID to look up"},
    },
)
def get_workflow_detail(db: Session, params: dict):
    wf_id = params.get("workflow_id")
    if not wf_id:
        return {"error": "workflow_id is required"}
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        return {"error": f"Workflow {wf_id} not found"}

    nodes = db.query(WorkflowNode).filter(WorkflowNode.workflow_id == wf_id).all()
    edges = db.query(WorkflowEdge).filter(WorkflowEdge.workflow_id == wf_id).all()

    node_list = []
    for n in nodes:
        node_list.append({
            "node_id": n.node_id, "type": n.node_type, "subtype": n.node_subtype,
            "label": n.label, "config": n.config,
        })

    edge_list = []
    for e in edges:
        edge_list.append({
            "from": e.source_node_id, "to": e.target_node_id,
            "source_handle": e.source_handle, "label": e.label,
        })

    execs = db.query(WorkflowExecution).filter(
        WorkflowExecution.workflow_id == wf_id
    ).order_by(WorkflowExecution.started_at.desc()).limit(5).all()
    exec_list = [{
        "id": ex.id, "status": ex.status, "trigger_type": ex.trigger_type,
        "started_at": ex.started_at.isoformat() if ex.started_at else None,
        "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
        "items_processed": ex.items_processed,
        "error": ex.error,
    } for ex in execs]

    return {
        "id": wf.id, "name": wf.name, "description": wf.description,
        "status": wf.status, "is_enabled": wf.is_enabled,
        "campaign_id": wf.campaign_id,
        "run_count": wf.run_count,
        "last_run_at": wf.last_run_at.isoformat() if wf.last_run_at else None,
        "nodes": node_list, "edges": edge_list,
        "recent_executions": exec_list,
    }


@agent_tool(
    "get_workflow_execution",
    "Get detailed logs for a specific workflow execution, showing what each node did. "
    "WHEN TO CALL: When the user asks about a workflow run result, errors, or what happened.",
    {
        "execution_id": {"type": "integer", "description": "Execution ID to look up"},
    },
)
def get_workflow_execution_tool(db: Session, params: dict):
    exec_id = params.get("execution_id")
    if not exec_id:
        return {"error": "execution_id is required"}
    ex = db.query(WorkflowExecution).filter(WorkflowExecution.id == exec_id).first()
    if not ex:
        return {"error": f"Execution {exec_id} not found"}

    logs = db.query(WorkflowExecutionLog).filter(
        WorkflowExecutionLog.execution_id == exec_id
    ).order_by(WorkflowExecutionLog.executed_at).all()

    return {
        "id": ex.id, "workflow_id": ex.workflow_id,
        "status": ex.status, "trigger_type": ex.trigger_type,
        "started_at": ex.started_at.isoformat() if ex.started_at else None,
        "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
        "items_processed": ex.items_processed,
        "error": ex.error,
        "logs": [{
            "node_id": l.node_id, "node_type": l.node_type, "node_subtype": l.node_subtype,
            "status": l.status, "items_in": l.items_in, "items_out": l.items_out,
            "error": l.error,
            "executed_at": l.executed_at.isoformat() if l.executed_at else None,
        } for l in logs],
    }


@agent_tool(
    "create_campaign_workflow",
    "Create a new automation workflow for a campaign with a full node graph (trigger, conditions, actions). "
    "Write operation. "
    "WHEN TO CALL: When the user asks to create or build a workflow for a campaign. "
    "You must provide the nodes and edges that define the workflow DAG. "
    "Common node types — trigger: campaign_run, schedule, webhook; "
    "condition: severity_check, exploit_check, tag_check, owner_check, sla_check; "
    "action: assign_owner, create_ticket, send_email, send_slack, update_status, add_tag, run_query, webhook.",
    {
        "campaign_id": {"type": "integer", "description": "Campaign ID to attach the workflow to"},
        "name": {"type": "string", "description": "Workflow name"},
        "description": {"type": "string", "description": "Workflow description/goal"},
        "nodes": {
            "type": "array",
            "description": (
                "List of workflow nodes. Each node: "
                "{node_id: str, node_type: 'trigger'|'condition'|'action', "
                "node_subtype: str, label: str, config: dict}. "
                "Example subtypes — trigger: campaign_run, schedule; "
                "condition: severity_check (config: {operator:'gte', value:4}), "
                "exploit_check, tag_check; "
                "action: assign_owner, create_ticket (config: {provider:'jira', project:'SEC'}), "
                "send_slack (config: {channel:'#alerts', message:'...'}), "
                "send_email (config: {to:'...', subject:'...'}), "
                "update_status (config: {status:'in_progress'}), add_tag."
            ),
        },
        "edges": {
            "type": "array",
            "description": (
                "List of edges connecting nodes. Each edge: "
                "{edge_id: str, source_node_id: str, target_node_id: str, "
                "source_handle: 'output'|'true'|'false' (default 'output')}. "
                "Use source_handle 'true'/'false' for condition node branches."
            ),
        },
        "is_enabled": {"type": "boolean", "description": "Enable the workflow immediately (default false)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def create_campaign_workflow(db: Session, params: dict):
    campaign_id = params.get("campaign_id")
    name = params.get("name")
    nodes_data = params.get("nodes") or []
    edges_data = params.get("edges") or []

    if not name:
        return {"error": "Workflow name is required"}
    if not nodes_data:
        return {"error": "At least one node is required"}

    # Verify campaign exists and belongs to org
    if campaign_id:
        org_id = params.get("_org_id")
        org_ids = params.get("_org_ids", [org_id] if org_id else [])
        campaign = db.query(Campaign).filter(
            Campaign.id == campaign_id,
            Campaign.org_id.in_(org_ids),
        ).first()
        if not campaign:
            return {"error": f"Campaign {campaign_id} not found"}

    wf = Workflow(
        org_id=params.get("_org_id"),
        campaign_id=campaign_id,
        name=name,
        description=params.get("description", ""),
        status="active" if params.get("is_enabled") else "draft",
        is_enabled=bool(params.get("is_enabled")),
    )
    db.add(wf)
    db.flush()

    for nd in nodes_data:
        db.add(WorkflowNode(
            workflow_id=wf.id,
            node_id=nd.get("node_id", f"node-{nodes_data.index(nd)+1}"),
            node_type=nd.get("node_type", "action"),
            node_subtype=nd.get("node_subtype", ""),
            label=nd.get("label", ""),
            config=nd.get("config", {}),
            position_x=nd.get("position_x", 0),
            position_y=nd.get("position_y", 0),
        ))

    for ed in edges_data:
        db.add(WorkflowEdge(
            workflow_id=wf.id,
            edge_id=ed.get("edge_id", f"edge-{edges_data.index(ed)+1}"),
            source_node_id=ed.get("source_node_id"),
            target_node_id=ed.get("target_node_id"),
            source_handle=ed.get("source_handle", "output"),
            target_handle=ed.get("target_handle", "input"),
            label=ed.get("label"),
        ))

    db.commit()
    db.refresh(wf)
    return {
        "workflow_id": wf.id,
        "name": wf.name,
        "campaign_id": wf.campaign_id,
        "status": wf.status,
        "is_enabled": wf.is_enabled,
        "node_count": len(nodes_data),
        "edge_count": len(edges_data),
    }


@agent_tool(
    "create_workflow_from_template",
    "Create a workflow from a pre-built template. Much simpler than building nodes manually. "
    "Write operation. "
    "WHEN TO CALL: When the user wants a standard workflow (e.g. 'create a Jira ticketing workflow', "
    "'set up a Slack alert workflow'). Use list_workflow_templates first to show available templates. "
    "Available templates include: critical_triage, patch_tuesday, exploit_response, owner_routing, "
    "sla_breach_email, email_notification, regression_response, quick_wins_sprint, "
    "integration_complete_campaign, threat_intel_response, new_asset_onboard, critical_finding_alert, "
    "multi_owner_ticketing, and more.",
    {
        "template_id": {"type": "string", "description": "Template ID (e.g. 'critical_triage', 'sla_breach_email', 'multi_owner_ticketing')"},
        "name": {"type": "string", "description": "Custom name for the workflow (optional, defaults to template name)"},
        "campaign_id": {"type": "integer", "description": "Campaign ID to attach the workflow to (optional)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def create_workflow_from_template(db: Session, params: dict):
    from services.workflow_engine import create_workflow_from_template as _create_from_template

    template_id = params.get("template_id")
    if not template_id:
        return {"error": "template_id is required"}

    try:
        wf = _create_from_template(
            db,
            template_id,
            name=params.get("name"),
            campaign_id=params.get("campaign_id"),
        )
        # Set org_id
        if params.get("_org_id"):
            wf.org_id = params["_org_id"]
            db.commit()
            db.refresh(wf)

        nodes = db.query(WorkflowNode).filter(WorkflowNode.workflow_id == wf.id).all()
        return {
            "workflow_id": wf.id,
            "name": wf.name,
            "campaign_id": wf.campaign_id,
            "status": wf.status,
            "node_count": len(nodes),
            "nodes": [
                {"node_id": n.node_id, "type": n.node_type, "subtype": n.node_subtype, "label": n.label}
                for n in nodes
            ],
        }
    except ValueError as e:
        return {"error": str(e)}


@agent_tool(
    "list_workflow_templates",
    "List available pre-built workflow templates with their descriptions and categories. "
    "WHEN TO CALL: When the user asks what workflow templates are available, or before creating "
    "a workflow from a template to help them pick one.",
    {
        "category": {"type": "string", "description": "Filter by category: triage, patching, incident, integration, sla (optional)"},
    },
)
def list_workflow_templates_tool(db: Session, params: dict):
    from services.workflow_catalog import WORKFLOW_TEMPLATES, TEMPLATE_CATEGORIES

    category = params.get("category")
    templates = WORKFLOW_TEMPLATES
    if category:
        templates = [t for t in templates if t.get("category") == category]

    return {
        "categories": TEMPLATE_CATEGORIES,
        "templates": [
            {
                "id": t["id"],
                "name": t["name"],
                "description": t["description"],
                "category": t.get("category"),
                "node_count": len(t.get("nodes", [])),
            }
            for t in templates
        ],
    }


@agent_tool(
    "run_workflow",
    "Execute/run a workflow manually. Write operation. "
    "WHEN TO CALL: When the user asks to run, trigger, or execute a workflow.",
    {
        "workflow_id": {"type": "integer", "description": "Workflow ID to execute"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def run_workflow_tool(db: Session, params: dict):
    from services.workflow_engine import execute_workflow

    workflow_id = params.get("workflow_id")
    if not workflow_id:
        return {"error": "workflow_id is required"}

    # Verify workflow exists and belongs to org
    org_id = params.get("_org_id")
    org_ids = params.get("_org_ids", [org_id] if org_id else [])
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        return {"error": f"Workflow {workflow_id} not found"}
    if wf.org_id and org_ids and wf.org_id not in org_ids:
        return {"error": f"Workflow {workflow_id} not found"}

    try:
        result = execute_workflow(db, workflow_id)
        return result
    except Exception as e:
        return {"error": f"Workflow execution failed: {str(e)}"}


@agent_tool(
    "toggle_workflow",
    "Enable or disable a workflow, or change its status (draft/active/paused). Write operation. "
    "WHEN TO CALL: When the user asks to enable, disable, activate, pause, or change the status of a workflow.",
    {
        "workflow_id": {"type": "integer", "description": "Workflow ID to update"},
        "is_enabled": {"type": "boolean", "description": "Enable (true) or disable (false) the workflow"},
        "status": {"type": "string", "description": "Set status: draft, active, or paused (optional)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def toggle_workflow_tool(db: Session, params: dict):
    workflow_id = params.get("workflow_id")
    if not workflow_id:
        return {"error": "workflow_id is required"}

    org_id = params.get("_org_id")
    org_ids = params.get("_org_ids", [org_id] if org_id else [])
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        return {"error": f"Workflow {workflow_id} not found"}
    if wf.org_id and org_ids and wf.org_id not in org_ids:
        return {"error": f"Workflow {workflow_id} not found"}

    if params.get("is_enabled") is not None:
        wf.is_enabled = params["is_enabled"]
    if params.get("status"):
        wf.status = params["status"]

    db.commit()
    return {
        "workflow_id": wf.id,
        "name": wf.name,
        "is_enabled": wf.is_enabled,
        "status": wf.status,
    }


# ── Agent Management Tools ─────────────────────────────────────────────

@agent_tool(
    "list_agents",
    "List all agents in the organization with their schedules and recent run info. "
    "WHEN TO CALL: When the user asks about existing agents, wants to see what agents are available, "
    "or before creating a schedule (to find the agent ID).",
    {
        "search": {"type": "string", "description": "Optional: filter agents by name or description"},
    },
)
def list_agents_tool(db: Session, params: dict):
    q = db.query(Agent).filter(Agent.name != "__copilot__")
    search = params.get("search")
    if search:
        q = q.filter(
            (Agent.name.ilike(f"%{search}%")) | (Agent.description.ilike(f"%{search}%"))
        )
    agents = q.order_by(Agent.created_at.desc()).limit(50).all()
    result = []
    for a in agents:
        schedules = db.query(AgentSchedule).filter(AgentSchedule.agent_id == a.id).all()
        # Get the most recent run for this agent
        last_run = (
            db.query(AgentRun)
            .filter(AgentRun.agent_id == a.id)
            .order_by(AgentRun.created_at.desc())
            .first()
        )
        entry = {
            "id": a.id, "name": a.name, "description": a.description,
            "model": a.model, "tools": a.tools,
            "guardrails": a.guardrails,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "schedules": [{
                "id": s.id, "cron_expression": s.cron_expression,
                "is_enabled": s.is_enabled,
                "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
            } for s in schedules],
        }
        if last_run:
            entry["last_run_timestamp"] = last_run.created_at.isoformat() if last_run.created_at else None
            entry["last_run_status"] = last_run.status
            entry["last_run_output"] = (last_run.output[:500] if last_run.output else None)
        result.append(entry)
    return {"agents": result, "count": len(result)}


@agent_tool(
    "get_agent_run",
    "Get the full output and trace from a specific agent run, or the latest run for an agent. "
    "WHEN TO CALL: When the user asks to see what an agent found, wants to review agent output, "
    "or asks about the results of the last agent execution.",
    {
        "agent_id": {"type": "integer", "description": "Agent ID to get the latest run for"},
        "run_id": {"type": "integer", "description": "Specific run ID (if omitted, returns the latest run)"},
    },
)
def get_agent_run(db: Session, params: dict):
    agent_id = params.get("agent_id")
    run_id = params.get("run_id")

    if run_id:
        run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
    elif agent_id:
        run = (
            db.query(AgentRun)
            .filter(AgentRun.agent_id == agent_id)
            .order_by(AgentRun.created_at.desc())
            .first()
        )
    else:
        return {"error": "Either agent_id or run_id is required"}

    if not run:
        return {"error": "No runs found"}

    agent = db.query(Agent).filter(Agent.id == run.agent_id).first()
    return {
        "run_id": run.id,
        "agent_id": run.agent_id,
        "agent_name": agent.name if agent else None,
        "status": run.status,
        "input": run.input,
        "output": run.output,
        "error": run.error,
        "steps_used": run.steps_used,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


# ── Advanced Analysis Tools (Hexa-inspired) ────────────────────────

@agent_tool(
    "analyze_attack_surface",
    "Combine internet-facing assets, network connections, privileged users, and exploitable findings "
    "to produce an attack surface risk narrative with attack path analysis. "
    "WHEN TO CALL: When the user asks about overall exposure, attack paths, attack surface risk, "
    "or when you discover internet-facing assets with exploitable vulnerabilities.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID (optional)"},
        "limit": {"type": "integer", "description": "Max assets to analyze (default 20)"},
    },
)
def analyze_attack_surface(db: Session, params: dict):
    scan_id = params.get("scan_id")
    limit = min(params.get("limit", 20), 50)

    # 1. Internet-facing assets with vulnerabilities
    inet_q = db.query(Asset).filter(Asset.is_internet_facing == True)
    if scan_id:
        inet_q = inet_q.filter(Asset.scan_id == scan_id)
    inet_assets = inet_q.order_by(Asset.risk_score.desc()).limit(limit).all()

    # 2. Get exploitable findings on internet-facing assets
    inet_ids = [a.id for a in inet_assets]
    exploit_findings = []
    if inet_ids:
        exploit_findings = (
            db.query(Finding)
            .filter(
                Finding.asset_id.in_(inet_ids),
                Finding.exploit_available == True,
            )
            .order_by(Finding.priority_score.desc())
            .limit(50)
            .all()
        )

    # 3. Privileged users on those assets
    priv_users = []
    if inet_ids:
        priv_users = (
            db.query(InventoryUser)
            .filter(
                InventoryUser.asset_id.in_(inet_ids),
                or_(
                    InventoryUser.is_local_admin == True,
                    InventoryUser.is_domain_admin == True,
                    InventoryUser.is_privileged == True,
                ),
            )
            .limit(50)
            .all()
        )

    # 4. Listening services on internet-facing assets
    services = []
    if inet_ids:
        services = (
            db.query(InventoryService)
            .filter(InventoryService.asset_id.in_(inet_ids))
            .limit(100)
            .all()
        )

    # 5. Network connections showing lateral movement paths
    net_conns = []
    if inet_ids:
        net_conns = (
            db.query(InventoryNetConn)
            .filter(
                InventoryNetConn.asset_id.in_(inet_ids),
                InventoryNetConn.state == "ESTABLISHED",
            )
            .limit(50)
            .all()
        )

    # 6. KEV / ransomware-linked findings
    kev_findings = []
    if inet_ids:
        kev_findings = (
            db.query(Finding)
            .filter(
                Finding.asset_id.in_(inet_ids),
                Finding.is_kev == True,
            )
            .limit(30)
            .all()
        )

    # Build attack path narratives per asset
    asset_profiles = []
    for a in inet_assets:
        asset_exploits = [f for f in exploit_findings if f.asset_id == a.id]
        asset_kev = [f for f in kev_findings if f.asset_id == a.id]
        asset_priv = [u for u in priv_users if u.asset_id == a.id]
        asset_services = [s for s in services if s.asset_id == a.id]
        asset_conns = [c for c in net_conns if c.asset_id == a.id]

        # Determine risk tier
        risk_tier = "LOW"
        if asset_kev:
            risk_tier = "CRITICAL"
        elif asset_exploits and asset_priv:
            risk_tier = "CRITICAL"
        elif asset_exploits:
            risk_tier = "HIGH"
        elif a.critical_count > 0:
            risk_tier = "HIGH"

        # Build attack path description
        paths = []
        if asset_exploits:
            top_exploit = asset_exploits[0]
            _cve = top_exploit.cves[0] if top_exploit.cves else "N/A"
            path = f"External attacker exploits {top_exploit.plugin_name} (CVE: {_cve})"
            if asset_priv:
                _u = asset_priv[0]
                _lvl = "domain_admin" if _u.is_domain_admin else "local_admin" if _u.is_local_admin else "privileged"
                path += f" → escalates to {_u.username} ({_lvl})"
            if asset_conns:
                internal_targets = set(c.remote_addr for c in asset_conns if c.remote_addr)
                if internal_targets:
                    path += f" → lateral movement to {len(internal_targets)} internal hosts"
            paths.append(path)

        asset_profiles.append({
            "asset_id": a.id,
            "ip": a.ip,
            "hostname": a.hostname,
            "os": a.os,
            "risk_score": a.risk_score,
            "risk_tier": risk_tier,
            "critical_findings": a.critical_count,
            "high_findings": a.high_count,
            "exploitable_count": len(asset_exploits),
            "kev_count": len(asset_kev),
            "privileged_users": [{"username": u.username, "level": "domain_admin" if u.is_domain_admin else "local_admin" if u.is_local_admin else "privileged"} for u in asset_priv],
            "exposed_services": [{"name": s.service_name, "startup_type": s.startup_type} for s in asset_services[:10]],
            "internal_connections": len(asset_conns),
            "attack_paths": paths,
        })

    # Summary stats
    total_exploitable = len(set(f.id for f in exploit_findings))
    total_kev = len(set(f.id for f in kev_findings))
    critical_assets = len([a for a in asset_profiles if a["risk_tier"] == "CRITICAL"])

    return {
        "summary": {
            "internet_facing_assets": len(inet_assets),
            "critical_risk_assets": critical_assets,
            "total_exploitable_findings": total_exploitable,
            "total_kev_findings": total_kev,
            "total_privileged_accounts_exposed": len(priv_users),
            "total_exposed_services": len(services),
        },
        "attack_surface": asset_profiles,
    }


@agent_tool(
    "suggest_tagging_schema",
    "Analyze asset metadata (OS, environment, hostnames, IPs, services) and suggest an organized "
    "tagging strategy. Returns recommended tag categories, values, and which assets they apply to. "
    "WHEN TO CALL: When the user asks about organizing assets, or when you notice many untagged assets.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID (optional)"},
        "limit": {"type": "integer", "description": "Max assets to analyze (default 100)"},
    },
)
def suggest_tagging_schema(db: Session, params: dict):
    scan_id = params.get("scan_id")
    limit = min(params.get("limit", 100), 500)

    q = db.query(Asset)
    if scan_id:
        q = q.filter(Asset.scan_id == scan_id)
    assets = q.order_by(Asset.risk_score.desc()).limit(limit).all()

    if not assets:
        return {"error": "No assets found to analyze"}

    # Existing tags
    existing_tags = db.query(Tag).all()
    existing_categories = set(t.category for t in existing_tags)

    # Tagged asset count
    tagged_asset_ids = set(
        r[0] for r in db.query(TagAssignment.asset_id).distinct().all()
    )
    total = len(assets)
    untagged = len([a for a in assets if a.id not in tagged_asset_ids])

    suggestions = []

    # 1. Environment-based tagging (from environment_tag field)
    env_groups = {}
    for a in assets:
        env = a.environment_tag or "unclassified"
        env_groups.setdefault(env, []).append(a.id)
    if len(env_groups) > 1 and "env" not in existing_categories:
        suggestions.append({
            "category": "env",
            "rationale": "Segment assets by environment for risk-based prioritization",
            "values": [
                {"value": env, "asset_count": len(ids), "sample_assets": ids[:5]}
                for env, ids in sorted(env_groups.items(), key=lambda x: -len(x[1]))
            ],
        })

    # 2. OS-based tagging
    os_groups = {}
    for a in assets:
        if a.os:
            os_family = "windows" if "windows" in a.os.lower() else \
                        "linux" if "linux" in a.os.lower() else \
                        "macos" if "mac" in a.os.lower() or "darwin" in a.os.lower() else \
                        "network" if any(k in a.os.lower() for k in ["cisco", "juniper", "fortinet", "palo alto"]) else \
                        "other"
            os_groups.setdefault(os_family, []).append(a.id)
    if len(os_groups) > 1 and "os" not in existing_categories:
        suggestions.append({
            "category": "os",
            "rationale": "Group by OS family for targeted patching and remediation routing",
            "values": [
                {"value": os_fam, "asset_count": len(ids), "sample_assets": ids[:5]}
                for os_fam, ids in sorted(os_groups.items(), key=lambda x: -len(x[1]))
            ],
        })

    # 3. Criticality-based tagging
    crit_groups = {}
    for a in assets:
        crit = a.criticality or "unset"
        crit_groups.setdefault(crit, []).append(a.id)
    if len(crit_groups) > 1 and "criticality" not in existing_categories:
        suggestions.append({
            "category": "criticality",
            "rationale": "Ensure SLA and remediation priority aligns with business criticality",
            "values": [
                {"value": c, "asset_count": len(ids), "sample_assets": ids[:5]}
                for c, ids in sorted(crit_groups.items(), key=lambda x: -len(x[1]))
            ],
        })

    # 4. Network segment tagging (from IP subnets)
    subnet_groups = {}
    for a in assets:
        if a.ip:
            parts = a.ip.split(".")
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                subnet_groups.setdefault(subnet, []).append(a.id)
    significant_subnets = {k: v for k, v in subnet_groups.items() if len(v) >= 3}
    if significant_subnets and "network" not in existing_categories:
        suggestions.append({
            "category": "network",
            "rationale": "Identify network segments for zone-based security policies and blast radius analysis",
            "values": [
                {"value": subnet, "asset_count": len(ids), "sample_assets": ids[:5]}
                for subnet, ids in sorted(significant_subnets.items(), key=lambda x: -len(x[1]))[:10]
            ],
        })

    # 5. Internet-facing tagging
    inet_assets = [a for a in assets if a.is_internet_facing]
    if inet_assets and "exposure" not in existing_categories:
        suggestions.append({
            "category": "exposure",
            "rationale": "Distinguish internet-facing assets for prioritized remediation and stricter SLAs",
            "values": [
                {"value": "internet-facing", "asset_count": len(inet_assets), "sample_assets": [a.id for a in inet_assets[:5]]},
                {"value": "internal-only", "asset_count": total - len(inet_assets), "sample_assets": [a.id for a in assets if not a.is_internet_facing][:5]},
            ],
        })

    # 6. Server role tagging (from hostname patterns)
    role_patterns = {
        "database": ["db", "sql", "mysql", "postgres", "mongo", "oracle", "redis"],
        "web-server": ["web", "www", "apache", "nginx", "iis", "httpd"],
        "domain-controller": ["dc", "ad", "ldap", "kdc"],
        "mail-server": ["mail", "smtp", "exchange", "mx"],
        "file-server": ["file", "nas", "nfs", "smb", "share"],
    }
    role_groups = {}
    for a in assets:
        name = (a.hostname or "").lower()
        for role, keywords in role_patterns.items():
            if any(kw in name for kw in keywords):
                role_groups.setdefault(role, []).append(a.id)
                break
    if role_groups and "role" not in existing_categories:
        suggestions.append({
            "category": "role",
            "rationale": "Tag by server role for team-based remediation routing and impact assessment",
            "values": [
                {"value": role, "asset_count": len(ids), "sample_assets": ids[:5]}
                for role, ids in sorted(role_groups.items(), key=lambda x: -len(x[1]))
            ],
        })

    return {
        "total_assets": total,
        "untagged_assets": untagged,
        "untagged_pct": round(untagged / total * 100) if total else 0,
        "existing_tag_categories": list(existing_categories),
        "suggestions": suggestions,
    }


@agent_tool(
    "recommend_agents",
    "Analyze the org's vulnerability data and recommend pre-built agent templates the user should deploy. "
    "Matches data patterns to relevant agent templates (daily triage, patch Tuesday, compliance, etc.). "
    "WHEN TO CALL: When the user asks about automation, agents, or you notice repetitive analysis patterns.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID (optional)"},
    },
)
def recommend_agents(db: Session, params: dict):
    org_id = params.get("_org_id")
    scan_id = params.get("scan_id")

    # Check what's already deployed
    existing_agents = db.query(Agent).filter(Agent.org_id == org_id).all()
    existing_names = set((a.name or "").lower() for a in existing_agents)
    existing_scheduled = set()
    for a in existing_agents:
        schedules = db.query(AgentSchedule).filter(AgentSchedule.agent_id == a.id, AgentSchedule.is_enabled == True).first()
        if schedules:
            existing_scheduled.add(a.name.lower() if a.name else "")

    # Analyze the org's data to determine which agents would be valuable
    recommendations = []

    # Count key metrics
    finding_q = db.query(Finding)
    asset_q = db.query(Asset)
    if scan_id:
        finding_q = finding_q.filter(Finding.scan_id == scan_id)
        asset_q = asset_q.filter(Asset.scan_id == scan_id)

    total_findings = finding_q.count()
    critical_findings = finding_q.filter(Finding.severity == 4).count()
    exploit_findings = finding_q.filter(Finding.exploit_available == True).count()
    sla_breached = finding_q.filter(Finding.sla_status == "breached").count()
    inet_assets = asset_q.filter(Asset.is_internet_facing == True).count()
    total_assets = asset_q.count()

    # Check for patches
    patch_count = db.query(InventoryPatch).count()

    # Check for campaigns
    campaign_count = db.query(Campaign).filter(Campaign.org_id == org_id).count()

    # 1. Daily Triage — always valuable if there are findings
    if total_findings > 0 and "daily triage" not in existing_scheduled:
        recommendations.append({
            "template": "daily_triage",
            "name": "Daily Triage Bot",
            "reason": f"You have {total_findings:,} findings and {critical_findings:,} critical. "
                      "A daily triage agent surfaces the top risks every morning so nothing slips through.",
            "suggested_schedule": "0 8 * * 1-5",
            "schedule_description": "Weekdays at 8:00 AM",
            "priority": "high" if critical_findings > 10 else "medium",
            "tools": ["list_scans", "get_scan_summary", "get_sla_status", "get_top_risky_assets",
                       "get_regression_findings", "get_quick_wins", "get_exploit_findings",
                       "get_plugin_family_stats", "write_scratchpad"],
        })

    # 2. Patch Tuesday — if there are missing patches
    if patch_count > 0 and "patch tuesday" not in existing_scheduled:
        recommendations.append({
            "template": "patch_tuesday",
            "name": "Patch Tuesday Planner",
            "reason": f"You have {patch_count:,} missing patches tracked. "
                      "A monthly Patch Tuesday agent builds a prioritized deployment plan automatically.",
            "suggested_schedule": "0 9 * * 3#2",
            "schedule_description": "Second Wednesday of each month at 9:00 AM",
            "priority": "high" if patch_count > 50 else "medium",
            "tools": ["list_scans", "get_scan_summary", "get_missing_patches", "get_exploit_findings",
                       "get_os_breakdown", "get_remediation_grouping", "get_internet_facing_risk",
                       "query_assets", "write_scratchpad"],
        })

    # 3. SLA Monitor — if SLA breaches exist
    if sla_breached > 0 and "sla monitor" not in existing_scheduled:
        recommendations.append({
            "template": "sla_monitor",
            "name": "SLA Compliance Monitor",
            "reason": f"You have {sla_breached:,} SLA breaches right now. "
                      "An SLA monitor agent alerts you before breaches happen and escalates overdue items.",
            "suggested_schedule": "0 7 * * *",
            "schedule_description": "Every day at 7:00 AM",
            "priority": "high",
            "tools": ["get_sla_status", "query_findings", "get_owner_workload",
                       "send_slack_message", "send_email_alert", "write_scratchpad"],
        })

    # 4. Exploit Watch — if exploitable findings exist
    if exploit_findings > 10 and "exploit watch" not in existing_scheduled:
        recommendations.append({
            "template": "exploit_watch",
            "name": "Exploit Intelligence Watch",
            "reason": f"You have {exploit_findings:,} findings with known exploits. "
                      "This agent monitors for new exploit activity and escalates emerging threats.",
            "suggested_schedule": "0 */6 * * *",
            "schedule_description": "Every 6 hours",
            "priority": "high" if exploit_findings > 50 else "medium",
            "tools": ["get_exploit_findings", "get_threat_cves", "get_threat_campaigns",
                       "correlate_cves_with_findings", "query_findings", "write_scratchpad"],
        })

    # 5. Internet Exposure Monitor — if internet-facing assets exist
    if inet_assets > 0 and "exposure monitor" not in existing_scheduled:
        recommendations.append({
            "template": "exposure_monitor",
            "name": "Internet Exposure Monitor",
            "reason": f"You have {inet_assets:,} internet-facing assets. "
                      "This agent continuously monitors your external attack surface for new risks.",
            "suggested_schedule": "0 */4 * * *",
            "schedule_description": "Every 4 hours",
            "priority": "high" if inet_assets > 5 else "medium",
            "tools": ["get_internet_facing_risk", "analyze_attack_surface", "get_exploit_findings",
                       "query_findings", "query_assets", "write_scratchpad"],
        })

    # 6. Campaign Progress Tracker — if campaigns exist
    if campaign_count > 0 and "campaign tracker" not in existing_scheduled:
        recommendations.append({
            "template": "campaign_tracker",
            "name": "Campaign Progress Tracker",
            "reason": f"You have {campaign_count:,} remediation campaigns. "
                      "This agent checks progress daily and alerts owners who are falling behind.",
            "suggested_schedule": "0 9 * * 1-5",
            "schedule_description": "Weekdays at 9:00 AM",
            "priority": "medium",
            "tools": ["list_campaigns", "get_campaign", "get_owner_workload",
                       "send_slack_message", "send_email_alert", "write_scratchpad"],
        })

    # Sort by priority
    priority_order = {"high": 0, "medium": 1, "low": 2}
    recommendations.sort(key=lambda r: priority_order.get(r["priority"], 2))

    return {
        "existing_agents": len(existing_agents),
        "existing_scheduled": len(existing_scheduled),
        "recommendations": recommendations,
        "note": "Use create_agent and create_agent_schedule to deploy any of these. "
                "I can set them up for you — just say which ones you'd like.",
    }


@agent_tool(
    "build_report",
    "Create a saved report/dashboard template with properly configured widgets. Write operation. "
    "WHEN TO CALL: When the user asks for a dashboard, report, or recurring summary view. "
    "Always confirm with the user before creating. "
    "NEVER call this without setting confirmed=true after user approval.\n\n"
    "WIDGET FORMAT: Each widget needs type, title, width, and config with a preset.\n"
    "TYPES: card, bar_chart, line_chart, pie_chart, table, heatmap, gauge, radar, treemap, "
    "risk_grade, funnel, header, divider\n"
    "WIDTHS: quarter (25%), third (33%), half (50%), two-thirds (66%), full (100%)\n\n"
    "GLOBAL PRESETS (show all data, no filtering):\n"
    "- Cards: critical_count, high_count, medium_count, low_count, total_findings, total_assets, "
    "exploit_count, sla_compliance, sla_breached, quick_wins, regression_count\n"
    "- Pie/bar: severity_breakdown, effort_breakdown, sla_status, family_breakdown, owner_breakdown\n"
    "- Tables: top_assets, quick_wins_table, remediation_queue_data, aggregated_solutions_table\n"
    "- Time series: preset='custom_series' with metrics=['critical','high','medium','low'], time_group='scan'\n"
    "- Special: risk_grade, gauge_sla_compliance, radar_risk_dimensions, treemap_family_severity\n\n"
    "FILTERED PRESETS (for topic-specific reports — ransomware, plugin family, exploits, etc.):\n"
    "- finding_count_filtered — card showing count of findings matching filters\n"
    "- severity_breakdown_filtered — pie/bar chart showing severity breakdown of filtered findings\n"
    "- findings_list — table listing individual filtered findings (supports limit)\n"
    "Filters go in config.filters: ransomware_linked, plugin_family, has_exploit, is_kev, severity, "
    "sla_status, effort_level, search, sort_by, order, page_size\n\n"
    "IMPORTANT: For any topic-specific report (ransomware, a plugin family, exploits, KEV, etc.) "
    "use the FILTERED presets with appropriate filters, NOT the global presets.\n\n"
    "EXAMPLE — Ransomware report:\n"
    '[{"type":"card","title":"Ransomware Findings","width":"quarter","config":{"preset":"finding_count_filtered","filters":{"ransomware_linked":"true"}}}, '
    '{"type":"pie_chart","title":"By Severity","width":"half","config":{"preset":"severity_breakdown_filtered","filters":{"ransomware_linked":"true"}}}, '
    '{"type":"table","title":"Top Findings","width":"full","config":{"preset":"findings_list","limit":20,"filters":{"ransomware_linked":"true","sort_by":"priority_score","order":"desc"}}}]\n\n'
    "EXAMPLE — Global overview:\n"
    '[{"type":"card","title":"Critical","width":"quarter","config":{"preset":"critical_count"}}, '
    '{"type":"pie_chart","title":"Severity","width":"half","config":{"preset":"severity_breakdown","donut":true}}, '
    '{"type":"table","title":"Riskiest Assets","width":"full","config":{"preset":"top_assets","limit":10}}]',
    {
        "name": {"type": "string", "description": "Report name (e.g. 'Executive Risk Summary')"},
        "description": {"type": "string", "description": "What the report should show"},
        "widgets": {
            "type": "array",
            "description": "List of widget objects. Each must have: type, title, width, config (with preset).",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "description": "Widget type: card, bar_chart, line_chart, pie_chart, table, heatmap, gauge, radar, treemap, risk_grade, funnel, header, divider"},
                    "title": {"type": "string", "description": "Widget display title"},
                    "width": {"type": "string", "description": "Layout width: quarter, third, half, two-thirds, full"},
                    "config": {"type": "object", "description": "Widget config with preset and type-specific options"},
                },
            },
        },
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def build_report(db: Session, params: dict):
    from models.models import ReportTemplate
    import uuid

    name = params.get("name")
    if not name:
        return {"error": "Report name is required"}

    widgets = params.get("widgets", [])
    if not widgets:
        return {"error": "At least one widget is required. See the tool description for the exact format."}

    valid_types = {
        "card", "bar_chart", "line_chart", "pie_chart", "table", "heatmap",
        "gauge", "radar", "treemap", "risk_grade", "funnel", "header", "divider", "image",
    }
    valid_widths = {"quarter", "third", "half", "two-thirds", "full"}

    normalized = []
    for i, w in enumerate(widgets):
        wtype = w.get("type", "card")
        if wtype not in valid_types:
            return {"error": f"Widget {i+1}: invalid type '{wtype}'. Valid: {sorted(valid_types)}"}

        width = w.get("width", "half")
        if width not in valid_widths:
            width = "half"

        config = w.get("config", {})
        widget_id = f"ai_{uuid.uuid4().hex[:6]}"

        normalized.append({
            "id": widget_id,
            "type": wtype,
            "title": w.get("title", f"Widget {i+1}"),
            "width": width,
            "config": config,
        })

    # Check for existing report with same name
    existing = db.query(ReportTemplate).filter(
        ReportTemplate.name == name,
        ReportTemplate.org_id == params.get("_org_id"),
    ).first()
    if existing:
        existing.config = {"widgets": normalized}
        existing.description = params.get("description", "")
        db.commit()
        return {
            "report_id": existing.id,
            "name": name,
            "widget_count": len(normalized),
            "updated": True,
            "message": f"Report '{name}' updated with {len(normalized)} widgets.",
        }

    template = ReportTemplate(
        org_id=params.get("_org_id"),
        name=name,
        description=params.get("description", ""),
        config={"widgets": normalized},
    )
    db.add(template)
    db.commit()
    db.refresh(template)
    return {
        "report_id": template.id,
        "name": name,
        "widget_count": len(normalized),
        "message": f"Report '{name}' created with {len(normalized)} widgets. "
                   f"View it at /reports/{template.id}",
    }


@agent_tool(
    "create_agent",
    "Create a new AI agent with a name, instructions, selected tools, and optional guardrails. Write operation. "
    "WHEN TO CALL: When the user wants to set up a new automated agent for tasks like daily triage, "
    "compliance monitoring, or remediation tracking. Always confirm with the user before creating. "
    "NEVER call this without setting confirmed=true after user approval.",
    {
        "name": {"type": "string", "description": "Agent name (e.g. 'Daily Triage Bot', 'Compliance Monitor')"},
        "description": {"type": "string", "description": "Brief description of what the agent does"},
        "system_prompt": {"type": "string", "description": "Instructions for the agent — what it should do when run"},
        "tools": {"type": "array", "items": {"type": "string"}, "description": "List of tool names the agent can use (from the tool catalog)"},
        "model": {"type": "string", "description": "Optional: LLM model to use (default: claude-sonnet-4-6)"},
        "guardrails": {"type": "object", "description": "Optional: {max_steps: int, read_only: bool} — constraints on agent behavior"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def create_agent_tool(db: Session, params: dict):
    name = params.get("name")
    system_prompt = params.get("system_prompt")
    if not name or not system_prompt:
        return {"error": "name and system_prompt are required"}
    tools = params.get("tools", [])
    # Validate tool names
    invalid = [t for t in tools if t not in TOOL_REGISTRY]
    if invalid:
        return {"error": f"Unknown tools: {invalid}. Use list_agents or get_tool_catalog to see available tools."}
    agent = Agent(
        name=name,
        description=params.get("description", ""),
        system_prompt=system_prompt,
        tools=tools,
        model=params.get("model", "claude-sonnet-4-6"),
        guardrails=params.get("guardrails", {"max_steps": 15}),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return {
        "id": agent.id, "name": agent.name, "description": agent.description,
        "model": agent.model, "tools": agent.tools, "guardrails": agent.guardrails,
        "message": f"Agent '{agent.name}' created successfully (ID: {agent.id}). You can now schedule it with create_agent_schedule.",
    }


@agent_tool(
    "create_agent_schedule",
    "Create a cron schedule for an existing agent so it runs automatically. Write operation. "
    "WHEN TO CALL: After creating an agent or when the user wants to schedule an existing agent. "
    "Always confirm with the user before creating. "
    "NEVER call this without setting confirmed=true after user approval.",
    {
        "agent_id": {"type": "integer", "description": "ID of the agent to schedule (use list_agents to find it)"},
        "cron_expression": {"type": "string", "description": "Cron schedule (e.g. '0 8 * * 1-5' for weekdays at 8am, '0 */6 * * *' for every 6 hours)"},
        "input": {"type": "string", "description": "Default input/prompt for scheduled runs"},
        "is_enabled": {"type": "boolean", "description": "Whether the schedule is active (default: true)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this action"},
    },
)
def create_agent_schedule_tool(db: Session, params: dict):
    agent_id = params.get("agent_id")
    cron_expr = params.get("cron_expression")
    if not agent_id or not cron_expr:
        return {"error": "agent_id and cron_expression are required"}
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        return {"error": f"Agent {agent_id} not found"}
    schedule = AgentSchedule(
        agent_id=agent_id,
        cron_expression=cron_expr,
        input_template=params.get("input", ""),
        is_enabled=params.get("is_enabled", True),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    # Notify scheduler to pick up new job
    try:
        from agents.agent_scheduler import sync_schedules
        sync_schedules()
    except Exception:
        pass  # Scheduler may not be running in all environments
    return {
        "id": schedule.id, "agent_id": agent_id, "agent_name": agent.name,
        "cron_expression": cron_expr, "is_enabled": schedule.is_enabled,
        "message": f"Schedule created for agent '{agent.name}' — cron: {cron_expr}",
    }


# ── EASM Scanning ───────────────────────────────────────────────────

def _run_async(coro):
    """Run an async coroutine from sync code, even when an event loop is already running."""
    import asyncio
    import concurrent.futures
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # We're inside an async context (FastAPI) — run in a new thread with its own loop
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=60)
    else:
        return asyncio.run(coro)


@agent_tool(
    "trigger_easm_scan",
    "Trigger an External Attack Surface Management (EASM) scan for a domain. "
    "This discovers internet-facing assets, subdomains, open ports, certificates, and tech stack. "
    "The scan runs asynchronously — assets are imported when it completes. "
    "WHEN TO CALL: When the user asks to scan a domain, run an EASM scan, discover external assets, "
    "or map their attack surface. NEVER call without confirmed=true.",
    {
        "domain": {"type": "string", "description": "The domain to scan (e.g., 'example.com')"},
        "scan_type": {"type": "string", "description": "'full' (default), 'discovery' (find assets only), or 'enrichment' (enrich known assets)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved"},
    },
)
def trigger_easm_scan_tool(db: Session, params: dict):
    domain = params.get("domain")
    if not domain:
        return {"error": "domain is required (e.g., 'example.com')"}
    if not params.get("confirmed"):
        return {"error": f"Confirm: trigger an EASM scan for '{domain}'? This will discover internet-facing assets."}
    scan_type = params.get("scan_type", "full")
    if scan_type not in ("full", "discovery", "enrichment"):
        return {"error": "scan_type must be 'full', 'discovery', or 'enrichment'"}

    org_id = params.get("_org_id")
    org = db.query(Organization).filter(Organization.id == org_id).first() if org_id else None
    if not org:
        return {"error": "Organization context required. Make sure an org is selected."}

    if not org.easm_org_id:
        # Try to set up EASM for this org first
        try:
            from services.easm import create_easm_org, add_easm_domain
            easm_org_id = _run_async(create_easm_org(org.name or domain))
            if easm_org_id:
                org.easm_org_id = easm_org_id
                org.easm_domain = domain
                db.commit()
            else:
                return {"error": "Failed to initialize EASM — the hakuna-scanner service may be unavailable. Check Settings > EASM."}
        except Exception as e:
            return {"error": f"Failed to initialize EASM: {str(e)}"}

    try:
        from services.easm import scan_domain
        result = _run_async(scan_domain(db, org, domain, scan_type))
        if result is None:
            return {"error": "Failed to trigger scan — hakuna-scanner may be unavailable."}
        return {
            "message": f"EASM scan triggered for '{domain}' (type: {scan_type}). Assets will be imported when the scan completes.",
            "scan_id": result.get("scan_id"),
            "run_id": result.get("run_id"),
            "domain": domain,
            "status": result.get("status", "running"),
            "next_step": "The scan runs in the background. Use list_scans to check status, or I can check back later.",
        }
    except Exception as e:
        return {"error": f"Failed to trigger EASM scan: {str(e)}"}


@agent_tool(
    "check_easm_scan_status",
    "Check the status of a running EASM scan and import discovered assets if complete. "
    "WHEN TO CALL: When the user asks about EASM scan progress, or to refresh/import EASM results.",
    {
        "scan_id": {"type": "integer", "description": "ID of the EASM scan to check"},
    },
)
def check_easm_scan_status(db: Session, params: dict):
    scan_id = params.get("scan_id")
    if not scan_id:
        return {"error": "scan_id is required"}
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": f"Scan {scan_id} not found"}
    if not scan.raw_metadata or not scan.raw_metadata.get("hakuna_org_id"):
        return {"error": f"Scan {scan_id} is not an EASM scan"}

    org_id = params.get("_org_id")
    org = db.query(Organization).filter(Organization.id == org_id).first() if org_id else None
    if not org:
        return {"error": "Organization context required."}

    try:
        from services.easm import refresh_easm_scan
        result = _run_async(refresh_easm_scan(db, org, scan_id))
        return result or {"status": "unknown", "message": "Could not determine scan status."}
    except Exception as e:
        return {"error": f"Failed to check scan status: {str(e)}"}


@agent_tool(
    "list_easm_domains",
    "List the domains configured for EASM scanning in this organization. "
    "WHEN TO CALL: When the user asks about their EASM configuration, monitored domains, or attack surface scope.",
    {},
)
def list_easm_domains(db: Session, params: dict):
    org_id = params.get("_org_id")
    org = db.query(Organization).filter(Organization.id == org_id).first() if org_id else None
    if not org:
        return {"error": "Organization context required."}
    if not org.easm_org_id:
        return {
            "domains": [],
            "message": "EASM is not configured for this organization. Use trigger_easm_scan with a domain to get started.",
        }
    try:
        from services.easm import get_easm_domains
        domains = _run_async(get_easm_domains(org.easm_org_id))
        return {"domains": domains or [], "easm_org_id": org.easm_org_id}
    except Exception as e:
        return {"error": f"Failed to fetch EASM domains: {str(e)}"}


# ── Settings Tools ──────────────────────────────────────────────────

# ── Scan Management ─────────────────────────────────────────────────

@agent_tool(
    "delete_scan",
    "Delete a scan and all its associated findings, assets, and inventory data. "
    "This is a destructive operation — all data from this scan will be permanently removed. "
    "WHEN TO CALL: When the user wants to remove a test scan, duplicate upload, or old scan data. "
    "NEVER call without confirmed=true after user approval.",
    {
        "scan_id": {"type": "integer", "description": "ID of the scan to delete"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user has approved this destructive action"},
    },
)
def delete_scan(db: Session, params: dict):
    scan_id = params.get("scan_id")
    if not scan_id:
        return {"error": "scan_id is required"}
    if not params.get("confirmed"):
        return {"error": "This is a destructive action. Describe what will be deleted and ask the user to confirm first."}
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": f"Scan {scan_id} not found"}
    scan_name = scan.filename or f"Scan #{scan_id}"
    # Count what will be deleted
    finding_count = db.query(Finding).filter(Finding.scan_id == scan_id).count()
    asset_count = db.query(Asset).filter(Asset.scan_id == scan_id).count()
    # Delete related data
    db.query(Finding).filter(Finding.scan_id == scan_id).delete()
    db.query(Asset).filter(Asset.scan_id == scan_id).delete()
    db.delete(scan)
    db.commit()
    return {
        "message": f"Scan '{scan_name}' deleted along with {finding_count} findings and {asset_count} assets.",
        "deleted": {"scan_id": scan_id, "findings": finding_count, "assets": asset_count},
    }


@agent_tool(
    "rename_scan",
    "Rename a scan's display name. "
    "WHEN TO CALL: When the user wants to rename or relabel a scan for better organization.",
    {
        "scan_id": {"type": "integer", "description": "ID of the scan to rename"},
        "new_name": {"type": "string", "description": "New name/label for the scan"},
        "confirmed": {"type": "boolean", "description": "Set to true after user approval"},
    },
)
def rename_scan(db: Session, params: dict):
    scan_id = params.get("scan_id")
    new_name = params.get("new_name")
    if not scan_id or not new_name:
        return {"error": "scan_id and new_name are required"}
    if not params.get("confirmed"):
        return {"error": "Describe the rename and ask the user to confirm."}
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": f"Scan {scan_id} not found"}
    old_name = scan.filename
    scan.filename = new_name
    db.commit()
    return {"message": f"Scan renamed from '{old_name}' to '{new_name}'", "scan_id": scan_id}


# ── Deduplication Settings ──────────────────────────────────────────

@agent_tool(
    "get_dedup_config",
    "Retrieve the current deduplication configuration including strategies and key fields for assets, findings, and inventory. "
    "WHEN TO CALL: When the user asks about dedup settings, how duplicates are handled, or wants to review/change dedup config. "
    "Always call this before updating dedup config to show the user what will change.",
    {},
)
def get_dedup_config(db: Session, params: dict):
    from services.dedup import load_config
    config = load_config()
    return {
        "config": config,
        "help": {
            "strategies": "keep_first (oldest wins), keep_last (newest wins), merge (combine fields)",
            "key_fields": "Fields used to identify duplicates. E.g., assets match on ip+hostname, findings match on plugin_id+asset_id+port.",
        },
    }


@agent_tool(
    "update_dedup_config",
    "Update the deduplication configuration. You can change the strategy (keep_first, keep_last, merge) "
    "and key fields used to match duplicates for assets, findings, and inventory. "
    "WHEN TO CALL: When the user wants to change how duplicates are detected or resolved. "
    "ALWAYS call get_dedup_config first to show current settings. NEVER call without confirmed=true.",
    {
        "asset_config": {"type": "object", "description": "Optional: {strategy: 'keep_first'|'keep_last'|'merge', key_fields: ['ip','hostname',...]}"},
        "findings_config": {"type": "object", "description": "Optional: {strategy: 'keep_first'|'keep_last'|'merge', key_fields: ['plugin_id','asset_id','port',...]}"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def update_dedup_config(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "Show the user what will change and ask for confirmation first."}
    from services.dedup import load_config, save_config
    config = load_config()
    if params.get("asset_config"):
        ac = params["asset_config"]
        if "strategy" in ac:
            config.setdefault("assets", {})["strategy"] = ac["strategy"]
        if "key_fields" in ac:
            config.setdefault("assets", {})["key_fields"] = ac["key_fields"]
    if params.get("findings_config"):
        fc = params["findings_config"]
        if "strategy" in fc:
            config.setdefault("findings", {})["strategy"] = fc["strategy"]
        if "key_fields" in fc:
            config.setdefault("findings", {})["key_fields"] = fc["key_fields"]
    save_config(config)
    return {"message": "Dedup configuration updated.", "config": config}


@agent_tool(
    "run_dedup",
    "Run deduplication on-demand for assets, findings, or inventory. "
    "WHEN TO CALL: When the user wants to deduplicate data after changing config or after a scan upload. "
    "NEVER call without confirmed=true.",
    {
        "entity_type": {"type": "string", "description": "'assets', 'findings', or 'inventory'"},
        "scan_id": {"type": "integer", "description": "Optional: limit dedup to a specific scan"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def run_dedup(db: Session, params: dict):
    entity_type = params.get("entity_type", "assets")
    if not params.get("confirmed"):
        return {"error": "Describe what will be deduplicated and ask for confirmation."}
    from services.dedup import run_db_dedup
    result = run_db_dedup(db, entity_type, scan_id=params.get("scan_id"))
    return {"message": f"Dedup completed for {entity_type}.", "result": result}


# ── Risk Scoring Settings ───────────────────────────────────────────

@agent_tool(
    "get_risk_config",
    "Retrieve the current risk scoring configuration including formula weights, severity scores, "
    "and criticality auto-rules. "
    "WHEN TO CALL: When the user asks about risk scoring, how priority scores are calculated, "
    "or wants to review/change risk configuration.",
    {},
)
def get_risk_config(db: Session, params: dict):
    from core.risk_config import load_config_for_org, has_org_override
    org_id = params.get("_org_id")
    config = load_config_for_org(db, org_id)
    config["is_org_override"] = has_org_override(db, org_id)
    return {
        "config": config,
        "help": {
            "formula_weights": "Weights for each factor in the 0-10 priority score: severity, exploitability, intel, criticality, controls, reachability. Must sum to ~1.0.",
            "severity_scores": "Base score (0-10) for each severity level: critical, high, medium, low, info.",
            "criticality_rules": "Auto-rules that assign asset criticality (critical/high/medium/low) based on conditions like hostname patterns, IP ranges, tags, etc.",
            "resolution_mode": "How multiple matching rules resolve: first_match, last_match, or max.",
        },
    }


@agent_tool(
    "update_risk_config",
    "Update risk scoring weights or severity base scores. "
    "WHEN TO CALL: When the user wants to tune how priority scores are calculated. "
    "ALWAYS call get_risk_config first. NEVER call without confirmed=true.",
    {
        "formula_weights": {"type": "object", "description": "Optional: {severity: 0.35, exploitability: 0.25, intel: 0.15, criticality: 0.15, controls: 0.05, reachability: 0.05}"},
        "severity_scores": {"type": "object", "description": "Optional: {critical: 10, high: 8, medium: 5, low: 2, info: 0}"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def update_risk_config(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "Show the user what will change and ask for confirmation first."}
    from core.risk_config import load_config_for_org, save_config_for_org
    org_id = params.get("_org_id")
    config = load_config_for_org(db, org_id)
    config.pop("is_org_override", None)
    if params.get("formula_weights"):
        config["formula_weights"] = {**config.get("formula_weights", {}), **params["formula_weights"]}
    if params.get("severity_scores"):
        config["severity_scores"] = {**config.get("severity_scores", {}), **params["severity_scores"]}
    save_config_for_org(db, org_id, config)
    return {"message": "Risk scoring configuration updated. Run recalculate_risk_scores to apply to existing data.", "config": config}


@agent_tool(
    "manage_criticality_rules",
    "List, create, update, or delete criticality auto-rules that assign asset criticality levels "
    "based on conditions (hostname patterns, IP ranges, tags, OS, etc.). "
    "WHEN TO CALL: When the user wants to configure how assets are classified as critical/high/medium/low. "
    "For create/update/delete, NEVER call without confirmed=true.",
    {
        "action": {"type": "string", "description": "'list', 'create', 'update', or 'delete'"},
        "rule": {"type": "object", "description": "For create/update: {name, criticality: 'critical'|'high'|'medium'|'low', conditions: [{field, op, value}], condition_logic: 'AND'|'OR', priority: int}"},
        "rule_index": {"type": "integer", "description": "For update/delete: index of the rule in the list"},
        "confirmed": {"type": "boolean", "description": "Required for create/update/delete"},
    },
)
def manage_criticality_rules(db: Session, params: dict):
    action = params.get("action", "list")
    from core.risk_config import load_config_for_org, save_config_for_org
    org_id = params.get("_org_id")
    config = load_config_for_org(db, org_id)
    config.pop("is_org_override", None)
    rules = config.get("criticality_rules", [])

    if action == "list":
        return {
            "rules": rules,
            "resolution_mode": config.get("resolution_mode", "first_match"),
            "help": "Rules assign criticality to assets based on conditions. Fields: hostname, fqdn, ip, os, netbios_name, has_tag. Ops: eq, neq, contains, regex, cidr, starts_with, ends_with.",
        }
    if not params.get("confirmed"):
        return {"error": "Describe the change and ask for confirmation first."}
    if action == "create":
        rule = params.get("rule", {})
        if not rule.get("name") or not rule.get("criticality"):
            return {"error": "Rule must have name and criticality"}
        rules.append(rule)
        config["criticality_rules"] = rules
        save_config_for_org(db, org_id, config)
        return {"message": f"Criticality rule '{rule['name']}' created.", "rules": rules}
    elif action == "update":
        idx = params.get("rule_index")
        if idx is None or idx >= len(rules):
            return {"error": f"Invalid rule_index. There are {len(rules)} rules (0-indexed)."}
        rules[idx] = {**rules[idx], **params.get("rule", {})}
        config["criticality_rules"] = rules
        save_config_for_org(db, org_id, config)
        return {"message": f"Criticality rule at index {idx} updated.", "rules": rules}
    elif action == "delete":
        idx = params.get("rule_index")
        if idx is None or idx >= len(rules):
            return {"error": f"Invalid rule_index. There are {len(rules)} rules (0-indexed)."}
        removed = rules.pop(idx)
        config["criticality_rules"] = rules
        save_config_for_org(db, org_id, config)
        return {"message": f"Criticality rule '{removed.get('name', idx)}' deleted.", "rules": rules}
    return {"error": f"Unknown action '{action}'. Use list, create, update, or delete."}


@agent_tool(
    "recalculate_risk_scores",
    "Recompute risk scores for all assets and findings based on current risk configuration. "
    "Optionally re-apply criticality rules before recalculating. "
    "WHEN TO CALL: After updating risk config or criticality rules. NEVER call without confirmed=true.",
    {
        "scan_id": {"type": "integer", "description": "Optional: limit to a specific scan"},
        "apply_criticality_rules": {"type": "boolean", "description": "Whether to re-evaluate criticality rules first (default true)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def recalculate_risk_scores(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "This will recalculate scores for all data. Ask for confirmation."}
    from core.risk_config import load_config_for_org, evaluate_criticality_rules
    org_id = params.get("_org_id")
    config = load_config_for_org(db, org_id)
    scan_id = params.get("scan_id")
    apply_crit = params.get("apply_criticality_rules", True)

    q = db.query(Asset)
    if scan_id:
        q = q.filter(Asset.scan_id == scan_id)
    assets = q.all()

    if apply_crit:
        rules = config.get("criticality_rules", [])
        if rules:
            for asset in assets:
                result = evaluate_criticality_rules(asset, rules, config.get("resolution_mode", "first_match"))
                if result:
                    asset.criticality = result

    # Recalculate risk scores using the prioritizer
    from services.prioritizer import calculate_priority_score
    updated_assets = 0
    for asset in assets:
        findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()
        for f in findings:
            f.priority_score = calculate_priority_score(f, asset)
        asset.risk_score = max((f.priority_score for f in findings), default=0)
        updated_assets += 1

    db.commit()
    return {"message": f"Risk scores recalculated for {updated_assets} assets.", "scan_id": scan_id}


# ── SLA Settings ────────────────────────────────────────────────────

@agent_tool(
    "get_sla_config",
    "Retrieve the current SLA configuration: remediation deadlines and warning thresholds per severity level. "
    "WHEN TO CALL: When the user asks about SLA policies, deadlines, or wants to review/change SLA settings.",
    {},
)
def get_sla_config(db: Session, params: dict):
    configs = db.query(SLAConfig).order_by(SLAConfig.severity.desc()).all()
    if not configs:
        return {
            "configs": [],
            "message": "No SLA configuration found. Default SLAs will be used: Critical=15d, High=30d, Medium=90d, Low=180d.",
        }
    return {
        "configs": [
            {
                "id": c.id,
                "severity": c.severity,
                "severity_label": {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}.get(c.severity, str(c.severity)),
                "days_to_remediate": c.days_to_remediate,
                "warn_days_before": c.warn_days_before,
                "is_enabled": c.is_enabled,
            }
            for c in configs
        ],
    }


@agent_tool(
    "update_sla_config",
    "Update SLA deadlines and warning thresholds for one or more severity levels. "
    "WHEN TO CALL: When the user wants to change remediation deadlines. "
    "ALWAYS call get_sla_config first. NEVER call without confirmed=true.",
    {
        "configs": {
            "type": "array",
            "description": "Array of {severity: int (4=Critical,3=High,2=Medium,1=Low,0=Info), days_to_remediate: int, warn_days_before: int, is_enabled: bool}",
        },
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def update_sla_config(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "Show the user what will change and ask for confirmation first."}
    configs = params.get("configs", [])
    if not configs:
        return {"error": "Provide at least one SLA config entry."}
    results = []
    for entry in configs:
        sev = entry.get("severity")
        if sev is None:
            continue
        existing = db.query(SLAConfig).filter(SLAConfig.severity == sev).first()
        if existing:
            if "days_to_remediate" in entry:
                existing.days_to_remediate = entry["days_to_remediate"]
            if "warn_days_before" in entry:
                existing.warn_days_before = entry["warn_days_before"]
            if "is_enabled" in entry:
                existing.is_enabled = entry["is_enabled"]
        else:
            existing = SLAConfig(
                severity=sev,
                days_to_remediate=entry.get("days_to_remediate", 30),
                warn_days_before=entry.get("warn_days_before", 7),
                is_enabled=entry.get("is_enabled", True),
            )
            db.add(existing)
        results.append({"severity": sev, "days_to_remediate": existing.days_to_remediate})
    db.commit()
    return {"message": f"SLA configuration updated for {len(results)} severity levels.", "updated": results}


@agent_tool(
    "recalculate_sla",
    "Recompute SLA due dates and status for all findings based on current SLA configuration. "
    "WHEN TO CALL: After updating SLA config. NEVER call without confirmed=true.",
    {
        "scan_id": {"type": "integer", "description": "Optional: limit to a specific scan"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def recalculate_sla(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "Ask for confirmation before recalculating SLA for all findings."}
    from services.sla_engine import recalculate_sla_for_scan
    scan_id = params.get("scan_id")
    if scan_id:
        result = recalculate_sla_for_scan(db, scan_id)
        return {"message": f"SLA recalculated for scan {scan_id}.", "result": result}
    # Recalculate for all scans
    scans = db.query(Scan).all()
    total = 0
    for scan in scans:
        result = recalculate_sla_for_scan(db, scan.id)
        total += result.get("updated", 0) if isinstance(result, dict) else 0
    return {"message": f"SLA recalculated across {len(scans)} scans ({total} findings updated)."}


# ── Exception / Waiver Management ───────────────────────────────────

@agent_tool(
    "list_exceptions",
    "List all global exceptions/waivers with their type, scope, and status. "
    "WHEN TO CALL: When the user asks about exceptions, waivers, risk acceptances, false positives, or compensating controls.",
    {
        "exception_type": {"type": "string", "description": "Optional filter: 'false_positive', 'accepted_risk', 'compensating_control', 'technical_debt', 'severity_override'"},
        "active_only": {"type": "boolean", "description": "Only show non-expired exceptions (default true)"},
    },
)
def list_exceptions(db: Session, params: dict):
    q = db.query(FindingException)
    if params.get("exception_type"):
        q = q.filter(FindingException.exception_type == params["exception_type"])
    if params.get("active_only", True):
        q = q.filter(
            (FindingException.expires_at == None) |
            (FindingException.expires_at > datetime.utcnow())
        )
    exceptions = q.order_by(FindingException.created_at.desc()).limit(50).all()
    return {
        "total": q.count(),
        "exceptions": [
            {
                "id": e.id,
                "plugin_id": e.plugin_id,
                "plugin_name": e.plugin_name,
                "asset_ip": e.asset_ip,
                "exception_type": e.exception_type,
                "reason": e.reason,
                "approved_by": e.approved_by,
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                "exclude_from_reports": e.exclude_from_reports,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in exceptions
        ],
    }


@agent_tool(
    "manage_exception",
    "Create, update, or delete a global exception/waiver. Supports types: false_positive, accepted_risk, "
    "compensating_control, technical_debt, severity_override. "
    "WHEN TO CALL: When the user wants to manage exceptions from the settings page. "
    "NEVER call without confirmed=true.",
    {
        "action": {"type": "string", "description": "'create', 'update', or 'delete'"},
        "exception_id": {"type": "integer", "description": "For update/delete: the exception ID"},
        "plugin_id": {"type": "string", "description": "For create: Nessus plugin ID to exempt"},
        "plugin_name": {"type": "string", "description": "For create: plugin name for reference"},
        "asset_ip": {"type": "string", "description": "For create: scope to specific asset IP (optional, omit for global)"},
        "exception_type": {"type": "string", "description": "false_positive, accepted_risk, compensating_control, technical_debt, severity_override"},
        "reason": {"type": "string", "description": "Justification for the exception"},
        "approved_by": {"type": "string", "description": "Name of the approver"},
        "expires_at": {"type": "string", "description": "ISO date when exception expires (optional)"},
        "exclude_from_reports": {"type": "boolean", "description": "Whether to hide matched findings from reports (default false)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def manage_exception(db: Session, params: dict):
    action = params.get("action", "create")
    if not params.get("confirmed"):
        return {"error": "Describe the exception and ask for confirmation first."}
    if action == "create":
        if not params.get("plugin_id") or not params.get("exception_type"):
            return {"error": "plugin_id and exception_type are required"}
        exc = FindingException(
            plugin_id=params["plugin_id"],
            plugin_name=params.get("plugin_name", ""),
            asset_ip=params.get("asset_ip"),
            exception_type=params["exception_type"],
            reason=params.get("reason", ""),
            approved_by=params.get("approved_by", ""),
            exclude_from_reports=params.get("exclude_from_reports", False),
        )
        if params.get("expires_at"):
            try:
                exc.expires_at = datetime.fromisoformat(params["expires_at"].replace("Z", "+00:00"))
            except ValueError:
                return {"error": "Invalid expires_at format. Use ISO format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"}
        db.add(exc)
        db.commit()
        db.refresh(exc)
        return {"message": f"Exception created (ID: {exc.id}) for plugin {exc.plugin_id}.", "id": exc.id}
    elif action == "update":
        exc_id = params.get("exception_id")
        if not exc_id:
            return {"error": "exception_id is required for update"}
        exc = db.query(FindingException).filter(FindingException.id == exc_id).first()
        if not exc:
            return {"error": f"Exception {exc_id} not found"}
        for field in ["exception_type", "reason", "approved_by", "exclude_from_reports", "asset_ip"]:
            if field in params:
                setattr(exc, field, params[field])
        if "expires_at" in params:
            try:
                exc.expires_at = datetime.fromisoformat(params["expires_at"].replace("Z", "+00:00")) if params["expires_at"] else None
            except ValueError:
                return {"error": "Invalid expires_at format"}
        db.commit()
        return {"message": f"Exception {exc_id} updated."}
    elif action == "delete":
        exc_id = params.get("exception_id")
        if not exc_id:
            return {"error": "exception_id is required for delete"}
        exc = db.query(FindingException).filter(FindingException.id == exc_id).first()
        if not exc:
            return {"error": f"Exception {exc_id} not found"}
        db.delete(exc)
        db.commit()
        return {"message": f"Exception {exc_id} deleted."}
    return {"error": f"Unknown action '{action}'."}


# ── Ownership Rules ─────────────────────────────────────────────────

@agent_tool(
    "list_ownership_rules",
    "List all ownership rules that auto-assign owners to assets/findings based on conditions. "
    "WHEN TO CALL: When the user asks about ownership rules, who owns what, or how ownership is assigned.",
    {},
)
def list_ownership_rules(db: Session, params: dict):
    rules = db.query(OwnershipRule).order_by(OwnershipRule.priority).all()
    return {
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "target_type": r.target_type,
                "conditions": r.conditions,
                "condition_logic": r.condition_logic,
                "priority": r.priority,
                "owner_name": r.owner_name,
                "owner_email": r.owner_email,
                "owner_role": r.owner_role,
                "team": r.team,
                "is_enabled": r.is_enabled,
            }
            for r in rules
        ],
        "help": "Rules are evaluated in priority order (lower number = higher priority). Conditions use the same operators as auto-tag rules.",
    }


@agent_tool(
    "manage_ownership_rule",
    "Create, update, or delete an ownership rule that auto-assigns owners to assets/findings. "
    "WHEN TO CALL: When the user wants to set up or modify ownership assignment rules. "
    "NEVER call without confirmed=true.",
    {
        "action": {"type": "string", "description": "'create', 'update', or 'delete'"},
        "rule_id": {"type": "integer", "description": "For update/delete: the rule ID"},
        "name": {"type": "string", "description": "Rule name"},
        "description": {"type": "string", "description": "Rule description"},
        "target_type": {"type": "string", "description": "'asset', 'finding', or 'both'"},
        "conditions": {"type": "array", "description": "Array of {field, op, value} condition objects"},
        "condition_logic": {"type": "string", "description": "'AND' or 'OR'"},
        "priority": {"type": "integer", "description": "Priority (lower = evaluated first)"},
        "owner_name": {"type": "string", "description": "Owner name to assign"},
        "owner_email": {"type": "string", "description": "Owner email to assign"},
        "owner_role": {"type": "string", "description": "Owner role. Common values: IT, HelpDesk, DevOps, SRE, Platform, Networking, CloudOps, DBA, SecOps, SOC, AppSec, CloudSec, IAM, GRC, Engineering, Mobile, Data, Custom"},
        "team": {"type": "string", "description": "Team name to assign"},
        "is_enabled": {"type": "boolean", "description": "Whether the rule is active"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def manage_ownership_rule(db: Session, params: dict):
    action = params.get("action", "create")
    if not params.get("confirmed"):
        return {"error": "Describe the rule and ask for confirmation first."}
    if action == "create":
        if not params.get("name"):
            return {"error": "name is required"}
        rule = OwnershipRule(
            name=params["name"],
            description=params.get("description", ""),
            target_type=params.get("target_type", "asset"),
            conditions=params.get("conditions", []),
            condition_logic=params.get("condition_logic", "AND"),
            priority=params.get("priority", 100),
            owner_name=params.get("owner_name"),
            owner_email=params.get("owner_email"),
            owner_role=params.get("owner_role"),
            team=params.get("team"),
            is_enabled=params.get("is_enabled", True),
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return {"message": f"Ownership rule '{rule.name}' created (ID: {rule.id}).", "id": rule.id}
    elif action == "update":
        rule_id = params.get("rule_id")
        if not rule_id:
            return {"error": "rule_id is required for update"}
        rule = db.query(OwnershipRule).filter(OwnershipRule.id == rule_id).first()
        if not rule:
            return {"error": f"Ownership rule {rule_id} not found"}
        for field in ["name", "description", "target_type", "conditions", "condition_logic", "priority",
                       "owner_name", "owner_email", "owner_role", "team", "is_enabled"]:
            if field in params:
                setattr(rule, field, params[field])
        db.commit()
        return {"message": f"Ownership rule '{rule.name}' updated."}
    elif action == "delete":
        rule_id = params.get("rule_id")
        if not rule_id:
            return {"error": "rule_id is required for delete"}
        rule = db.query(OwnershipRule).filter(OwnershipRule.id == rule_id).first()
        if not rule:
            return {"error": f"Ownership rule {rule_id} not found"}
        name = rule.name
        db.delete(rule)
        db.commit()
        return {"message": f"Ownership rule '{name}' deleted."}
    return {"error": f"Unknown action '{action}'."}


@agent_tool(
    "run_ownership_rules",
    "Apply all enabled ownership rules to assign owners to assets/findings. "
    "WHEN TO CALL: After creating/updating ownership rules or when the user wants to re-apply ownership. "
    "NEVER call without confirmed=true.",
    {
        "scan_id": {"type": "integer", "description": "Optional: limit to a specific scan"},
        "overwrite": {"type": "boolean", "description": "Whether to overwrite existing ownership (default false)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def run_ownership_rules(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "Ask for confirmation before applying ownership rules."}
    from services.tags import run_all_ownership_rules
    result = run_all_ownership_rules(
        db,
        scan_id=params.get("scan_id"),
        overwrite=params.get("overwrite", False),
    )
    return {"message": "Ownership rules applied.", "result": result}


# ── RBAC — Custom Roles ────────────────────────────────────────────

@agent_tool(
    "list_custom_roles",
    "List all custom roles defined for the organization, including their permissions. "
    "WHEN TO CALL: When the user asks about roles, permissions, RBAC, or access control.",
    {},
)
def list_custom_roles(db: Session, params: dict):
    roles = db.query(CustomRole).filter(CustomRole.is_active == True).all()
    return {
        "roles": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "base_permissions": r.base_permissions,
                "deny_permissions": r.deny_permissions,
            }
            for r in roles
        ],
        "available_permissions": [
            "read", "write", "delete", "export",
            "manage_campaigns", "manage_sla", "manage_risk_config",
            "manage_dedup", "manage_exceptions", "manage_ownership",
            "manage_ownership_rules", "manage_tags", "manage_auto_tag_rules",
            "manage_reports", "export_reports",
        ],
    }


@agent_tool(
    "manage_custom_role",
    "Create, update, or delete a custom RBAC role with granular permissions. "
    "WHEN TO CALL: When the user wants to create or modify roles and permissions. "
    "NEVER call without confirmed=true.",
    {
        "action": {"type": "string", "description": "'create', 'update', or 'delete'"},
        "role_id": {"type": "integer", "description": "For update/delete: the role ID"},
        "name": {"type": "string", "description": "Role name"},
        "description": {"type": "string", "description": "Role description"},
        "base_permissions": {"type": "object", "description": "Permission flags: {read: true, write: true, manage_tags: false, ...}"},
        "deny_permissions": {"type": "object", "description": "Deny flags (override allow): {delete: true, ...}"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def manage_custom_role(db: Session, params: dict):
    action = params.get("action", "create")
    if not params.get("confirmed"):
        return {"error": "Describe the role and permissions and ask for confirmation first."}
    if action == "create":
        if not params.get("name"):
            return {"error": "name is required"}
        role = CustomRole(
            name=params["name"],
            description=params.get("description", ""),
            base_permissions=params.get("base_permissions", {}),
            deny_permissions=params.get("deny_permissions", {}),
        )
        db.add(role)
        db.commit()
        db.refresh(role)
        return {"message": f"Custom role '{role.name}' created (ID: {role.id}).", "id": role.id}
    elif action == "update":
        role_id = params.get("role_id")
        if not role_id:
            return {"error": "role_id is required for update"}
        role = db.query(CustomRole).filter(CustomRole.id == role_id).first()
        if not role:
            return {"error": f"Role {role_id} not found"}
        for field in ["name", "description", "base_permissions", "deny_permissions"]:
            if field in params:
                setattr(role, field, params[field])
        db.commit()
        return {"message": f"Role '{role.name}' updated."}
    elif action == "delete":
        role_id = params.get("role_id")
        if not role_id:
            return {"error": "role_id is required for delete"}
        role = db.query(CustomRole).filter(CustomRole.id == role_id).first()
        if not role:
            return {"error": f"Role {role_id} not found"}
        name = role.name
        role.is_active = False  # Soft delete
        db.commit()
        return {"message": f"Role '{name}' deactivated."}
    return {"error": f"Unknown action '{action}'."}


# ── Integration Builder ─────────────────────────────────────────────

@agent_tool(
    "list_integration_builder_connectors",
    "List available out-of-the-box connector templates and active integrations in the integration builder. "
    "WHEN TO CALL: When the user asks about integration builder, connectors, data import/export pipelines, "
    "or wants to set up a new integration.",
    {},
)
def list_integration_builder_connectors(db: Session, params: dict):
    # Active integrations
    integrations = db.query(Integration).order_by(Integration.created_at.desc()).all()
    return {
        "integrations": [
            {
                "id": i.id,
                "name": i.name,
                "direction": i.direction,
                "entity": i.entity,
                "transport_type": i.transport_type,
                "enabled": i.enabled,
                "schedule": i.schedule,
                "last_run_at": i.last_run_at.isoformat() if i.last_run_at else None,
                "last_run_status": i.last_run_status,
            }
            for i in integrations
        ],
        "help": {
            "directions": "pull (import data into Hakuna) or push (export data from Hakuna)",
            "transport_types": "api (REST API), sql (database query), file (CSV/JSON upload)",
            "entities": "finding, asset, action — the Hakuna data type to import/export",
            "link": "Navigate to [Integration Builder](/settings?tab=integration-builder) to visually configure connectors.",
        },
    }


@agent_tool(
    "manage_integration",
    "Enable, disable, delete, or trigger a run for an existing integration in the integration builder. "
    "WHEN TO CALL: When the user wants to manage an existing integration. "
    "NEVER call without confirmed=true.",
    {
        "action": {"type": "string", "description": "'enable', 'disable', 'delete', or 'run'"},
        "integration_id": {"type": "integer", "description": "ID of the integration to manage"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def manage_integration(db: Session, params: dict):
    action = params.get("action")
    integration_id = params.get("integration_id")
    if not action or not integration_id:
        return {"error": "action and integration_id are required"}
    if not params.get("confirmed"):
        return {"error": "Describe the action and ask for confirmation first."}

    integ = db.query(Integration).filter(Integration.id == integration_id).first()
    if not integ:
        return {"error": f"Integration {integration_id} not found"}

    if action == "enable":
        integ.enabled = True
        db.commit()
        return {"message": f"Integration '{integ.name}' enabled."}
    elif action == "disable":
        integ.enabled = False
        db.commit()
        return {"message": f"Integration '{integ.name}' disabled."}
    elif action == "delete":
        name = integ.name
        db.delete(integ)
        db.commit()
        return {"message": f"Integration '{name}' deleted."}
    elif action == "run":
        integ.last_run_at = datetime.utcnow()
        integ.last_run_status = "running"
        db.commit()
        try:
            from services.integration_scheduler import run_integration_now
            result = run_integration_now(db, integration_id)
            return {"message": f"Integration '{integ.name}' triggered.", "result": result}
        except ImportError:
            return {"message": f"Integration '{integ.name}' marked for execution. The scheduler will pick it up."}
    return {"error": f"Unknown action '{action}'. Use enable, disable, delete, or run."}


@agent_tool(
    "get_integration_runs",
    "Get recent run history for an integration showing status, record counts, and errors. "
    "WHEN TO CALL: When the user asks about integration sync status, run history, or troubleshooting.",
    {
        "integration_id": {"type": "integer", "description": "ID of the integration"},
        "limit": {"type": "integer", "description": "Max runs to return (default 10)"},
    },
)
def get_integration_runs(db: Session, params: dict):
    integration_id = params.get("integration_id")
    if not integration_id:
        return {"error": "integration_id is required"}
    limit = min(params.get("limit", 10), 50)
    integ = db.query(Integration).filter(Integration.id == integration_id).first()
    if not integ:
        return {"error": f"Integration {integration_id} not found"}
    runs = (
        db.query(IntegrationRun)
        .filter(IntegrationRun.integration_id == integration_id)
        .order_by(IntegrationRun.started_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "integration": integ.name,
        "runs": [
            {
                "id": r.id,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "records_processed": r.records_processed,
                "records_created": r.records_created,
                "records_updated": r.records_updated,
                "errors": r.errors,
            }
            for r in runs
        ],
    }


@agent_tool(
    "get_integration_builder_targets",
    "List all importable data model targets (e.g. finding, asset, software, certificate) with their "
    "field schemas. Use this to understand what entities can be imported and what fields they accept. "
    "WHEN TO CALL: When the user wants to create a new integration and needs to know which entity "
    "types are available or what fields a target entity has.",
    {
        "target_slug": {
            "type": "string",
            "description": "Optional: specific target slug (e.g. 'finding', 'asset', 'software') to get its field schema. "
            "Omit to list all available targets.",
        },
    },
)
def get_integration_builder_targets(db: Session, params: dict):
    from integrations.model_registry import list_targets as list_registry_targets, get_target_schema
    from integrations.schema import get_schema

    slug = params.get("target_slug")
    if slug:
        schema = get_target_schema(slug) or get_schema(slug)
        if not schema:
            return {"error": f"Target '{slug}' not found. Use this tool without target_slug to list all."}
        return {"target": slug, "schema": schema}
    return list_registry_targets()


@agent_tool(
    "get_integration_builder_connector_detail",
    "Get full details for a specific connector template including authentication requirements, "
    "default transport config, and credential acquisition flow. "
    "WHEN TO CALL: When the user wants to set up a new integration and you need the connector's "
    "auth requirements and config structure.",
    {
        "connector_id": {
            "type": "string",
            "description": "The connector template ID (e.g. 'jira', 'servicenow', 'qualys', 'tenable-io')",
        },
    },
)
def get_integration_builder_connector_detail(db: Session, params: dict):
    from integrations.connector_loader import get_connector
    connector_id = params.get("connector_id")
    if not connector_id:
        return {"error": "connector_id is required"}
    c = get_connector(connector_id)
    if not c:
        return {"error": f"Connector '{connector_id}' not found. Use list_integration_builder_connectors to see available connectors."}
    return c


@agent_tool(
    "list_integration_credentials",
    "List saved credentials (metadata only, never secrets) for the current organization. "
    "WHEN TO CALL: When the user wants to create an integration and you need to find existing "
    "credentials to reuse, or to check what credentials are available.",
    {},
)
def list_integration_credentials(db: Session, params: dict):
    from models.models import IntegrationCredential
    creds = db.query(IntegrationCredential).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "connector_id": c.connector_id,
            "auth_type": c.auth_type,
            "instance_url": c.instance_url,
            "connected_user": c.connected_user,
            "created_at": str(c.created_at) if c.created_at else None,
        }
        for c in creds
    ]


@agent_tool(
    "create_integration_credential",
    "Store new credentials for use with an integration. The credential values are encrypted at rest. "
    "WHEN TO CALL: When the user provides API keys, tokens, or other auth details for a new integration. "
    "NEVER call without confirmed=true. NEVER log or echo back the credential values.",
    {
        "name": {"type": "string", "description": "Human-readable name (e.g. 'Jira Cloud - Production')"},
        "connector_id": {"type": "string", "description": "Connector template ID (e.g. 'jira', 'servicenow')"},
        "auth_type": {"type": "string", "description": "Auth type: 'api_key', 'basic', 'bearer', 'oauth2'"},
        "values": {"type": "object", "description": "Credential key-value pairs (e.g. {\"api_key\": \"...\", \"email\": \"...\"})"},
        "instance_url": {"type": "string", "description": "Optional: base URL of the external system (e.g. 'https://company.atlassian.net')"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def create_integration_credential(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "Describe the action and ask for confirmation first."}
    from models.models import IntegrationCredential
    from services import credential_vault

    name = params.get("name")
    connector_id = params.get("connector_id")
    auth_type = params.get("auth_type")
    values = params.get("values")
    if not all([name, connector_id, auth_type, values]):
        return {"error": "name, connector_id, auth_type, and values are all required"}

    try:
        encrypted = credential_vault.encrypt(values)
    except Exception as e:
        return {"error": f"Failed to encrypt credentials: {e}"}

    cred = IntegrationCredential(
        name=name,
        connector_id=connector_id,
        auth_type=auth_type,
        encrypted_values=encrypted,
        instance_url=params.get("instance_url"),
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return {"id": cred.id, "name": cred.name, "message": "Credential saved securely."}


@agent_tool(
    "create_integration",
    "Create a new integration pipeline in the integration builder. This configures a pull (import) or "
    "push (export) data pipeline between Hakuna and an external system. "
    "WHEN TO CALL: When the user wants to set up a new integration after you have gathered the "
    "connector details, credentials, entity type, and field mapping. "
    "NEVER call without confirmed=true.",
    {
        "name": {"type": "string", "description": "Integration name (e.g. 'Jira Cloud — Import Tickets')"},
        "direction": {"type": "string", "description": "'pull' (import into Hakuna) or 'push' (export from Hakuna)"},
        "entity": {"type": "string", "description": "Target entity type (e.g. 'finding', 'asset', 'software')"},
        "transport_type": {"type": "string", "description": "'api', 'sql', 'file', or 'mcp'"},
        "transport_config": {"type": "object", "description": "Transport configuration (URL, method, headers, etc.)"},
        "credentials_id": {"type": "string", "description": "Optional: ID of saved credentials to use"},
        "records_path": {"type": "string", "description": "Optional: JSONPath to the records array in API responses"},
        "field_map": {"type": "array", "description": "Field mapping rules: [{\"source\": \"api.field\", \"target\": \"hakuna_field\", \"transform\": ...}]"},
        "dedup_key": {"type": "array", "description": "Optional: fields used for deduplication (e.g. ['plugin_id', 'asset_id'])"},
        "schedule": {"type": "string", "description": "Optional: cron expression (e.g. '0 */6 * * *' for every 6 hours)"},
        "enabled": {"type": "boolean", "description": "Whether to enable immediately (default false)"},
        "template_id": {"type": "string", "description": "Optional: connector template ID this was built from"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def create_integration(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "Describe the integration config and ask for confirmation first."}

    name = params.get("name")
    direction = params.get("direction")
    entity = params.get("entity")
    transport_type = params.get("transport_type")
    if not all([name, direction, entity, transport_type]):
        return {"error": "name, direction, entity, and transport_type are required"}
    if direction not in ("pull", "push"):
        return {"error": "direction must be 'pull' or 'push'"}
    if transport_type not in ("api", "sql", "file", "mcp"):
        return {"error": "transport_type must be 'api', 'sql', 'file', or 'mcp'"}

    from integrations.model_registry import get_registry
    valid_entities = set(get_registry().keys()) | {"action"}
    if entity not in valid_entities:
        return {"error": f"entity must be one of: {sorted(valid_entities)}"}

    from integrations.connector_loader import get_connector as _get_connector
    logo_url = None
    template_id = params.get("template_id")
    if template_id:
        tpl = _get_connector(template_id)
        if tpl:
            logo_url = tpl.get("logo")

    integration = Integration(
        name=name,
        direction=direction,
        entity=entity,
        transport_type=transport_type,
        transport_config=params.get("transport_config", {}),
        credentials_id=params.get("credentials_id"),
        records_path=params.get("records_path"),
        field_map=params.get("field_map", []),
        dedup_key=params.get("dedup_key", []),
        params=params.get("params", {}),
        schedule=params.get("schedule"),
        enabled=params.get("enabled", False),
        template_id=template_id,
        logo_url=logo_url,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)

    if integration.enabled and integration.schedule:
        try:
            from services.integration_scheduler import register_integration
            register_integration(integration.id, integration.schedule)
        except ImportError:
            pass

    return {
        "id": integration.id,
        "name": integration.name,
        "direction": integration.direction,
        "entity": integration.entity,
        "enabled": integration.enabled,
        "message": f"Integration '{integration.name}' created successfully.",
        "next_step": "Use manage_integration with action='run' to trigger a test run, or action='enable' to activate it.",
    }


@agent_tool(
    "update_integration",
    "Update an existing integration's configuration (field mapping, schedule, transport config, etc.). "
    "WHEN TO CALL: When the user wants to modify an existing integration's settings. "
    "NEVER call without confirmed=true.",
    {
        "integration_id": {"type": "integer", "description": "ID of the integration to update"},
        "name": {"type": "string", "description": "Optional: new name"},
        "transport_config": {"type": "object", "description": "Optional: updated transport configuration"},
        "credentials_id": {"type": "string", "description": "Optional: new credentials ID"},
        "records_path": {"type": "string", "description": "Optional: updated records path"},
        "field_map": {"type": "array", "description": "Optional: updated field mapping rules"},
        "dedup_key": {"type": "array", "description": "Optional: updated dedup key fields"},
        "schedule": {"type": "string", "description": "Optional: updated cron schedule"},
        "enabled": {"type": "boolean", "description": "Optional: enable or disable"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def update_integration(db: Session, params: dict):
    if not params.get("confirmed"):
        return {"error": "Describe the changes and ask for confirmation first."}
    integration_id = params.get("integration_id")
    if not integration_id:
        return {"error": "integration_id is required"}

    integ = db.query(Integration).filter(Integration.id == integration_id).first()
    if not integ:
        return {"error": f"Integration {integration_id} not found"}

    updatable = ["name", "transport_config", "credentials_id", "records_path",
                 "field_map", "dedup_key", "schedule", "enabled"]
    changed = []
    for field in updatable:
        val = params.get(field)
        if val is not None:
            setattr(integ, field, val)
            changed.append(field)

    if not changed:
        return {"error": "No fields to update. Provide at least one field to change."}

    db.commit()
    db.refresh(integ)

    # Update scheduler
    try:
        from services.integration_scheduler import register_integration, deregister_integration
        if integ.enabled and integ.schedule:
            register_integration(integ.id, integ.schedule)
        else:
            deregister_integration(integ.id)
    except ImportError:
        pass

    return {
        "id": integ.id,
        "name": integ.name,
        "updated_fields": changed,
        "enabled": integ.enabled,
        "message": f"Integration '{integ.name}' updated ({', '.join(changed)}).",
    }


@agent_tool(
    "get_integration_detail",
    "Get the full configuration of an integration including transport config, field mapping, "
    "credentials reference, and schedule. "
    "WHEN TO CALL: When you need to inspect or troubleshoot an existing integration's setup.",
    {
        "integration_id": {"type": "integer", "description": "ID of the integration"},
    },
)
def get_integration_detail(db: Session, params: dict):
    integration_id = params.get("integration_id")
    if not integration_id:
        return {"error": "integration_id is required"}
    integ = db.query(Integration).filter(Integration.id == integration_id).first()
    if not integ:
        return {"error": f"Integration {integration_id} not found"}
    return {
        "id": integ.id,
        "name": integ.name,
        "direction": integ.direction,
        "entity": integ.entity,
        "transport_type": integ.transport_type,
        "transport_config": integ.transport_config,
        "credentials_id": integ.credentials_id,
        "records_path": integ.records_path,
        "field_map": integ.field_map,
        "dedup_key": integ.dedup_key,
        "params": integ.params,
        "schedule": integ.schedule,
        "enabled": integ.enabled,
        "template_id": integ.template_id,
        "logo_url": integ.logo_url,
        "last_run_at": str(integ.last_run_at) if integ.last_run_at else None,
        "last_run_status": integ.last_run_status,
        "created_at": str(integ.created_at) if integ.created_at else None,
    }


@agent_tool(
    "suggest_field_mapping",
    "Auto-suggest field mappings between source data fields and a Hakuna target entity. "
    "Provide sample source field names and the target entity to get intelligent mapping suggestions. "
    "WHEN TO CALL: When building a new integration and you need to map external fields to Hakuna fields.",
    {
        "source_fields": {
            "type": "array",
            "description": "List of field names/paths from the source data (e.g. ['ip_address', 'hostname', 'os_name'])",
        },
        "target_entity": {
            "type": "string",
            "description": "Hakuna target entity slug (e.g. 'asset', 'finding', 'software')",
        },
    },
)
def suggest_field_mapping(db: Session, params: dict):
    from services.field_mapper import auto_suggest
    from integrations.model_registry import get_target_schema
    from integrations.schema import get_schema

    source_fields = params.get("source_fields")
    target_entity = params.get("target_entity")
    if not source_fields or not target_entity:
        return {"error": "source_fields and target_entity are required"}

    schema = get_target_schema(target_entity) or get_schema(target_entity)
    if not schema:
        return {"error": f"Target entity '{target_entity}' not found"}

    # Build pseudo-paths list matching detect_paths output format
    paths = [{"path": f, "type": "string", "sample": ""} for f in source_fields]
    suggestions = auto_suggest(paths, schema)
    return {
        "target_entity": target_entity,
        "suggestions": suggestions,
        "note": "Review and adjust these suggestions before creating the integration.",
    }


# ── Tag Management (extended) ───────────────────────────────────────

@agent_tool(
    "manage_tag",
    "Update or delete an existing tag. Use create_tag for new tags. "
    "WHEN TO CALL: When the user wants to rename, recolor, reparent, or delete a tag. "
    "NEVER call without confirmed=true.",
    {
        "action": {"type": "string", "description": "'update' or 'delete'"},
        "tag_id": {"type": "integer", "description": "ID of the tag to manage"},
        "category": {"type": "string", "description": "For update: new category"},
        "value": {"type": "string", "description": "For update: new value/name"},
        "color": {"type": "string", "description": "For update: new color hex code"},
        "description": {"type": "string", "description": "For update: new description"},
        "parent_id": {"type": "integer", "description": "For update: new parent tag ID (for hierarchical tags)"},
        "delete_strategy": {"type": "string", "description": "For delete: 'reparent' (move children up) or 'cascade' (delete children too)"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def manage_tag(db: Session, params: dict):
    action = params.get("action")
    tag_id = params.get("tag_id")
    if not action or not tag_id:
        return {"error": "action and tag_id are required"}
    if not params.get("confirmed"):
        return {"error": "Describe the change and ask for confirmation first."}

    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        return {"error": f"Tag {tag_id} not found"}

    if action == "update":
        for field in ["category", "value", "color", "description", "parent_id"]:
            if field in params:
                setattr(tag, field, params[field])
        db.commit()
        return {"message": f"Tag '{tag.category}:{tag.value}' updated."}
    elif action == "delete":
        strategy = params.get("delete_strategy", "reparent")
        name = f"{tag.category}:{tag.value}"
        # Handle children
        children = db.query(Tag).filter(Tag.parent_id == tag_id).all()
        if strategy == "cascade":
            for child in children:
                db.query(TagAssignment).filter(TagAssignment.tag_id == child.id).delete()
                db.delete(child)
        else:  # reparent
            for child in children:
                child.parent_id = tag.parent_id
        # Remove assignments and delete
        db.query(TagAssignment).filter(TagAssignment.tag_id == tag_id).delete()
        db.delete(tag)
        db.commit()
        return {"message": f"Tag '{name}' deleted ({strategy} strategy, {len(children)} children handled)."}
    return {"error": f"Unknown action '{action}'."}


@agent_tool(
    "manage_auto_tag_rule",
    "Update, delete, enable, or disable an existing auto-tag rule. Use create_auto_tag_rule for new rules. "
    "WHEN TO CALL: When the user wants to modify or remove an auto-tag rule. "
    "NEVER call without confirmed=true.",
    {
        "action": {"type": "string", "description": "'update', 'delete', 'enable', or 'disable'"},
        "rule_id": {"type": "integer", "description": "ID of the auto-tag rule"},
        "name": {"type": "string", "description": "For update: new name"},
        "tag_id": {"type": "integer", "description": "For update: new tag to assign"},
        "conditions": {"type": "array", "description": "For update: new conditions [{field, op, value}]"},
        "condition_logic": {"type": "string", "description": "For update: 'AND' or 'OR'"},
        "confirmed": {"type": "boolean", "description": "REQUIRED: Set to true only after user approval"},
    },
)
def manage_auto_tag_rule(db: Session, params: dict):
    action = params.get("action")
    rule_id = params.get("rule_id")
    if not action or not rule_id:
        return {"error": "action and rule_id are required"}
    if not params.get("confirmed"):
        return {"error": "Describe the change and ask for confirmation first."}

    rule = db.query(AutoTagRule).filter(AutoTagRule.id == rule_id).first()
    if not rule:
        return {"error": f"Auto-tag rule {rule_id} not found"}

    if action == "update":
        for field in ["name", "description", "tag_id", "target_type", "conditions", "condition_logic"]:
            if field in params:
                setattr(rule, field, params[field])
        db.commit()
        return {"message": f"Auto-tag rule '{rule.name}' updated."}
    elif action in ("enable", "disable"):
        rule.is_enabled = (action == "enable")
        db.commit()
        return {"message": f"Auto-tag rule '{rule.name}' {'enabled' if rule.is_enabled else 'disabled'}."}
    elif action == "delete":
        name = rule.name
        db.delete(rule)
        db.commit()
        return {"message": f"Auto-tag rule '{name}' deleted."}
    return {"error": f"Unknown action '{action}'."}


# ── Web & SQL tools ─────────────────────────────────────────────────

@agent_tool(
    "search_web",
    "Search the internet for security advisories, CVE details, vendor patches, exploit information, or remediation guidance. "
    "Returns top results with titles, URLs, and snippets. "
    "WHEN TO CALL: When you need real-time threat intel, CVE context not in the database, vendor advisory links, or remediation steps from external sources.",
    {
        "query": {"type": "string", "description": "Search query (e.g. 'CVE-2024-3400 PAN-OS exploit mitigation')"},
        "max_results": {"type": "integer", "description": "Number of results to return (default 5, max 10)"},
    },
)
def search_web(db: Session, params: dict):
    query = params.get("query", "").strip()
    if not query:
        return {"error": "query is required"}
    max_results = min(int(params.get("max_results", 5)), 10)
    try:
        from ddgs import DDGS
        with DDGS() as ddgs:
            raw = list(ddgs.text(query, max_results=max_results))
        results = [
            {"title": r.get("title", ""), "url": r.get("href", ""), "snippet": r.get("body", "")}
            for r in raw
        ]
        return {"query": query, "results": results, "count": len(results)}
    except Exception as e:
        logger.exception("search_web failed")
        return {"error": f"Web search failed: {str(e)}"}


@agent_tool(
    "fetch_url",
    "Fetch the content of a web page and extract its main text. Useful for reading CVE advisories, vendor patches, "
    "NVD entries, CISA KEV details, or documentation pages. Returns extracted text (up to 8000 chars). "
    "WHEN TO CALL: When you have a specific URL from a search result or the user and need to read its content.",
    {
        "url": {"type": "string", "description": "Full URL to fetch (e.g. 'https://nvd.nist.gov/vuln/detail/CVE-2024-3400')"},
    },
)
def fetch_url(db: Session, params: dict):
    import httpx
    from bs4 import BeautifulSoup

    url = params.get("url", "").strip()
    if not url:
        return {"error": "url is required"}
    if not url.startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}

    try:
        resp = httpx.get(url, timeout=15, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (compatible; HakunaCopilot/1.0)"
        })
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code} fetching {url}"}
    except Exception as e:
        return {"error": f"Failed to fetch URL: {str(e)}"}

    content_type = resp.headers.get("content-type", "")
    if "html" not in content_type and "text" not in content_type:
        return {"error": f"Unsupported content type: {content_type}"}

    soup = BeautifulSoup(resp.text, "lxml")
    # Remove noise
    for tag in soup(["script", "style", "nav", "footer", "header", "aside", "form"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    # Collapse blank lines
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    text = "\n".join(lines)

    max_chars = 8000
    truncated = len(text) > max_chars
    return {
        "url": url,
        "title": soup.title.string.strip() if soup.title and soup.title.string else "",
        "content": text[:max_chars],
        "truncated": truncated,
        "length": len(text),
    }


# Table → org_id filter mapping for run_sql_query
# "direct" = table has org_id column; "via_scan" = filter through scan_id → scans.org_id
_SQL_TABLE_ORG_FILTER = {
    "scans":               "direct",
    "assets":              "via_scan",
    "findings":            "via_scan",
    "tags":                "direct",
    "tag_assignments":     None,       # safe — joins to tags/findings which are filtered
    "campaigns":           "direct",
    "campaign_findings":   None,       # joins to campaigns
    "sla_configs":         "direct",
    "auto_tag_rules":      "direct",
    "ownership_rules":     "direct",
    "finding_exceptions":  "direct",
    "finding_tickets":     None,       # joins to findings
    "scan_comparisons":    "direct",
    "inventory_users":     "via_scan",
    "inventory_groups":    "via_scan",
    "inventory_services":  "via_scan",
    "inventory_net_conns": "via_scan",
    "inventory_patches":   "via_scan",
    "inventory_logged_on": "via_scan",
    "inventory_scheduled_tasks": "via_scan",
    "inventory_software":  "via_scan",
    "inventory_security_controls": "via_scan",
    "inventory_certificates": "via_scan",
    "inventory_shares":    "via_scan",
}

_BLOCKED_SQL_KEYWORDS = {
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE",
    "REPLACE", "GRANT", "REVOKE", "EXEC", "EXECUTE", "MERGE", "UPSERT",
    "ATTACH", "DETACH", "PRAGMA", "VACUUM", "REINDEX",
}


@agent_tool(
    "run_sql_query",
    "Execute a read-only SQL SELECT query against the database for ad-hoc analysis that existing tools can't answer. "
    "The query is automatically scoped to the current organization — you do NOT need to add org_id filters. "
    "Returns up to 200 rows. Use standard SQL; both SQLite and PostgreSQL are supported. "
    "WHEN TO CALL: When the user asks an analytical question that requires custom aggregation, joins, or grouping "
    "that no existing tool directly supports (e.g. 'which assets have the most critical findings older than 30 days?'). "
    "Prefer dedicated query tools (query_findings, query_assets, etc.) for standard lookups.",
    {
        "sql": {"type": "string", "description": "SQL SELECT query. Do NOT include org_id filters — they are injected automatically."},
        "params": {"type": "object", "description": "Optional named bind parameters (e.g. {\"cve\": \"CVE-2024-3400\"})"},
    },
)
def run_sql_query(db: Session, params: dict):
    import sqlglot
    from sqlglot import exp
    from sqlalchemy import text

    sql = params.get("sql", "").strip()
    bind_params = params.get("params") or {}
    org_id = params.get("_org_id")
    if not sql:
        return {"error": "sql is required"}
    if not org_id:
        return {"error": "Organization context is required"}

    # ── 1. Block non-SELECT statements ──────────────────────────────
    first_keyword = sql.strip().split()[0].upper() if sql.strip() else ""
    if first_keyword in _BLOCKED_SQL_KEYWORDS:
        return {"error": f"Only SELECT queries are allowed. Got: {first_keyword}"}

    # ── 2. Parse with sqlglot ───────────────────────────────────────
    try:
        parsed = sqlglot.parse(sql)
    except Exception as e:
        return {"error": f"SQL parse error: {str(e)}"}

    if not parsed or len(parsed) != 1:
        return {"error": "Provide exactly one SQL statement"}

    stmt = parsed[0]
    if not isinstance(stmt, exp.Select):
        return {"error": "Only SELECT queries are allowed"}

    # Check for subquery DML
    for node in stmt.walk():
        if isinstance(node, (exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Create, exp.Alter)):
            return {"error": "Only SELECT queries are allowed — no DML/DDL in subqueries"}

    # ── 3. Validate tables against allowlist ────────────────────────
    referenced_tables = set()
    for table_node in stmt.find_all(exp.Table):
        table_name = table_node.name.lower()
        referenced_tables.add(table_name)

    disallowed = referenced_tables - set(_SQL_TABLE_ORG_FILTER.keys())
    if disallowed:
        return {
            "error": f"Tables not allowed: {', '.join(sorted(disallowed))}",
            "allowed_tables": sorted(_SQL_TABLE_ORG_FILTER.keys()),
        }

    # ── 4. Inject org_id filters ────────────────────────────────────
    org_conditions = []
    for table_name in referenced_tables:
        filter_type = _SQL_TABLE_ORG_FILTER.get(table_name)
        if filter_type == "direct":
            org_conditions.append(f"{table_name}.org_id = :_org_id")
        elif filter_type == "via_scan":
            org_conditions.append(
                f"{table_name}.scan_id IN (SELECT id FROM scans WHERE scans.org_id = :_org_id)"
            )

    # Append org filters to the original query
    if org_conditions:
        org_where = " AND ".join(org_conditions)
        if " WHERE " in sql.upper():
            final_sql = f"{sql} AND {org_where}"
        else:
            final_sql = f"{sql} WHERE {org_where}"
    else:
        final_sql = sql

    # Add row limit
    final_sql = f"SELECT * FROM ({final_sql}) AS _limited LIMIT 200"

    # ── 5. Execute ──────────────────────────────────────────────────
    bind_params["_org_id"] = org_id
    try:
        result = db.execute(text(final_sql), bind_params)
        columns = list(result.keys())
        rows = [dict(zip(columns, row)) for row in result.fetchall()]

        # Serialize datetime objects
        for row in rows:
            for k, v in row.items():
                if isinstance(v, datetime):
                    row[k] = v.isoformat()

        return {
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "truncated": len(rows) == 200,
            "sql_executed": final_sql,
        }
    except Exception as e:
        db.rollback()
        return {"error": f"Query execution failed: {str(e)}"}


@agent_tool(
    "get_blast_radius",
    "Compute blast radius for an asset — analyzes reachable assets, privileged users, "
    "network connections, exploitable findings, and lateral movement paths to produce a "
    "risk score (0–10) and list of attack vectors. "
    "WHEN TO CALL: When assessing the impact of compromising a specific asset, evaluating "
    "lateral movement risk, or understanding what an attacker could reach from a foothold.",
    {
        "asset_id": {"type": "integer", "description": "The asset ID to analyze (required)"},
        "finding_id": {"type": "integer", "description": "Scope blast radius to a specific finding (optional)"},
    },
)
def get_blast_radius_tool(db: Session, params: dict):
    from sqlalchemy import or_

    asset_id = params.get("asset_id")
    finding_id = params.get("finding_id")
    org_id = params.get("_org_id")
    if not asset_id:
        return {"error": "asset_id is required"}

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return {"error": "Asset not found"}

    # Determine org scope
    asset_org_id = None
    if asset.scan_id:
        scan_row = db.query(Scan).filter(Scan.id == asset.scan_id).first()
        if scan_row:
            asset_org_id = scan_row.org_id

    # Get all org assets for relationship lookups
    if asset_org_id:
        all_assets = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(
            Scan.org_id == asset_org_id
        ).all()
        rel_asset_ids = {r[0] for r in db.query(AssetRelationship.target_asset_id).filter(
            AssetRelationship.org_id == asset_org_id,
        ).all()} | {r[0] for r in db.query(AssetRelationship.source_asset_id).filter(
            AssetRelationship.org_id == asset_org_id,
        ).all()}
        if rel_asset_ids:
            extra = db.query(Asset).filter(Asset.id.in_(rel_asset_ids), Asset.scan_id.is_(None)).all()
            all_assets.extend(extra)
    elif org_id:
        all_assets = db.query(Asset).outerjoin(Scan, Asset.scan_id == Scan.id).filter(
            or_(Scan.org_id == org_id, Asset.scan_id.is_(None))
        ).all()
    else:
        all_assets = [asset]

    asset_map = {a.id: a for a in all_assets}
    ip_to_asset_id = {a.ip: a.id for a in all_assets if a.ip}
    all_org_asset_ids = [a.id for a in all_assets]

    # ── Reachable assets via network connections ──
    reachable_ids = set()
    for conn in db.query(InventoryNetConn).filter(
        InventoryNetConn.asset_id == asset_id,
        InventoryNetConn.state.in_(["ESTABLISHED", "established"]),
    ).all():
        if conn.remote_addr and conn.remote_addr in ip_to_asset_id:
            dst_id = ip_to_asset_id[conn.remote_addr]
            if dst_id != asset_id:
                reachable_ids.add(dst_id)

    # ── Reachable via infrastructure relationships ──
    for rel in db.query(AssetRelationship).filter(
        AssetRelationship.source_asset_id == asset_id,
    ).all():
        reachable_ids.add(rel.target_asset_id)
    for rel in db.query(AssetRelationship).filter(
        AssetRelationship.target_asset_id == asset_id,
    ).all():
        reachable_ids.add(rel.source_asset_id)
    reachable_ids.discard(asset_id)

    # ── Privileged users on this asset ──
    priv_users = db.query(InventoryUser).filter(
        InventoryUser.asset_id == asset_id,
        or_(
            InventoryUser.is_domain_admin == True,
            InventoryUser.is_local_admin == True,
            InventoryUser.is_privileged == True,
        ),
    ).all()

    da_exposed = any(u.is_domain_admin for u in priv_users)
    la_exposed = any(u.is_local_admin for u in priv_users)
    kerb_exposed = any(bool(u.spns) for u in priv_users)

    # ── Domain admin lateral movement: assets reachable via shared DA accounts ──
    if da_exposed:
        da_usernames = [u.username for u in priv_users if u.is_domain_admin and u.username]
        for username in da_usernames:
            for other_u in db.query(InventoryUser).filter(
                InventoryUser.asset_id.in_(all_org_asset_ids),
                InventoryUser.username == username,
                InventoryUser.is_domain_admin == True,
                InventoryUser.asset_id != asset_id,
            ).limit(10).all():
                reachable_ids.add(other_u.asset_id)

    # ── Logged-on privileged users (credential exposure) ──
    logged_on = db.query(InventoryLoggedOn).filter(
        InventoryLoggedOn.asset_id == asset_id,
    ).all()
    cred_exposure_users = []
    for logon in logged_on:
        if not logon.username:
            continue
        user = db.query(InventoryUser).filter(
            InventoryUser.asset_id.in_(all_org_asset_ids),
            InventoryUser.username == logon.username,
            or_(
                InventoryUser.is_domain_admin == True,
                InventoryUser.is_local_admin == True,
                InventoryUser.is_privileged == True,
            ),
        ).first()
        if user:
            cred_exposure_users.append(user.username)

    # ── Domain controller reachability ──
    dc_asset_ids = set()
    if reachable_ids:
        for dc in db.query(InventoryComputer).filter(
            InventoryComputer.asset_id.in_(reachable_ids),
            InventoryComputer.is_domain_controller == True,
        ).all():
            dc_asset_ids.add(dc.asset_id)
    dc_reachable = len(dc_asset_ids) > 0

    # ── Exploitable findings ──
    if finding_id:
        scoped = db.query(Finding).filter(Finding.id == finding_id).first()
        exploit_findings = [scoped] if scoped else []
    else:
        exploit_findings = db.query(Finding).filter(
            Finding.asset_id == asset_id,
            Finding.severity >= 3,
            Finding.exploit_available == True,
        ).limit(20).all()

    # ── Weak credentials ──
    weak_creds = db.query(InventoryCredential).filter(
        InventoryCredential.asset_id == asset_id,
    ).limit(5).all()
    has_weak_creds = len(weak_creds) > 0

    # ── Missing critical patches ──
    missing_patches = db.query(InventoryPatch).filter(
        InventoryPatch.asset_id == asset_id,
    ).all()
    critical_patches = [p for p in missing_patches if (p.vuln_count or 0) >= 5]

    # ── Exposed databases ──
    exposed_dbs = db.query(InventoryDatabaseInstance).filter(
        InventoryDatabaseInstance.asset_id == asset_id,
        InventoryDatabaseInstance.is_running == True,
    ).all()

    # ── Expired certificates ──
    expired_certs = db.query(InventoryCertificate).filter(
        InventoryCertificate.asset_id == asset_id,
        InventoryCertificate.is_expired == True,
    ).all()

    # ── Writeable shares ──
    writeable_shares = db.query(InventoryShare).filter(
        InventoryShare.asset_id == asset_id,
        InventoryShare.is_writeable == True,
    ).limit(5).all()

    # ── Domain trusts ──
    is_dc = db.query(InventoryComputer).filter(
        InventoryComputer.asset_id == asset_id,
        InventoryComputer.is_domain_controller == True,
    ).first() is not None
    domain_trusts = []
    if is_dc:
        domain_trusts = db.query(InventoryDomainTrust).filter(
            InventoryDomainTrust.asset_id == asset_id,
        ).all()

    # ── Listening risky services ──
    _RISKY_PORTS = {
        22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-S",
        6379: "Redis", 27017: "MongoDB",
    }
    risky_services = []
    for conn in db.query(InventoryNetConn).filter(
        InventoryNetConn.asset_id == asset_id,
        InventoryNetConn.state.in_(["LISTEN", "LISTENING"]),
    ).all():
        port = conn.local_port
        if port and port in _RISKY_PORTS:
            risky_services.append(f"{port}/{_RISKY_PORTS[port]}")

    # ── Firewall lateral movement paths ──
    firewall_lateral_paths = []
    try:
        import ipaddress as _ipamod
        if asset.ip and org_id:
            fw_policies = db.query(FirewallPolicy).filter(
                FirewallPolicy.org_id == org_id,
                FirewallPolicy.enabled.is_(True),
                FirewallPolicy.action.in_(["allow", "accept", "permit"]),
            ).all()
            _FW_RISKY = {22, 23, 445, 3389, 5985, 5986}
            for policy in fw_policies:
                in_src = any(
                    _ipamod.ip_address(asset.ip) in _ipamod.ip_network(c, strict=False)
                    if c.strip().lower() != "any"
                    else True
                    for c in (policy.src_cidrs or [])
                )
                if not in_src:
                    continue
                ports = set()
                for svc in (policy.services or []):
                    if isinstance(svc, dict) and isinstance(svc.get("port"), int):
                        ports.add(svc["port"])
                risky = ports & _FW_RISKY
                if risky:
                    for dst_cidr in (policy.dst_cidrs or []):
                        for other_a in all_assets:
                            if not other_a.ip or other_a.id == asset_id:
                                continue
                            try:
                                if dst_cidr.strip().lower() == "any" or _ipamod.ip_address(other_a.ip) in _ipamod.ip_network(dst_cidr, strict=False):
                                    reachable_ids.add(other_a.id)
                                    firewall_lateral_paths.append({
                                        "rule_id": policy.rule_id,
                                        "vendor": policy.vendor,
                                        "dst_ip": other_a.ip,
                                        "ports": sorted(risky),
                                    })
                            except (ValueError, TypeError):
                                pass
    except Exception:
        pass

    # ── Compute blast radius score (same formula as /api/blast-radius) ──
    is_internet_facing = asset.is_internet_facing or False
    reachable_count = len(reachable_ids) + (1 if is_internet_facing else 0)
    has_exploitable = len(exploit_findings) > 0
    has_trust_paths = len(domain_trusts) > 0
    has_missing_patches = len(critical_patches) > 0
    has_exposed_dbs = len(exposed_dbs) > 0
    has_expired_certs = len(expired_certs) > 0
    has_fw_lateral = len(firewall_lateral_paths) > 0

    score = min(reachable_count * 1.5, 5.0)
    if dc_reachable:              score += 3.0
    if da_exposed:                score += 2.0
    elif la_exposed:              score += 1.0
    if kerb_exposed:              score += 1.0
    if len(cred_exposure_users):  score += 0.5
    if has_weak_creds:            score += 1.5
    if has_exploitable:           score += 1.0
    if has_trust_paths:           score += 0.5
    if has_missing_patches:       score += 0.5
    if has_exposed_dbs:           score += 0.5
    if has_expired_certs:         score += 0.3
    if is_internet_facing:        score += 1.5
    if has_fw_lateral:            score += min(len(firewall_lateral_paths) * 0.5, 2.0)
    if len(writeable_shares):     score += 0.5
    score = min(round(score, 1), 10.0)

    # ── Build attack vectors summary ──
    vectors = []
    if is_internet_facing:
        vectors.append({"type": "internet_facing", "severity": "critical",
                        "label": "Internet-facing asset — externally reachable"})
    for u in priv_users:
        if u.is_domain_admin:
            vectors.append({"type": "domain_admin", "severity": "critical",
                            "label": f"Domain Admin credential on host: {u.username}"})
        elif u.is_local_admin:
            vectors.append({"type": "local_admin", "severity": "high",
                            "label": f"Local Admin account: {u.username}"})
        if u.spns:
            vectors.append({"type": "kerberoastable", "severity": "high",
                            "label": f"Kerberoastable account: {u.username}"})
    for username in cred_exposure_users:
        vectors.append({"type": "credential_exposure", "severity": "high",
                        "label": f"Credential exposure: {username} logged on"})
    for f in exploit_findings:
        cve_str = ", ".join((f.cves or [])[:3]) or f.plugin_name or f"Plugin {f.plugin_id}"
        vectors.append({"type": "vuln_exploit", "severity": "critical" if f.severity >= 4 else "high",
                        "label": f"Exploitable: {cve_str}" + (" [KEV]" if f.is_kev else "")})
    for cred in weak_creds:
        proto = (cred.protocol or "unknown").upper()
        vectors.append({"type": "weak_credential", "severity": "critical",
                        "label": f"{cred.credential_type or 'Weak'} credential ({proto}:{cred.port or '?'})"})
    for share in writeable_shares:
        vectors.append({"type": "writeable_share", "severity": "medium",
                        "label": f"Writeable share: {share.share_name or '?'}"})
    if risky_services:
        vectors.append({"type": "service_exposure", "severity": "medium",
                        "label": f"Risky services: {', '.join(risky_services[:6])}"})
    if exposed_dbs:
        db_names = ", ".join(f"{d.db_type}:{d.port}" for d in exposed_dbs[:3])
        vectors.append({"type": "db_exposure", "severity": "high",
                        "label": f"Running databases: {db_names}"})
    if critical_patches:
        total_cves = sum(p.vuln_count or 0 for p in critical_patches)
        vectors.append({"type": "missing_patch", "severity": "high",
                        "label": f"Missing {len(critical_patches)} critical patches ({total_cves} CVEs)"})
    if expired_certs:
        vectors.append({"type": "expired_cert", "severity": "medium",
                        "label": f"{len(expired_certs)} expired certificate(s)"})
    for trust in domain_trusts:
        vectors.append({"type": "domain_trust", "severity": "medium",
                        "label": f"Domain trust → {trust.trusted_domain}"})
    for fwp in firewall_lateral_paths[:5]:
        port_str = ", ".join(str(p) for p in fwp["ports"][:3])
        vectors.append({"type": "firewall_lateral_movement", "severity": "high",
                        "label": f"FW allow ({fwp['vendor']}): → {fwp['dst_ip']} on port {port_str}"})

    # ── Reachable asset summaries ──
    reachable_summary = []
    for rid in list(reachable_ids)[:15]:
        ra = asset_map.get(rid)
        if ra:
            reachable_summary.append({
                "id": ra.id,
                "label": ra.hostname or ra.fqdn or ra.ip or f"Asset {ra.id}",
                "ip": ra.ip,
                "risk_score": ra.risk_score,
                "criticality": ra.criticality,
                "is_internet_facing": ra.is_internet_facing,
                "critical_count": ra.critical_count,
                "high_count": ra.high_count,
            })

    return {
        "asset_id": asset_id,
        "asset_label": asset.hostname or asset.fqdn or asset.ip or f"Asset {asset_id}",
        "finding_id": finding_id,
        "score": score,
        "reachable_assets": reachable_count,
        "privileged_users": len(priv_users),
        "da_exposed": da_exposed,
        "dc_reachable": dc_reachable,
        "kerberoastable_exposed": kerb_exposed,
        "has_weak_creds": has_weak_creds,
        "has_exploitable": has_exploitable,
        "has_exposed_dbs": has_exposed_dbs,
        "has_fw_lateral": has_fw_lateral,
        "is_internet_facing": is_internet_facing,
        "is_domain_controller": is_dc,
        "vectors": vectors[:30],
        "reachable_asset_details": reachable_summary,
    }
