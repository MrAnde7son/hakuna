"""
Mini Agent Tool Registry — defines tools available to user-built agents.

Each tool is a function that receives (db, params) and returns a JSON-serializable result.
Tools are registered with a decorator and exposed via TOOL_REGISTRY.
"""
import json
import logging
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import func, case, distinct
from models.models import (
    Asset, Finding, Scan,
    InventoryUser, InventoryGroup, InventoryService, InventoryNetConn,
    InventoryPatch, InventoryLoggedOn, InventoryScheduledTask,
    InventorySoftware, InventorySecurityControl, InventoryCertificate,
    InventoryShare,
    Tag, TagAssignment, SLAConfig, FindingException,
    ScanComparison, Campaign, CampaignFinding,
    IntegrationConfig, AutoTagRule,
    Integration, IntegrationRun,
)
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
    "Search findings by severity, plugin family, CVE, keyword, or scan. Returns up to 50 results. "
    "WHEN TO CALL: When you need to find specific findings matching criteria. Use this instead of requesting bulk scan dumps.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "severity_min": {"type": "integer", "description": "Minimum severity (0=Info..4=Critical)"},
        "plugin_family": {"type": "string", "description": "Filter by plugin family substring"},
        "cve": {"type": "string", "description": "Search for a specific CVE ID"},
        "keyword": {"type": "string", "description": "Search plugin name, synopsis, or description"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def query_findings(db: Session, params: dict):
    q = db.query(Finding)
    if params.get("scan_id"):
        q = q.filter(Finding.scan_id == params["scan_id"])
    if params.get("severity_min") is not None:
        q = q.filter(Finding.severity >= params["severity_min"])
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
    limit = min(params.get("limit", 50), 200)
    rows = q.order_by(Finding.priority_score.desc()).limit(limit).all()
    return [
        {
            "id": f.id, "plugin_id": f.plugin_id, "plugin_name": f.plugin_name,
            "severity": f.severity, "severity_label": f.severity_label,
            "cvss3": f.cvss3_score, "vpr": f.vpr_score,
            "priority_score": f.priority_score, "effort": f.effort_level,
            "asset_id": f.asset_id, "cves": f.cves,
            "solution": (f.solution or "")[:500],
        }
        for f in rows
    ]


@agent_tool(
    "query_assets",
    "Search assets by IP, hostname, OS, criticality, or scan. Returns up to 50 results. "
    "WHEN TO CALL: When you need to find specific assets or get asset details for a filtered set.",
    {
        "scan_id": {"type": "integer", "description": "Filter by scan ID"},
        "ip": {"type": "string", "description": "Filter by IP substring"},
        "hostname": {"type": "string", "description": "Filter by hostname substring"},
        "os": {"type": "string", "description": "Filter by OS substring"},
        "min_criticality": {"type": "integer", "description": "Minimum criticality (1-10)"},
        "limit": {"type": "integer", "description": "Max results (default 50)"},
    },
)
def query_assets(db: Session, params: dict):
    q = db.query(Asset)
    if params.get("scan_id"):
        q = q.filter(Asset.scan_id == params["scan_id"])
    if params.get("ip"):
        q = q.filter(Asset.ip.ilike(f"%{params['ip']}%"))
    if params.get("hostname"):
        q = q.filter(Asset.hostname.ilike(f"%{params['hostname']}%"))
    if params.get("os"):
        q = q.filter(Asset.os.ilike(f"%{params['os']}%"))
    if params.get("min_criticality"):
        q = q.filter(Asset.criticality >= params["min_criticality"])
    limit = min(params.get("limit", 50), 200)
    rows = q.order_by(Asset.risk_score.desc()).limit(limit).all()
    return [
        {
            "id": a.id, "ip": a.ip, "hostname": a.hostname, "fqdn": a.fqdn,
            "os": a.os, "criticality": a.criticality, "risk_score": a.risk_score,
            "critical_count": a.critical_count, "high_count": a.high_count,
            "medium_count": a.medium_count, "low_count": a.low_count,
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
    created = 0
    for aid in asset_ids[:100]:  # cap at 100
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
    return {"scan_id": scan_id, "rules_executed": len(results), "results": results[:20]}


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
