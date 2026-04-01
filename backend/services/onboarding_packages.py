"""
Onboarding packages — predefined configurations that auto-provision
tags, SLA policies, campaigns, agents, workflows, RBAC roles, auto-tag rules,
ownership rules, report templates, and exception rules based on user objectives.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from models.models import (
    Organization, Tag, AutoTagRule, OwnershipRule, SLAConfig,
    Campaign, Agent, ReportTemplate, FindingException, CustomRole,
)

logger = logging.getLogger(__name__)

# ── Industry options (for org profile) ──────────────────────────

INDUSTRIES = [
    {"id": "financial_services", "label": "Financial Services"},
    {"id": "healthcare", "label": "Healthcare"},
    {"id": "technology", "label": "Technology"},
    {"id": "government", "label": "Government"},
    {"id": "retail", "label": "Retail & E-commerce"},
    {"id": "manufacturing", "label": "Manufacturing"},
    {"id": "energy", "label": "Energy & Utilities"},
    {"id": "education", "label": "Education"},
    {"id": "media", "label": "Media & Entertainment"},
    {"id": "telecom", "label": "Telecommunications"},
    {"id": "consulting", "label": "Consulting & MSSP"},
    {"id": "other", "label": "Other"},
]

# ── Team function options ───────────────────────────────────────

TEAM_FUNCTIONS = [
    {"id": "secops", "label": "Security Operations (SOC)"},
    {"id": "vuln_mgmt", "label": "Vulnerability Management"},
    {"id": "it_ops", "label": "IT Operations"},
    {"id": "devops", "label": "DevOps / Platform Engineering"},
    {"id": "appsec", "label": "Application Security"},
    {"id": "grc", "label": "GRC / Compliance"},
    {"id": "executive", "label": "Executive / CISO Office"},
    {"id": "network", "label": "Network Engineering"},
    {"id": "helpdesk", "label": "IT Help Desk"},
]

# ── Objective definitions (what the user wants to achieve) ──────

OBJECTIVES = [
    {
        "id": "prioritize_vulns",
        "label": "Prioritize vulnerabilities by real-world risk",
        "description": "Go beyond CVSS — factor in exploit maturity, asset criticality, threat intel, and business context.",
        "icon": "target",
    },
    {
        "id": "drive_remediation",
        "label": "Drive remediation workflows",
        "description": "Create campaigns, assign owners, track SLAs, and hold teams accountable for fixing findings.",
        "icon": "wrench",
    },
    {
        "id": "ai_agents",
        "label": "Add AI agents to your VM workflow",
        "description": "Use AI to triage findings, draft remediation plans, explain CVEs, and automate repetitive analysis.",
        "icon": "bot",
    },
    {
        "id": "attack_path",
        "label": "Model attack paths and exposure",
        "description": "Map network zones, identify lateral movement risks, and focus on findings that matter most.",
        "icon": "route",
    },
    {
        "id": "board_reporting",
        "label": "Board reporting and dashboards",
        "description": "Executive-ready reports showing risk trends, SLA compliance, remediation velocity, and team performance.",
        "icon": "bar-chart",
    },
    {
        "id": "integrations",
        "label": "Integrate with ticketing and chat tools",
        "description": "Push findings to Jira, ServiceNow, Slack, or Teams. Bi-directional sync keeps everything in one place.",
        "icon": "link",
    },
    {
        "id": "compliance",
        "label": "Meet compliance and audit requirements",
        "description": "Track exception waivers, maintain audit trails, enforce SLA policies, and generate compliance evidence.",
        "icon": "shield-check",
    },
    {
        "id": "mssp",
        "label": "Manage multiple client environments (MSSP)",
        "description": "Multi-tenant isolation, per-client dashboards, parent-child org hierarchy, and aggregated reporting.",
        "icon": "building",
    },
]

# ── Package definitions ─────────────────────────────────────────
# Each package maps to an objective and defines what gets created.

def _base_tags(org_id: int) -> list[dict]:
    """Tags every org should have."""
    return [
        {"org_id": org_id, "category": "environment", "value": "Production", "color": "#ef4444"},
        {"org_id": org_id, "category": "environment", "value": "Staging", "color": "#f59e0b"},
        {"org_id": org_id, "category": "environment", "value": "Development", "color": "#22c55e"},
        {"org_id": org_id, "category": "environment", "value": "QA", "color": "#3b82f6"},
        {"org_id": org_id, "category": "criticality", "value": "Business Critical", "color": "#dc2626"},
        {"org_id": org_id, "category": "criticality", "value": "Important", "color": "#f97316"},
        {"org_id": org_id, "category": "criticality", "value": "Standard", "color": "#6366f1"},
        {"org_id": org_id, "category": "criticality", "value": "Low Impact", "color": "#94a3b8"},
    ]


def _network_tags(org_id: int) -> list[dict]:
    """Network zone tags for attack path modeling."""
    return [
        {"org_id": org_id, "category": "network_zone", "value": "DMZ", "color": "#ef4444"},
        {"org_id": org_id, "category": "network_zone", "value": "Internal", "color": "#3b82f6"},
        {"org_id": org_id, "category": "network_zone", "value": "PCI", "color": "#a855f7"},
        {"org_id": org_id, "category": "network_zone", "value": "Guest", "color": "#94a3b8"},
        {"org_id": org_id, "category": "network_zone", "value": "Management", "color": "#f59e0b"},
        {"org_id": org_id, "category": "network_zone", "value": "Cloud", "color": "#06b6d4"},
    ]


def _team_tags(org_id: int, functions: list[str]) -> list[dict]:
    """Team-based tags derived from selected functions."""
    fn_map = {
        "secops": "Security Operations",
        "vuln_mgmt": "Vulnerability Management",
        "it_ops": "IT Operations",
        "devops": "DevOps",
        "appsec": "Application Security",
        "grc": "GRC / Compliance",
        "executive": "Executive",
        "network": "Network Engineering",
        "helpdesk": "Help Desk",
    }
    colors = ["#6366f1", "#8b5cf6", "#ec4899", "#14b8a6", "#f97316", "#06b6d4", "#84cc16", "#ef4444", "#64748b"]
    tags = []
    for i, fn_id in enumerate(functions):
        label = fn_map.get(fn_id, fn_id)
        tags.append({
            "org_id": org_id,
            "category": "team",
            "value": label,
            "color": colors[i % len(colors)],
        })
    return tags


# ── SLA presets by org maturity ─────────────────────────────────

SLA_PRESETS = {
    "aggressive": [
        {"severity": 4, "severity_label": "Critical", "days_to_remediate": 7, "warn_days_before": 3, "is_enabled": True},
        {"severity": 3, "severity_label": "High", "days_to_remediate": 14, "warn_days_before": 5, "is_enabled": True},
        {"severity": 2, "severity_label": "Medium", "days_to_remediate": 30, "warn_days_before": 7, "is_enabled": True},
        {"severity": 1, "severity_label": "Low", "days_to_remediate": 90, "warn_days_before": 14, "is_enabled": True},
        {"severity": 0, "severity_label": "Info", "days_to_remediate": 365, "warn_days_before": 30, "is_enabled": False},
    ],
    "standard": [
        {"severity": 4, "severity_label": "Critical", "days_to_remediate": 15, "warn_days_before": 5, "is_enabled": True},
        {"severity": 3, "severity_label": "High", "days_to_remediate": 30, "warn_days_before": 7, "is_enabled": True},
        {"severity": 2, "severity_label": "Medium", "days_to_remediate": 90, "warn_days_before": 14, "is_enabled": True},
        {"severity": 1, "severity_label": "Low", "days_to_remediate": 180, "warn_days_before": 30, "is_enabled": True},
        {"severity": 0, "severity_label": "Info", "days_to_remediate": 365, "warn_days_before": 30, "is_enabled": False},
    ],
    "relaxed": [
        {"severity": 4, "severity_label": "Critical", "days_to_remediate": 30, "warn_days_before": 7, "is_enabled": True},
        {"severity": 3, "severity_label": "High", "days_to_remediate": 60, "warn_days_before": 14, "is_enabled": True},
        {"severity": 2, "severity_label": "Medium", "days_to_remediate": 180, "warn_days_before": 30, "is_enabled": True},
        {"severity": 1, "severity_label": "Low", "days_to_remediate": 365, "warn_days_before": 60, "is_enabled": True},
        {"severity": 0, "severity_label": "Info", "days_to_remediate": 365, "warn_days_before": 30, "is_enabled": False},
    ],
}


# ── Campaign templates ──────────────────────────────────────────

CAMPAIGN_TEMPLATES = {
    "quick_wins": {
        "name": "Quick Wins",
        "description": "Low-effort, high-impact findings that can be remediated quickly.",
        "query": [
            {"field": "severity", "operator": "gte", "value": 3},
            {"field": "exploit_available", "operator": "eq", "value": True},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
    "critical_path": {
        "name": "Critical Path",
        "description": "Critical and high severity findings on business-critical assets.",
        "query": [
            {"field": "severity", "operator": "gte", "value": 4},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
    "sla_breaches": {
        "name": "SLA Breaches",
        "description": "Findings that have exceeded their remediation SLA deadline.",
        "query": [
            {"field": "sla_status", "operator": "eq", "value": "breached"},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
    "patch_tuesday": {
        "name": "Patch Tuesday",
        "description": "Findings addressable by applying latest vendor patches.",
        "query": [
            {"field": "solution", "operator": "contains", "value": "patch"},
            {"field": "severity", "operator": "gte", "value": 2},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
}


# ── Agent templates ─────────────────────────────────────────────

AGENT_TEMPLATES = {
    "vuln_analyst": {
        "name": "Vulnerability Analyst",
        "description": "Analyzes findings, explains CVEs in plain language, and recommends prioritization.",
        "system_prompt": (
            "You are a vulnerability analyst assistant. When given findings or CVEs, "
            "explain the risk in plain language, assess exploitability, recommend priority, "
            "and suggest remediation steps. Reference CVSS, EPSS, and known exploits when available."
        ),
        "tools": ["search_findings", "search_assets", "get_finding_detail", "search_cves", "web_search"],
        "model": "claude-sonnet-4-6",
    },
    "remediation_advisor": {
        "name": "Remediation Advisor",
        "description": "Drafts remediation plans, generates patch scripts, and creates campaign strategies.",
        "system_prompt": (
            "You are a remediation advisor. Help security teams create actionable remediation plans. "
            "Draft step-by-step instructions, suggest patch commands, identify dependencies, "
            "and recommend testing procedures. Group related findings for efficient bulk remediation."
        ),
        "tools": ["search_findings", "search_assets", "get_finding_detail", "list_campaigns", "web_search"],
        "model": "claude-sonnet-4-6",
    },
    "threat_intel_analyst": {
        "name": "Threat Intel Analyst",
        "description": "Correlates findings with threat intelligence, tracks exploits, and maps to MITRE ATT&CK.",
        "system_prompt": (
            "You are a threat intelligence analyst. Correlate vulnerability findings with real-world threats. "
            "Check for active exploitation, map to MITRE ATT&CK techniques, assess threat actor interest, "
            "and provide context on exploit availability and weaponization."
        ),
        "tools": ["search_findings", "search_cves", "search_threat_intel", "web_search"],
        "model": "claude-sonnet-4-6",
    },
    "report_writer": {
        "name": "Executive Report Writer",
        "description": "Generates executive summaries, risk narratives, and board-ready security reports.",
        "system_prompt": (
            "You are a security report writer for executive and board audiences. "
            "Summarize vulnerability posture, risk trends, remediation progress, and SLA compliance. "
            "Use clear business language, avoid jargon, and provide actionable recommendations. "
            "Include metrics like mean time to remediate, finding age, and risk score trends."
        ),
        "tools": ["search_findings", "search_assets", "list_campaigns", "get_stats"],
        "model": "claude-sonnet-4-6",
    },
}


# ── Report template configs ─────────────────────────────────────

REPORT_TEMPLATES = {
    "executive_summary": {
        "name": "Executive Summary",
        "config": {
            "widgets": [
                {"type": "risk_score_gauge", "title": "Overall Risk Score", "size": "sm"},
                {"type": "severity_breakdown", "title": "Findings by Severity", "size": "sm"},
                {"type": "trend_chart", "title": "Risk Trend (30 days)", "size": "md"},
                {"type": "sla_compliance", "title": "SLA Compliance", "size": "sm"},
                {"type": "top_findings", "title": "Top 10 Critical Findings", "size": "lg"},
                {"type": "remediation_velocity", "title": "Remediation Velocity", "size": "md"},
            ]
        },
        "is_default": False,
    },
    "team_dashboard": {
        "name": "Team Dashboard",
        "config": {
            "widgets": [
                {"type": "findings_by_owner", "title": "Findings by Owner", "size": "md"},
                {"type": "campaign_progress", "title": "Campaign Progress", "size": "md"},
                {"type": "sla_status", "title": "SLA Status by Team", "size": "md"},
                {"type": "severity_breakdown", "title": "Open by Severity", "size": "sm"},
                {"type": "recent_activity", "title": "Recent Activity", "size": "lg"},
            ]
        },
        "is_default": False,
    },
    "compliance_report": {
        "name": "Compliance & Audit Report",
        "config": {
            "widgets": [
                {"type": "sla_compliance", "title": "SLA Compliance Rate", "size": "sm"},
                {"type": "exception_summary", "title": "Active Exceptions", "size": "sm"},
                {"type": "findings_age", "title": "Finding Age Distribution", "size": "md"},
                {"type": "severity_breakdown", "title": "Open Findings", "size": "sm"},
                {"type": "remediation_velocity", "title": "Mean Time to Remediate", "size": "md"},
                {"type": "audit_trail", "title": "Recent Changes", "size": "lg"},
            ]
        },
        "is_default": False,
    },
}


# ── Auto-tag rule templates ─────────────────────────────────────

AUTO_TAG_RULES = {
    "windows_servers": {
        "name": "Auto-tag Windows Servers",
        "target_type": "asset",
        "conditions": [{"field": "os", "operator": "contains", "value": "Windows Server"}],
        "condition_logic": "AND",
        "tag_category": "os_family",
        "tag_value": "Windows Server",
        "tag_color": "#3b82f6",
    },
    "linux_servers": {
        "name": "Auto-tag Linux Servers",
        "target_type": "asset",
        "conditions": [{"field": "os", "operator": "contains", "value": "Linux"}],
        "condition_logic": "AND",
        "tag_category": "os_family",
        "tag_value": "Linux",
        "tag_color": "#f59e0b",
    },
    "exploitable_findings": {
        "name": "Flag Exploitable Findings",
        "target_type": "finding",
        "conditions": [{"field": "exploit_available", "operator": "eq", "value": True}],
        "condition_logic": "AND",
        "tag_category": "risk",
        "tag_value": "Exploitable",
        "tag_color": "#ef4444",
    },
}


# ── RBAC role templates ─────────────────────────────────────────

ROLE_TEMPLATES = {
    "security_analyst": {
        "name": "Security Analyst",
        "description": "Full access to findings, assets, and campaigns. Can manage tags and run agents.",
        "base_permissions": {
            "page_findings": True, "page_assets": True, "page_campaigns": True,
            "page_reports": True, "page_threat_intel": True, "page_inventory": True,
            "page_agents": True, "page_remediation": True,
            "read_scans": True, "write_scans": True,
            "read_findings": True, "write_findings": True,
            "read_assets": True, "write_assets": True,
            "manage_tags": True, "manage_campaigns": True,
        },
    },
    "it_remediation": {
        "name": "IT Remediation",
        "description": "View findings and campaigns assigned to them. Cannot modify scan data or settings.",
        "base_permissions": {
            "page_findings": True, "page_assets": True, "page_campaigns": True,
            "page_remediation": True,
            "read_findings": True, "read_assets": True,
            "manage_campaigns": True,
        },
    },
    "executive_viewer": {
        "name": "Executive Viewer",
        "description": "Read-only access to reports and dashboards. No access to raw findings.",
        "base_permissions": {
            "page_reports": True,
            "read_scans": True,
        },
    },
    "compliance_auditor": {
        "name": "Compliance Auditor",
        "description": "Read access to findings, exceptions, SLA data, and audit trails for compliance review.",
        "base_permissions": {
            "page_findings": True, "page_assets": True, "page_reports": True,
            "read_findings": True, "read_assets": True, "read_scans": True,
        },
    },
}


# ── Objective → package mapping ─────────────────────────────────

OBJECTIVE_PACKAGES: dict[str, dict[str, Any]] = {
    "prioritize_vulns": {
        "label": "Vulnerability Prioritization",
        "description": "Tags, auto-tag rules, and risk-based prioritization config",
        "provisions": {
            "tags": ["base", "network"],
            "auto_tag_rules": ["windows_servers", "linux_servers", "exploitable_findings"],
            "sla_preset": "standard",
            "campaigns": ["quick_wins", "critical_path"],
            "reports": ["executive_summary"],
        },
    },
    "drive_remediation": {
        "label": "Remediation Workflows",
        "description": "Campaigns, ownership rules, SLA policies, and team-based tracking",
        "provisions": {
            "tags": ["base"],
            "sla_preset": "standard",
            "campaigns": ["quick_wins", "critical_path", "sla_breaches", "patch_tuesday"],
            "roles": ["it_remediation"],
            "reports": ["team_dashboard"],
        },
    },
    "ai_agents": {
        "label": "AI Security Agents",
        "description": "Pre-built AI agents for vulnerability analysis, remediation, and reporting",
        "provisions": {
            "agents": ["vuln_analyst", "remediation_advisor", "threat_intel_analyst"],
        },
    },
    "attack_path": {
        "label": "Attack Path Modeling",
        "description": "Network zone tags, exposure mapping, and threat-aware prioritization",
        "provisions": {
            "tags": ["base", "network"],
            "auto_tag_rules": ["windows_servers", "linux_servers"],
            "campaigns": ["critical_path"],
        },
    },
    "board_reporting": {
        "label": "Board Reporting & Dashboards",
        "description": "Executive-ready report templates and trend dashboards",
        "provisions": {
            "reports": ["executive_summary", "team_dashboard", "compliance_report"],
            "agents": ["report_writer"],
            "sla_preset": "standard",
            "roles": ["executive_viewer"],
        },
    },
    "integrations": {
        "label": "Integration Hub",
        "description": "Pre-configured integration templates for ticketing and chat tools",
        "provisions": {
            # Integrations require credentials, so we just set up tags/roles
            "tags": ["base"],
        },
    },
    "compliance": {
        "label": "Compliance & Audit",
        "description": "SLA enforcement, exception tracking, and audit-ready reporting",
        "provisions": {
            "sla_preset": "aggressive",
            "reports": ["compliance_report", "executive_summary"],
            "roles": ["compliance_auditor"],
            "campaigns": ["sla_breaches"],
        },
    },
    "mssp": {
        "label": "MSSP Multi-Tenant",
        "description": "Multi-client org structure, per-client dashboards, and aggregated reporting",
        "provisions": {
            "tags": ["base"],
            "reports": ["executive_summary", "team_dashboard"],
            "roles": ["security_analyst", "executive_viewer"],
            "sla_preset": "standard",
        },
    },
}


# ── Provisioning engine ─────────────────────────────────────────

def get_recommendations(objectives: list[str], team_functions: list[str], team_size: str) -> dict:
    """Return package recommendations based on user selections."""
    packages = {}
    for obj_id in objectives:
        pkg = OBJECTIVE_PACKAGES.get(obj_id)
        if pkg:
            packages[obj_id] = {
                "label": pkg["label"],
                "description": pkg["description"],
                "provisions": pkg["provisions"],
            }

    # Adjust SLA based on team size
    sla_note = None
    if team_size in ("1-5", "6-15"):
        sla_note = "Relaxed SLA timelines recommended for smaller teams."
    elif team_size in ("50-100", "100+"):
        sla_note = "Aggressive SLA timelines recommended for larger, mature teams."

    return {
        "packages": packages,
        "sla_note": sla_note,
    }


def apply_packages(
    db: Session,
    org_id: int,
    user_id: int,
    objectives: list[str],
    team_functions: list[str],
    team_size: str,
    profile: dict,
) -> dict:
    """
    Apply selected packages — create all the entities for the org.
    Returns a summary of what was created.
    """
    created = {
        "tags": 0,
        "auto_tag_rules": 0,
        "sla_configs": 0,
        "campaigns": 0,
        "agents": 0,
        "reports": 0,
        "roles": 0,
    }

    # Collect what to provision (deduplicated)
    tag_sets: set[str] = set()
    auto_tag_rule_ids: set[str] = set()
    campaign_ids: set[str] = set()
    agent_ids: set[str] = set()
    report_ids: set[str] = set()
    role_ids: set[str] = set()
    sla_preset = None

    for obj_id in objectives:
        pkg = OBJECTIVE_PACKAGES.get(obj_id)
        if not pkg:
            continue
        provisions = pkg["provisions"]
        for ts in provisions.get("tags", []):
            tag_sets.add(ts)
        for r in provisions.get("auto_tag_rules", []):
            auto_tag_rule_ids.add(r)
        for c in provisions.get("campaigns", []):
            campaign_ids.add(c)
        for a in provisions.get("agents", []):
            agent_ids.add(a)
        for r in provisions.get("reports", []):
            report_ids.add(r)
        for r in provisions.get("roles", []):
            role_ids.add(r)
        if provisions.get("sla_preset"):
            # Use the most aggressive preset if multiple objectives set it
            preset = provisions["sla_preset"]
            priority = {"aggressive": 3, "standard": 2, "relaxed": 1}
            if sla_preset is None or priority.get(preset, 0) > priority.get(sla_preset, 0):
                sla_preset = preset

    # Adjust SLA based on team size
    if sla_preset is None:
        sla_preset = "standard"
    if team_size in ("1-5", "6-15") and sla_preset == "aggressive":
        sla_preset = "standard"
    elif team_size in ("50-100", "100+") and sla_preset == "standard":
        sla_preset = "aggressive"

    # ── Create tags ──────────────────────────────────────────
    all_tags: list[dict] = []
    if "base" in tag_sets:
        all_tags.extend(_base_tags(org_id))
    if "network" in tag_sets:
        all_tags.extend(_network_tags(org_id))
    all_tags.extend(_team_tags(org_id, team_functions))

    for tag_data in all_tags:
        existing = db.query(Tag).filter(
            Tag.org_id == org_id,
            Tag.category == tag_data["category"],
            Tag.value == tag_data["value"],
        ).first()
        if not existing:
            db.add(Tag(**tag_data))
            created["tags"] += 1

    db.flush()

    # ── Create auto-tag rules ────────────────────────────────
    for rule_id in auto_tag_rule_ids:
        rule_def = AUTO_TAG_RULES.get(rule_id)
        if not rule_def:
            continue
        # Find or create the tag for this rule
        tag = db.query(Tag).filter(
            Tag.org_id == org_id,
            Tag.category == rule_def["tag_category"],
            Tag.value == rule_def["tag_value"],
        ).first()
        if not tag:
            tag = Tag(
                org_id=org_id,
                category=rule_def["tag_category"],
                value=rule_def["tag_value"],
                color=rule_def.get("tag_color", "#6366f1"),
            )
            db.add(tag)
            db.flush()

        existing = db.query(AutoTagRule).filter(
            AutoTagRule.org_id == org_id,
            AutoTagRule.name == rule_def["name"],
        ).first()
        if not existing:
            db.add(AutoTagRule(
                org_id=org_id,
                name=rule_def["name"],
                tag_id=tag.id,
                target_type=rule_def["target_type"],
                conditions=rule_def["conditions"],
                condition_logic=rule_def["condition_logic"],
                is_enabled=True,
            ))
            created["auto_tag_rules"] += 1

    # ── Create SLA configs ───────────────────────────────────
    sla_rows = SLA_PRESETS.get(sla_preset, SLA_PRESETS["standard"])
    for sla_data in sla_rows:
        existing = db.query(SLAConfig).filter(
            SLAConfig.org_id == org_id,
            SLAConfig.severity == sla_data["severity"],
        ).first()
        if existing:
            # Update if already exists
            existing.days_to_remediate = sla_data["days_to_remediate"]
            existing.warn_days_before = sla_data["warn_days_before"]
            existing.is_enabled = sla_data["is_enabled"]
        else:
            db.add(SLAConfig(org_id=org_id, **sla_data))
            created["sla_configs"] += 1

    # ── Create campaigns ─────────────────────────────────────
    for cmp_id in campaign_ids:
        cmp_def = CAMPAIGN_TEMPLATES.get(cmp_id)
        if not cmp_def:
            continue
        existing = db.query(Campaign).filter(
            Campaign.org_id == org_id,
            Campaign.name == cmp_def["name"],
        ).first()
        if not existing:
            db.add(Campaign(
                org_id=org_id,
                owner_id=user_id,
                **cmp_def,
            ))
            created["campaigns"] += 1

    # ── Create agents ────────────────────────────────────────
    for agent_id in agent_ids:
        agent_def = AGENT_TEMPLATES.get(agent_id)
        if not agent_def:
            continue
        existing = db.query(Agent).filter(
            Agent.org_id == org_id,
            Agent.name == agent_def["name"],
        ).first()
        if not existing:
            db.add(Agent(
                org_id=org_id,
                name=agent_def["name"],
                description=agent_def.get("description", ""),
                system_prompt=agent_def["system_prompt"],
                tools=agent_def["tools"],
                model=agent_def.get("model", "claude-sonnet-4-6"),
            ))
            created["agents"] += 1

    # ── Create report templates ──────────────────────────────
    for rpt_id in report_ids:
        rpt_def = REPORT_TEMPLATES.get(rpt_id)
        if not rpt_def:
            continue
        existing = db.query(ReportTemplate).filter(
            ReportTemplate.org_id == org_id,
            ReportTemplate.name == rpt_def["name"],
        ).first()
        if not existing:
            db.add(ReportTemplate(
                org_id=org_id,
                name=rpt_def["name"],
                config=rpt_def["config"],
                is_default=rpt_def.get("is_default", False),
            ))
            created["reports"] += 1

    # ── Create custom roles ──────────────────────────────────
    for role_id in role_ids:
        role_def = ROLE_TEMPLATES.get(role_id)
        if not role_def:
            continue
        existing = db.query(CustomRole).filter(
            CustomRole.org_id == org_id,
            CustomRole.name == role_def["name"],
        ).first()
        if not existing:
            db.add(CustomRole(
                org_id=org_id,
                name=role_def["name"],
                description=role_def.get("description", ""),
                base_permissions=role_def["base_permissions"],
            ))
            created["roles"] += 1

    # ── Save onboarding profile to org settings ──────────────
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if org:
        settings = org.settings or {}
        settings["onboarding"] = {
            "completed": True,
            "profile": profile,
            "objectives": objectives,
            "team_functions": team_functions,
            "team_size": team_size,
            "packages_applied": list(objectives),
        }
        org.settings = settings
        # Force SQLAlchemy to detect the change on JSON column
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(org, "settings")

    db.commit()
    logger.info("Onboarding packages applied for org %s: %s", org_id, created)
    return created
