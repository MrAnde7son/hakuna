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
    Workflow, WorkflowNode, WorkflowEdge,
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

# ── Notification preference options ─────────────────────────────

NOTIFICATION_OPTIONS = [
    {"id": "in_app", "label": "In-app notifications", "description": "Alerts within Hakuna's dashboard"},
    {"id": "email_digest", "label": "Daily email digest", "description": "Summary of new findings and SLA status every morning"},
    {"id": "email_realtime", "label": "Real-time email alerts", "description": "Immediate email for critical findings and SLA breaches"},
    {"id": "slack", "label": "Slack notifications", "description": "Post alerts to a Slack channel"},
    {"id": "teams", "label": "Microsoft Teams", "description": "Post alerts to a Teams channel"},
]

# ── Industry-specific configuration ────────────────────────────

INDUSTRY_CONFIG: dict[str, dict[str, Any]] = {
    "financial_services": {
        "compliance_frameworks": ["PCI DSS", "SOX", "GLBA", "FFIEC"],
        "tags": [
            {"category": "compliance", "value": "PCI DSS", "color": "#a855f7"},
            {"category": "compliance", "value": "SOX", "color": "#6366f1"},
            {"category": "data_class", "value": "Cardholder Data", "color": "#ef4444"},
            {"category": "data_class", "value": "Financial Records", "color": "#f97316"},
        ],
        "auto_tag_rules": [
            {
                "name": "Flag PCI-relevant findings",
                "target_type": "finding",
                "conditions": [{"field": "finding.plugin_family", "op": "contains", "value": "Web"}],
                "condition_logic": "AND",
                "tag_category": "compliance",
                "tag_value": "PCI DSS",
                "tag_color": "#a855f7",
            },
        ],
        "campaigns": [
            {
                "name": "PCI Compliance Gaps",
                "description": "Findings affecting systems in PCI scope that must be remediated for compliance.",
                "query": [{"field": "finding.severity", "op": "gte", "value": 2}],
                "query_logic": "AND",
                "status": "draft",
            },
        ],
        "exceptions": [
            {
                "plugin_id": "51192",
                "plugin_name": "SSL Certificate — Informational (Internal CA)",
                "exception_type": "false_positive",
                "reason": "Internal CA-signed certificates on non-public services are expected in financial environments.",
                "conditions": [
                    {"field": "finding.plugin_family", "op": "eq", "value": "General"},
                    {"field": "finding.severity", "op": "eq", "value": 0},
                ],
                "condition_logic": "AND",
            },
        ],
        "benchmarks": {
            "mttr_critical_days": 7,
            "mttr_high_days": 21,
            "sla_compliance_pct": 92,
            "findings_per_asset_avg": 12.5,
            "patch_coverage_pct": 88,
            "label": "Financial Services",
        },
        "agent_context": (
            "This organization is in financial services. Prioritize PCI DSS and SOX compliance. "
            "Flag any findings affecting cardholder data environments, payment processing, or financial reporting systems. "
            "Reference FFIEC and GLBA guidelines when relevant."
        ),
    },
    "healthcare": {
        "compliance_frameworks": ["HIPAA", "HITECH", "FDA 21 CFR Part 11"],
        "tags": [
            {"category": "compliance", "value": "HIPAA", "color": "#ef4444"},
            {"category": "compliance", "value": "HITECH", "color": "#f97316"},
            {"category": "data_class", "value": "PHI", "color": "#dc2626"},
            {"category": "data_class", "value": "ePHI", "color": "#ef4444"},
        ],
        "auto_tag_rules": [
            {
                "name": "Flag findings on healthcare systems",
                "target_type": "finding",
                "conditions": [{"field": "finding.severity", "op": "gte", "value": 3}],
                "condition_logic": "AND",
                "tag_category": "compliance",
                "tag_value": "HIPAA",
                "tag_color": "#ef4444",
            },
        ],
        "campaigns": [
            {
                "name": "HIPAA Critical Systems",
                "description": "High-severity findings on systems handling protected health information.",
                "query": [{"field": "finding.severity", "op": "gte", "value": 3}],
                "query_logic": "AND",
                "status": "draft",
            },
        ],
        "exceptions": [],
        "benchmarks": {
            "mttr_critical_days": 10,
            "mttr_high_days": 30,
            "sla_compliance_pct": 89,
            "findings_per_asset_avg": 14.2,
            "patch_coverage_pct": 85,
            "label": "Healthcare",
        },
        "agent_context": (
            "This organization is in healthcare. Prioritize HIPAA and HITECH compliance. "
            "Flag findings on systems handling PHI/ePHI. Consider FDA 21 CFR Part 11 for medical devices. "
            "Patient safety and data privacy are paramount."
        ),
    },
    "technology": {
        "compliance_frameworks": ["SOC 2", "ISO 27001", "GDPR"],
        "tags": [
            {"category": "compliance", "value": "SOC 2", "color": "#3b82f6"},
            {"category": "compliance", "value": "ISO 27001", "color": "#6366f1"},
            {"category": "data_class", "value": "Customer Data", "color": "#ef4444"},
            {"category": "data_class", "value": "Source Code", "color": "#f59e0b"},
        ],
        "auto_tag_rules": [],
        "campaigns": [
            {
                "name": "Customer-Facing Service Risks",
                "description": "Findings on production systems that serve customer traffic.",
                "query": [{"field": "finding.severity", "op": "gte", "value": 3}],
                "query_logic": "AND",
                "status": "draft",
            },
        ],
        "exceptions": [],
        "benchmarks": {
            "mttr_critical_days": 5,
            "mttr_high_days": 14,
            "sla_compliance_pct": 94,
            "findings_per_asset_avg": 8.3,
            "patch_coverage_pct": 92,
            "label": "Technology",
        },
        "agent_context": (
            "This organization is in technology/SaaS. Prioritize SOC 2 and ISO 27001 controls. "
            "Focus on customer-facing services, API security, CI/CD pipeline risks, and cloud infrastructure. "
            "Speed of remediation is critical for customer trust."
        ),
    },
    "government": {
        "compliance_frameworks": ["NIST 800-53", "FISMA", "CMMC", "FedRAMP"],
        "tags": [
            {"category": "compliance", "value": "NIST 800-53", "color": "#1e40af"},
            {"category": "compliance", "value": "CMMC", "color": "#3b82f6"},
            {"category": "compliance", "value": "FedRAMP", "color": "#6366f1"},
            {"category": "data_class", "value": "CUI", "color": "#ef4444"},
        ],
        "auto_tag_rules": [],
        "campaigns": [
            {
                "name": "CMMC Compliance Gaps",
                "description": "Findings that could impact CMMC certification status.",
                "query": [{"field": "finding.severity", "op": "gte", "value": 2}],
                "query_logic": "AND",
                "status": "draft",
            },
        ],
        "exceptions": [],
        "benchmarks": {
            "mttr_critical_days": 14,
            "mttr_high_days": 30,
            "sla_compliance_pct": 87,
            "findings_per_asset_avg": 16.8,
            "patch_coverage_pct": 82,
            "label": "Government",
        },
        "agent_context": (
            "This organization is in the government sector. Reference NIST 800-53, FISMA, and CMMC frameworks. "
            "Prioritize CUI protection, ensure findings are mapped to NIST controls, and consider FedRAMP impact levels."
        ),
    },
    "retail": {
        "compliance_frameworks": ["PCI DSS", "GDPR", "CCPA"],
        "tags": [
            {"category": "compliance", "value": "PCI DSS", "color": "#a855f7"},
            {"category": "compliance", "value": "GDPR", "color": "#3b82f6"},
            {"category": "data_class", "value": "Payment Data", "color": "#ef4444"},
            {"category": "data_class", "value": "Customer PII", "color": "#f97316"},
        ],
        "auto_tag_rules": [],
        "campaigns": [],
        "exceptions": [],
        "benchmarks": {
            "mttr_critical_days": 10,
            "mttr_high_days": 25,
            "sla_compliance_pct": 88,
            "findings_per_asset_avg": 11.0,
            "patch_coverage_pct": 86,
            "label": "Retail & E-commerce",
        },
        "agent_context": (
            "This organization is in retail/e-commerce. Prioritize PCI DSS for payment systems and "
            "GDPR/CCPA for customer data protection. Focus on web application security and point-of-sale systems."
        ),
    },
    "manufacturing": {
        "compliance_frameworks": ["IEC 62443", "NIST CSF", "ISO 27001"],
        "tags": [
            {"category": "compliance", "value": "IEC 62443", "color": "#f59e0b"},
            {"category": "compliance", "value": "NIST CSF", "color": "#3b82f6"},
            {"category": "asset_type", "value": "OT/ICS", "color": "#ef4444"},
            {"category": "asset_type", "value": "SCADA", "color": "#dc2626"},
        ],
        "auto_tag_rules": [],
        "campaigns": [],
        "exceptions": [],
        "benchmarks": {
            "mttr_critical_days": 14,
            "mttr_high_days": 45,
            "sla_compliance_pct": 83,
            "findings_per_asset_avg": 18.5,
            "patch_coverage_pct": 78,
            "label": "Manufacturing",
        },
        "agent_context": (
            "This organization is in manufacturing. Consider OT/ICS and SCADA system risks. "
            "Reference IEC 62443 for industrial control systems. Patching windows may be constrained by production schedules."
        ),
    },
    "energy": {
        "compliance_frameworks": ["NERC CIP", "NIST CSF", "IEC 62443"],
        "tags": [
            {"category": "compliance", "value": "NERC CIP", "color": "#ef4444"},
            {"category": "compliance", "value": "NIST CSF", "color": "#3b82f6"},
            {"category": "asset_type", "value": "OT/ICS", "color": "#ef4444"},
            {"category": "asset_type", "value": "Critical Infrastructure", "color": "#dc2626"},
        ],
        "auto_tag_rules": [],
        "campaigns": [],
        "exceptions": [],
        "benchmarks": {
            "mttr_critical_days": 15,
            "mttr_high_days": 45,
            "sla_compliance_pct": 85,
            "findings_per_asset_avg": 20.1,
            "patch_coverage_pct": 76,
            "label": "Energy & Utilities",
        },
        "agent_context": (
            "This organization is in energy/utilities. Reference NERC CIP for critical infrastructure protection. "
            "Consider OT/ICS risks and constrained maintenance windows. Uptime and safety are paramount."
        ),
    },
    "education": {
        "compliance_frameworks": ["FERPA", "NIST CSF", "GDPR"],
        "tags": [
            {"category": "compliance", "value": "FERPA", "color": "#6366f1"},
            {"category": "data_class", "value": "Student Records", "color": "#ef4444"},
        ],
        "auto_tag_rules": [],
        "campaigns": [],
        "exceptions": [],
        "benchmarks": {
            "mttr_critical_days": 14,
            "mttr_high_days": 45,
            "sla_compliance_pct": 80,
            "findings_per_asset_avg": 15.0,
            "patch_coverage_pct": 79,
            "label": "Education",
        },
        "agent_context": (
            "This organization is in education. Prioritize FERPA compliance for student data. "
            "Consider the diverse IT environment typical of educational institutions."
        ),
    },
    "telecom": {
        "compliance_frameworks": ["SOC 2", "ISO 27001", "GDPR", "CPNI"],
        "tags": [
            {"category": "compliance", "value": "SOC 2", "color": "#3b82f6"},
            {"category": "data_class", "value": "CPNI", "color": "#ef4444"},
            {"category": "data_class", "value": "Subscriber Data", "color": "#f97316"},
        ],
        "auto_tag_rules": [],
        "campaigns": [],
        "exceptions": [],
        "benchmarks": {
            "mttr_critical_days": 7,
            "mttr_high_days": 21,
            "sla_compliance_pct": 91,
            "findings_per_asset_avg": 13.2,
            "patch_coverage_pct": 87,
            "label": "Telecommunications",
        },
        "agent_context": (
            "This organization is in telecommunications. Protect CPNI and subscriber data. "
            "Focus on network infrastructure, service availability, and SOC 2 compliance."
        ),
    },
}

# Default benchmarks for industries without specific data
DEFAULT_BENCHMARKS = {
    "mttr_critical_days": 12,
    "mttr_high_days": 30,
    "sla_compliance_pct": 86,
    "findings_per_asset_avg": 13.0,
    "patch_coverage_pct": 84,
    "label": "All Industries",
}

# ── Package definitions ─────────────────────────────────────────

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


def _industry_tags(org_id: int, industry: str | None) -> list[dict]:
    """Industry-specific compliance and data classification tags."""
    cfg = INDUSTRY_CONFIG.get(industry or "", {})
    tags = []
    for tag_def in cfg.get("tags", []):
        tags.append({"org_id": org_id, **tag_def})
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
            {"field": "finding.severity", "op": "gte", "value": 3},
            {"field": "finding.exploit", "op": "is_true"},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
    "critical_path": {
        "name": "Critical Path",
        "description": "Critical and high severity findings on business-critical assets.",
        "query": [
            {"field": "finding.severity", "op": "gte", "value": 4},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
    "sla_breaches": {
        "name": "SLA Breaches",
        "description": "Findings that have exceeded their remediation SLA deadline.",
        "query": [
            {"field": "finding.sla_status", "op": "eq", "value": "breached"},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
    "patch_tuesday": {
        "name": "Patch Tuesday",
        "description": "Findings addressable by applying latest vendor patches.",
        "query": [
            {"field": "finding.solution", "op": "contains", "value": "patch"},
            {"field": "finding.severity", "op": "gte", "value": 2},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
    "siem_alert_response": {
        "name": "SIEM Alert Response",
        "description": "Assets with active SIEM alerts that have critical or high vulnerability findings requiring immediate attention.",
        "query": [
            {"field": "siem.has_active_alerts", "op": "is_true"},
            {"field": "finding.severity", "op": "gte", "value": 3},
        ],
        "query_logic": "AND",
        "status": "draft",
    },
    "internet_facing_alerts": {
        "name": "Internet-Facing Under Attack",
        "description": "Internet-facing assets generating SIEM alerts — highest risk combination.",
        "query": [
            {"field": "siem.alert_count", "op": "gte", "value": 1},
            {"field": "inventory.is_internet_facing", "op": "is_true"},
            {"field": "finding.severity", "op": "gte", "value": 3},
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
        "tools": ["query_findings", "query_assets", "get_finding_detail", "get_threat_cves", "get_exploit_findings"],
        "model": "vertex/gemini-2.5-pro",
    },
    "remediation_advisor": {
        "name": "Remediation Advisor",
        "description": "Drafts remediation plans, generates patch scripts, and creates campaign strategies.",
        "system_prompt": (
            "You are a remediation advisor. Help security teams create actionable remediation plans. "
            "Draft step-by-step instructions, suggest patch commands, identify dependencies, "
            "and recommend testing procedures. Group related findings for efficient bulk remediation."
        ),
        "tools": ["query_findings", "query_assets", "get_finding_detail", "list_campaigns", "get_remediation_grouping"],
        "model": "vertex/gemini-2.5-pro",
    },
    "threat_intel_analyst": {
        "name": "Threat Intel Analyst",
        "description": "Correlates findings with threat intelligence, tracks exploits, and maps to MITRE ATT&CK.",
        "system_prompt": (
            "You are a threat intelligence analyst. Correlate vulnerability findings with real-world threats. "
            "Check for active exploitation, map to MITRE ATT&CK techniques, assess threat actor interest, "
            "and provide context on exploit availability and weaponization."
        ),
        "tools": ["query_findings", "get_threat_cves", "get_threat_groups", "get_threat_campaigns"],
        "model": "vertex/gemini-2.5-pro",
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
        "tools": ["query_findings", "query_assets", "list_campaigns", "get_sla_status", "get_owner_workload"],
        "model": "vertex/gemini-2.5-pro",
    },
    "siem_analyst": {
        "name": "SIEM Alert Analyst",
        "description": "Investigates SIEM alerts, correlates events with vulnerability data, and recommends triage actions.",
        "system_prompt": (
            "You are a SIEM analyst. When given alerts or events, investigate the security context: "
            "query related SIEM events, check the asset's vulnerability exposure, look for patterns "
            "like brute force or lateral movement, and recommend triage actions (close, escalate, suppress). "
            "Correlate alerts with known vulnerabilities on the affected asset to assess actual risk. "
            "Always check exposure context: is the asset internet-facing? What critical vulns exist?"
        ),
        "tools": ["query_events", "list_alerts", "get_alert_with_events", "triage_alert", "get_exposure_context", "query_findings", "query_assets"],
        "model": "vertex/gemini-2.5-pro",
    },
    "detection_engineer": {
        "name": "Detection Engineer",
        "description": "Creates and tunes detection rules, analyzes false positive rates, and suggests suppression rules.",
        "system_prompt": (
            "You are a detection engineer. Help security teams create effective detection rules "
            "and reduce alert fatigue. Analyze event patterns to suggest new rules, review existing "
            "rules for false positive rates, recommend suppression rules for known-good activity, "
            "and suggest asset context filters to focus rules on high-value targets. "
            "When creating rules, consider threshold, window, group_by fields, and MITRE technique mapping."
        ),
        "tools": ["query_events", "list_alerts", "run_detection_rule_now", "query_assets", "get_exposure_context"],
        "model": "vertex/gemini-2.5-pro",
    },
}


# ── Report template configs ─────────────────────────────────────

REPORT_TEMPLATES = {
    "executive_summary": {
        "name": "Executive Summary",
        "config": {
            "widgets": [
                {"id": "ob-es1", "type": "risk_grade", "title": "Organization Risk Grade", "width": "half", "config": {"preset": "risk_grade", "show_benchmark": True}},
                {"id": "ob-es2", "type": "pie_chart", "title": "Severity Distribution", "width": "half", "config": {"preset": "severity_breakdown", "donut": True}},
                {"id": "ob-es3", "type": "card", "title": "Critical", "width": "quarter", "config": {"preset": "critical_count"}},
                {"id": "ob-es4", "type": "card", "title": "High", "width": "quarter", "config": {"preset": "high_count"}},
                {"id": "ob-es5", "type": "card", "title": "With Exploit", "width": "quarter", "config": {"preset": "exploit_count"}},
                {"id": "ob-es6", "type": "card", "title": "Mean Time to Remediate", "width": "quarter", "config": {"preset": "mttr_overall", "label": "days"}},
                {"id": "ob-es7", "type": "pie_chart", "title": "SLA Status", "width": "half", "config": {"preset": "sla_status", "donut": True}},
                {"id": "ob-es8", "type": "bar_chart", "title": "Top 10 by Severity", "width": "half", "config": {"preset": "severity_breakdown", "limit": 10}},
                {"id": "ob-es9", "type": "table", "title": "Top Critical Findings", "width": "full", "config": {"preset": "findings_list", "filters": {"severity": "4", "order": "desc", "sort_by": "priority_score"}, "limit": 10}},
            ]
        },
        "is_default": False,
    },
    "team_dashboard": {
        "name": "Team Dashboard",
        "config": {
            "widgets": [
                {"id": "ob-td1", "type": "card", "title": "Total Findings", "width": "quarter", "config": {"preset": "total_findings"}},
                {"id": "ob-td2", "type": "card", "title": "Critical", "width": "quarter", "config": {"preset": "critical_count"}},
                {"id": "ob-td3", "type": "card", "title": "SLA Breached", "width": "quarter", "config": {"preset": "sla_breached"}},
                {"id": "ob-td4", "type": "card", "title": "With Exploit", "width": "quarter", "config": {"preset": "exploit_count"}},
                {"id": "ob-td5", "type": "pie_chart", "title": "Findings by Severity", "width": "half", "config": {"preset": "severity_breakdown", "donut": True}},
                {"id": "ob-td6", "type": "pie_chart", "title": "SLA Status", "width": "half", "config": {"preset": "sla_status", "donut": True}},
                {"id": "ob-td7", "type": "bar_chart", "title": "Findings by Owner", "width": "half", "config": {"preset": "owner_finding_count"}},
                {"id": "ob-td8", "type": "bar_chart", "title": "Findings by Family", "width": "half", "config": {"preset": "family_breakdown", "limit": 10}},
                {"id": "ob-td9", "type": "table", "title": "Top Findings to Fix", "width": "full", "config": {"preset": "findings_list", "filters": {"order": "desc", "sort_by": "priority_score"}, "limit": 15}},
            ]
        },
        "is_default": False,
    },
    "siem_operations": {
        "name": "SIEM Operations",
        "config": {
            "widgets": [
                {"id": "ob-so1", "type": "card", "title": "Events (24h)", "width": "quarter", "config": {"preset": "siem_events_24h"}},
                {"id": "ob-so2", "type": "card", "title": "Open Alerts", "width": "quarter", "config": {"preset": "siem_alerts_open"}},
                {"id": "ob-so3", "type": "card", "title": "Active Rules", "width": "quarter", "config": {"preset": "siem_rules_active"}},
                {"id": "ob-so4", "type": "card", "title": "MTTR (min)", "width": "quarter", "config": {"preset": "siem_mttr", "label": "min"}},
                {"id": "ob-so5", "type": "bar_chart", "title": "Event Volume by Source", "width": "half", "config": {"preset": "siem_event_volume"}},
                {"id": "ob-so6", "type": "pie_chart", "title": "Alerts by Severity", "width": "half", "config": {"preset": "siem_alert_severity", "donut": True}},
                {"id": "ob-so7", "type": "bar_chart", "title": "Noisy Rules (FP Rate)", "width": "half", "config": {"preset": "siem_noisy_rules", "limit": 10}},
                {"id": "ob-so8", "type": "table", "title": "Top Assets by Alert Count", "width": "half", "config": {"preset": "siem_top_assets", "limit": 10}},
                {"id": "ob-so9", "type": "table", "title": "Recent Open Alerts", "width": "full", "config": {"preset": "siem_recent_alerts", "limit": 15}},
            ]
        },
        "is_default": False,
    },
    "compliance_report": {
        "name": "Compliance & Audit Report",
        "config": {
            "widgets": [
                {"id": "ob-cr1", "type": "risk_grade", "title": "Organization Risk Grade", "width": "half", "config": {"preset": "risk_grade"}},
                {"id": "ob-cr2", "type": "pie_chart", "title": "SLA Compliance", "width": "half", "config": {"preset": "sla_status", "donut": True}},
                {"id": "ob-cr3", "type": "card", "title": "SLA Breached", "width": "quarter", "config": {"preset": "sla_breached"}},
                {"id": "ob-cr4", "type": "card", "title": "Mean Time to Remediate", "width": "quarter", "config": {"preset": "mttr_overall", "label": "days"}},
                {"id": "ob-cr5", "type": "card", "title": "Active Exceptions", "width": "quarter", "config": {"preset": "excepted_findings"}},
                {"id": "ob-cr6", "type": "card", "title": "Total Findings", "width": "quarter", "config": {"preset": "total_findings"}},
                {"id": "ob-cr7", "type": "pie_chart", "title": "Severity Distribution", "width": "half", "config": {"preset": "severity_breakdown", "donut": True}},
                {"id": "ob-cr8", "type": "bar_chart", "title": "Findings by Age", "width": "half", "config": {"preset": "age_distribution"}},
                {"id": "ob-cr9", "type": "table", "title": "SLA Breaches", "width": "full", "config": {"preset": "findings_list", "filters": {"sla_status": "breached", "order": "desc", "sort_by": "priority_score"}, "limit": 20}},
            ]
        },
        "is_default": False,
    },
}

# ── Team-function → default dashboard mapping ──────────────────

FUNCTION_DEFAULT_DASHBOARD = {
    "secops": "executive_summary",
    "vuln_mgmt": "team_dashboard",
    "it_ops": "team_dashboard",
    "devops": "team_dashboard",
    "appsec": "team_dashboard",
    "grc": "compliance_report",
    "executive": "executive_summary",
    "network": "team_dashboard",
    "helpdesk": "team_dashboard",
}


# ── Auto-tag rule templates ─────────────────────────────────────

AUTO_TAG_RULES = {
    "windows_servers": {
        "name": "Auto-tag Windows Servers",
        "target_type": "asset",
        "conditions": [{"field": "os", "op": "contains", "value": "Windows Server"}],
        "condition_logic": "AND",
        "tag_category": "os_family",
        "tag_value": "Windows Server",
        "tag_color": "#3b82f6",
    },
    "linux_servers": {
        "name": "Auto-tag Linux Servers",
        "target_type": "asset",
        "conditions": [{"field": "os", "op": "contains", "value": "Linux"}],
        "condition_logic": "AND",
        "tag_category": "os_family",
        "tag_value": "Linux",
        "tag_color": "#f59e0b",
    },
    "exploitable_findings": {
        "name": "Flag Exploitable Findings",
        "target_type": "finding",
        "conditions": [{"field": "finding.exploit", "op": "is_true"}],
        "condition_logic": "AND",
        "tag_category": "risk",
        "tag_value": "Exploitable",
        "tag_color": "#ef4444",
    },
}


# ── Ownership rule templates ───────────────────────────────────

OWNERSHIP_RULES = {
    "secops": {
        "name": "Route critical findings to SecOps",
        "description": "Automatically assign critical/high severity findings to Security Operations team.",
        "target_type": "finding",
        "conditions": [{"field": "finding.severity", "op": "gte", "value": 4}],
        "condition_logic": "AND",
        "priority": 10,
        "team": "Security Operations",
        "owner_role": "SecOps",
    },
    "it_ops": {
        "name": "Route OS patches to IT Operations",
        "description": "Assign OS-level patch findings to IT Operations.",
        "target_type": "finding",
        "conditions": [{"field": "finding.plugin_family", "op": "contains", "value": "Windows"}],
        "condition_logic": "AND",
        "priority": 50,
        "team": "IT Operations",
        "owner_role": "IT Ops",
    },
    "devops": {
        "name": "Route container/cloud findings to DevOps",
        "description": "Assign container and cloud infrastructure findings to DevOps.",
        "target_type": "finding",
        "conditions": [{"field": "finding.plugin_family", "op": "contains", "value": "Web"}],
        "condition_logic": "AND",
        "priority": 40,
        "team": "DevOps",
        "owner_role": "DevOps",
    },
    "appsec": {
        "name": "Route web app findings to AppSec",
        "description": "Assign web application and code-level findings to Application Security.",
        "target_type": "finding",
        "conditions": [{"field": "finding.plugin_family", "op": "contains", "value": "CGI"}],
        "condition_logic": "AND",
        "priority": 30,
        "team": "Application Security",
        "owner_role": "AppSec",
    },
    "network": {
        "name": "Route network findings to Network Engineering",
        "description": "Assign network device and firewall findings to Network Engineering.",
        "target_type": "finding",
        "conditions": [{"field": "finding.plugin_family", "op": "contains", "value": "Firewalls"}],
        "condition_logic": "AND",
        "priority": 40,
        "team": "Network Engineering",
        "owner_role": "Network",
    },
    "grc": {
        "name": "Flag compliance findings for GRC review",
        "description": "Route compliance-related findings to GRC team for review.",
        "target_type": "finding",
        "conditions": [{"field": "finding.plugin_family", "op": "contains", "value": "Policy Compliance"}],
        "condition_logic": "AND",
        "priority": 60,
        "team": "GRC / Compliance",
        "owner_role": "GRC",
    },
}


# ── Workflow templates ──────────────────────────────────────────

WORKFLOW_TEMPLATES = {
    "notify_critical": {
        "name": "Notify on Critical Findings",
        "description": "Send an alert when new critical severity findings are discovered in a scan.",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_upload",
             "label": "Scan Uploaded", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "Critical only", "config": {"operator": "gte", "value": "4"}, "position_x": 300, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "send_email",
             "label": "Email alert", "config": {"to": "", "subject": "Critical findings detected in {{scan.name}}", "body": "{{count}} critical findings were found. Review immediately."},
             "position_x": 540, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e-1", "source_node_id": "t1", "target_node_id": "f1"},
            {"edge_id": "e-2", "source_node_id": "f1", "target_node_id": "a1"},
        ],
    },
    "auto_assign_exploitable": {
        "name": "Auto-assign Exploitable Findings",
        "description": "Automatically assign findings with known exploits to the security team for triage.",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_upload",
             "label": "Scan Uploaded", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "exploit_filter",
             "label": "Has exploit", "config": {"has_exploit": "true"}, "position_x": 300, "position_y": 200},
            {"node_id": "f2", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "High+", "config": {"operator": "gte", "value": "3"}, "position_x": 480, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "assign_owner",
             "label": "Assign to SecOps", "config": {"team": "Security Operations", "owner_role": "SecOps"},
             "position_x": 660, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e-1", "source_node_id": "t1", "target_node_id": "f1"},
            {"edge_id": "e-2", "source_node_id": "f1", "target_node_id": "f2"},
            {"edge_id": "e-3", "source_node_id": "f2", "target_node_id": "a1"},
        ],
    },
    "sla_breach_escalation": {
        "name": "SLA Breach Escalation",
        "description": "Escalate findings that breach their SLA deadline to management.",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "schedule",
             "label": "Daily at 8 AM", "config": {"schedule_mode": "cron", "cron_expr": "0 8 * * *"}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "SLA Breached", "config": {"conditions": [{"field": "finding.sla_status", "op": "eq", "value": "breached"}], "logic": "AND"},
             "position_x": 300, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "send_email",
             "label": "Email escalation", "config": {"to": "", "subject": "SLA Breach Alert — {{count}} overdue findings", "body": "The following findings have breached their SLA deadline and require immediate attention."},
             "position_x": 540, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e-1", "source_node_id": "t1", "target_node_id": "f1"},
            {"edge_id": "e-2", "source_node_id": "f1", "target_node_id": "a1"},
        ],
    },
}


# ── Common false-positive exception templates ──────────────────

EXCEPTION_TEMPLATES = {
    "ssl_self_signed_internal": {
        "plugin_id": "57582",
        "plugin_name": "Self-signed SSL Certificate (Internal)",
        "exception_type": "false_positive",
        "reason": "Self-signed certificates on internal-only services are expected and do not pose external risk.",
        "conditions": [
            {"field": "finding.plugin_family", "op": "eq", "value": "General"},
            {"field": "finding.severity", "op": "lte", "value": 1},
            {"field": "finding.plugin_name", "op": "contains", "value": "Self-Signed"},
        ],
        "condition_logic": "AND",
    },
    "info_disclosure_internal": {
        "plugin_id": "22964",
        "plugin_name": "Informational Service Detection (Internal)",
        "exception_type": "accepted_risk",
        "reason": "Informational service detection findings on internal networks are low risk and create noise.",
        "conditions": [
            {"field": "finding.severity", "op": "eq", "value": 0},
            {"field": "finding.plugin_family", "op": "eq", "value": "Service detection"},
        ],
        "condition_logic": "AND",
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
# Each package maps to an objective and defines what gets created.

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
        "description": "Campaigns, ownership rules, SLA policies, workflows, and team-based tracking",
        "provisions": {
            "tags": ["base"],
            "sla_preset": "standard",
            "campaigns": ["quick_wins", "critical_path", "sla_breaches", "patch_tuesday"],
            "roles": ["it_remediation"],
            "reports": ["team_dashboard"],
            "ownership_rules": True,
            "workflows": ["notify_critical", "auto_assign_exploitable", "sla_breach_escalation"],
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
    "siem_operations": {
        "label": "SIEM & Detection",
        "description": "SIEM event correlation, detection rules, alert triage, and exposure-aware campaigns",
        "provisions": {
            "reports": ["siem_operations", "executive_summary"],
            "campaigns": ["siem_alert_response", "internet_facing_alerts"],
            "agents": ["siem_analyst", "detection_engineer"],
            "workflows": ["notify_critical"],
        },
    },
    "integrations": {
        "label": "Integration Hub",
        "description": "Pre-configured integration templates for ticketing and chat tools",
        "provisions": {
            "tags": ["base"],
            "workflows": ["notify_critical"],
        },
    },
    "compliance": {
        "label": "Compliance & Audit",
        "description": "SLA enforcement, exception tracking, compliance tags, and audit-ready reporting",
        "provisions": {
            "sla_preset": "aggressive",
            "reports": ["compliance_report", "executive_summary"],
            "roles": ["compliance_auditor"],
            "campaigns": ["sla_breaches"],
            "exceptions": True,
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

def get_recommendations(
    objectives: list[str],
    team_functions: list[str],
    team_size: str,
    industry: str | None = None,
) -> dict:
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

    # Industry-specific additions
    industry_cfg = INDUSTRY_CONFIG.get(industry or "", {})
    industry_additions = None
    if industry_cfg:
        extras = []
        if industry_cfg.get("tags"):
            extras.append(f"{len(industry_cfg['tags'])} compliance tags")
        if industry_cfg.get("auto_tag_rules"):
            extras.append(f"{len(industry_cfg['auto_tag_rules'])} auto-tag rules")
        if industry_cfg.get("campaigns"):
            extras.append(f"{len(industry_cfg['campaigns'])} campaigns")
        if extras:
            industry_additions = {
                "label": f"{industry_cfg.get('benchmarks', {}).get('label', 'Industry')} Pack",
                "description": f"Industry-specific: {', '.join(extras)}",
                "frameworks": industry_cfg.get("compliance_frameworks", []),
            }

    # Industry benchmarks
    benchmarks = industry_cfg.get("benchmarks", DEFAULT_BENCHMARKS)

    return {
        "packages": packages,
        "sla_note": sla_note,
        "industry_additions": industry_additions,
        "benchmarks": benchmarks,
    }


def apply_packages(
    db: Session,
    org_id: int,
    user_id: int,
    objectives: list[str],
    team_functions: list[str],
    team_size: str,
    profile: dict,
    notification_prefs: list[str] | None = None,
) -> dict:
    """
    Apply selected packages — create all the entities for the org.
    Returns a summary of what was created.
    """
    industry = profile.get("industry")

    created = {
        "tags": 0,
        "auto_tag_rules": 0,
        "sla_configs": 0,
        "campaigns": 0,
        "agents": 0,
        "reports": 0,
        "roles": 0,
        "ownership_rules": 0,
        "workflows": 0,
        "exceptions": 0,
    }

    # Collect what to provision (deduplicated)
    tag_sets: set[str] = set()
    auto_tag_rule_ids: set[str] = set()
    campaign_ids: set[str] = set()
    agent_ids: set[str] = set()
    report_ids: set[str] = set()
    role_ids: set[str] = set()
    workflow_ids: set[str] = set()
    provision_ownership = False
    provision_exceptions = False
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
        for w in provisions.get("workflows", []):
            workflow_ids.add(w)
        if provisions.get("ownership_rules"):
            provision_ownership = True
        if provisions.get("exceptions"):
            provision_exceptions = True
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
    # Industry-specific tags
    all_tags.extend(_industry_tags(org_id, industry))

    for tag_data in all_tags:
        # UniqueConstraint is on (category, value) — not org-scoped
        existing = db.query(Tag).filter(
            Tag.category == tag_data["category"],
            Tag.value == tag_data["value"],
        ).first()
        if not existing:
            db.add(Tag(**tag_data))
            created["tags"] += 1

    db.flush()

    # ── Create auto-tag rules ────────────────────────────────
    # Standard rules
    for rule_id in auto_tag_rule_ids:
        rule_def = AUTO_TAG_RULES.get(rule_id)
        if not rule_def:
            continue
        created["auto_tag_rules"] += _create_auto_tag_rule(db, org_id, rule_def)

    # Industry-specific auto-tag rules
    industry_cfg = INDUSTRY_CONFIG.get(industry or "", {})
    for rule_def in industry_cfg.get("auto_tag_rules", []):
        created["auto_tag_rules"] += _create_auto_tag_rule(db, org_id, rule_def)

    # ── Create SLA configs ───────────────────────────────────
    sla_rows = SLA_PRESETS.get(sla_preset, SLA_PRESETS["standard"])
    for sla_data in sla_rows:
        existing = db.query(SLAConfig).filter(
            SLAConfig.severity == sla_data["severity"],
            SLAConfig.org_id == org_id,
        ).first()
        if existing:
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

    # Industry-specific campaigns
    for cmp_def in industry_cfg.get("campaigns", []):
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

    # ── Create agents (with industry context) ────────────────
    agent_industry_ctx = industry_cfg.get("agent_context", "")
    for agent_id in agent_ids:
        agent_def = AGENT_TEMPLATES.get(agent_id)
        if not agent_def:
            continue
        existing = db.query(Agent).filter(
            Agent.org_id == org_id,
            Agent.name == agent_def["name"],
        ).first()
        if not existing:
            system_prompt = agent_def["system_prompt"]
            if agent_industry_ctx:
                system_prompt = f"{system_prompt}\n\nIndustry context: {agent_industry_ctx}"
            db.add(Agent(
                org_id=org_id,
                name=agent_def["name"],
                description=agent_def.get("description", ""),
                system_prompt=system_prompt,
                tools=agent_def["tools"],
                model=agent_def.get("model", "vertex/gemini-2.5-pro"),
            ))
            created["agents"] += 1

    # ── Create report templates ──────────────────────────────
    # Determine default dashboard from primary team function
    primary_fn = team_functions[0] if team_functions else None
    default_dashboard_id = FUNCTION_DEFAULT_DASHBOARD.get(primary_fn, "executive_summary")

    for rpt_id in report_ids:
        rpt_def = REPORT_TEMPLATES.get(rpt_id)
        if not rpt_def:
            continue
        # UniqueConstraint on name (not org-scoped) — check globally
        existing = db.query(ReportTemplate).filter(
            ReportTemplate.name == rpt_def["name"],
        ).first()
        if existing:
            # Ensure it's associated with this org and set default if needed
            if existing.org_id is None:
                existing.org_id = org_id
            if rpt_id == default_dashboard_id:
                existing.is_default = True
        else:
            is_default = (rpt_id == default_dashboard_id)
            db.add(ReportTemplate(
                org_id=org_id,
                name=rpt_def["name"],
                config=rpt_def["config"],
                is_default=is_default,
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

    # ── Create ownership rules ───────────────────────────────
    if provision_ownership and team_functions:
        for fn_id in team_functions:
            rule_def = OWNERSHIP_RULES.get(fn_id)
            if not rule_def:
                continue
            existing = db.query(OwnershipRule).filter(
                OwnershipRule.org_id == org_id,
                OwnershipRule.name == rule_def["name"],
            ).first()
            if not existing:
                db.add(OwnershipRule(
                    org_id=org_id,
                    name=rule_def["name"],
                    description=rule_def.get("description", ""),
                    target_type=rule_def["target_type"],
                    conditions=rule_def["conditions"],
                    condition_logic=rule_def["condition_logic"],
                    priority=rule_def.get("priority", 100),
                    team=rule_def.get("team"),
                    owner_role=rule_def.get("owner_role"),
                    is_enabled=True,
                ))
                created["ownership_rules"] += 1

    # ── Create workflows ─────────────────────────────────────
    for wf_id in workflow_ids:
        wf_def = WORKFLOW_TEMPLATES.get(wf_id)
        if not wf_def:
            continue
        existing = db.query(Workflow).filter(
            Workflow.org_id == org_id,
            Workflow.name == wf_def["name"],
        ).first()
        if not existing:
            wf = Workflow(
                org_id=org_id,
                name=wf_def["name"],
                description=wf_def.get("description", ""),
                status="draft",
                is_enabled=False,
            )
            db.add(wf)
            db.flush()

            for node_def in wf_def["nodes"]:
                db.add(WorkflowNode(workflow_id=wf.id, **node_def))

            for edge_def in wf_def["edges"]:
                db.add(WorkflowEdge(
                    workflow_id=wf.id,
                    edge_id=edge_def["edge_id"],
                    source_node_id=edge_def["source_node_id"],
                    target_node_id=edge_def["target_node_id"],
                    source_handle=edge_def.get("source_handle", "output"),
                    target_handle=edge_def.get("target_handle", "input"),
                ))

            created["workflows"] += 1

    # ── Create exception rules ───────────────────────────────
    if provision_exceptions:
        # Common exceptions
        for exc_def in EXCEPTION_TEMPLATES.values():
            existing = db.query(FindingException).filter(
                FindingException.org_id == org_id,
                FindingException.plugin_id == exc_def["plugin_id"],
            ).first()
            if not existing:
                db.add(FindingException(
                    org_id=org_id,
                    plugin_id=exc_def["plugin_id"],
                    plugin_name=exc_def["plugin_name"],
                    exception_type=exc_def["exception_type"],
                    reason=exc_def["reason"],
                    conditions=exc_def.get("conditions"),
                    condition_logic=exc_def.get("condition_logic", "AND"),
                    is_active=True,
                    exclude_from_reports=True,
                ))
                created["exceptions"] += 1

        # Industry-specific exceptions
        for exc_def in industry_cfg.get("exceptions", []):
            existing = db.query(FindingException).filter(
                FindingException.org_id == org_id,
                FindingException.plugin_id == exc_def["plugin_id"],
            ).first()
            if not existing:
                db.add(FindingException(
                    org_id=org_id,
                    plugin_id=exc_def["plugin_id"],
                    plugin_name=exc_def["plugin_name"],
                    exception_type=exc_def["exception_type"],
                    reason=exc_def["reason"],
                    conditions=exc_def.get("conditions"),
                    condition_logic=exc_def.get("condition_logic", "AND"),
                    is_active=True,
                    exclude_from_reports=True,
                ))
                created["exceptions"] += 1

    # ── Save onboarding profile to org settings ──────────────
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if org:
        settings = org.settings or {}
        benchmarks = industry_cfg.get("benchmarks", DEFAULT_BENCHMARKS)
        settings["onboarding"] = {
            "completed": True,
            "profile": profile,
            "objectives": objectives,
            "team_functions": team_functions,
            "team_size": team_size,
            "packages_applied": list(objectives),
            "industry_benchmarks": benchmarks,
            "default_dashboard": default_dashboard_id,
        }
        if notification_prefs:
            settings["notification_preferences"] = notification_prefs
        org.settings = settings
        # Force SQLAlchemy to detect the change on JSON column
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(org, "settings")

    db.commit()
    logger.info("Onboarding packages applied for org %s: %s", org_id, created)

    # Mirror the user-stated profile into the org-shared memory layer so any
    # agent opted into the `org_profile` namespace gets industry / team-shape
    # / objectives in its system prompt without a bespoke tool. Failures here
    # must not break onboarding — the wizard's source-of-truth remains
    # `Organization.settings.onboarding`.
    try:
        from services.org_memory import sync_org_profile_to_memory
        sync_org_profile_to_memory(db, org_id)
        db.commit()
    except Exception:
        logger.exception("Failed to mirror onboarding profile to org_memory (non-fatal)")
        db.rollback()

    return created


def _create_auto_tag_rule(db: Session, org_id: int, rule_def: dict) -> int:
    """Create a single auto-tag rule, returning 1 if created, 0 if exists."""
    tag = db.query(Tag).filter(
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
        return 1
    return 0
