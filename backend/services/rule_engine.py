"""
Unified Rule Engine
-------------------
Single evaluation engine for criticality auto-rules, auto-tag rules, and campaign queries.

Condition format (all systems):
    {"field": "<field>", "op": "<operator>", "value": <optional>}

Field namespaces:
    Asset:      ip, hostname, fqdn, os, netbios_name, environment_tag
                criticality, risk_score, critical_count, high_count,
                medium_count, low_count, info_count
    Findings:   finding.severity, finding.cvss3, finding.vpr,
                finding.exploit, finding.zero_day, finding.has_cve,
                finding.has_cwe, finding.missing_patches, finding.plugin_family,
                finding.plugin_name, finding.cve, finding.cwe, finding.effort, finding.owner,
                finding.sla_status, finding.sla_days_remaining, finding.sla_due_date
    Inventory:  inventory.is_internet_facing, inventory.is_domain_controller,
                inventory.domain_admin_present, inventory.admin_logged_in,
                inventory.privileged_user_logged_in, inventory.kerberoastable_user,
                inventory.has_writeable_share, inventory.no_edr,
                inventory.no_av, inventory.no_firewall
    Tags:       tag   (ops: has_tag | not_has_tag)

Operators:
    String:   eq, neq, contains, not_contains, startswith, endswith, regex, glob, cidr
    Numeric:  eq, neq, gt, lt, gte, lte
    Presence: is_true, is_false
    Tag:      has_tag, not_has_tag

Extensibility — register new operators without modifying this module:
    register_string_op(name, handler)       — (lowered_val, lowered_value) -> bool
    register_string_raw_op(name, handler)   — (raw_val, raw_value) -> bool  (for cidr-like ops)
    register_numeric_op(name, handler)      — (float_val, float_value) -> bool
    register_tag_op(name, handler)          — (tags_lower, lowered_value) -> bool

Backward-compat migration:
    migrate_autotag_condition()  — old auto-tag {field: "ip_range", value: ...}
    migrate_campaign_condition() — old campaign {type: "has_exploit", value: ...}
"""
from __future__ import annotations

import re
import ipaddress
import fnmatch
import logging
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from core.ownership_teams import OWNERSHIP_ROLE_ENUM_OPTIONS

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# Unified Condition Catalog
# ─────────────────────────────────────────────────────────

CONDITION_CATALOG = [
    {
        "group": "Asset Properties",
        "conditions": [
            {
                "field": "ip", "label": "IP Address",
                "ops": ["eq", "neq", "contains", "startswith", "regex", "cidr"],
                "value_type": "string", "placeholder": "192.168.1.0",
            },
            {
                "field": "hostname", "label": "Hostname",
                "ops": ["eq", "neq", "contains", "startswith", "endswith", "regex", "glob"],
                "value_type": "string", "placeholder": "*.prod.*",
            },
            {
                "field": "fqdn", "label": "FQDN",
                "ops": ["eq", "neq", "contains", "startswith", "endswith", "regex"],
                "value_type": "string", "placeholder": ".example.com",
            },
            {
                "field": "os", "label": "Operating System",
                "ops": ["eq", "neq", "contains", "startswith", "regex"],
                "value_type": "string", "placeholder": "Windows Server",
            },
            {
                "field": "netbios_name", "label": "NetBIOS Name",
                "ops": ["eq", "neq", "contains", "startswith", "regex"],
                "value_type": "string", "placeholder": "CORP-DC01",
            },
            {
                "field": "environment_tag", "label": "Environment",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "External",  "value": "external"},
                    {"label": "Internet",  "value": "internet"},
                    {"label": "DMZ",       "value": "dmz"},
                    {"label": "Internal",  "value": "internal"},
                    {"label": "Cloud",     "value": "cloud"},
                    {"label": "OT",        "value": "ot"},
                ],
            },
            {
                "field": "criticality", "label": "Criticality",
                "ops": ["eq", "neq", "gte", "lte", "gt", "lt"],
                "value_type": "enum",
                "options": [
                    {"label": "1 — Minimal",    "value": 1},
                    {"label": "2 — Very Low",   "value": 2},
                    {"label": "3 — Low",        "value": 3},
                    {"label": "4 — Low-Medium", "value": 4},
                    {"label": "5 — Medium",     "value": 5},
                    {"label": "6 — Medium-High","value": 6},
                    {"label": "7 — High",       "value": 7},
                    {"label": "8 — Very High",  "value": 8},
                    {"label": "9 — Critical",   "value": 9},
                    {"label": "10 — Maximum",   "value": 10},
                ],
            },
            {
                "field": "risk_score", "label": "Risk Score",
                "ops": ["gte", "lte", "gt", "lt", "eq"],
                "value_type": "float", "placeholder": "7.0",
            },
            {
                "field": "source", "label": "Data Source",
                "ops": ["contains", "not_contains"],
                "value_type": "enum",
                "options": "__dynamic:sources__",
            },
            {
                "field": "scan", "label": "Scan",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": "__dynamic:scans__",
            },
            {
                "field": "inferred_team", "label": "Ownership Team",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": OWNERSHIP_ROLE_ENUM_OPTIONS,
            },
        ],
    },
    {
        "group": "Severity Counts",
        "conditions": [
            {"field": "critical_count", "label": "Critical Finding Count", "ops": ["eq", "gt", "gte", "lt", "lte"], "value_type": "integer", "placeholder": "1"},
            {"field": "high_count",     "label": "High Finding Count",     "ops": ["eq", "gt", "gte", "lt", "lte"], "value_type": "integer", "placeholder": "5"},
            {"field": "medium_count",   "label": "Medium Finding Count",   "ops": ["eq", "gt", "gte", "lt", "lte"], "value_type": "integer", "placeholder": "10"},
            {"field": "low_count",      "label": "Low Finding Count",      "ops": ["eq", "gt", "gte", "lt", "lte"], "value_type": "integer", "placeholder": "0"},
        ],
    },
    {
        "group": "Findings",
        "conditions": [
            {
                "field": "finding.severity", "label": "Severity",
                "ops": ["eq", "neq", "gte", "lte"],
                "value_type": "enum",
                "options": [
                    {"label": "Critical (4)", "value": 4},
                    {"label": "High (3)",     "value": 3},
                    {"label": "Medium (2)",   "value": 2},
                    {"label": "Low (1)",      "value": 1},
                    {"label": "Info (0)",     "value": 0},
                ],
            },
            {"field": "finding.cvss3",           "label": "CVSS3 Score",       "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "float",   "placeholder": "7.0"},
            {"field": "finding.vpr",             "label": "VPR Score",          "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "float",   "placeholder": "7.0"},
            {"field": "finding.exploit",         "label": "Has Known Exploit",  "ops": ["is_true", "is_false"],           "value_type": "none"},
            {"field": "finding.zero_day",        "label": "Has Zero-Day",       "ops": ["is_true", "is_false"],           "value_type": "none"},
            {"field": "finding.has_cve",         "label": "Has CVE Reference",  "ops": ["is_true", "is_false"],           "value_type": "none"},
            {"field": "finding.missing_patches", "label": "Has Missing Patches","ops": ["is_true", "is_false"],           "value_type": "none"},
            {"field": "finding.plugin_id",       "label": "Plugin ID",          "ops": ["eq", "neq", "contains", "startswith"],   "value_type": "string", "placeholder": "10287"},
            {"field": "finding.plugin_family",   "label": "Plugin Family",      "ops": ["eq", "neq", "contains", "not_contains"], "value_type": "string", "placeholder": "Windows"},
            {"field": "finding.plugin_name",     "label": "Plugin Name",        "ops": ["contains", "not_contains", "startswith", "eq"], "value_type": "string", "placeholder": "SSL"},
            {"field": "finding.port",            "label": "Port",               "ops": ["eq", "neq", "gt", "lt", "gte", "lte"], "value_type": "integer", "placeholder": "443"},
            {"field": "finding.protocol",        "label": "Protocol",           "ops": ["eq", "neq"],              "value_type": "enum", "options": [{"label": "TCP", "value": "tcp"}, {"label": "UDP", "value": "udp"}, {"label": "ICMP", "value": "icmp"}]},
            {"field": "finding.synopsis",        "label": "Synopsis",           "ops": ["contains", "not_contains", "regex"], "value_type": "string", "placeholder": "remote code execution"},
            {"field": "finding.description",     "label": "Description",        "ops": ["contains", "not_contains", "regex"], "value_type": "string", "placeholder": "buffer overflow"},
            {"field": "finding.solution",        "label": "Solution",           "ops": ["contains", "not_contains", "regex"], "value_type": "string", "placeholder": "Upgrade to"},
            {"field": "finding.cve",             "label": "CVE",    "ops": ["contains", "eq"],                "value_type": "string", "placeholder": "CVE-2021-44228"},
            {"field": "finding.cwe",             "label": "CWE",    "ops": ["contains", "eq", "contains_any", "contains_all"], "value_type": "string", "placeholder": "CWE-79"},
            {"field": "finding.has_cwe",         "label": "Has CWE",            "ops": ["is_true", "is_false"],           "value_type": "none"},
            {
                "field": "finding.sla_status", "label": "SLA Status",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "On Track",  "value": "on_track"},
                    {"label": "At Risk",   "value": "at_risk"},
                    {"label": "Breached",  "value": "breached"},
                ],
            },
            {"field": "finding.sla_days_remaining", "label": "SLA Days Remaining", "ops": ["lt", "lte", "gt", "gte", "eq"], "value_type": "integer", "placeholder": "3"},
            {"field": "finding.sla_due_date",        "label": "SLA Due Date",        "ops": ["lt", "lte", "gt", "gte"],       "value_type": "date",    "placeholder": "2025-12-31"},
            {
                "field": "finding.effort", "label": "Effort Level",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Quick Win", "value": "quick_win"},
                    {"label": "Medium",    "value": "medium"},
                    {"label": "Complex",   "value": "complex"},
                ],
            },
            {
                "field": "finding.owner", "label": "Owner Suggestion",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": OWNERSHIP_ROLE_ENUM_OPTIONS,
            },
            {
                "field": "owner_suggestion", "label": "Finding Ownership Team",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": OWNERSHIP_ROLE_ENUM_OPTIONS,
            },
            {"field": "finding.cvss4",               "label": "CVSS4 Score",           "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "float",   "placeholder": "7.0"},
            {"field": "finding.epss_score",           "label": "EPSS Score",            "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "float",   "placeholder": "0.5"},
            {
                "field": "finding.vulnerability_state", "label": "Vulnerability State",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Active",     "value": "Active"},
                    {"label": "New",        "value": "New"},
                    {"label": "Resurfaced", "value": "Resurfaced"},
                    {"label": "Fixed",      "value": "Fixed"},
                ],
            },
            {
                "field": "finding.exploit_maturity", "label": "Exploit Maturity",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Weaponized", "value": "weaponized"},
                    {"label": "Functional", "value": "functional"},
                    {"label": "PoC",        "value": "poc"},
                    {"label": "Unproven",   "value": "unproven"},
                ],
            },
            {"field": "finding.is_regression",   "label": "Is Regression",        "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "finding.times_seen",       "label": "Times Seen (# Scans)", "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "integer", "placeholder": "3"},
            {
                "field": "finding.workflow_status", "label": "Workflow Status",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Open",                 "value": "open"},
                    {"label": "In Progress",          "value": "in_progress"},
                    {"label": "Resolved",             "value": "resolved"},
                    {"label": "Accepted Risk",        "value": "accepted_risk"},
                    {"label": "False Positive",       "value": "false_positive"},
                    {"label": "Compensating Control", "value": "compensating_control"},
                ],
            },
            {"field": "finding.has_exception",   "label": "Has Exception",        "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "finding.product",  "label": "Product",   "ops": ["eq", "neq", "contains", "not_contains"], "value_type": "enum", "options": "__dynamic:products__"},
            {"field": "finding.cpe",      "label": "CPE",       "ops": ["eq", "neq", "contains", "not_contains"], "value_type": "enum", "options": "__dynamic:cpes__"},
            {
                "field": "finding.risk_factor", "label": "Risk Factor",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Critical", "value": "Critical"},
                    {"label": "High",     "value": "High"},
                    {"label": "Medium",   "value": "Medium"},
                    {"label": "Low",      "value": "Low"},
                    {"label": "None",     "value": "None"},
                ],
            },
            {
                "field": "finding.validation", "label": "AI Validation Verdict",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Any validated",  "value": "validated"},
                    {"label": "True positive",  "value": "true_positive"},
                    {"label": "False positive", "value": "false_positive"},
                    {"label": "Needs review",   "value": "needs_review"},
                    {"label": "Not validated",  "value": "not_validated"},
                ],
            },
            {
                "field": "finding.corroborated", "label": "Corroborated (≥2 scanners)",
                "ops": ["is_true", "is_false"],
                "value_type": "none",
            },
        ],
    },
    {
        "group": "Identity & Access",
        "conditions": [
            {"field": "inventory.is_internet_facing",        "label": "Is Internet-Facing",          "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.is_domain_controller",      "label": "Is Domain Controller",         "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.is_database_server",  "label": "Is Database Server",   "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.is_web_server",        "label": "Is Web Server",         "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.is_dns_server",        "label": "Is DNS Server",         "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.is_mail_server",       "label": "Is Mail Server",        "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.domain_admin_present",      "label": "Domain Admin Present",         "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.admin_logged_in",           "label": "Admin User Logged In",         "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.privileged_user_logged_in", "label": "Privileged User Logged In",    "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.kerberoastable_user",       "label": "Kerberoastable User Present",  "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.has_writeable_share",       "label": "Has Writeable Share",          "ops": ["is_true", "is_false"], "value_type": "none"},
        ],
    },
    {
        "group": "Security Controls",
        "conditions": [
            {"field": "inventory.no_edr",      "label": "No EDR Detected",      "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.no_av",       "label": "No AV Detected",       "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "inventory.no_firewall", "label": "No Firewall Detected", "ops": ["is_true", "is_false"], "value_type": "none"},
        ],
    },
    {
        "group": "ATT&CK / Threat Intel",
        "conditions": [
            {"field": "finding.is_kev",            "label": "In CISA KEV",            "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "finding.ransomware_linked",  "label": "Ransomware Linked",       "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "finding.trending_in_news",   "label": "Trending in News",        "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "finding.has_ttps",           "label": "Has ATT&CK TTP Match",   "ops": ["is_true", "is_false"], "value_type": "none"},
            {
                "field": "finding.tactic", "label": "ATT&CK Tactic",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Initial Access",        "value": "initial-access"},
                    {"label": "Execution",             "value": "execution"},
                    {"label": "Persistence",           "value": "persistence"},
                    {"label": "Privilege Escalation",  "value": "privilege-escalation"},
                    {"label": "Defense Evasion",       "value": "defense-evasion"},
                    {"label": "Credential Access",     "value": "credential-access"},
                    {"label": "Discovery",             "value": "discovery"},
                    {"label": "Lateral Movement",      "value": "lateral-movement"},
                    {"label": "Collection",            "value": "collection"},
                    {"label": "Command and Control",   "value": "command-and-control"},
                    {"label": "Exfiltration",          "value": "exfiltration"},
                    {"label": "Impact",                "value": "impact"},
                ],
            },
            {"field": "finding.technique_id",  "label": "ATT&CK Technique ID", "ops": ["eq", "contains"], "value_type": "string", "placeholder": "T1059"},
            {"field": "finding.threat_group",  "label": "Threat Group",         "ops": ["eq", "contains"], "value_type": "string", "placeholder": "APT29"},
        ],
    },
    {
        "group": "SIEM Alerts",
        "conditions": [
            {"field": "siem.alert_count", "label": "Open Alert Count", "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "integer", "placeholder": "1"},
            {"field": "siem.critical_alert_count", "label": "Critical Alert Count", "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "integer", "placeholder": "1"},
            {"field": "siem.high_alert_count", "label": "High Alert Count", "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "integer", "placeholder": "1"},
            {"field": "siem.event_count_24h", "label": "Events (Last 24h)", "ops": ["gte", "lte", "gt", "lt", "eq"], "value_type": "integer", "placeholder": "10"},
            {"field": "siem.has_active_alerts", "label": "Has Active Alerts", "ops": ["is_true", "is_false"], "value_type": "none"},
        ],
    },
    {
        "group": "Tags",
        "conditions": [
            {"field": "tag", "label": "Tag", "ops": ["has_tag", "not_has_tag"], "value_type": "string", "placeholder": "network:dmz"},
        ],
    },
]

# Well-known source types with friendly labels
_SOURCE_LABELS = {
    "nessus": "Nessus", "easm": "EASM", "vm_scanner": "VM Scanner",
    "qualys": "Qualys", "rapid7": "Rapid7", "openvas": "OpenVAS",
}


def get_condition_catalog(db: Session = None, org_ids=None) -> list:
    """Return the condition catalog with dynamic options hydrated from the DB."""
    import copy
    catalog = copy.deepcopy(CONDITION_CATALOG)
    _dynamic_resolvers = {
        "__dynamic:sources__": lambda: _resolve_source_options(db, org_ids),
        "__dynamic:scans__": lambda: _resolve_scan_options(db, org_ids),
        "__dynamic:products__": lambda: _resolve_product_options(db),
        "__dynamic:cpes__": lambda: _resolve_cpe_options(db),
    }
    for group in catalog:
        for cond in group.get("conditions", []):
            opts = cond.get("options")
            if isinstance(opts, str) and opts in _dynamic_resolvers:
                cond["options"] = _dynamic_resolvers[opts]()

    # Append per-org custom field definitions as dynamic groups
    custom_groups = _resolve_custom_field_groups(db, org_ids)
    catalog.extend(custom_groups)

    return catalog


def _resolve_custom_field_groups(db, org_ids) -> list:
    """Load org CustomFieldDefinition rows and convert them into catalog groups.

    Asset custom fields use field id `cf:<key>`; finding custom fields use
    `finding.cf:<key>`. Evaluation is handled in _eval_asset / _eval_finding_row.
    """
    if db is None:
        return []
    try:
        from models.models import CustomFieldDefinition
    except Exception:
        return []

    try:
        q = db.query(CustomFieldDefinition).filter(
            CustomFieldDefinition.is_active.is_(True),
        )
        if org_ids:
            q = q.filter(CustomFieldDefinition.org_id.in_(org_ids))
        defs = q.all()
    except Exception:
        logger.debug("Failed to resolve custom field definitions", exc_info=True)
        return []

    if not defs:
        return []

    # Deduplicate across orgs by (entity_type, key) — last wins
    by_key: dict = {}
    for d in defs:
        by_key[(d.entity_type, d.key)] = d

    asset_conds: list = []
    finding_conds: list = []
    for (entity_type, key), d in by_key.items():
        value_type, ops = _custom_field_ops(d.data_type, d.enum_values)
        cond = {
            "field": f"cf:{key}" if entity_type == "asset" else f"finding.cf:{key}",
            "label": d.label or key,
            "ops": ops,
            "value_type": value_type,
            "placeholder": d.description or "",
        }
        if d.data_type == "enum" and d.enum_values:
            cond["options"] = [{"label": v, "value": v} for v in d.enum_values]
        if entity_type == "asset":
            asset_conds.append(cond)
        else:
            finding_conds.append(cond)

    groups: list = []
    if asset_conds:
        groups.append({"group": "Custom Fields (Asset)", "conditions": sorted(asset_conds, key=lambda c: c["label"])})
    if finding_conds:
        groups.append({"group": "Custom Fields (Finding)", "conditions": sorted(finding_conds, key=lambda c: c["label"])})
    return groups


def _custom_field_ops(data_type: str, enum_values):
    """Return (value_type, ops) for a custom field definition's data_type."""
    if data_type == "number":
        return "number", ["eq", "neq", "gt", "lt", "gte", "lte"]
    if data_type == "boolean":
        return "boolean", ["is_true", "is_false"]
    if data_type == "enum":
        return "enum", ["eq", "neq"]
    if data_type == "date":
        return "string", ["eq", "neq", "gt", "lt", "gte", "lte"]
    # string / fallback
    return "string", ["eq", "neq", "contains", "not_contains", "startswith", "endswith", "regex"]


def _resolve_product_options(db):
    """Build product options from SBOM components linked to findings."""
    if db is None:
        return []
    try:
        from models.models import SBOMComponent, SBOMVulnerability
        rows = (
            db.query(SBOMComponent.name)
            .join(SBOMVulnerability, SBOMVulnerability.component_id == SBOMComponent.id)
            .filter(SBOMVulnerability.finding_id.isnot(None), SBOMComponent.name.isnot(None))
            .distinct().all()
        )
        return [{"label": r[0], "value": r[0]} for r in sorted(rows, key=lambda r: r[0])]
    except Exception:
        logger.debug("Failed to resolve product options", exc_info=True)
        return []


def _resolve_cpe_options(db):
    """Build CPE options from SBOM components linked to findings."""
    if db is None:
        return []
    try:
        from models.models import SBOMComponent, SBOMVulnerability
        rows = (
            db.query(SBOMComponent.cpe)
            .join(SBOMVulnerability, SBOMVulnerability.component_id == SBOMComponent.id)
            .filter(SBOMVulnerability.finding_id.isnot(None), SBOMComponent.cpe.isnot(None))
            .distinct().all()
        )
        return [{"label": r[0], "value": r[0]} for r in sorted(rows, key=lambda r: r[0])]
    except Exception:
        logger.debug("Failed to resolve CPE options", exc_info=True)
        return []


def _resolve_source_options(db, org_ids=None):
    """Build source options from scans + integration source_systems in the DB."""
    if db is None:
        return [{"label": v, "value": k} for k, v in _SOURCE_LABELS.items()]
    from sqlalchemy import or_
    from models.models import Scan, Finding, Integration

    # Collect source_type values from scans
    q = db.query(Scan.source_type).distinct()
    if org_ids:
        q = q.filter(or_(Scan.org_id.in_(org_ids), Scan.org_id.is_(None)))
    scan_sources = {r[0] for r in q.all() if r[0]}

    # Collect source_type values from findings (covers integration builder data).
    # Finding.org_id is only present in production where it's added via ALTER TABLE
    # migration; handle its absence gracefully so the catalog still loads.
    try:
        fq = db.query(Finding.source_type).distinct()
        if org_ids and hasattr(Finding, "org_id"):
            fq = fq.filter(Finding.org_id.in_(org_ids))
        finding_sources = {r[0] for r in fq.all() if r[0]}
    except Exception:
        logger.debug("Failed to resolve finding sources for catalog", exc_info=True)
        finding_sources = set()

    # Build a label map from integration names (template_id/custom → friendly name)
    integration_labels = {}
    try:
        iq = db.query(Integration.template_id, Integration.name).filter(
            Integration.direction == "pull",
            Integration.template_id.isnot(None),
        )
        if org_ids:
            iq = iq.filter(or_(Integration.org_id.in_(org_ids), Integration.org_id.is_(None)))
        for tmpl_id, name in iq.all():
            if tmpl_id and name:
                integration_labels[tmpl_id] = name
    except Exception:
        pass

    all_sources = sorted(scan_sources | finding_sources)
    combined_labels = {**_SOURCE_LABELS, **integration_labels}
    return [{"label": combined_labels.get(s, s), "value": s} for s in all_sources]


def _resolve_scan_options(db, org_ids=None):
    """Build scan options from Scan table for the condition catalog."""
    if db is None:
        return []
    from sqlalchemy import or_
    from models.models import Scan

    try:
        q = db.query(Scan.id, Scan.filename, Scan.source_type, Scan.created_at).order_by(Scan.created_at.desc())
        if org_ids:
            q = q.filter(or_(Scan.org_id.in_(org_ids), Scan.org_id.is_(None)))
        scans = q.limit(200).all()
        options = []
        for s in scans:
            source = _SOURCE_LABELS.get(s.source_type, s.source_type or "")
            name = s.filename or f"Scan #{s.id}"
            label = f"{name} ({source})" if source else name
            options.append({"label": label, "value": s.id})
        return options
    except Exception:
        logger.debug("Failed to resolve scan options for catalog", exc_info=True)
        return []


# ─────────────────────────────────────────────────────────
# Backward-compat migration
# ─────────────────────────────────────────────────────────

# Old auto-tag field names → (new_field, op)
_AUTOTAG_FIELD_MAP: dict[str, tuple[str, str]] = {
    "ip_range":               ("ip",                     "cidr"),
    "hostname_pattern":       ("hostname",               "glob"),
    "fqdn_contains":          ("fqdn",                   "contains"),
    "os_contains":            ("os",                     "contains"),
    "environment_equals":     ("environment_tag",        "eq"),
    "criticality_gte":        ("criticality",            "gte"),
    "criticality_lte":        ("criticality",            "lte"),
    "severity_gte":           ("finding.severity",       "gte"),
    "severity_equals":        ("finding.severity",       "eq"),
    "cvss3_gte":              ("finding.cvss3",          "gte"),
    "vpr_gte":                ("finding.vpr",            "gte"),
    "has_exploit":            ("finding.exploit",        "is_true"),
    "has_cve":                ("finding.has_cve",        "is_true"),
    "plugin_family_contains": ("finding.plugin_family",  "contains"),
    "plugin_family_equals":   ("finding.plugin_family",  "eq"),
    "plugin_name_contains":   ("finding.plugin_name",    "contains"),
    "effort_equals":          ("finding.effort",         "eq"),
    "owner_suggestion_equals":("finding.owner",          "eq"),
}

# Old campaign condition type → (new_field, op, forced_value or None=keep original)
_CAMPAIGN_TYPE_MAP: dict[str, tuple[str, str, object]] = {
    "has_critical_vuln":         ("finding.severity",                "gte",     4),
    "has_high_vuln":             ("finding.severity",                "gte",     3),
    "severity_gte":              ("finding.severity",                "gte",     None),
    "has_exploit":               ("finding.exploit",                 "is_true", None),
    "has_zero_day":              ("finding.zero_day",                "is_true", None),
    "has_missing_patches":       ("finding.missing_patches",         "is_true", None),
    "is_internet_facing":        ("inventory.is_internet_facing",    "is_true", None),
    "environment_equals":        ("environment_tag",                 "eq",      None),
    "criticality_gte":           ("criticality",                     "gte",     None),
    "is_domain_controller":      ("inventory.is_domain_controller",  "is_true", None),
    "admin_logged_in":           ("inventory.admin_logged_in",       "is_true", None),
    "privileged_user_logged_in": ("inventory.privileged_user_logged_in", "is_true", None),
    "kerberoastable_user":       ("inventory.kerberoastable_user",   "is_true", None),
    "domain_admin_present":      ("inventory.domain_admin_present",  "is_true", None),
    "has_writeable_share":       ("inventory.has_writeable_share",   "is_true", None),
    "no_edr":                    ("inventory.no_edr",                "is_true", None),
    "no_av":                     ("inventory.no_av",                 "is_true", None),
    "no_firewall":               ("inventory.no_firewall",           "is_true", None),
    "plugin_family_contains":    ("finding.plugin_family",           "contains",None),
    "cve_contains":              ("finding.cve",                     "contains",None),
    "effort_equals":             ("finding.effort",                  "eq",      None),
    "owner_equals":              ("finding.owner",                   "eq",      None),
}


def migrate_autotag_condition(cond: dict) -> dict:
    """Convert old auto-tag {field, value} to unified {field, op, value}."""
    if "op" in cond:
        return cond  # already new format
    old_field = cond.get("field", "")
    if old_field in _AUTOTAG_FIELD_MAP:
        new_field, op = _AUTOTAG_FIELD_MAP[old_field]
        value = None if op in ("is_true", "is_false") else cond.get("value")
        return {"field": new_field, "op": op, "value": value}
    return cond  # unknown field, pass through


def migrate_campaign_condition(cond: dict) -> dict:
    """Convert old campaign {type, value} to unified {field, op, value}."""
    if "field" in cond:
        return cond  # already new format
    old_type = cond.get("type", "")
    if old_type in _CAMPAIGN_TYPE_MAP:
        new_field, op, forced_val = _CAMPAIGN_TYPE_MAP[old_type]
        value = forced_val if forced_val is not None else cond.get("value")
        if op in ("is_true", "is_false"):
            value = None
        return {"field": new_field, "op": op, "value": value}
    return cond


def migrate_conditions(conditions: list, mode: str = "autotag") -> list:
    """Migrate a list of conditions. mode: 'autotag' or 'campaign'."""
    fn = migrate_campaign_condition if mode == "campaign" else migrate_autotag_condition
    return [fn(c) for c in (conditions or [])]


# ─────────────────────────────────────────────────────────
# Operator registries  (OCP: add new operators without modifying evaluators)
# ─────────────────────────────────────────────────────────

# Each handler: (asset_val: str, value: str) -> bool   (both already lowered)
_STRING_OPS: dict[str, callable] = {
    "eq":           lambda av, v: av == v,
    "neq":          lambda av, v: av != v,
    "contains":     lambda av, v: v in av,
    "not_contains": lambda av, v: v not in av,
    "startswith":   lambda av, v: av.startswith(v),
    "endswith":     lambda av, v: av.endswith(v),
    "glob":         lambda av, v: bool(fnmatch.fnmatch(av, v)),
}

# These need the *original* (non-lowered) values, handled specially in _str_op
_STRING_RAW_OPS: dict[str, callable] = {}


def _regex_op(av: str, v: str) -> bool:
    try:
        return bool(re.search(v, av, re.IGNORECASE))
    except re.error:
        return False


def _cidr_op(raw_val: str, raw_value: str) -> bool:
    try:
        return ipaddress.ip_address(raw_val) in ipaddress.ip_network(str(raw_value), strict=False)
    except Exception:
        return False


_STRING_RAW_OPS["regex"] = _regex_op
_STRING_RAW_OPS["cidr"] = _cidr_op

# Each handler: (asset_num: float, v: float) -> bool   (v already coerced)
_NUMERIC_OPS: dict[str, callable] = {
    "eq":  lambda n, v: n == v,
    "neq": lambda n, v: n != v,
    "gt":  lambda n, v: n > v,
    "lt":  lambda n, v: n < v,
    "gte": lambda n, v: n >= v,
    "lte": lambda n, v: n <= v,
}


def register_string_op(name: str, handler: callable) -> None:
    """Register a custom string operator.

    handler signature: (lowered_asset_val: str, lowered_value: str) -> bool
    """
    _STRING_OPS[name] = handler


def register_string_raw_op(name: str, handler: callable) -> None:
    """Register a string operator that receives original (non-lowered) values.

    handler signature: (raw_asset_val: str, raw_value: str) -> bool
    """
    _STRING_RAW_OPS[name] = handler


def register_numeric_op(name: str, handler: callable) -> None:
    """Register a custom numeric operator.

    handler signature: (asset_num: float, coerced_value: float) -> bool
    """
    _NUMERIC_OPS[name] = handler


def _str_op(asset_val: str, op: str, value: str) -> bool:
    av = asset_val.lower()
    # in / not_in accept a list (or comma-separated string) of allowed values.
    # Compliance YAMLs lean on these heavily for "workflow_status in [resolved,
    # false_positive]" style guardrails — handle here so the comparison stays
    # case-insensitive end-to-end without callers having to lowercase.
    if op in ("in", "not_in"):
        if isinstance(value, (list, tuple, set)):
            choices = {str(x).lower() for x in value if x is not None}
        else:
            choices = {s.strip().lower() for s in str(value or "").split(",") if s.strip()}
        present = av in choices
        return present if op == "in" else not present
    v = str(value or "").lower()
    # Check raw-value operators first (regex, cidr, custom)
    if op in _STRING_RAW_OPS:
        return _STRING_RAW_OPS[op](asset_val, str(value or ""))
    handler = _STRING_OPS.get(op)
    if handler:
        return handler(av, v)
    return False


def _num_op(asset_num: float, op: str, value) -> bool:
    if op in ("in", "not_in"):
        if isinstance(value, (list, tuple, set)):
            raw_choices = list(value)
        else:
            raw_choices = [s.strip() for s in str(value or "").split(",") if s.strip()]
        choices: set[float] = set()
        for c in raw_choices:
            try:
                choices.add(float(c))
            except (TypeError, ValueError):
                continue
        present = asset_num in choices
        return present if op == "in" else not present
    try:
        v = float(value)
    except (TypeError, ValueError):
        return False
    handler = _NUMERIC_OPS.get(op)
    if handler:
        return handler(asset_num, v)
    return False


_NUMERIC_ASSET_FIELDS = {
    "criticality", "risk_score",
    "critical_count", "high_count", "medium_count", "low_count", "info_count",
}

# ─────────────────────────────────────────────────────────
# Per-namespace evaluators
# ─────────────────────────────────────────────────────────

def _list_has(items: list, value) -> bool:
    """Check if value is in a list, with type coercion (str↔int for ports)."""
    for it in items:
        if str(it).lower() == str(value).lower():
            return True
        # Numeric coercion: "443" matches 443
        try:
            if float(it) == float(value):
                return True
        except (TypeError, ValueError):
            pass
    return False


_CF_NUMERIC_OPS = {"gt", "lt", "gte", "lte"}


def _eval_custom_field_value(raw, op: str, value) -> bool:
    """Evaluate a user-defined custom field value.

    Duck-types on the stored value: numeric ops coerce to float, boolean ops
    check truthiness, everything else uses string comparison. This keeps the
    evaluator agnostic to the CustomFieldDefinition's data_type — the op the
    user picked in the RuleBuilder (constrained by value_type in the catalog)
    implicitly selects the right comparison mode.
    """
    # Presence check works uniformly — empty string/None/0 are falsy
    if op in ("is_true", "is_false"):
        truthy = bool(raw) and raw not in ("false", "False", "0")
        return truthy if op == "is_true" else not truthy

    # Numeric ops: coerce both sides to float, False if either fails
    if op in _CF_NUMERIC_OPS:
        try:
            return _num_op(float(raw if raw is not None else 0), op, value)
        except (TypeError, ValueError):
            return False

    # Default: string comparison
    return _str_op("" if raw is None else str(raw), op, value)


def _eval_scan(cond: dict, db: Session, asset_id: int) -> bool:
    """Evaluate whether an asset has findings in a given scan."""
    from models.models import Finding
    op = cond.get("op", "eq")
    value = cond.get("value")
    if value is None:
        return False
    try:
        target_scan_id = int(value)
    except (ValueError, TypeError):
        return False
    has_findings = db.query(Finding.id).filter(
        Finding.asset_id == asset_id,
        Finding.scan_id == target_scan_id,
    ).first() is not None
    return has_findings if op == "eq" else not has_findings


def _eval_asset(cond: dict, asset: dict) -> bool:
    """Evaluate an asset-namespace condition against an asset dict."""
    field = cond["field"]
    op    = cond.get("op", "eq")
    value = cond.get("value")

    # User-defined custom fields: cf:<key> → look up in asset.custom_fields
    if field.startswith("cf:"):
        key = field[3:]
        custom = asset.get("custom_fields") or {}
        return _eval_custom_field_value(custom.get(key), op, value)

    # source_systems is a JSON list — check membership
    if field == "source":
        sources = asset.get("source_systems") or []
        val = str(value or "").lower()
        has = any(val == s.lower() for s in sources)
        return has if op == "contains" else not has

    if op in ("is_true", "is_false"):
        result = bool(asset.get(field))
        return result if op == "is_true" else not result

    # List-aware operators: work on list/JSON-array fields (open_ports, tech_stack, cpe, etc.)
    if op in ("has_any", "has_all", "has_item", "not_has_item", "list_contains"):
        raw = asset.get(field)
        items = raw if isinstance(raw, list) else []
        if op == "has_item":
            # Single value membership: value in list (coerce types for port ints)
            return _list_has(items, value)
        if op == "not_has_item":
            return not _list_has(items, value)
        if op == "list_contains":
            # Substring match: any item in list contains the value string
            val = str(value or "").lower()
            return any(val in str(it).lower() for it in items)
        # has_any / has_all: value is comma-separated list of values
        targets = [v.strip() for v in str(value or "").split(",") if v.strip()]
        if op == "has_any":
            return any(_list_has(items, t) for t in targets)
        if op == "has_all":
            return all(_list_has(items, t) for t in targets)

    if field in _NUMERIC_ASSET_FIELDS:
        return _num_op(float(asset.get(field) or 0), op, value)

    return _str_op(str(asset.get(field) or ""), op, value)


def _eval_finding_row(cond: dict, finding) -> bool:
    """Evaluate a finding.* condition against a single Finding ORM object."""
    sub   = cond["field"][len("finding."):]
    op    = cond.get("op", "eq")
    value = cond.get("value")

    # User-defined custom fields: finding.cf:<key>
    if sub.startswith("cf:"):
        key = sub[3:]
        custom = getattr(finding, "custom_fields", None) or {}
        return _eval_custom_field_value(custom.get(key), op, value)

    if sub == "severity":
        return _num_op(float(finding.severity or 0), op, value)
    if sub == "cvss3":
        return _num_op(float(finding.cvss3_score or 0), op, value)
    if sub == "vpr":
        return _num_op(float(finding.vpr_score or 0), op, value)
    if sub == "exploit":
        result = bool(finding.exploit_available)
        return result if op == "is_true" else not result
    if sub == "zero_day":
        result = bool(finding.zero_day)
        return result if op == "is_true" else not result
    if sub == "has_cve":
        result = len(finding.cves or []) > 0
        return result if op == "is_true" else not result
    if sub == "missing_patches":
        # This requires DB — only supported in asset-level context; return False for finding-row eval
        return False
    if sub == "port":
        return _num_op(float(finding.port or 0), op, value)
    if sub == "protocol":
        return _str_op((finding.protocol or "").lower(), op, str(value or "").lower())
    if sub == "synopsis":
        return _str_op(finding.synopsis or "", op, value)
    if sub == "description":
        return _str_op(finding.description or "", op, value)
    if sub == "solution":
        return _str_op(finding.solution or "", op, value)
    if sub == "plugin_id":
        return _str_op(str(finding.plugin_id or ""), op, value)
    if sub == "plugin_family":
        return _str_op(finding.plugin_family or "", op, value)
    if sub == "plugin_name":
        return _str_op(finding.plugin_name or "", op, value)
    if sub == "cve":
        cves = [c.upper() for c in (finding.cves or [])]
        val  = str(value or "").upper()
        # Support comma-separated bulk CVE search
        vals = [v.strip() for v in val.split(",") if v.strip()]
        if op == "eq":       return any(v in cves for v in vals)
        if op == "contains": return any(v in c for v in vals for c in cves)
        return False
    if sub == "has_cwe":
        result = len(getattr(finding, "cwe_ids", None) or []) > 0
        return result if op == "is_true" else not result
    if sub == "cwe":
        cwes = [c.upper() for c in (getattr(finding, "cwe_ids", None) or [])]
        if isinstance(value, (list, tuple, set)):
            vals = [str(v).strip().upper() for v in value if str(v).strip()]
        else:
            vals = [v.strip().upper() for v in str(value or "").split(",") if v.strip()]
        if op in ("eq", "contains_any"):
            return any(v in cwes for v in vals)
        if op == "contains":
            return any(v in c for v in vals for c in cwes)
        if op == "contains_all":
            return all(v in cwes for v in vals)
        return False
    if sub == "effort":
        return _str_op(finding.effort_level or "", op, value)
    if sub == "owner":
        return _str_op(finding.owner_suggestion or "", op, value)
    if sub == "sla_status":
        return _str_op(finding.sla_status or "", op, value)
    if sub == "sla_days_remaining":
        from datetime import date
        if not finding.sla_due_date:
            return False
        days = (finding.sla_due_date - date.today()).days
        return _num_op(float(days), op, value)
    if sub == "sla_due_date":
        from datetime import date
        if not finding.sla_due_date:
            return False
        try:
            threshold = date.fromisoformat(str(value))
        except (ValueError, TypeError):
            return False
        return _num_op(finding.sla_due_date.toordinal(), op, threshold.toordinal())
    if sub == "cvss4":
        return _num_op(float(finding.cvss4_score or 0), op, value)
    if sub == "epss_score":
        return _num_op(float(finding.epss_score or 0), op, value)
    if sub == "vulnerability_state":
        return _str_op(finding.vulnerability_state or "", op, value)
    if sub == "exploit_maturity":
        return _str_op(finding.exploit_maturity or "", op, value)
    if sub == "is_regression":
        result = bool(finding.is_regression)
        return result if op == "is_true" else not result
    if sub == "times_seen":
        return _num_op(float(finding.times_seen or 1), op, value)
    if sub == "workflow_status":
        return _str_op(finding.workflow_status or "open", op, value)
    if sub == "has_exception":
        result = finding.exception_id is not None
        return result if op == "is_true" else not result
    if sub == "risk_factor":
        return _str_op(finding.risk_factor or "", op, str(value or ""))
    if sub == "validation":
        verdict = (getattr(finding, "llm_validation", None) or {}).get("verdict")
        target = str(value or "")
        if target == "validated":
            present = verdict in ("true_positive", "false_positive", "needs_review")
            return present if op == "eq" else not present
        if target == "not_validated":
            present = verdict is None
            return present if op == "eq" else not present
        matched = verdict == target
        return matched if op == "eq" else not matched
    if sub == "corroborated":
        custom = getattr(finding, "custom_fields", None) or {}
        result = bool((custom.get("corroboration") or {}).get("corroborated"))
        return result if op == "is_true" else not result
    if sub in ("product", "cpe"):
        # Product/CPE are resolved via SBOM join at asset level, not per-finding row
        return False
    if sub == "is_kev":
        result = bool(finding.is_kev)
        return result if op == "is_true" else not result
    if sub == "ransomware_linked":
        result = bool(finding.ransomware_linked)
        return result if op == "is_true" else not result
    if sub == "trending_in_news":
        result = bool(finding.trending_in_news)
        return result if op == "is_true" else not result
    if sub == "has_ttps":
        result = bool(finding.matched_ttps)
        return result if op == "is_true" else not result
    if sub == "tactic":
        ttps = finding.matched_ttps or []
        val = str(value or "").lower()
        matched = any(
            (op == "eq" and t.get("tactic", "").lower() == val) or
            (op == "neq" and t.get("tactic", "").lower() != val) or
            (op == "contains" and val in t.get("tactic", "").lower())
            for t in ttps
        )
        return matched
    if sub == "technique_id":
        ttps = finding.matched_ttps or []
        val = str(value or "").upper()
        if op == "eq":      return any(t.get("technique_id", "").upper() == val for t in ttps)
        if op == "contains": return any(val in t.get("technique_id", "").upper() for t in ttps)
        return False
    if sub == "threat_group":
        # Handled in _eval_finding_asset which has DB access
        return False
    return False


def _eval_finding_asset(cond: dict, db: Session, asset_id: int, scan_id) -> bool:
    """Return True if any finding on this asset satisfies the finding.* condition."""
    from models.models import Finding, InventoryPatch

    sub = cond["field"][len("finding."):]
    op  = cond.get("op", "eq")

    # Special: missing_patches comes from InventoryPatch, not Finding
    if sub == "missing_patches":
        q = db.query(InventoryPatch).filter(InventoryPatch.asset_id == asset_id)
        if scan_id:
            q = q.filter(InventoryPatch.scan_id == scan_id)
        result = q.first() is not None
        return result if op == "is_true" else not result

    # Special: threat_group requires DB lookup to resolve technique IDs for the group
    if sub == "threat_group":
        from models.threat_intel_models import ThreatGroup, ThreatGroupTTP, TTP
        val = str(cond.get("value") or "").lower()
        group_q = db.query(ThreatGroup).filter(
            ThreatGroup.name.ilike(f"%{val}%") if op == "contains" else ThreatGroup.name.ilike(val)
        )
        groups = group_q.all()
        if not groups:
            return False
        group_ids = [g.id for g in groups]
        technique_ids = [
            row.technique_id
            for row in db.query(TTP.technique_id)
            .join(ThreatGroupTTP, TTP.id == ThreatGroupTTP.ttp_id)
            .filter(ThreatGroupTTP.group_id.in_(group_ids))
            .all()
        ]
        if not technique_ids:
            return False
        findings_q = db.query(Finding).filter(Finding.asset_id == asset_id)
        if scan_id:
            findings_q = findings_q.filter(Finding.scan_id == scan_id)
        return any(
            any(t.get("technique_id") in technique_ids for t in (f.matched_ttps or []))
            for f in findings_q.all()
        )

    # Special: product/cpe require joining through SBOM tables
    if sub in ("product", "cpe"):
        from models.models import SBOMComponent, SBOMVulnerability
        value = str(cond.get("value") or "")
        col = SBOMComponent.name if sub == "product" else SBOMComponent.cpe
        comp_q = (
            db.query(SBOMComponent)
            .join(SBOMVulnerability, SBOMVulnerability.component_id == SBOMComponent.id)
            .filter(SBOMComponent.asset_id == asset_id)
            .filter(SBOMVulnerability.finding_id.isnot(None))
        )
        if scan_id:
            comp_q = comp_q.filter(SBOMComponent.scan_id == scan_id)
        vals = [getattr(c, "name" if sub == "product" else "cpe") or "" for c in comp_q.all()]
        return any(_str_op(v, op, value) for v in vals)

    q = db.query(Finding).filter(Finding.asset_id == asset_id)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return any(_eval_finding_row(cond, f) for f in q.all())


def _eval_inventory(cond: dict, db: Session, asset_id: int, scan_id,
                    asset_dict: dict | None = None) -> bool:
    """Evaluate an inventory.* condition."""
    from models.models import (
        Asset, InventoryLoggedOn, InventoryUser, InventoryComputer,
        InventoryShare, InventorySecurityControl,
    )

    sub = cond["field"][len("inventory."):]
    op  = cond.get("op", "is_true")

    def _result(flag: bool) -> bool:
        return flag if op == "is_true" else not flag

    if sub == "is_internet_facing":
        # Derived from environment_tag — no DB needed if asset_dict provided
        if asset_dict:
            tag = (asset_dict.get("environment_tag") or "").lower()
        else:
            a = db.query(Asset).filter(Asset.id == asset_id).first()
            tag = (a.environment_tag if a else "").lower()
        return _result(tag in ("external", "internet", "dmz", "public"))

    if sub == "is_domain_controller":
        q = db.query(InventoryComputer).filter(
            InventoryComputer.asset_id == asset_id,
            InventoryComputer.is_domain_controller == True,
        )
        if scan_id:
            q = q.filter(InventoryComputer.scan_id == scan_id)
        return _result(q.first() is not None)

    if sub in ("is_database_server", "is_web_server", "is_dns_server", "is_mail_server"):
        from models.models import InventoryDatabaseInstance, InventoryService
        from sqlalchemy import or_, func as sqlfunc
        role_map = {
            "is_database_server": ["mssql", "sqlserver", "mysql", "mysqld", "postgres",
                                   "postgresql", "oracle", "mongodb", "mariadb", "redis", "db2"],
            "is_web_server":  ["iis", "w3svc", "apache", "httpd", "nginx", "tomcat", "kestrel"],
            "is_dns_server":  ["dns", "named", "bind", "dnsmasq", "unbound"],
            "is_mail_server": ["exchange", "smtp", "imap", "pop3", "postfix", "sendmail", "exim"],
        }
        patterns = role_map[sub]
        svc_q = db.query(InventoryService).filter(
            InventoryService.asset_id == asset_id,
            InventoryService.is_running == True,
            or_(*[sqlfunc.lower(InventoryService.service_name).contains(p) for p in patterns] +
                 [sqlfunc.lower(InventoryService.display_name).contains(p) for p in patterns])
        )
        if scan_id:
            svc_q = svc_q.filter(InventoryService.scan_id == scan_id)
        svc_match = svc_q.first() is not None
        db_match = False
        if sub == "is_database_server":
            db_q = db.query(InventoryDatabaseInstance).filter(
                InventoryDatabaseInstance.asset_id == asset_id
            )
            if scan_id:
                db_q = db_q.filter(InventoryDatabaseInstance.scan_id == scan_id)
            db_match = db_q.first() is not None
        return _result(svc_match or db_match)

    if sub == "domain_admin_present":
        q = db.query(InventoryUser).filter(
            InventoryUser.asset_id == asset_id,
            InventoryUser.is_domain_admin == True,
        )
        if scan_id:
            q = q.filter(InventoryUser.scan_id == scan_id)
        return _result(q.first() is not None)

    if sub == "admin_logged_in":
        q = db.query(InventoryLoggedOn).filter(InventoryLoggedOn.asset_id == asset_id)
        if scan_id:
            q = q.filter(InventoryLoggedOn.scan_id == scan_id)
        for lo in q.all():
            uname = (lo.username or "").lower()
            if "admin" in uname:
                return _result(True)
            uq = db.query(InventoryUser).filter(
                InventoryUser.asset_id == asset_id,
                func.lower(InventoryUser.username) == uname,
                InventoryUser.is_privileged == True,
            )
            if scan_id:
                uq = uq.filter(InventoryUser.scan_id == scan_id)
            if uq.first():
                return _result(True)
        return _result(False)

    if sub == "privileged_user_logged_in":
        q = db.query(InventoryLoggedOn).filter(InventoryLoggedOn.asset_id == asset_id)
        if scan_id:
            q = q.filter(InventoryLoggedOn.scan_id == scan_id)
        for lo in q.all():
            uname = (lo.username or "").lower()
            uq = db.query(InventoryUser).filter(
                InventoryUser.asset_id == asset_id,
                func.lower(InventoryUser.username) == uname,
            ).filter(
                (InventoryUser.is_domain_admin == True) | (InventoryUser.is_local_admin == True)
            )
            if scan_id:
                uq = uq.filter(InventoryUser.scan_id == scan_id)
            if uq.first():
                return _result(True)
        return _result(False)

    if sub == "kerberoastable_user":
        q = db.query(InventoryUser).filter(InventoryUser.asset_id == asset_id)
        if scan_id:
            q = q.filter(InventoryUser.scan_id == scan_id)
        return _result(any(u.spns and len(u.spns) > 0 for u in q.all()))

    if sub == "has_writeable_share":
        q = db.query(InventoryShare).filter(
            InventoryShare.asset_id == asset_id,
            InventoryShare.is_writeable == True,
        )
        if scan_id:
            q = q.filter(InventoryShare.scan_id == scan_id)
        return _result(q.first() is not None)

    if sub in ("no_edr", "no_av", "no_firewall"):
        control_type = sub[3:]  # strips "no_"
        q = db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == asset_id,
            InventorySecurityControl.control_type == control_type,
        )
        if scan_id:
            q = q.filter(InventorySecurityControl.scan_id == scan_id)
        # "no_X is_true" → control absent → q.first() is None
        absent = q.first() is None
        return _result(absent)

    return False


def _eval_tag(cond: dict, db: Session | None, asset_id: int | None,
              asset_tags: list[str] | None = None) -> bool:
    """Evaluate a tag condition."""
    op    = cond.get("op", "has_tag")
    value = str(cond.get("value") or "").lower().strip()

    if asset_tags is None and db is not None and asset_id is not None:
        from models.models import Tag, TagAssignment
        rows = (
            db.query(Tag.category, Tag.value)
            .join(TagAssignment, TagAssignment.tag_id == Tag.id)
            .filter(TagAssignment.asset_id == asset_id)
            .all()
        )
        asset_tags = [f"{r.category}:{r.value}" for r in rows]
    elif asset_tags is None:
        # Also check "tags" list in asset_dict (passed by recalculate endpoint)
        asset_tags = []

    tags_lower = [t.lower() for t in asset_tags]
    handler = _TAG_OPS.get(op)
    if handler:
        return handler(tags_lower, value)
    return False


# Tag operator registry  (value is already lowered+stripped)
_TAG_OPS: dict[str, callable] = {
    "has_tag":     lambda tags, v: any(v in t for t in tags),
    "not_has_tag": lambda tags, v: all(v not in t for t in tags),
}


def _eval_siem(cond: dict, db: Session, asset_id: int) -> bool:
    """Evaluate a SIEM alert/event condition for an asset."""
    from models.models import Alert, SIEMEvent
    from datetime import datetime, timedelta

    field = cond.get("field", "")
    op = cond.get("op", "gte")
    value = cond.get("value")
    sub = field.split(".", 1)[-1]

    if sub == "has_active_alerts":
        count = db.query(Alert).filter(
            Alert.asset_id == asset_id,
            Alert.status == "open",
            Alert.suppressed == False,
        ).count()
        return _result_for_bool(op, count > 0)

    if sub == "alert_count":
        count = db.query(Alert).filter(
            Alert.asset_id == asset_id,
            Alert.status == "open",
            Alert.suppressed == False,
        ).count()
        return _num_op(count, op, value)

    if sub == "critical_alert_count":
        count = db.query(Alert).filter(
            Alert.asset_id == asset_id,
            Alert.status == "open",
            Alert.suppressed == False,
            Alert.severity == "critical",
        ).count()
        return _num_op(count, op, value)

    if sub == "high_alert_count":
        count = db.query(Alert).filter(
            Alert.asset_id == asset_id,
            Alert.status == "open",
            Alert.suppressed == False,
            Alert.severity == "high",
        ).count()
        return _num_op(count, op, value)

    if sub == "event_count_24h":
        cutoff = datetime.utcnow() - timedelta(hours=24)
        count = db.query(SIEMEvent).filter(
            SIEMEvent.asset_id == asset_id,
            SIEMEvent.event_time >= cutoff,
        ).count()
        return _num_op(count, op, value)

    return False


def _result_for_bool(op: str, val: bool) -> bool:
    if op == "is_true":
        return val
    if op == "is_false":
        return not val
    return val


def register_tag_op(name: str, handler: callable) -> None:
    """Register a custom tag operator.

    handler signature: (tags_lower: list[str], lowered_value: str) -> bool
    """
    _TAG_OPS[name] = handler


# ─────────────────────────────────────────────────────────
# Public evaluation API
# ─────────────────────────────────────────────────────────

def evaluate_condition(
    cond: dict,
    asset_dict: dict | None = None,
    db: Session | None = None,
    asset_id: int | None = None,
    scan_id=None,
    asset_tags: list[str] | None = None,
) -> bool:
    """
    Evaluate a single condition for an asset.

    - Asset-namespace conditions use asset_dict only (no DB needed).
    - finding.* conditions: if db provided, queries DB; otherwise returns False.
    - inventory.* conditions: requires db + asset_id.
    - tag conditions: uses asset_tags list if provided, else queries DB.
    """
    try:
        field = cond.get("field", "")

        if field == "tag":
            tags = asset_dict.get("tags") if asset_dict else None
            return _eval_tag(cond, db, asset_id, asset_tags or tags)

        if field.startswith("siem."):
            if db is None or asset_id is None:
                return False
            return _eval_siem(cond, db, asset_id)

        if field.startswith("inventory."):
            if db is None or asset_id is None:
                return False
            return _eval_inventory(cond, db, asset_id, scan_id, asset_dict)

        if field.startswith("finding."):
            if db is None or asset_id is None:
                return False
            return _eval_finding_asset(cond, db, asset_id, scan_id)

        if field == "scan":
            if db is None or asset_id is None:
                return False
            return _eval_scan(cond, db, asset_id)

        # Asset namespace
        if asset_dict is not None:
            return _eval_asset(cond, asset_dict)

        return False
    except Exception as e:
        logger.debug(f"evaluate_condition error ({cond}): {e}")
        return False


def evaluate_conditions(
    conditions: list[dict],
    logic: str,
    asset_dict: dict | None = None,
    db: Session | None = None,
    asset_id: int | None = None,
    scan_id=None,
    asset_tags: list[str] | None = None,
) -> bool:
    """Evaluate a list of conditions with AND/OR logic for an asset."""
    if not conditions:
        return False
    results = [
        evaluate_condition(c, asset_dict=asset_dict, db=db, asset_id=asset_id,
                           scan_id=scan_id, asset_tags=asset_tags)
        for c in conditions
    ]
    return all(results) if str(logic).upper() == "AND" else any(results)


def evaluate_condition_for_finding(
    cond: dict,
    finding,
    asset_dict: dict | None = None,
) -> bool:
    """
    Evaluate a single condition against a specific Finding ORM object.
    Asset-namespace conditions are evaluated against asset_dict.
    Inventory conditions are not supported in this mode (return False).
    """
    try:
        field = cond.get("field", "")
        if field.startswith("finding."):
            return _eval_finding_row(cond, finding)
        if field.startswith("inventory."):
            return False
        if field == "tag":
            return False
        if asset_dict:
            return _eval_asset(cond, asset_dict)
        return False
    except Exception as e:
        logger.debug(f"evaluate_condition_for_finding error ({cond}): {e}")
        return False


def evaluate_conditions_for_finding(
    conditions: list[dict],
    logic: str,
    finding,
    asset_dict: dict | None = None,
) -> bool:
    """Evaluate conditions against a specific Finding object (for finding-level tagging)."""
    if not conditions:
        return False
    results = [evaluate_condition_for_finding(c, finding, asset_dict) for c in conditions]
    return all(results) if str(logic).upper() == "AND" else any(results)


def get_matching_assets(
    conditions: list[dict],
    logic: str,
    db: Session,
    scan_id=None,
    org_ids=None,
) -> list:
    """
    Return Asset ORM objects that match the given conditions.
    Used by campaign queries and auto-tag asset-level rules.

    org_ids scopes the asset pool to the caller's tenant(s). Pass None only
    from trusted contexts that must span all orgs.
    """
    from models.models import Asset, Finding, Scan
    from sqlalchemy import select

    q = db.query(Asset)
    if org_ids is not None:
        # Asset has no org_id column — tenant scope flows through Scan.
        q = q.join(Scan, Asset.scan_id == Scan.id).filter(Scan.org_id.in_(org_ids))
    if scan_id:
        # Assets are deduplicated across scans — their scan_id reflects the latest scan.
        # Match assets that have *any finding* in this scan, not just Asset.scan_id == scan_id.
        asset_ids_in_scan = select(Finding.asset_id).where(
            Finding.scan_id == scan_id
        ).distinct()
        q = q.filter(Asset.id.in_(asset_ids_in_scan))
    assets = q.all()

    return [
        a for a in assets
        if evaluate_conditions(
            conditions, logic,
            asset_dict={
                "ip": a.ip, "hostname": a.hostname, "fqdn": a.fqdn,
                "os": a.os, "netbios_name": a.netbios_name,
                "environment_tag": a.environment_tag,
                "criticality": a.criticality or 5,
                "risk_score": a.risk_score or 0.0,
                "critical_count": a.critical_count or 0,
                "high_count": a.high_count or 0,
                "medium_count": a.medium_count or 0,
                "low_count": a.low_count or 0,
                "info_count": a.info_count or 0,
                "source_systems": a.source_systems or [],
                "custom_fields": a.custom_fields or {},
            },
            db=db, asset_id=a.id, scan_id=scan_id,
        )
    ]
