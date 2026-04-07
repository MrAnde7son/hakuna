"""
Dynamic tool selection for the Security Copilot.


Instead of sending all ~111 tool schemas on every request (~15-30K tokens),
this module selects only the relevant tools based on the user's message and
conversation history. Typical requests use 20-35 tools, saving 70-80% of
tool-schema token cost.
"""
from typing import Optional

# Tools always included regardless of message content.
CORE_TOOLS = [
    "request_clarification",
    "read_scratchpad",
    "write_scratchpad",
    "clear_scratchpad",
    "search_documents",
    "run_sql_query",
]

# Fallback tools included when no category keywords match,
# so the LLM always has something useful for generic queries.
FALLBACK_TOOLS = [
    "query_findings",
    "query_assets",
    "list_scans",
    "get_scan_summary",
    "get_top_risky_assets",
    "get_finding_detail",
    "get_asset_profile",
    "get_sla_status",
    "get_exploit_findings",
]

# Category definitions: keywords -> tool names.
# A category is activated when ANY keyword appears in the message or recent history.
TOOL_CATEGORIES = {
    "findings": {
        "keywords": [
            "finding", "findings", "vuln", "cve", "severity", "critical",
            "high", "medium", "low", "plugin", "exploit", "regression",
            "quick win", "sla", "priority", "risk score", "breach",
            "remediation group", "workflow status",
        ],
        "tools": [
            "query_findings", "get_finding_detail", "get_sla_status",
            "get_remediation_grouping", "get_exploit_findings",
            "get_regression_findings", "get_quick_wins",
            "get_plugin_family_stats", "get_workflow_status_summary",
            "update_finding_status", "correlate_cves_with_findings",
            "get_blast_radius",
        ],
    },
    "assets": {
        "keywords": [
            "asset", "host", "ip", "server", "machine", "endpoint",
            "os", "operating system", "internet-facing", "risky",
        ],
        "tools": [
            "query_assets", "get_asset_profile", "get_top_risky_assets",
            "get_os_breakdown", "get_internet_facing_risk",
            "get_security_controls",
        ],
    },
    "inventory": {
        "keywords": [
            "inventory", "user", "service", "patch", "software",
            "certificate", "share", "network connection", "lateral",
            "kerberos", "admin", "logged",
        ],
        "tools": [
            "get_inventory_users", "get_inventory_services",
            "get_network_connections", "get_missing_patches",
            "get_installed_software", "get_certificates",
            "get_writeable_shares",
        ],
    },
    "scans": {
        "keywords": ["scan", "compare", "import", "upload"],
        "tools": [
            "list_scans", "get_scan_summary", "compare_scans",
            "delete_scan", "rename_scan",
        ],
    },
    "tags": {
        "keywords": [
            "tag", "label", "classify", "organize", "categorize",
            "auto-tag", "tagging",
        ],
        "tools": [
            "list_tags", "get_tag_stats", "tag_assets", "create_tag",
            "bulk_tag_findings", "create_auto_tag_rule",
            "run_auto_tag_rules", "manage_tag", "manage_auto_tag_rule",
            "suggest_tagging_schema",
        ],
    },
    "campaigns": {
        "keywords": [
            "campaign", "remediation plan", "track", "assign",
            "owner", "workload",
        ],
        "tools": [
            "create_campaign", "list_campaigns", "get_campaign",
            "get_owner_workload",
        ],
    },
    "ticketing": {
        "keywords": ["ticket", "jira", "servicenow"],
        "tools": [
            "create_jira_ticket", "create_servicenow_ticket",
        ],
    },
    "notifications": {
        "keywords": [
            "slack", "teams", "email", "notify", "alert", "webhook",
            "send message",
        ],
        "tools": [
            "send_slack_message", "send_teams_message",
            "send_email_alert", "send_webhook",
        ],
    },
    "threat_intel": {
        "keywords": [
            "threat", "apt", "ransomware", "ttp", "mitre", "att&ck",
            "threat group", "threat campaign",
        ],
        "tools": [
            "get_threat_groups", "get_threat_cves",
            "get_threat_campaigns", "get_ttps",
            "correlate_cves_with_findings",
        ],
    },
    "workflows": {
        "keywords": [
            "workflow", "automation", "template", "trigger",
        ],
        "tools": [
            "list_workflows", "get_workflow_detail",
            "get_workflow_execution", "create_campaign_workflow",
            "create_workflow_from_template", "list_workflow_templates",
            "run_workflow", "toggle_workflow",
        ],
    },
    "agents": {
        "keywords": ["agent", "schedule", "bot", "recommend agent"],
        "tools": [
            "list_agents", "get_agent_run", "create_agent",
            "create_agent_schedule", "recommend_agents",
        ],
    },
    "integrations": {
        "keywords": [
            "integration", "connector", "sync", "credential",
            "field mapping",
        ],
        "tools": [
            "list_integrations", "call_integration_fetch",
            "call_integration_push",
            "list_integration_builder_connectors",
            "manage_integration", "get_integration_runs",
            "get_integration_builder_targets",
            "get_integration_builder_connector_detail",
            "list_integration_credentials",
            "create_integration_credential",
            "create_integration", "update_integration",
            "get_integration_detail", "suggest_field_mapping",
        ],
    },
    "settings": {
        "keywords": [
            "setting", "config", "dedup", "risk scoring", "weight",
            "sla config", "exception", "waiver", "ownership rule",
            "role", "rbac", "permission", "criticality",
        ],
        "tools": [
            "get_dedup_config", "update_dedup_config", "run_dedup",
            "get_risk_config", "update_risk_config",
            "manage_criticality_rules", "recalculate_risk_scores",
            "get_sla_config", "update_sla_config", "recalculate_sla",
            "list_exceptions", "manage_exception", "create_exception",
            "list_ownership_rules", "manage_ownership_rule",
            "run_ownership_rules", "list_custom_roles",
            "manage_custom_role",
        ],
    },
    "reports": {
        "keywords": ["report", "dashboard", "widget", "executive"],
        "tools": ["build_report"],
    },
    "analysis": {
        "keywords": ["attack surface", "attack path", "analyze"],
        "tools": ["analyze_attack_surface"],
    },
    "easm": {
        "keywords": ["easm", "external attack surface", "domain scan"],
        "tools": [
            "trigger_easm_scan", "check_easm_scan_status",
            "list_easm_domains",
        ],
    },
    "web": {
        "keywords": ["search web", "fetch url", "advisory", "look up", "research"],
        "tools": ["search_web", "fetch_url"],
    },
}


def select_tools_for_message(
    message: str,
    conversation_history: Optional[list] = None,
) -> list:
    """Pick relevant tools based on keywords in the user message and recent history.

    Returns a deduplicated list of tool names: core + matched categories,
    or core + fallback if nothing matched.
    """
    # Build a combined text blob from the current message + recent history
    text = message.lower()
    if conversation_history:
        for msg in conversation_history[-6:]:
            content = msg.get("content", "")
            if isinstance(content, str):
                text += " " + content.lower()
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text += " " + block.get("text", "").lower()

    selected = set(CORE_TOOLS)
    matched_any = False

    for _category, config in TOOL_CATEGORIES.items():
        for keyword in config["keywords"]:
            if keyword in text:
                selected.update(config["tools"])
                matched_any = True
                break

    if not matched_any:
        selected.update(FALLBACK_TOOLS)

    return list(selected)
