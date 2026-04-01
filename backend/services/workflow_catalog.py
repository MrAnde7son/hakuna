"""
Workflow node catalog and OOTB templates — separated from the execution engine
so that catalog changes (adding new node types, templates) don't require
modifying execution logic (OCP).
"""

NODE_CATALOG = {
    "triggers": [
        {
            "subtype": "manual",
            "label": "Manual Trigger",
            "description": "Run workflow manually or from campaign",
            "icon": "Play",
            "config_schema": {},
        },
        {
            "subtype": "schedule",
            "label": "Schedule",
            "description": "Run on a time schedule (preset or custom cron expression)",
            "icon": "Clock",
            "config_schema": {
                "schedule_mode": {"type": "enum", "label": "Mode",
                                  "options": [
                                      {"value": "simple", "label": "Simple"},
                                      {"value": "cron", "label": "Custom (Cron)"},
                                  ]},
                "interval": {"type": "enum", "label": "Interval",
                             "options": ["hourly", "daily", "weekly", "monthly"],
                             "visible_when": {"schedule_mode": "simple"}},
                "time": {"type": "string", "label": "Time (HH:MM)", "placeholder": "09:00",
                         "visible_when": {"schedule_mode": "simple"}},
                "cron_expr": {"type": "string", "label": "Cron Expression",
                              "placeholder": "0 8 * * *",
                              "visible_when": {"schedule_mode": "cron"}},
            },
        },
        {
            "subtype": "on_upload",
            "label": "On Scan Upload",
            "description": "Triggers when a new scan is uploaded",
            "icon": "Upload",
            "config_schema": {},
        },
        {
            "subtype": "on_campaign_run",
            "label": "On Campaign Run",
            "description": "Triggers when the attached campaign is executed",
            "icon": "Target",
            "config_schema": {},
        },
        {
            "subtype": "on_integration_execution",
            "label": "On Integration Execution",
            "description": "Triggers when an integration finishes — filter by outcome",
            "icon": "Plug",
            "config_schema": {
                "integration_id": {"type": "string", "label": "Integration (leave blank for all)",
                                   "placeholder": "Any integration"},
                "status_filter": {"type": "multi_enum", "label": "Trigger on status",
                                  "options": [
                                      {"value": "success", "label": "Success"},
                                      {"value": "partial", "label": "Partial"},
                                      {"value": "error", "label": "Error"},
                                  ],
                                  "default": ["success", "partial", "error"]},
            },
        },
        {
            "subtype": "on_new_threat_intel",
            "label": "On New Threat Intel",
            "description": "Triggers when new CVEs, threat groups, or campaigns are synced",
            "icon": "Shield",
            "config_schema": {
                "intel_type": {"type": "enum", "label": "Intel Type",
                               "options": [
                                   {"value": "any", "label": "Any type"},
                                   {"value": "cve", "label": "New CVEs"},
                                   {"value": "threat_group", "label": "New Threat Groups"},
                                   {"value": "threat_campaign", "label": "New Threat Campaigns"},
                                   {"value": "kev", "label": "New KEV Entries"},
                                   {"value": "exploit", "label": "New Exploits"},
                               ]},
                "severity_threshold": {"type": "enum", "label": "Min CVSS Severity",
                                       "options": [
                                           {"value": "", "label": "Any"},
                                           {"value": "7.0", "label": "High (7.0+)"},
                                           {"value": "9.0", "label": "Critical (9.0+)"},
                                       ]},
                "only_affecting_environment": {"type": "boolean",
                                               "label": "Only if affecting my environment",
                                               "default": True},
            },
        },
        {
            "subtype": "on_new_asset",
            "label": "On New Asset",
            "description": "Triggers when a previously unseen asset is discovered",
            "icon": "Monitor",
            "config_schema": {
                "asset_filter": {"type": "enum", "label": "Asset Filter",
                                 "options": [
                                     {"value": "any", "label": "Any new asset"},
                                     {"value": "internet_facing", "label": "Internet-facing only"},
                                     {"value": "high_criticality", "label": "High criticality (1-3) only"},
                                 ]},
            },
        },
        {
            "subtype": "on_new_finding",
            "label": "On New Finding",
            "description": "Triggers when a new vulnerability is discovered",
            "icon": "AlertCircle",
            "config_schema": {
                "min_severity": {"type": "enum", "label": "Minimum Severity",
                                 "options": [
                                     {"value": "0", "label": "Any (including Info)"},
                                     {"value": "1", "label": "Low and above"},
                                     {"value": "2", "label": "Medium and above"},
                                     {"value": "3", "label": "High and above"},
                                     {"value": "4", "label": "Critical only"},
                                 ],
                                 "default": "2"},
                "only_exploitable": {"type": "boolean",
                                     "label": "Only with known exploits",
                                     "default": False},
            },
        },
    ],
    "filters": [
        {
            "subtype": "severity_filter",
            "label": "Severity Filter",
            "description": "Filter findings by severity level",
            "icon": "Filter",
            "config_schema": {
                "operator": {"type": "enum", "label": "Operator",
                             "options": ["eq", "gte", "lte", "gt", "lt"]},
                "value": {"type": "enum", "label": "Severity",
                          "options": [
                              {"value": "0", "label": "Info"},
                              {"value": "1", "label": "Low"},
                              {"value": "2", "label": "Medium"},
                              {"value": "3", "label": "High"},
                              {"value": "4", "label": "Critical"},
                          ]},
            },
        },
        {
            "subtype": "score_filter",
            "label": "Score Filter",
            "description": "Filter by CVSS, VPR, or priority score",
            "icon": "BarChart2",
            "config_schema": {
                "field": {"type": "enum", "label": "Score Field",
                          "options": ["cvss3_score", "priority_score", "vpr_score", "risk_score"]},
                "operator": {"type": "enum", "label": "Operator",
                             "options": ["gte", "lte", "gt", "lt"]},
                "value": {"type": "number", "label": "Threshold"},
            },
        },
        {
            "subtype": "exploit_filter",
            "label": "Exploit Available",
            "description": "Filter findings with known exploits",
            "icon": "Zap",
            "config_schema": {
                "has_exploit": {"type": "enum", "label": "Has Exploit",
                                "options": ["true", "false"]},
            },
        },
        {
            "subtype": "tag_filter",
            "label": "Tag Filter",
            "description": "Filter by tag presence",
            "icon": "Tag",
            "config_schema": {
                "tag_category": {"type": "string", "label": "Tag Category"},
                "tag_value": {"type": "string", "label": "Tag Value"},
                "mode": {"type": "enum", "label": "Mode", "options": ["include", "exclude"]},
            },
        },
        {
            "subtype": "asset_filter",
            "label": "Asset Property Filter",
            "description": "Filter based on asset properties",
            "icon": "Server",
            "config_schema": {
                "field": {"type": "enum", "label": "Property",
                          "options": ["os", "criticality", "environment_tag", "hostname", "ip"]},
                "operator": {"type": "enum", "label": "Operator",
                             "options": ["eq", "neq", "contains", "gte", "lte"]},
                "value": {"type": "string", "label": "Value"},
            },
        },
        {
            "subtype": "condition_filter",
            "label": "Condition Filter",
            "description": "Filter by arbitrary field conditions (e.g. SLA status, workflow status)",
            "icon": "GitBranch",
            "config_schema": {
                "conditions": {"type": "array", "label": "Conditions",
                               "item_schema": {
                                   "field": {"type": "string", "label": "Field (e.g. finding.sla_status, asset.os)"},
                                   "op": {"type": "enum", "label": "Operator",
                                          "options": ["eq", "neq", "contains", "gte", "lte", "gt", "lt"]},
                                   "value": {"type": "string", "label": "Value"},
                               }},
                "logic": {"type": "enum", "label": "Logic", "options": ["AND", "OR"]},
            },
        },
    ],
    "actions": [
        {
            "subtype": "assign_owner",
            "label": "Assign Owner",
            "description": "Set owner on matched findings",
            "icon": "UserPlus",
            "config_schema": {
                "owner_name": {"type": "string", "label": "Owner Name"},
                "owner_email": {"type": "string", "label": "Owner Email"},
                "owner_role": {"type": "enum", "label": "Role",
                               "options": ["IT", "DevOps", "SecOps", "AppSec"]},
                "team": {"type": "string", "label": "Team"},
            },
        },
        {
            "subtype": "add_tag",
            "label": "Add Tag",
            "description": "Apply a tag to matched assets/findings",
            "icon": "Tag",
            "config_schema": {
                "tag_category": {"type": "string", "label": "Tag Category"},
                "tag_value": {"type": "string", "label": "Tag Value"},
                "target": {"type": "enum", "label": "Apply To",
                           "options": ["finding", "asset", "both"]},
            },
        },
        {
            "subtype": "change_status",
            "label": "Change Status",
            "description": "Update finding status in campaign",
            "icon": "CheckCircle",
            "config_schema": {
                "status": {"type": "enum", "label": "New Status",
                           "options": ["open", "in_progress", "resolved", "wont_fix"]},
            },
        },
        {
            "subtype": "set_criticality",
            "label": "Set Asset Criticality",
            "description": "Update criticality level on matched assets",
            "icon": "AlertTriangle",
            "config_schema": {
                "criticality": {"type": "enum", "label": "Criticality",
                                "options": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]},
            },
        },
        {
            "subtype": "send_email",
            "label": "Send Email",
            "description": "Send email notification with findings summary",
            "icon": "Mail",
            "config_schema": {
                "to": {"type": "string", "label": "To (email addresses, comma-separated)"},
                "subject": {"type": "string", "label": "Subject"},
                "body_template": {"type": "string", "label": "Body Template",
                                  "placeholder": "Found {{count}} findings on {{assets}} assets"},
                "include_findings_table": {"type": "boolean", "label": "Include Findings Table"},
            },
        },
        {
            "subtype": "send_webhook",
            "label": "Send Webhook",
            "description": "POST data to an external URL",
            "icon": "Globe",
            "config_schema": {
                "url": {"type": "string", "label": "Webhook URL"},
                "method": {"type": "enum", "label": "Method",
                           "options": ["POST", "PUT", "PATCH"]},
                "headers": {"type": "string", "label": "Custom Headers (JSON)", "placeholder": '{"Authorization": "Bearer ..."}'},
                "include_findings": {"type": "boolean", "label": "Include Finding Data"},
            },
        },
        {
            "subtype": "create_ticket",
            "label": "Create Ticket",
            "description": "Create a ticket in Jira, ServiceNow, or other ITSM",
            "icon": "Ticket",
            "config_schema": {
                "integration": {"type": "enum", "label": "Integration",
                                "options": ["jira", "servicenow", "azure_devops", "linear", "github_issues"]},
                "project": {"type": "string", "label": "Project / Queue"},
                "issue_type": {"type": "enum", "label": "Issue Type",
                               "options": ["bug", "task", "story", "incident", "change_request"]},
                "title_template": {"type": "string", "label": "Title Template",
                                   "placeholder": "[{{severity}}] {{plugin_name}} on {{asset_ip}}"},
                "description_template": {"type": "string", "label": "Description Template"},
                "assignee": {"type": "string", "label": "Assignee (email or username)"},
                "labels": {"type": "string", "label": "Labels (comma-separated)"},
                "priority": {"type": "enum", "label": "Priority",
                             "options": ["highest", "high", "medium", "low", "lowest"]},
                "group_by": {"type": "enum", "label": "Grouping",
                             "options": ["one_per_finding", "one_per_asset", "one_for_all"]},
            },
        },
        {
            "subtype": "slack_notify",
            "label": "Slack Notification",
            "description": "Send a message to a Slack channel",
            "icon": "MessageSquare",
            "config_schema": {
                "webhook_url": {"type": "string", "label": "Slack Webhook URL"},
                "channel": {"type": "string", "label": "Channel (optional override)"},
                "message_template": {"type": "string", "label": "Message",
                                     "placeholder": ":warning: Found {{count}} critical findings requiring attention"},
                "include_summary": {"type": "boolean", "label": "Include Summary Table"},
            },
        },
        {
            "subtype": "teams_notify",
            "label": "Teams Notification",
            "description": "Send a message to Microsoft Teams",
            "icon": "MessageSquare",
            "config_schema": {
                "webhook_url": {"type": "string", "label": "Teams Webhook URL"},
                "message_template": {"type": "string", "label": "Message"},
                "include_summary": {"type": "boolean", "label": "Include Summary Card"},
            },
        },
        {
            "subtype": "run_agent",
            "label": "Run Agent",
            "description": "Invoke an AI agent to analyze workflow items and take intelligent actions",
            "icon": "Bot",
            "config_schema": {
                "agent_id": {"type": "agent_select", "label": "Agent"},
                "input_template": {
                    "type": "string",
                    "label": "Input Template",
                    "placeholder": "Analyze these {{count}} findings on {{assets}} assets and determine remediation priority.",
                },
                "pass_items_downstream": {
                    "type": "boolean",
                    "label": "Pass original items to next step (instead of agent output)",
                    "default": True,
                },
            },
        },
        {
            "subtype": "run_script",
            "label": "Run Script (Coming Soon)",
            "description": "Execute a remediation script or command — not yet active, logs only",
            "icon": "Terminal",
            "config_schema": {
                "script_type": {"type": "enum", "label": "Type",
                                "options": ["powershell", "bash", "python", "ansible_playbook"]},
                "script": {"type": "string", "label": "Script / Command"},
                "target_scope": {"type": "enum", "label": "Target",
                                 "options": ["all_matched_assets", "per_asset"]},
                "credentials": {"type": "string", "label": "Credential Reference"},
            },
        },
    ],
}


TEMPLATE_CATEGORIES = [
    {"id": "triage", "label": "Triage & Routing", "icon": "GitBranch"},
    {"id": "patching", "label": "Patching", "icon": "Shield"},
    {"id": "incident", "label": "Incident Response", "icon": "Zap"},
    {"id": "integration", "label": "Integration", "icon": "Globe"},
    {"id": "sla", "label": "SLA Management", "icon": "Clock"},
    {"id": "notification", "label": "Notification", "icon": "Mail"},
    {"id": "compliance", "label": "Compliance & Audit", "icon": "CheckSquare"},
]
WORKFLOW_TEMPLATES = [
    {
        "id": "critical_triage",
        "name": "Critical Finding Triage",
        "description": "Filter critical/exploitable findings, assign to SecOps, notify via Slack",
        "category": "triage",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_campaign_run",
             "label": "Campaign Runs", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "Critical Only", "config": {"operator": "gte", "value": "4"}, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "assign_owner",
             "label": "Assign SecOps", "config": {"owner_role": "SecOps", "team": "Security Operations"}, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Notify Slack", "config": {"message_template": ":rotating_light: {{count}} critical findings found"}, "position_x": 660, "position_y": 320},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "a1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "patch_tuesday",
        "name": "Patch Tuesday Automation",
        "description": "Auto-create Jira tickets for high+ findings, group by asset",
        "category": "patching",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_campaign_run",
             "label": "Campaign Runs", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "High & Critical", "config": {"operator": "gte", "value": "3"}, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "create_ticket",
             "label": "Create Jira Tickets", "config": {"integration": "jira", "issue_type": "task",
             "title_template": "[{{severity}}] {{plugin_name}} on {{asset_ip}}",
             "group_by": "one_per_asset", "priority": "high"}, "position_x": 660, "position_y": 200},
            {"node_id": "a2", "node_type": "action", "node_subtype": "change_status",
             "label": "Mark In Progress", "config": {"status": "in_progress"}, "position_x": 960, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "a1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "exploit_response",
        "name": "Exploitable Finding Response",
        "description": "Tag and escalate findings with known exploits, email security team",
        "category": "incident",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_campaign_run",
             "label": "Campaign Runs", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "exploit_filter",
             "label": "Has Exploit", "config": {"has_exploit": "true"}, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "add_tag",
             "label": "Tag as Urgent", "config": {"tag_category": "priority", "tag_value": "urgent", "target": "both"}, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "set_criticality",
             "label": "Raise Criticality", "config": {"criticality": "10"}, "position_x": 660, "position_y": 320},
            {"node_id": "a3", "node_type": "action", "node_subtype": "send_email",
             "label": "Email SecOps", "config": {"subject": "Exploitable findings detected",
             "body_template": "{{count}} findings with known exploits require immediate attention"}, "position_x": 960, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "a1", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "owner_routing",
        "name": "Smart Owner Routing",
        "description": "Route findings to different teams based on severity and asset type",
        "category": "triage",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_campaign_run",
             "label": "Campaign Runs", "config": {}, "position_x": 60, "position_y": 260},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "Critical?", "config": {"operator": "gte", "value": "4"}, "position_x": 360, "position_y": 260},
            {"node_id": "a1", "node_type": "action", "node_subtype": "assign_owner",
             "label": "Assign SecOps", "config": {"owner_role": "SecOps"}, "position_x": 660, "position_y": 120},
            {"node_id": "f2", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "High?", "config": {"operator": "gte", "value": "3"}, "position_x": 660, "position_y": 380},
            {"node_id": "a2", "node_type": "action", "node_subtype": "assign_owner",
             "label": "Assign IT", "config": {"owner_role": "IT"}, "position_x": 960, "position_y": 260},
            {"node_id": "a3", "node_type": "action", "node_subtype": "assign_owner",
             "label": "Assign DevOps", "config": {"owner_role": "DevOps"}, "position_x": 960, "position_y": 480},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input", "label": "Critical"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "f2", "source_handle": "remainder", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "f2", "target_node_id": "a2", "source_handle": "output", "target_handle": "input", "label": "High"},
            {"edge_id": "e5", "source_node_id": "f2", "target_node_id": "a3", "source_handle": "remainder", "target_handle": "input", "label": "Rest"},
        ],
    },
    {
        "id": "webhook_integration",
        "name": "Webhook Integration",
        "description": "Send filtered findings to any external system via webhook",
        "category": "integration",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "manual",
             "label": "Manual Run", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "High+", "config": {"operator": "gte", "value": "3"}, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "send_webhook",
             "label": "Send to API", "config": {"method": "POST", "include_findings": True}, "position_x": 660, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "sla_breach_email",
        "name": "SLA Breach & At-Risk Email Alert",
        "description": "Runs daily, finds all breached or at-risk findings, and emails a summary to the security team",
        "category": "sla",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "schedule",
             "label": "Daily at 8 AM", "config": {"schedule_mode": "cron", "cron_expr": "0 8 * * *"}, "position_x": 60, "position_y": 260},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "Breached SLA", "config": {
                 "conditions": [{"field": "finding.sla_status", "op": "eq", "value": "breached"}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 120},
            {"node_id": "f2", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "At-Risk SLA", "config": {
                 "conditions": [{"field": "finding.sla_status", "op": "eq", "value": "at_risk"}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 400},
            {"node_id": "a1", "node_type": "action", "node_subtype": "send_email",
             "label": "Email: Breached", "config": {
                 "subject": "⚠️ SLA Breached: {{count}} overdue findings",
                 "body_template": "{{count}} findings have breached their SLA deadline across {{assets}} assets. Immediate action required.\n\nPlease review and remediate these findings as soon as possible.",
                 "include_findings_table": True
             }, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "send_email",
             "label": "Email: At-Risk", "config": {
                 "subject": "🕐 SLA At Risk: {{count}} findings due soon",
                 "body_template": "{{count}} findings are at risk of breaching their SLA deadline across {{assets}} assets. Please prioritize remediation.",
                 "include_findings_table": True
             }, "position_x": 660, "position_y": 400},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "t1", "target_node_id": "f2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "f2", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "email_notification",
        "name": "Email Notification",
        "description": "Filter high+ findings and email a summary with findings table to the security team",
        "category": "notification",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_campaign_run",
             "label": "Campaign Runs", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "High & Critical", "config": {"operator": "gte", "value": "3"}, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "send_email",
             "label": "Email Security Team", "config": {
                 "subject": "Remediation Required: {{count}} High/Critical Findings",
                 "body_template": "Hello,\n\nA campaign run has identified {{count}} high or critical findings across {{assets}} asset(s) that require remediation.\n\nPlease review the findings table below and coordinate remediation with the appropriate teams.\n\nRegards,\Hakuna Exposure Management Platform",
                 "include_findings_table": True
             }, "position_x": 660, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
        ],
    },
    # ── New Templates ────────────────────────────────────────────────────
    {
        "id": "regression_response",
        "name": "Regression Response",
        "description": "Auto-detect regressed findings (previously fixed, now reappeared), tag them, re-open tickets, and alert the owner",
        "category": "incident",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_upload",
             "label": "Scan Uploaded", "config": {}, "position_x": 60, "position_y": 260},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "Is Regression?", "config": {
                 "conditions": [{"field": "finding.is_regression", "op": "is_true", "value": ""}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 260},
            {"node_id": "a1", "node_type": "action", "node_subtype": "add_tag",
             "label": "Tag Regression", "config": {"tag_category": "status", "tag_value": "regression", "target": "both"}, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "change_status",
             "label": "Re-open Finding", "config": {"status": "open"}, "position_x": 660, "position_y": 260},
            {"node_id": "a3", "node_type": "action", "node_subtype": "create_ticket",
             "label": "Create Regression Ticket", "config": {
                 "integration": "jira", "issue_type": "bug",
                 "title_template": "[REGRESSION] {{plugin_name}} on {{asset_ip}}",
                 "group_by": "one_per_asset", "priority": "high"
             }, "position_x": 960, "position_y": 120},
            {"node_id": "a4", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Alert Slack", "config": {
                 "message_template": ":warning: {{count}} regressed findings detected — previously fixed vulnerabilities have reappeared. Tickets created."
             }, "position_x": 960, "position_y": 380},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "a1", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e5", "source_node_id": "a2", "target_node_id": "a4", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "exception_expiry_review",
        "name": "Exception Expiry Review",
        "description": "Weekly check for expiring risk exceptions — email owners for recertification and tag findings as review-due",
        "category": "compliance",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "schedule",
             "label": "Weekly Monday 9 AM", "config": {"schedule_mode": "cron", "cron_expr": "0 9 * * 1"}, "position_x": 60, "position_y": 260},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "Expiring Soon", "config": {
                 "conditions": [{"field": "exception.expires_within_days", "op": "lte", "value": "14"}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 140},
            {"node_id": "f2", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "Review Overdue", "config": {
                 "conditions": [{"field": "exception.review_overdue", "op": "is_true", "value": ""}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 400},
            {"node_id": "a1", "node_type": "action", "node_subtype": "add_tag",
             "label": "Tag Review Due", "config": {"tag_category": "compliance", "tag_value": "exception-review-due", "target": "finding"}, "position_x": 660, "position_y": 140},
            {"node_id": "a2", "node_type": "action", "node_subtype": "send_email",
             "label": "Email: Expiring", "config": {
                 "subject": "Action Required: {{count}} risk exceptions expiring within 14 days",
                 "body_template": "The following risk exceptions are expiring soon and require recertification.\n\nPlease review each exception and either renew or allow it to expire so the findings return to active remediation.\n\nFailure to recertify will result in automatic re-activation of the underlying findings.",
                 "include_findings_table": True
             }, "position_x": 960, "position_y": 140},
            {"node_id": "a3", "node_type": "action", "node_subtype": "send_email",
             "label": "Email: Overdue Review", "config": {
                 "subject": "Overdue: {{count}} risk exceptions past review-by date",
                 "body_template": "The following risk exceptions have passed their scheduled review date and require immediate recertification.\n\nThese exceptions remain active but are overdue for review. Please recertify or revoke them promptly.",
                 "include_findings_table": True
             }, "position_x": 960, "position_y": 400},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "t1", "target_node_id": "f2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "a1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e5", "source_node_id": "f2", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "scan_delta_digest",
        "name": "New Scan Delta Digest",
        "description": "On scan upload, compare with previous scan and send a Slack/Teams summary of new, fixed, and recurring findings",
        "category": "notification",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_upload",
             "label": "Scan Uploaded", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "compute_delta",
             "label": "Compare with Previous", "config": {"compare_mode": "auto_previous"}, "position_x": 360, "position_y": 200},
            {"node_id": "a2", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Slack Delta Summary", "config": {
                 "message_template": ":bar_chart: *Scan Delta Report*\n\n:new: *New findings*: {{new_count}}\n:white_check_mark: *Fixed findings*: {{fixed_count}}\n:repeat: *Recurring*: {{recurring_count}}\n:arrow_up: *Regressions*: {{regression_count}}\n\nTotal assets scanned: {{asset_count}}"
             }, "position_x": 660, "position_y": 120},
            {"node_id": "a3", "node_type": "action", "node_subtype": "teams_notify",
             "label": "Teams Delta Summary", "config": {
                 "message_template": "Scan Delta Report — New: {{new_count}} | Fixed: {{fixed_count}} | Recurring: {{recurring_count}} | Regressions: {{regression_count}}"
             }, "position_x": 660, "position_y": 320},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "a1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "a1", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "internet_facing_escalation",
        "name": "Internet-Facing Escalation",
        "description": "Escalate high/critical findings on internet-facing assets — assign SecOps, create emergency Jira ticket, notify all channels",
        "category": "incident",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_upload",
             "label": "Scan Uploaded", "config": {}, "position_x": 60, "position_y": 260},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "Internet-Facing?", "config": {
                 "conditions": [{"field": "asset.ctx_reachability", "op": "eq", "value": "internet_facing"}],
                 "logic": "AND"
             }, "position_x": 320, "position_y": 260},
            {"node_id": "f2", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "High & Critical", "config": {"operator": "gte", "value": "3"}, "position_x": 580, "position_y": 260},
            {"node_id": "a1", "node_type": "action", "node_subtype": "set_criticality",
             "label": "Max Criticality", "config": {"criticality": "10"}, "position_x": 840, "position_y": 100},
            {"node_id": "a2", "node_type": "action", "node_subtype": "assign_owner",
             "label": "Assign SecOps", "config": {"owner_role": "SecOps", "team": "Security Operations"}, "position_x": 840, "position_y": 260},
            {"node_id": "a3", "node_type": "action", "node_subtype": "create_ticket",
             "label": "Emergency Jira Ticket", "config": {
                 "integration": "jira", "issue_type": "bug",
                 "title_template": "[EMERGENCY] {{plugin_name}} — internet-facing {{asset_ip}}",
                 "group_by": "one_per_finding", "priority": "highest"
             }, "position_x": 1100, "position_y": 100},
            {"node_id": "a4", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Slack Alert", "config": {
                 "message_template": ":rotating_light: *INTERNET-FACING ESCALATION*\n{{count}} high/critical findings on internet-facing assets require immediate action. Emergency tickets created."
             }, "position_x": 1100, "position_y": 260},
            {"node_id": "a5", "node_type": "action", "node_subtype": "send_email",
             "label": "Email CISO", "config": {
                 "subject": "URGENT: {{count}} high/critical vulns on internet-facing assets",
                 "body_template": "Internet-facing assets have been identified with high or critical vulnerabilities that present immediate external risk.\n\nEmergency Jira tickets have been created and assigned to Security Operations.\n\nPlease escalate through your incident response process.",
                 "include_findings_table": True
             }, "position_x": 1100, "position_y": 420},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "f2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "f2", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "f2", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e5", "source_node_id": "a1", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e6", "source_node_id": "a2", "target_node_id": "a4", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e7", "source_node_id": "a2", "target_node_id": "a5", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "eol_software_campaign",
        "name": "EOL/Unsupported Software Campaign",
        "description": "Identify end-of-life software findings, create a remediation campaign, assign owners by tag, and generate grouped migration tickets",
        "category": "patching",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_upload",
             "label": "Scan Uploaded", "config": {}, "position_x": 60, "position_y": 260},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "EOL Software?", "config": {
                 "conditions": [{"field": "solution.root_cause_type", "op": "eq", "value": "eol_software"}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 260},
            {"node_id": "a1", "node_type": "action", "node_subtype": "add_tag",
             "label": "Tag EOL", "config": {"tag_category": "risk", "tag_value": "end-of-life", "target": "both"}, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "create_campaign",
             "label": "Create EOL Campaign", "config": {
                 "name_template": "EOL Software Migration — {{date}}",
                 "description": "Remediate end-of-life software by migrating to supported versions"
             }, "position_x": 660, "position_y": 400},
            {"node_id": "a3", "node_type": "action", "node_subtype": "create_ticket",
             "label": "Migration Tickets", "config": {
                 "integration": "jira", "issue_type": "task",
                 "title_template": "[EOL] Migrate {{affected_component}} from {{current_version}} to supported version",
                 "group_by": "one_per_asset", "priority": "high"
             }, "position_x": 960, "position_y": 260},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "a1", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "credential_coverage_check",
        "name": "Credential Scan Coverage Check",
        "description": "Weekly audit of uncredentialed scans — tag affected assets and notify scan operations team to fix coverage gaps",
        "category": "compliance",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "schedule",
             "label": "Weekly Friday 6 AM", "config": {"schedule_mode": "cron", "cron_expr": "0 6 * * 5"}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "Uncredentialed?", "config": {
                 "conditions": [{"field": "asset.credentialed_scan", "op": "is_false", "value": ""}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "add_tag",
             "label": "Tag Uncredentialed", "config": {"tag_category": "scan-quality", "tag_value": "uncredentialed", "target": "asset"}, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "send_email",
             "label": "Email Scan Ops", "config": {
                 "subject": "Scan Coverage Gap: {{count}} assets scanned without credentials",
                 "body_template": "The following assets were scanned without credentials, which means many local vulnerabilities, installed software, and configuration issues may be missed.\n\nPlease update scan policies to include valid credentials for these targets.\n\nUncredentialed scans typically miss 40-60% of vulnerabilities.",
                 "include_findings_table": True
             }, "position_x": 660, "position_y": 320},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "quick_wins_sprint",
        "name": "Quick Wins Sprint",
        "description": "Find high-efficiency remediation actions (one fix resolves many vulns), create a time-boxed campaign, and assign tickets",
        "category": "triage",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "manual",
             "label": "Manual Trigger", "config": {}, "position_x": 60, "position_y": 260},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "High Efficiency?", "config": {
                 "conditions": [
                     {"field": "solution.efficiency_score", "op": "gte", "value": "7.0"},
                     {"field": "solution.risk_reduction", "op": "gte", "value": "5.0"},
                 ],
                 "logic": "OR"
             }, "position_x": 360, "position_y": 260},
            {"node_id": "a1", "node_type": "action", "node_subtype": "create_campaign",
             "label": "Quick Wins Campaign", "config": {
                 "name_template": "Quick Wins Sprint — {{date}}",
                 "description": "Time-boxed sprint targeting highest-efficiency remediation actions for maximum risk reduction"
             }, "position_x": 660, "position_y": 140},
            {"node_id": "a2", "node_type": "action", "node_subtype": "create_ticket",
             "label": "Create Sprint Tickets", "config": {
                 "integration": "jira", "issue_type": "task",
                 "title_template": "[QUICK WIN] {{action_type}}: {{affected_component}} ({{finding_count}} vulns, {{asset_count}} assets)",
                 "group_by": "one_per_solution", "priority": "medium"
             }, "position_x": 660, "position_y": 400},
            {"node_id": "a3", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Announce Sprint", "config": {
                 "message_template": ":zap: *Quick Wins Sprint Created*\n{{count}} high-efficiency actions identified that will resolve multiple vulnerabilities per fix.\nEstimated risk reduction: {{risk_reduction}}%\nCampaign and Jira tickets ready for assignment."
             }, "position_x": 960, "position_y": 260},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "a2", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "mssp_client_digest",
        "name": "MSSP Client Digest",
        "description": "Scheduled weekly/monthly digest per client org — summarizes new findings, SLA status, trending, and sends branded email report",
        "category": "notification",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "schedule",
             "label": "Weekly Monday 7 AM", "config": {"schedule_mode": "cron", "cron_expr": "0 7 * * 1"}, "position_x": 60, "position_y": 260},
            {"node_id": "a1", "node_type": "action", "node_subtype": "generate_report",
             "label": "Generate Client Report", "config": {
                 "report_type": "client_digest",
                 "sections": ["executive_summary", "new_findings", "sla_compliance", "trending", "top_risks"],
                 "per_org": True
             }, "position_x": 360, "position_y": 260},
            {"node_id": "a2", "node_type": "action", "node_subtype": "send_email",
             "label": "Email Client Digest", "config": {
                 "subject": "Weekly Security Report — {{org_name}} — {{date}}",
                 "body_template": "Dear {{org_name}} Team,\n\nPlease find your weekly vulnerability management digest below.\n\nKey Highlights:\n- New findings this week: {{new_count}}\n- Findings resolved: {{fixed_count}}\n- SLA compliance rate: {{sla_compliance_pct}}%\n- Current risk grade: {{risk_grade}}\n\nPlease review the detailed findings table and contact your account team with questions.",
                 "include_findings_table": True,
                 "per_org": True
             }, "position_x": 660, "position_y": 160},
            {"node_id": "a3", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Internal Summary", "config": {
                 "message_template": ":envelope: *MSSP Client Digests Sent*\n{{org_count}} client reports delivered. Aggregate: {{total_new}} new findings, {{total_fixed}} resolved, avg SLA compliance: {{avg_sla_pct}}%"
             }, "position_x": 660, "position_y": 380},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "a1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "a1", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "integration_error_alert",
        "name": "Integration Error Alert",
        "description": "Alert when any integration run fails — send Slack notification and email the admin",
        "category": "integration",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_integration_execution",
             "label": "Integration Failed", "config": {"status_filter": ["error"]}, "position_x": 60, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Slack Alert", "config": {
                 "message_template": ":x: *Integration Failed*\n\nIntegration `{{integration_name}}` failed.\n:clipboard: Error: {{error_message}}\n:arrow_right: Triggered by: {{triggered_by}}"
             }, "position_x": 360, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "send_email",
             "label": "Email Admin", "config": {
                 "subject": "Integration Failed: {{integration_name}}",
                 "body_template": "The integration '{{integration_name}}' failed during its {{triggered_by}} run.\n\nError: {{error_message}}\n\nPlease check the integration run history for details.",
                 "include_findings_table": False
             }, "position_x": 360, "position_y": 320},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "t1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "integration_complete_campaign",
        "name": "Post-Integration Campaign",
        "description": "After an integration pulls new data, run a campaign to triage new findings and notify the team",
        "category": "integration",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_integration_execution",
             "label": "Integration Completed", "config": {"status_filter": ["success"]}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "High & Critical", "config": {"operator": "gte", "value": "3"}, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "assign_owner",
             "label": "Assign SecOps", "config": {"owner_role": "SecOps", "team": "Security Operations"}, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Notify Slack", "config": {
                 "message_template": ":white_check_mark: Integration `{{integration_name}}` completed — {{records_inserted}} new, {{records_updated}} updated. {{count}} high/critical findings assigned to SecOps."
             }, "position_x": 660, "position_y": 320},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "a1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
        ],
    },
    # ── Threat Intel & Data-Driven Templates ─────────────────────────────
    {
        "id": "threat_intel_response",
        "name": "Threat Intel Auto-Response",
        "description": "When new high-severity CVEs are synced and affect your environment, auto-tag affected findings and notify via Slack",
        "category": "incident",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_new_threat_intel",
             "label": "New Threat Intel", "config": {
                 "intel_type": "cve", "severity_threshold": "7.0",
                 "only_affecting_environment": True
             }, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "exploit_filter",
             "label": "Has Exploit?", "config": {"has_exploit": "true"}, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "add_tag",
             "label": "Tag Emerging Threat", "config": {"tag_category": "threat_intel", "tag_value": "emerging_threat", "target": "both"}, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Alert Team", "config": {
                 "message_template": ":rotating_light: *New Threat Intel Alert*\n{{count}} findings in your environment are affected by newly discovered high-severity CVEs with known exploits. Immediate review recommended."
             }, "position_x": 660, "position_y": 320},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "a1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "new_asset_onboard",
        "name": "New Asset Onboarding",
        "description": "When a new internet-facing asset is discovered, auto-tag, assign to SecOps, and create a review ticket",
        "category": "triage",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_new_asset",
             "label": "New Asset", "config": {"asset_filter": "internet_facing"}, "position_x": 60, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "add_tag",
             "label": "Tag New Asset", "config": {"tag_category": "lifecycle", "tag_value": "new_discovery", "target": "asset"}, "position_x": 360, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "assign_owner",
             "label": "Assign SecOps", "config": {"owner_role": "SecOps", "team": "Security Operations"}, "position_x": 360, "position_y": 320},
            {"node_id": "a3", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Notify Team", "config": {
                 "message_template": ":new: *New Internet-Facing Asset Discovered*\n{{count}} new asset(s) detected. Auto-assigned to SecOps for review."
             }, "position_x": 660, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "t1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "a1", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "critical_finding_alert",
        "name": "Critical Finding Instant Alert",
        "description": "Immediately alert when new critical or exploitable findings are discovered — no waiting for campaign runs",
        "category": "incident",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_new_finding",
             "label": "New Finding", "config": {"min_severity": "3", "only_exploitable": False}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "Critical Only", "config": {"operator": "gte", "value": "4"}, "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "create_ticket",
             "label": "Create Urgent Ticket", "config": {
                 "integration": "jira", "issue_type": "bug",
                 "title_template": "[CRITICAL] {{plugin_name}} on {{asset_ip}}",
                 "priority": "highest"
             }, "position_x": 660, "position_y": 120},
            {"node_id": "a2", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Alert Channel", "config": {
                 "message_template": ":fire: *Critical Finding Detected*\n`{{plugin_name}}` on `{{asset_hostname}}` ({{asset_ip}}) — CVSS {{cvss3_score}}. Jira ticket created."
             }, "position_x": 660, "position_y": 320},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e3", "source_node_id": "a1", "target_node_id": "a2", "source_handle": "output", "target_handle": "input"},
        ],
    },
    {
        "id": "multi_owner_ticketing",
        "name": "Multi-Owner Ticket Routing",
        "description": "Route findings to different ticketing systems (Jira, ServiceNow) based on finding ownership",
        "category": "triage",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_campaign_run",
             "label": "Campaign Runs", "config": {}, "position_x": 60, "position_y": 300},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "Owner = Infra Team", "config": {
                 "conditions": [{"field": "owner_name", "op": "eq", "value": "Infra Team"}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 180},
            {"node_id": "a1", "node_type": "action", "node_subtype": "create_ticket",
             "label": "ServiceNow Ticket", "config": {
                 "integration": "servicenow", "issue_type": "incident",
                 "title_template": "[{{severity}}] {{plugin_name}} on {{asset_ip}}",
                 "priority": "high"
             }, "position_x": 720, "position_y": 100},
            {"node_id": "f2", "node_type": "filter", "node_subtype": "condition_filter",
             "label": "Owner = Dev Team", "config": {
                 "conditions": [{"field": "owner_name", "op": "eq", "value": "Dev Team"}],
                 "logic": "AND"
             }, "position_x": 360, "position_y": 420},
            {"node_id": "a2", "node_type": "action", "node_subtype": "create_ticket",
             "label": "Jira Ticket", "config": {
                 "integration": "jira", "issue_type": "bug",
                 "title_template": "[{{severity}}] {{plugin_name}} on {{asset_ip}}",
                 "priority": "high"
             }, "position_x": 720, "position_y": 340},
            {"node_id": "a3", "node_type": "action", "node_subtype": "change_status",
             "label": "Mark In Progress", "config": {"status": "in_progress"},
             "position_x": 720, "position_y": 500},
            {"node_id": "a4", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Notify Unmatched", "config": {
                 "message_template": "{{count}} findings have no matching owner for ticket routing — please assign owners"
             }, "position_x": 720, "position_y": 620},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1", "source_handle": "output", "target_handle": "input", "label": "Infra Team"},
            {"edge_id": "e3", "source_node_id": "f1", "target_node_id": "f2", "source_handle": "remainder", "target_handle": "input"},
            {"edge_id": "e4", "source_node_id": "f2", "target_node_id": "a2", "source_handle": "output", "target_handle": "input", "label": "Dev Team"},
            {"edge_id": "e5", "source_node_id": "a1", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e6", "source_node_id": "a2", "target_node_id": "a3", "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e7", "source_node_id": "f2", "target_node_id": "a4", "source_handle": "remainder", "target_handle": "input", "label": "No match"},
        ],
    },
]
