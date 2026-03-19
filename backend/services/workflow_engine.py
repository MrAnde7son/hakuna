"""
Workflow execution engine — walks the node graph and executes actions.
Supports OOTB templates, custom workflows, retry logic, and cron scheduling.
"""
import logging
import threading
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from models.models import (
    Workflow, WorkflowNode, WorkflowEdge,
    WorkflowExecution, WorkflowExecutionLog,
    Finding, Asset, Campaign, CampaignFinding,
    Tag, TagAssignment, FindingOwnership, AssetOwnership,
)
import services.integrations as integrations

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Node catalog — defines available node types
# ─────────────────────────────────────────────

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


# ─────────────────────────────────────────────
# OOTB Workflow Templates
# ─────────────────────────────────────────────

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
                 "body_template": "Hello,\n\nA campaign run has identified {{count}} high or critical findings across {{assets}} asset(s) that require remediation.\n\nPlease review the findings table below and coordinate remediation with the appropriate teams.\n\nRegards,\Hakuna Remediation Platform",
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
]

TEMPLATE_CATEGORIES = [
    {"id": "triage", "label": "Triage & Routing", "icon": "GitBranch"},
    {"id": "patching", "label": "Patching", "icon": "Shield"},
    {"id": "incident", "label": "Incident Response", "icon": "Zap"},
    {"id": "integration", "label": "Integration", "icon": "Globe"},
    {"id": "sla", "label": "SLA Management", "icon": "Clock"},
    {"id": "notification", "label": "Notification", "icon": "Mail"},
    {"id": "compliance", "label": "Compliance & Audit", "icon": "CheckSquare"},
]


def create_workflow_from_template(db: Session, template_id: str, name: str = None,
                                  campaign_id: int = None) -> Workflow:
    """Create a new workflow from an OOTB template."""
    template = next((t for t in WORKFLOW_TEMPLATES if t["id"] == template_id), None)
    if not template:
        raise ValueError(f"Template '{template_id}' not found")

    wf = Workflow(
        name=name or template["name"],
        description=template["description"],
        campaign_id=campaign_id,
        status="draft",
    )
    db.add(wf)
    db.flush()

    for nd in template["nodes"]:
        db.add(WorkflowNode(
            workflow_id=wf.id,
            node_id=nd["node_id"],
            node_type=nd["node_type"],
            node_subtype=nd["node_subtype"],
            label=nd.get("label", ""),
            config=nd.get("config", {}),
            position_x=nd.get("position_x", 0),
            position_y=nd.get("position_y", 0),
        ))

    for ed in template["edges"]:
        db.add(WorkflowEdge(
            workflow_id=wf.id,
            edge_id=ed["edge_id"],
            source_node_id=ed["source_node_id"],
            target_node_id=ed["target_node_id"],
            source_handle=ed.get("source_handle", "output"),
            target_handle=ed.get("target_handle", "input"),
            label=ed.get("label"),
        ))

    db.commit()
    db.refresh(wf)
    return wf


# ─────────────────────────────────────────────
# Execution engine
# ─────────────────────────────────────────────

def execute_workflow(db: Session, workflow_id: int, trigger_data: dict = None) -> dict:
    """Execute a workflow by walking its node graph from trigger to actions."""
    workflow = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not workflow:
        raise ValueError(f"Workflow {workflow_id} not found")

    nodes = {n.node_id: n for n in workflow.nodes}
    edges = workflow.edges

    # Build adjacency list: source -> [(target, source_handle)]
    adj: dict[str, list[tuple[str, str]]] = {}
    for e in edges:
        adj.setdefault(e.source_node_id, []).append((e.target_node_id, e.source_handle or "output"))

    # Find trigger nodes
    trigger_nodes = [n for n in nodes.values() if n.node_type == "trigger"]
    if not trigger_nodes:
        raise ValueError("Workflow has no trigger node")

    # Create execution record
    execution = WorkflowExecution(
        workflow_id=workflow_id,
        status="running",
        trigger_type=trigger_nodes[0].node_subtype if trigger_nodes else "manual",
        started_at=datetime.utcnow(),
    )
    db.add(execution)
    db.flush()

    total_processed = 0
    summary = {"nodes_executed": 0, "actions_taken": 0, "errors": []}

    # Gather initial data items (findings from campaign or trigger data)
    items = _gather_trigger_data(db, workflow, trigger_nodes[0], trigger_data)

    # Walk the graph: BFS with fan-in support.
    # Nodes accumulate inputs from all incoming edges before executing.
    # Build in-degree map to know when all parents have delivered.
    in_edges: dict[str, list[str]] = {}  # target -> [source, ...]
    for e in edges:
        in_edges.setdefault(e.target_node_id, []).append(e.source_node_id)

    # Pending items: node_id -> list of items waiting
    pending_items: dict[str, list] = {}
    # Track how many parent deliveries each node has received
    deliveries: dict[str, int] = {}
    executed = set()

    queue = [(trigger_nodes[0].node_id, items)]

    while queue:
        current_node_id, current_items = queue.pop(0)

        node = nodes.get(current_node_id)
        if not node:
            continue

        # For non-trigger nodes with multiple parents, accumulate inputs
        parent_count = len(in_edges.get(current_node_id, []))
        if parent_count > 1 and current_node_id not in executed:
            pending_items.setdefault(current_node_id, []).extend(current_items)
            deliveries[current_node_id] = deliveries.get(current_node_id, 0) + 1
            if deliveries[current_node_id] < parent_count:
                continue  # still waiting for more parents
            current_items = pending_items.pop(current_node_id, current_items)

        if current_node_id in executed:
            continue
        executed.add(current_node_id)

        result = _execute_node(db, node, current_items, execution)
        summary["nodes_executed"] += 1

        log = WorkflowExecutionLog(
            execution_id=execution.id,
            node_id=node.node_id,
            node_type=node.node_type,
            node_subtype=node.node_subtype,
            status=result["status"],
            items_in=len(current_items),
            items_out=len(result.get("items", [])),
            output_data=result.get("output", {}),
            error=result.get("error"),
        )
        db.add(log)

        if result["status"] == "failed":
            summary["errors"].append({
                "node_id": node.node_id,
                "error": result.get("error", "Unknown error"),
            })
            continue

        if node.node_type == "action":
            summary["actions_taken"] += 1
            total_processed += len(current_items)

        # Route to next nodes
        next_edges = adj.get(current_node_id, [])
        for target_id, handle in next_edges:
            if node.node_type == "filter":
                if handle == "output":
                    queue.append((target_id, result.get("items", [])))
                elif handle == "remainder":
                    queue.append((target_id, result.get("remainder", [])))
            else:
                queue.append((target_id, result.get("items", current_items)))

    # Finalize
    execution.status = "completed" if not summary["errors"] else "failed"
    execution.completed_at = datetime.utcnow()
    execution.items_processed = total_processed
    execution.result_summary = summary
    if summary["errors"]:
        execution.error = "; ".join(e["error"] for e in summary["errors"][:3])

    workflow.last_run_at = datetime.utcnow()
    workflow.run_count = (workflow.run_count or 0) + 1

    db.commit()

    return {
        "execution_id": execution.id,
        "status": execution.status,
        "items_processed": total_processed,
        "summary": summary,
    }


def _gather_trigger_data(db: Session, workflow: Workflow, trigger_node: WorkflowNode,
                         trigger_data: dict = None) -> list:
    """Gather initial data items based on trigger type and campaign link."""
    if trigger_data and "findings" in trigger_data:
        return trigger_data["findings"]

    # If linked to a campaign, use campaign findings
    campaign_id = workflow.campaign_id
    if campaign_id:
        return _load_campaign_findings(db, campaign_id)

    # If trigger_data has scan_id, gather findings from that scan
    scan_id = (trigger_data or {}).get("scan_id")
    if scan_id:
        return _load_scan_findings(db, scan_id)

    # For new-asset triggers, convert asset data into items
    if trigger_node.node_subtype == "on_new_asset":
        return _load_asset_items(db, trigger_data or {})

    # For new-finding triggers, load the finding items directly
    if trigger_node.node_subtype == "on_new_finding":
        return _load_new_finding_items(db, trigger_data or {})

    # For threat intel triggers, find affected findings in the environment
    if trigger_node.node_subtype == "on_new_threat_intel":
        return _load_threat_intel_affected_findings(db, trigger_data or {})

    return []


def _load_campaign_findings(db: Session, campaign_id: int) -> list:
    """Load findings from a campaign's results."""
    rows = (
        db.query(CampaignFinding, Finding, Asset)
        .join(Finding, Finding.id == CampaignFinding.finding_id)
        .outerjoin(Asset, Asset.id == Finding.asset_id)
        .filter(CampaignFinding.campaign_id == campaign_id)
        .all()
    )
    return [_finding_to_item(finding, asset, campaign_finding_id=cf.id)
            for cf, finding, asset in rows]


def _load_scan_findings(db: Session, scan_id: int) -> list:
    """Load findings from a scan."""
    rows = (
        db.query(Finding, Asset)
        .outerjoin(Asset, Asset.id == Finding.asset_id)
        .filter(Finding.scan_id == scan_id, Finding.severity >= 1)
        .limit(5000)
        .all()
    )
    return [_finding_to_item(f, asset) for f, asset in rows]


def _load_asset_items(db: Session, trigger_data: dict) -> list:
    """Convert new asset IDs from trigger data into workflow items."""
    asset_ids = trigger_data.get("asset_ids", [])
    if not asset_ids:
        return []
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).limit(5000).all()
    items = []
    for asset in assets:
        items.append({
            "finding_id": None,
            "asset_id": asset.id,
            "asset_ip": asset.ip,
            "asset_hostname": asset.hostname,
            "asset_os": asset.os,
            "asset_criticality": asset.criticality,
            "asset_environment": asset.environment_tag,
            "asset_risk_score": getattr(asset, "risk_score", 0),
            "is_internet_facing": getattr(asset, "is_internet_facing", False),
            "severity": 0,
        })
    return items


def _load_new_finding_items(db: Session, trigger_data: dict) -> list:
    """Load newly inserted findings from trigger data."""
    finding_ids = trigger_data.get("finding_ids", [])
    if not finding_ids:
        return []
    rows = (
        db.query(Finding, Asset)
        .outerjoin(Asset, Asset.id == Finding.asset_id)
        .filter(Finding.id.in_(finding_ids))
        .limit(5000)
        .all()
    )
    return [_finding_to_item(f, asset) for f, asset in rows]


def _load_threat_intel_affected_findings(db: Session, trigger_data: dict) -> list:
    """Find findings in the environment affected by newly synced threat intel."""
    new_cve_ids = trigger_data.get("new_cve_ids", [])
    if not new_cve_ids:
        return []
    # Find findings whose cves overlap with the new intel
    rows = (
        db.query(Finding, Asset)
        .outerjoin(Asset, Asset.id == Finding.asset_id)
        .filter(Finding.cves.isnot(None))
        .limit(10000)
        .all()
    )
    new_cve_set = set(new_cve_ids)
    items = []
    for finding, asset in rows:
        if finding.cves and any(c in new_cve_set for c in finding.cves):
            items.append(_finding_to_item(finding, asset))
    return items


def _finding_to_item(finding: Finding, asset: Asset, campaign_finding_id: int = None) -> dict:
    """Convert a Finding + Asset to a workflow data item."""
    return {
        "finding_id": finding.id,
        "campaign_finding_id": campaign_finding_id,
        "plugin_id": finding.plugin_id,
        "plugin_name": finding.plugin_name,
        "plugin_family": finding.plugin_family,
        "severity": finding.severity,
        "severity_label": finding.severity_label,
        "cvss3_score": finding.cvss3_score,
        "vpr_score": finding.vpr_score,
        "priority_score": finding.priority_score,
        "exploit_available": finding.exploit_available,
        "cves": finding.cves or [],
        "solution": finding.solution,
        "asset_id": finding.asset_id,
        "asset_ip": asset.ip if asset else None,
        "asset_hostname": asset.hostname if asset else None,
        "asset_os": asset.os if asset else None,
        "asset_criticality": asset.criticality if asset else 5,
        "asset_environment": asset.environment_tag if asset else None,
        "asset_risk_score": asset.risk_score if asset else 0,
    }


MAX_RETRIES = 2
RETRY_DELAY = 1  # seconds


def _execute_node(db: Session, node: WorkflowNode, items: list, execution: WorkflowExecution) -> dict:
    """Execute a single node with retry logic for action nodes."""
    retries = MAX_RETRIES if node.node_type == "action" else 0
    last_error = None

    for attempt in range(retries + 1):
        try:
            if node.node_type == "trigger":
                severity_counts = {}
                for item in items:
                    label = item.get("severity_label") or str(item.get("severity", "?"))
                    severity_counts[label] = severity_counts.get(label, 0) + 1
                unique_assets = len({item.get("asset_id") for item in items if item.get("asset_id")})
                output = {
                    "count": len(items),
                    "assets": unique_assets,
                    "severity_breakdown": severity_counts,
                    "sample": [
                        {
                            "plugin_name": i.get("plugin_name"),
                            "severity_label": i.get("severity_label"),
                            "asset_hostname": i.get("asset_hostname") or i.get("asset_ip"),
                            "cvss3_score": i.get("cvss3_score"),
                        }
                        for i in items[:5]
                    ],
                }
                return {"status": "success", "items": items, "output": output}
            elif node.node_type == "filter":
                return _execute_filter(db, node, items)
            elif node.node_type == "action":
                return _execute_action(db, node, items)
            return {"status": "skipped", "items": items}
        except Exception as e:
            last_error = e
            if attempt < retries:
                logger.warning(f"Node {node.node_id} ({node.node_subtype}) attempt {attempt + 1} failed: {e}, retrying...")
                import time
                time.sleep(RETRY_DELAY)
            else:
                logger.error(f"Node {node.node_id} ({node.node_subtype}) failed after {attempt + 1} attempts: {e}")

    return {"status": "failed", "error": str(last_error), "items": items}


def _execute_filter(db: Session, node: WorkflowNode, items: list) -> dict:
    """Evaluate a filter and split items into matched / remainder."""
    config = node.config or {}
    subtype = node.node_subtype
    matched = []
    remainder = []

    for item in items:
        passes = False

        if subtype == "severity_filter":
            op = config.get("operator", "gte")
            threshold = int(config.get("value", "3"))
            passes = _compare(item.get("severity", 0), op, threshold)

        elif subtype == "score_filter":
            field = config.get("field", "cvss3_score")
            op = config.get("operator", "gte")
            threshold = float(config.get("value", 7.0))
            passes = _compare(item.get(field, 0) or 0, op, threshold)

        elif subtype == "exploit_filter":
            want = config.get("has_exploit", "true") == "true"
            passes = bool(item.get("exploit_available")) == want

        elif subtype == "tag_filter":
            cat = config.get("tag_category", "")
            val = config.get("tag_value", "")
            mode = config.get("mode", "include")
            tag = db.query(Tag).filter(Tag.category == cat, Tag.value == val).first()
            has_tag = False
            if tag:
                fid = item.get("finding_id")
                aid = item.get("asset_id")
                has_tag = db.query(TagAssignment).filter(
                    TagAssignment.tag_id == tag.id,
                    (TagAssignment.finding_id == fid) | (TagAssignment.asset_id == aid),
                ).first() is not None
            passes = has_tag if mode == "include" else not has_tag

        elif subtype == "condition_filter":
            conditions = config.get("conditions", [])
            logic = config.get("logic", "AND")
            passes = _eval_conditions(item, conditions, logic, db)

        elif subtype == "asset_filter":
            field = config.get("field", "os")
            op = config.get("operator", "contains")
            value = config.get("value", "")
            asset_val = item.get(f"asset_{field}", "") or ""
            if field in ("criticality",):
                try:
                    passes = _compare(int(asset_val), op, int(value))
                except (ValueError, TypeError):
                    passes = False
            else:
                passes = _compare_str(str(asset_val), op, str(value))

        if passes:
            matched.append(item)
        else:
            remainder.append(item)

    return {
        "status": "success",
        "items": matched,
        "remainder": remainder,
        "output": {"matched": len(matched), "remainder": len(remainder)},
    }


def _execute_action(db: Session, node: WorkflowNode, items: list) -> dict:
    """Execute an action node on the given items."""
    config = node.config or {}
    subtype = node.node_subtype
    affected = 0

    if subtype == "assign_owner":
        owner_name = config.get("owner_name", "")
        owner_email = config.get("owner_email", "")
        owner_role = config.get("owner_role", "IT")
        team = config.get("team", "")

        for item in items:
            cf_id = item.get("campaign_finding_id")
            if cf_id:
                cf = db.query(CampaignFinding).filter(CampaignFinding.id == cf_id).first()
                if cf:
                    cf.owner_name = owner_name
                    cf.owner_email = owner_email
                    cf.owner_role = owner_role
                    cf.team = team
                    affected += 1
            else:
                finding_id = item.get("finding_id")
                if finding_id:
                    ownership = db.query(FindingOwnership).filter(
                        FindingOwnership.finding_id == finding_id).first()
                    if not ownership:
                        ownership = FindingOwnership(finding_id=finding_id)
                        db.add(ownership)
                    ownership.owner_name = owner_name
                    ownership.owner_email = owner_email
                    ownership.owner_role = owner_role
                    ownership.team = team
                    affected += 1

    elif subtype == "add_tag":
        cat = config.get("tag_category", "")
        val = config.get("tag_value", "")
        target = config.get("target", "finding")

        tag = db.query(Tag).filter(Tag.category == cat, Tag.value == val).first()
        if not tag:
            tag = Tag(category=cat, value=val, color="#6366f1")
            db.add(tag)
            db.flush()

        seen_f, seen_a = set(), set()
        for item in items:
            if target in ("finding", "both"):
                fid = item.get("finding_id")
                if fid and fid not in seen_f:
                    seen_f.add(fid)
                    if not db.query(TagAssignment).filter(
                        TagAssignment.tag_id == tag.id, TagAssignment.finding_id == fid).first():
                        db.add(TagAssignment(tag_id=tag.id, finding_id=fid, assigned_by="workflow"))
                        affected += 1
            if target in ("asset", "both"):
                aid = item.get("asset_id")
                if aid and aid not in seen_a:
                    seen_a.add(aid)
                    if not db.query(TagAssignment).filter(
                        TagAssignment.tag_id == tag.id, TagAssignment.asset_id == aid).first():
                        db.add(TagAssignment(tag_id=tag.id, asset_id=aid, assigned_by="workflow"))
                        affected += 1

    elif subtype == "change_status":
        new_status = config.get("status", "in_progress")
        for item in items:
            cf_id = item.get("campaign_finding_id")
            if cf_id:
                cf = db.query(CampaignFinding).filter(CampaignFinding.id == cf_id).first()
                if cf:
                    cf.status = new_status
                    affected += 1

    elif subtype == "set_criticality":
        crit = int(config.get("criticality", 5))
        seen = set()
        for item in items:
            aid = item.get("asset_id")
            if aid and aid not in seen:
                seen.add(aid)
                asset = db.query(Asset).filter(Asset.id == aid).first()
                if asset:
                    asset.criticality = crit
                    affected += 1

    elif subtype == "send_email":
        result = integrations.send_email(db, config, items)
        logger.info(f"[Workflow Email] Sent to {result.get('recipients', [])}, {len(items)} items")
        affected = len(items)

    elif subtype == "send_webhook":
        result = integrations.send_webhook(config, items)
        logger.info(f"[Workflow Webhook] {config.get('method', 'POST')} {config.get('url')} → {result.get('status_code')}")
        affected = len(items)

    elif subtype == "create_ticket":
        integration = config.get("integration", "jira")
        if integration == "servicenow":
            result = integrations.create_servicenow_ticket(db, config, items)
        else:
            result = integrations.create_jira_ticket(db, config, items)
        logger.info(f"[Workflow Ticket] {integration}: created {result.get('tickets_created', 0)} ticket(s)")
        affected = result.get("tickets_created", 0)

    elif subtype == "slack_notify":
        result = integrations.send_slack_notification(db, config, items)
        logger.info(f"[Workflow Slack] Sent, {len(items)} items")
        affected = len(items)

    elif subtype == "teams_notify":
        result = integrations.send_teams_notification(db, config, items)
        logger.info(f"[Workflow Teams] Sent, {len(items)} items")
        affected = len(items)

    elif subtype == "run_script":
        script_type = config.get("script_type", "bash")
        script = config.get("script", "")
        logger.info(f"[Workflow Script] {script_type}: {script} | {len(items)} targets (dry-run)")
        affected = len(items)

    db.flush()
    return {
        "status": "success",
        "items": items,
        "output": {"affected": affected, "action": subtype},
    }


def _render_template(template: str, items: list) -> str:
    """Simple template rendering with {{var}} placeholders."""
    if not template:
        return f"{len(items)} items processed"
    unique_assets = set(i.get("asset_ip") or i.get("asset_hostname", "") for i in items)
    result = template
    result = result.replace("{{count}}", str(len(items)))
    result = result.replace("{{assets}}", str(len(unique_assets)))
    if items:
        first = items[0]
        result = result.replace("{{severity}}", first.get("severity_label", ""))
        result = result.replace("{{plugin_name}}", first.get("plugin_name", ""))
        result = result.replace("{{asset_ip}}", first.get("asset_ip", ""))
    return result


def _group_for_tickets(items: list, group_by: str, title_tpl: str) -> list:
    """Group items into ticket payloads based on grouping strategy."""
    if group_by == "one_for_all":
        return [{"title": _render_template(title_tpl, items), "items": items}]
    elif group_by == "one_per_asset":
        by_asset = {}
        for item in items:
            key = item.get("asset_id", "unknown")
            by_asset.setdefault(key, []).append(item)
        return [{"title": _render_template(title_tpl, group), "items": group}
                for group in by_asset.values()]
    else:  # one_per_finding
        return [{"title": _render_template(title_tpl, [item]), "items": [item]}
                for item in items]


def _eval_conditions(item: dict, conditions: list, logic: str, db: Session) -> bool:
    """Evaluate a list of conditions against a workflow data item."""
    results = []
    for cond in conditions:
        field = cond.get("field", "")
        op = cond.get("op", "eq")
        value = cond.get("value", "")

        # Resolve field value: support "finding.X" and "asset.X" prefixes
        if field.startswith("finding."):
            key = field.split(".", 1)[1]
            # Map common finding fields to item keys
            actual = item.get(key, item.get(f"finding_{key}"))
        elif field.startswith("asset."):
            key = field.split(".", 1)[1]
            actual = item.get(f"asset_{key}", item.get(key))
        else:
            actual = item.get(field)

        if actual is None:
            actual = ""

        # Try numeric comparison first, fall back to string
        try:
            results.append(_compare(float(actual), op, float(value)))
        except (ValueError, TypeError):
            results.append(_compare_str(str(actual), op, str(value)))

    if not results:
        return True
    return all(results) if logic == "AND" else any(results)


def _compare(a, op, b):
    """Numeric comparison."""
    ops = {"eq": lambda: a == b, "neq": lambda: a != b, "gt": lambda: a > b,
           "lt": lambda: a < b, "gte": lambda: a >= b, "lte": lambda: a <= b}
    return ops.get(op, lambda: False)()


def _compare_str(a, op, b):
    """String comparison."""
    a_l, b_l = a.lower(), b.lower()
    ops = {"eq": lambda: a_l == b_l, "neq": lambda: a_l != b_l,
           "contains": lambda: b_l in a_l, "gte": lambda: a_l >= b_l, "lte": lambda: a_l <= b_l}
    return ops.get(op, lambda: False)()


# ─────────────────────────────────────────────
# Cron-style Scheduler
# ─────────────────────────────────────────────

INTERVAL_SECONDS = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
    "monthly": 2592000,
}

_scheduler_thread = None
_scheduler_stop = threading.Event()


def _cron_matches(cron_expr: str, dt: datetime) -> bool:
    """Check if a datetime matches a cron expression (minute hour dom month dow).
    Supports: numbers, *, */N, and comma-separated values."""
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return False

    fields = [dt.minute, dt.hour, dt.day, dt.month, dt.weekday()]
    # cron weekday: 0=Sun..6=Sat; Python weekday: 0=Mon..6=Sun → convert
    fields[4] = (fields[4] + 1) % 7
    ranges = [
        (0, 59),   # minute
        (0, 23),   # hour
        (1, 31),   # day of month
        (1, 12),   # month
        (0, 6),    # day of week
    ]

    for part, actual, (lo, hi) in zip(parts, fields, ranges):
        if not _cron_field_matches(part, actual, lo, hi):
            return False
    return True


def _cron_field_matches(field: str, value: int, lo: int, hi: int) -> bool:
    """Check if a single cron field matches a value."""
    for token in field.split(","):
        token = token.strip()
        if token == "*":
            return True
        if token.startswith("*/"):
            try:
                step = int(token[2:])
                if step > 0 and value % step == 0:
                    return True
            except ValueError:
                pass
        elif "-" in token:
            try:
                a, b = token.split("-", 1)
                if int(a) <= value <= int(b):
                    return True
            except ValueError:
                pass
        else:
            try:
                if int(token) == value:
                    return True
            except ValueError:
                pass
    return False


def _schedule_is_due(trigger: WorkflowNode, wf: Workflow, now: datetime) -> bool:
    """Check if a 'schedule' trigger (interval + optional time) is due."""
    config = trigger.config or {}
    interval_key = config.get("interval", "daily")
    interval_secs = INTERVAL_SECONDS.get(interval_key, 86400)

    # Check if enough time has passed since last run
    if wf.last_run_at:
        next_run = wf.last_run_at + timedelta(seconds=interval_secs)
        if now < next_run:
            return False

    # Respect time-of-day if configured (for daily/weekly/monthly)
    target_time = config.get("time")
    if target_time and interval_key in ("daily", "weekly", "monthly"):
        try:
            hh, mm = target_time.split(":")
            target_hour, target_min = int(hh), int(mm)
            # Allow a 2-minute window around the target time
            if abs(now.hour * 60 + now.minute - (target_hour * 60 + target_min)) > 2:
                return False
        except (ValueError, AttributeError):
            pass

    return True


def start_scheduler(session_factory):
    """Start the background scheduler thread that runs scheduled workflows."""
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return  # already running

    _scheduler_stop.clear()

    def _scheduler_loop():
        logger.info("Workflow scheduler started")
        while not _scheduler_stop.wait(60):  # check every 60 seconds
            try:
                _check_scheduled_workflows(session_factory)
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True, name="workflow-scheduler")
    _scheduler_thread.start()


def stop_scheduler():
    """Stop the background scheduler."""
    _scheduler_stop.set()


def _check_scheduled_workflows(session_factory):
    """Check for workflows with schedule triggers that are due to run."""
    db = session_factory()
    try:
        workflows = db.query(Workflow).filter(
            Workflow.is_enabled == True,
            Workflow.status == "active",
        ).all()

        now = datetime.utcnow()

        for wf in workflows:
            # Find schedule trigger (unified: supports both simple and cron modes)
            # Also match legacy "cron" subtype for backward compat
            trigger = next(
                (n for n in wf.nodes
                 if n.node_type == "trigger" and n.node_subtype in ("schedule", "cron")),
                None,
            )
            if not trigger:
                continue

            should_run = False
            config = trigger.config or {}
            schedule_mode = config.get("schedule_mode", "")

            # Legacy "cron" subtype or schedule_mode == "cron"
            if trigger.node_subtype == "cron" or schedule_mode == "cron":
                cron_expr = config.get("cron_expr", "")
                if _cron_matches(cron_expr, now):
                    # Prevent double-run: skip if already ran this minute
                    if wf.last_run_at and (now - wf.last_run_at).total_seconds() < 60:
                        continue
                    should_run = True
            else:  # simple schedule mode
                should_run = _schedule_is_due(trigger, wf, now)

            if not should_run:
                continue

            logger.info(f"Scheduler: executing workflow '{wf.name}' (id={wf.id}, trigger={trigger.node_subtype})")
            try:
                execute_workflow(db, wf.id, trigger_data={"triggered_by": "scheduler"})
            except Exception as e:
                logger.error(f"Scheduler: workflow {wf.id} failed: {e}")
    finally:
        db.close()


# ─────────────────────────────────────────────
# Event-driven trigger dispatcher
# ─────────────────────────────────────────────

def fire_event_workflows(db: Session, event_type: str, event_data: dict = None):
    """Fire all active workflows that have a trigger matching the given event.

    event_type: one of 'on_upload', 'on_integration_execution', 'on_new_threat_intel',
                'on_new_asset', 'on_new_finding'
    event_data: dict with event-specific context (scan_id, integration details, new items, etc.)
    """
    event_data = event_data or {}

    # Also match legacy subtypes for backward compat
    legacy_map = {
        "on_integration_execution": ["on_integration_execution", "on_integration_complete", "on_integration_error"],
    }
    match_subtypes = legacy_map.get(event_type, [event_type])

    try:
        trigger_nodes = db.query(WorkflowNode).join(Workflow).filter(
            Workflow.is_enabled == True,
            Workflow.status == "active",
            WorkflowNode.node_type == "trigger",
            WorkflowNode.node_subtype.in_(match_subtypes),
        ).all()

        fired = 0
        for node in trigger_nodes:
            if _trigger_matches_event(node, event_type, event_data):
                try:
                    execute_workflow(db, node.workflow_id, trigger_data=event_data)
                    fired += 1
                except Exception as wf_err:
                    logger.warning("Failed to fire workflow %s for event %s: %s",
                                   node.workflow_id, event_type, wf_err)

        if fired:
            logger.info("Fired %d workflow(s) for event %s", fired, event_type)
        return fired
    except Exception as e:
        logger.warning("Failed to fire event workflows for %s: %s", event_type, e)
        return 0


def _trigger_matches_event(node: WorkflowNode, event_type: str, event_data: dict) -> bool:
    """Check if a trigger node's config matches the incoming event data."""
    config = node.config or {}

    if event_type == "on_upload":
        return True  # on_upload triggers always match

    if event_type == "on_integration_execution":
        # Check integration_id filter
        if config.get("integration_id") and config["integration_id"] != event_data.get("integration_id"):
            return False
        # Check status filter
        status = event_data.get("status", "")
        status_filter = config.get("status_filter")

        # Legacy: on_integration_error only fires on error
        if node.node_subtype == "on_integration_error":
            return status == "error"
        # Legacy: on_integration_complete fires on any (or specific status)
        if node.node_subtype == "on_integration_complete":
            single_filter = config.get("status_filter", "")
            return not single_filter or single_filter == status

        # New unified: status_filter is a list
        if isinstance(status_filter, list) and status_filter:
            return status in status_filter
        return True  # no filter = any status

    if event_type == "on_new_threat_intel":
        intel_type = config.get("intel_type", "any")
        event_intel_type = event_data.get("intel_type", "any")
        if intel_type != "any" and intel_type != event_intel_type:
            return False

        # Severity threshold — only for CVE events
        severity_threshold = config.get("severity_threshold", "")
        if severity_threshold and event_intel_type == "cve":
            max_cvss = event_data.get("max_cvss", 0)
            if max_cvss < float(severity_threshold):
                return False

        # Only affecting environment — check if any findings exist for new CVEs
        if config.get("only_affecting_environment", False):
            return event_data.get("affects_environment", False)

        return True

    if event_type == "on_new_asset":
        asset_filter = config.get("asset_filter", "any")
        if asset_filter == "any":
            return True
        if asset_filter == "internet_facing":
            return any(a.get("is_internet_facing") for a in event_data.get("assets", []))
        if asset_filter == "high_criticality":
            return any((a.get("criticality") or 5) <= 3 for a in event_data.get("assets", []))
        return True

    if event_type == "on_new_finding":
        min_severity = int(config.get("min_severity", "0"))
        only_exploitable = config.get("only_exploitable", False)
        findings = event_data.get("findings", [])
        if min_severity:
            findings = [f for f in findings if (f.get("severity") or 0) >= min_severity]
        if only_exploitable:
            findings = [f for f in findings if f.get("exploit_available")]
        return len(findings) > 0

    return True
