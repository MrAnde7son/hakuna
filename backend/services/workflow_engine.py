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
            "description": "Run on a time schedule",
            "icon": "Clock",
            "config_schema": {
                "interval": {"type": "enum", "label": "Interval",
                             "options": ["hourly", "daily", "weekly", "monthly"]},
                "time": {"type": "string", "label": "Time (HH:MM)", "placeholder": "09:00"},
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
            "label": "Run Script",
            "description": "Execute a remediation script or command",
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
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "cron",
             "label": "Daily at 8 AM", "config": {"cron_expr": "0 8 * * *"}, "position_x": 60, "position_y": 260},
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
]

TEMPLATE_CATEGORIES = [
    {"id": "triage", "label": "Triage & Routing", "icon": "GitBranch"},
    {"id": "patching", "label": "Patching", "icon": "Shield"},
    {"id": "incident", "label": "Incident Response", "icon": "Zap"},
    {"id": "integration", "label": "Integration", "icon": "Globe"},
    {"id": "sla", "label": "SLA Management", "icon": "Clock"},
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

    # Walk the graph: BFS with data flowing through
    queue = [(trigger_nodes[0].node_id, items)]
    visited = set()

    while queue:
        current_node_id, current_items = queue.pop(0)
        if current_node_id in visited:
            continue
        visited.add(current_node_id)

        node = nodes.get(current_node_id)
        if not node:
            continue

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
                # Filters pass matched items on "output", remainder on "remainder"
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

    return []


def _load_campaign_findings(db: Session, campaign_id: int) -> list:
    """Load findings from a campaign's results."""
    items = []
    cfs = db.query(CampaignFinding).filter(CampaignFinding.campaign_id == campaign_id).all()
    for cf in cfs:
        finding = db.query(Finding).filter(Finding.id == cf.finding_id).first()
        if not finding:
            continue
        asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
        items.append(_finding_to_item(finding, asset, campaign_finding_id=cf.id))
    return items


def _load_scan_findings(db: Session, scan_id: int) -> list:
    """Load findings from a scan."""
    items = []
    findings = db.query(Finding).filter(Finding.scan_id == scan_id, Finding.severity >= 1).limit(5000).all()
    for f in findings:
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        items.append(_finding_to_item(f, asset))
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
                return {"status": "success", "items": items, "output": {"count": len(items)}}
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
        # Find all enabled workflows with schedule trigger nodes
        workflows = db.query(Workflow).filter(
            Workflow.is_enabled == True,
            Workflow.status == "active",
        ).all()

        now = datetime.utcnow()

        for wf in workflows:
            trigger = next(
                (n for n in wf.nodes if n.node_type == "trigger" and n.node_subtype == "schedule"),
                None,
            )
            if not trigger:
                continue

            interval_key = (trigger.config or {}).get("interval", "daily")
            interval_secs = INTERVAL_SECONDS.get(interval_key, 86400)

            # Check if enough time has passed since last run
            if wf.last_run_at:
                next_run = wf.last_run_at + timedelta(seconds=interval_secs)
                if now < next_run:
                    continue

            # Time to run
            logger.info(f"Scheduler: executing workflow '{wf.name}' (id={wf.id}, interval={interval_key})")
            try:
                execute_workflow(db, wf.id, trigger_data={"triggered_by": "scheduler"})
            except Exception as e:
                logger.error(f"Scheduler: workflow {wf.id} failed: {e}")
    finally:
        db.close()
