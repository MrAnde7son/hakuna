"""
Workflow execution engine — walks the node graph and executes actions.
Supports OOTB templates, custom workflows, retry logic, and cron scheduling.

Node catalog and templates live in workflow_catalog.py (OCP: add new node
types without modifying execution logic).

Extensibility — register new handlers without modifying this module:
    register_action(subtype, handler)           — (db, config, items) -> (affected, items)
    register_filter(subtype, handler)           — (item, config, db) -> bool
    register_trigger_matcher(event_type, fn)    — (node, event_data) -> bool
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
    Agent, AggregatedSolution, FindingException, Scan,
    ReportTemplate,
)

logger = logging.getLogger(__name__)

# Re-export catalog for backward compatibility (consumers import from here)
from services.workflow_catalog import NODE_CATALOG, TEMPLATE_CATEGORIES, WORKFLOW_TEMPLATES  # noqa: F401


def create_ticket_workflow(
    db: Session,
    campaign_id: int,
    campaign_name: str,
    integration: str = "jira",
    project: str = None,
    issue_type: str = "task",
    group_by: str = "one_per_asset",
    priority: str = None,
    labels: str = None,
) -> Workflow:
    """Create a simple trigger → create_ticket workflow for a campaign."""
    wf = Workflow(
        name=f"Auto-ticket: {campaign_name}",
        description=f"Automatically create {integration.title()} tickets for campaign findings",
        campaign_id=campaign_id,
        status="active",
        is_enabled=True,
    )
    db.add(wf)
    db.flush()

    # Trigger node: on_campaign_run
    db.add(WorkflowNode(
        workflow_id=wf.id,
        node_id="t1",
        node_type="trigger",
        node_subtype="on_campaign_run",
        label="Campaign Run",
        config={},
        position_x=100,
        position_y=200,
    ))

    # Action node: create_ticket
    ticket_config = {
        "integration": integration,
        "issue_type": issue_type,
        "group_by": group_by,
        "title_template": "[{severity_label}] {plugin_name} on {asset_ip}",
        "description_template": (
            "Remediation required.\n\n"
            "Severity: {severity_label}\nPlugin: {plugin_name}\n"
            "Asset: {asset_ip} ({asset_hostname})\n\nSolution: {solution}"
        ),
    }
    if project:
        ticket_config["project"] = project
    if priority:
        ticket_config["priority"] = priority
    if labels:
        ticket_config["labels"] = labels

    db.add(WorkflowNode(
        workflow_id=wf.id,
        node_id="a1",
        node_type="action",
        node_subtype="create_ticket",
        label=f"Create {integration.title()} Ticket",
        config=ticket_config,
        position_x=400,
        position_y=200,
    ))

    # Edge: trigger → action
    db.add(WorkflowEdge(
        workflow_id=wf.id,
        edge_id="e1",
        source_node_id="t1",
        target_node_id="a1",
        source_handle="output",
        target_handle="input",
    ))

    db.flush()
    return wf


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
    return [_finding_to_item(finding, asset, campaign_finding_id=cf.id, db=db)
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
    return [_finding_to_item(f, asset, db=db) for f, asset in rows]


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
    return [_finding_to_item(f, asset, db=db) for f, asset in rows]


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
            items.append(_finding_to_item(finding, asset, db=db))
    return items


def _finding_to_item(finding: Finding, asset: Asset, campaign_finding_id: int = None, db: Session = None) -> dict:
    """Convert a Finding + Asset to a workflow data item."""
    # Use aggregated remediation when available — it provides richer,
    # root-cause-grouped guidance compared to the per-finding solution text.
    remediation = finding.solution or ""
    agg_title = ""
    agg_description = ""
    if finding.aggregated_solution_id and db:
        agg = db.query(AggregatedSolution).filter(
            AggregatedSolution.id == finding.aggregated_solution_id
        ).first()
        if agg:
            agg_title = agg.title or ""
            agg_description = agg.description or ""
            remediation = agg.description or finding.solution or ""

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
        "remediation": remediation,
        "aggregated_solution_title": agg_title,
        "aggregated_solution_description": agg_description,
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


# ─────────────────────────────────────────────
# Filter handlers (OCP: add new filter by adding an entry)
# ─────────────────────────────────────────────

def _filter_severity(item, config, db):
    op = config.get("operator", "gte")
    threshold = int(config.get("value", "3"))
    return _compare(item.get("severity", 0), op, threshold)


def _filter_score(item, config, db):
    field = config.get("field", "cvss3_score")
    op = config.get("operator", "gte")
    threshold = float(config.get("value", 7.0))
    return _compare(item.get(field, 0) or 0, op, threshold)


def _filter_exploit(item, config, db):
    want = config.get("has_exploit", "true") == "true"
    return bool(item.get("exploit_available")) == want


def _filter_tag(item, config, db):
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
    return has_tag if mode == "include" else not has_tag


def _filter_condition(item, config, db):
    conditions = config.get("conditions", [])
    logic = config.get("logic", "AND")
    return _eval_conditions(item, conditions, logic, db)


def _filter_asset(item, config, db):
    field = config.get("field", "os")
    op = config.get("operator", "contains")
    value = config.get("value", "")
    asset_val = item.get(f"asset_{field}", "") or ""
    if field in ("criticality",):
        try:
            return _compare(int(asset_val), op, int(value))
        except (ValueError, TypeError):
            return False
    return _compare_str(str(asset_val), op, str(value))


_FILTER_HANDLERS = {
    "severity_filter": _filter_severity,
    "score_filter": _filter_score,
    "exploit_filter": _filter_exploit,
    "tag_filter": _filter_tag,
    "condition_filter": _filter_condition,
    "asset_filter": _filter_asset,
}


def _execute_filter(db: Session, node: WorkflowNode, items: list) -> dict:
    """Evaluate a filter and split items into matched / remainder."""
    config = node.config or {}
    handler = _FILTER_HANDLERS.get(node.node_subtype)
    matched = []
    remainder = []

    for item in items:
        passes = handler(item, config, db) if handler else False
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


# ─────────────────────────────────────────────
# Action handlers (OCP: add new action by adding an entry)
# ─────────────────────────────────────────────

def _action_assign_owner(db, config, items):
    import services.integrations  # noqa: avoid circular at module level
    owner_name = config.get("owner_name", "")
    owner_email = config.get("owner_email", "")
    owner_role = config.get("owner_role", "IT")
    team = config.get("team", "")
    affected = 0
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
    return affected, items


def _action_add_tag(db, config, items):
    cat = config.get("tag_category", "")
    val = config.get("tag_value", "")
    target = config.get("target", "finding")
    tag = db.query(Tag).filter(Tag.category == cat, Tag.value == val).first()
    if not tag:
        tag = Tag(category=cat, value=val, color="#6366f1")
        db.add(tag)
        db.flush()
    affected = 0
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
    return affected, items


def _action_change_status(db, config, items):
    new_status = config.get("status", "in_progress")
    affected = 0
    for item in items:
        cf_id = item.get("campaign_finding_id")
        if cf_id:
            cf = db.query(CampaignFinding).filter(CampaignFinding.id == cf_id).first()
            if cf:
                cf.status = new_status
                affected += 1
    return affected, items


def _action_set_criticality(db, config, items):
    crit = int(config.get("criticality", 5))
    seen = set()
    affected = 0
    for item in items:
        aid = item.get("asset_id")
        if aid and aid not in seen:
            seen.add(aid)
            asset = db.query(Asset).filter(Asset.id == aid).first()
            if asset:
                asset.criticality = crit
                affected += 1
    return affected, items


def _action_send_email(db, config, items):
    import services.integrations as integrations
    # Collect any report attachments passed down from an upstream generate_report node.
    carriers = [i for i in items if isinstance(i, dict) and i.get("_report_attachment")]
    real_items = [i for i in items if not (isinstance(i, dict) and i.get("_report_attachment"))]
    if carriers:
        merged = dict(config)
        existing = list(merged.get("attachments") or [])
        existing.extend(c["_report_attachment"] for c in carriers)
        merged["attachments"] = existing
        result = integrations.send_email(db, merged, real_items)
    else:
        result = integrations.send_email(db, config, items)
    logger.info(f"[Workflow Email] Sent to {result.get('recipients', [])}, {len(items)} items")
    return len(items), items


def _action_send_webhook(db, config, items):
    import services.integrations as integrations
    result = integrations.send_webhook(config, items)
    logger.info(f"[Workflow Webhook] {config.get('method', 'POST')} {config.get('url')} → {result.get('status_code')}")
    return len(items), items


def _action_create_ticket(db, config, items):
    import services.integrations as integrations
    integration = config.get("integration", "jira")
    if integration == "servicenow":
        result = integrations.create_servicenow_ticket(db, config, items)
    else:
        result = integrations.create_jira_ticket(db, config, items)
    logger.info(f"[Workflow Ticket] {integration}: created {result.get('tickets_created', 0)} ticket(s)")
    return result.get("tickets_created", 0), items


def _action_slack_notify(db, config, items):
    import services.integrations as integrations
    integrations.send_slack_notification(db, config, items)
    logger.info(f"[Workflow Slack] Sent, {len(items)} items")
    return len(items), items


def _action_teams_notify(db, config, items):
    import services.integrations as integrations
    integrations.send_teams_notification(db, config, items)
    logger.info(f"[Workflow Teams] Sent, {len(items)} items")
    return len(items), items


def _action_run_agent(db, config, items):
    import agents.agent_engine as agent_engine
    agent_id = config.get("agent_id")
    input_template = config.get("input_template", "")
    pass_items_downstream = config.get("pass_items_downstream", True)

    ag = db.query(Agent).filter(Agent.id == agent_id).first() if agent_id else None
    if not ag:
        logger.warning(f"[Workflow Agent] Agent {agent_id!r} not found — skipping")
        return 0, items

    unique_assets = list({i.get("asset_ip") or i.get("asset_hostname", "unknown") for i in items})
    finding_lines = []
    for item in items[:50]:
        severity = item.get("severity_label") or item.get("severity", "")
        name = item.get("plugin_name") or item.get("finding_name", "")
        host = item.get("asset_ip") or item.get("asset_hostname", "")
        finding_lines.append(f"- [{severity}] {name} on {host}")

    findings_summary = "\n".join(finding_lines)
    if len(items) > 50:
        findings_summary += f"\n... and {len(items) - 50} more findings"

    rendered_input = _render_template(input_template, items) if input_template else (
        f"Workflow context: {len(items)} findings across {len(unique_assets)} assets.\n\n"
        f"Findings:\n{findings_summary}"
    )

    run = agent_engine.run_agent(ag, rendered_input, db)
    logger.info(f"[Workflow Agent] {ag.name} run={run.id} status={run.status} steps={run.steps_used}")

    if not pass_items_downstream and run.output:
        items = [{"agent_run_id": run.id, "agent_output": run.output, "agent_name": ag.name}]

    return 1, items


def _action_create_exception(db, config, items):
    """Create persistent risk exceptions for matched findings and link them.

    Groups items by plugin_id (+ asset_ip when scope=per_finding), creates one
    FindingException row per group, then links each matched Finding via
    exception_id and sets workflow_status to the exception type."""
    exception_type = config.get("exception_type", "accepted_risk")
    scope = config.get("scope", "per_finding")
    reason = config.get("reason", "")
    approved_by = config.get("approved_by", "workflow")
    try:
        expires_in_days = int(config.get("expires_in_days", 90) or 0)
    except (TypeError, ValueError):
        expires_in_days = 90
    try:
        review_in_days = int(config.get("review_in_days", 0) or 0)
    except (TypeError, ValueError):
        review_in_days = 0
    compensating_control_detail = config.get("compensating_control_detail") or None
    debt_category = config.get("debt_category") or None
    mitigation_plan = config.get("mitigation_plan") or None
    exclude_from_reports = bool(config.get("exclude_from_reports", True))

    now = datetime.utcnow()
    expires_at = now + timedelta(days=expires_in_days) if expires_in_days > 0 else None
    review_by = now + timedelta(days=review_in_days) if review_in_days > 0 else None

    # Group finding_ids by (plugin_id, asset_ip) or (plugin_id,) depending on scope.
    groups: dict = {}
    for item in items:
        finding_id = item.get("finding_id")
        plugin_id = item.get("plugin_id")
        if not finding_id or not plugin_id:
            continue
        if scope == "per_plugin":
            key = (plugin_id, None)
        else:
            key = (plugin_id, item.get("asset_ip"))
        groups.setdefault(key, {
            "plugin_name": item.get("plugin_name"),
            "finding_ids": [],
        })["finding_ids"].append(finding_id)

    affected = 0
    exceptions_created = 0
    for (plugin_id, asset_ip), group in groups.items():
        finding_ids = group["finding_ids"]
        # Resolve org_id via the Finding's parent Scan (tenant scoping).
        sample = db.query(Finding).filter(Finding.id == finding_ids[0]).first()
        if not sample:
            continue
        parent_scan = db.query(Scan).filter(Scan.id == sample.scan_id).first()
        sample_org_id = parent_scan.org_id if parent_scan else None

        exc = FindingException(
            org_id=sample_org_id,
            plugin_id=plugin_id,
            plugin_name=group["plugin_name"],
            asset_ip=asset_ip,
            exception_type=exception_type,
            reason=reason,
            approved_by=approved_by,
            compensating_control_detail=compensating_control_detail if exception_type == "compensating_control" else None,
            debt_category=debt_category if exception_type == "technical_debt" else None,
            mitigation_plan=mitigation_plan if exception_type == "technical_debt" else None,
            exclude_from_reports=exclude_from_reports,
            expires_at=expires_at,
            review_by=review_by,
            is_active=True,
        )
        db.add(exc)
        db.flush()
        exceptions_created += 1

        # Link each matched finding to the new exception.
        findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
        for f in findings:
            f.exception_id = exc.id
            f.workflow_status = exception_type
            f.status_changed_at = now
            affected += 1

    logger.info(
        f"[Workflow Exception] created={exceptions_created} linked_findings={affected} "
        f"type={exception_type} scope={scope}"
    )
    return affected, items


def _action_run_script(db, config, items):
    script_type = config.get("script_type", "bash")
    script = config.get("script", "")
    logger.info(f"[Workflow Script] {script_type}: {script} | {len(items)} targets (dry-run)")
    return len(items), items


def _action_generate_report(db, config, items):
    """Render a saved ReportTemplate to PDF and pass it downstream.

    config keys:
      report_template_id   — ID of the ReportTemplate to render (required, unless report_name given)
      report_name          — Alternative lookup by template name
      attach_to_email      — when True (default), place the PDF into
                             downstream items under `_pdf_attachment` so a
                             following `send_email` node picks it up as an
                             attachment via config.attachments.

    The rendered PDF bytes are stored on a synthetic item so the next
    `send_email` node (which iterates over items) can attach them.
    """
    from services.report_renderer import render_report_pdf

    template = None
    tpl_id = config.get("report_template_id")
    if tpl_id:
        template = db.query(ReportTemplate).filter(ReportTemplate.id == int(tpl_id)).first()
    if not template and config.get("report_name"):
        template = db.query(ReportTemplate).filter(
            ReportTemplate.name == config["report_name"]
        ).first()
    if not template:
        logger.warning("[Workflow Report] template not found (id=%s name=%s)",
                       tpl_id, config.get("report_name"))
        return 0, items

    try:
        pdf_bytes = render_report_pdf(db, template)
    except Exception as e:
        logger.exception("[Workflow Report] render failed for template %s", template.id)
        return 0, items

    filename = f"{(template.name or 'report').replace('/', '-')}-{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    attachment = {
        "filename": filename,
        "content": pdf_bytes,
        "mime_type": "application/pdf",
    }
    # Emit a synthetic item carrying the attachment so the next send_email node
    # can pick it up via _attachments_from_items() without changing its signature.
    carrier = {
        "_report_attachment": attachment,
        "_report_template_id": template.id,
        "_report_name": template.name,
    }
    logger.info("[Workflow Report] rendered '%s' (%d bytes)", template.name, len(pdf_bytes))

    if config.get("attach_to_email", True):
        # Prepend the carrier so downstream can find it easily.
        items = [carrier] + list(items)
    else:
        items = [carrier]
    return 1, items


_ACTION_HANDLERS = {
    "assign_owner": _action_assign_owner,
    "add_tag": _action_add_tag,
    "change_status": _action_change_status,
    "set_criticality": _action_set_criticality,
    "send_email": _action_send_email,
    "send_webhook": _action_send_webhook,
    "create_ticket": _action_create_ticket,
    "slack_notify": _action_slack_notify,
    "teams_notify": _action_teams_notify,
    "run_agent": _action_run_agent,
    "run_script": _action_run_script,
    "create_exception": _action_create_exception,
    "generate_report": _action_generate_report,
}


def _execute_action(db: Session, node: WorkflowNode, items: list) -> dict:
    """Execute an action node on the given items."""
    config = node.config or {}
    handler = _ACTION_HANDLERS.get(node.node_subtype)
    if handler:
        affected, items = handler(db, config, items)
    else:
        logger.warning(f"Unknown action subtype: {node.node_subtype}")
        affected = 0

    db.flush()
    return {
        "status": "success",
        "items": items,
        "output": {"affected": affected, "action": node.node_subtype},
    }


# ─────────────────────────────────────────────
# Public registration API  (OCP: extend without modifying this module)
# ─────────────────────────────────────────────

def register_action(subtype: str, handler: callable) -> None:
    """Register a workflow action handler.

    handler signature: (db: Session, config: dict, items: list) -> (affected: int, items: list)
    """
    _ACTION_HANDLERS[subtype] = handler


def register_filter(subtype: str, handler: callable) -> None:
    """Register a workflow filter handler.

    handler signature: (item: dict, config: dict, db: Session) -> bool
    """
    _FILTER_HANDLERS[subtype] = handler


def register_trigger_matcher(event_type: str, matcher: callable) -> None:
    """Register a trigger matcher for an event type.

    matcher signature: (node: WorkflowNode, event_data: dict) -> bool
    """
    _TRIGGER_MATCHERS[event_type] = matcher


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


def _match_on_upload(node: WorkflowNode, event_data: dict) -> bool:
    return True  # on_upload triggers always match


def _match_on_integration_execution(node: WorkflowNode, event_data: dict) -> bool:
    config = node.config or {}
    if config.get("integration_id") and config["integration_id"] != event_data.get("integration_id"):
        return False
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


def _match_on_new_threat_intel(node: WorkflowNode, event_data: dict) -> bool:
    config = node.config or {}
    intel_type = config.get("intel_type", "any")
    event_intel_type = event_data.get("intel_type", "any")
    if intel_type != "any" and intel_type != event_intel_type:
        return False

    severity_threshold = config.get("severity_threshold", "")
    if severity_threshold and event_intel_type == "cve":
        max_cvss = event_data.get("max_cvss", 0)
        if max_cvss < float(severity_threshold):
            return False

    if config.get("only_affecting_environment", False):
        return event_data.get("affects_environment", False)

    return True


def _match_on_new_asset(node: WorkflowNode, event_data: dict) -> bool:
    config = node.config or {}
    asset_filter = config.get("asset_filter", "any")
    if asset_filter == "any":
        return True
    if asset_filter == "internet_facing":
        return any(a.get("is_internet_facing") for a in event_data.get("assets", []))
    if asset_filter == "high_criticality":
        return any((a.get("criticality") or 5) <= 3 for a in event_data.get("assets", []))
    return True


def _match_on_new_finding(node: WorkflowNode, event_data: dict) -> bool:
    config = node.config or {}
    min_severity = int(config.get("min_severity", "0"))
    only_exploitable = config.get("only_exploitable", False)
    findings = event_data.get("findings", [])
    if min_severity:
        findings = [f for f in findings if (f.get("severity") or 0) >= min_severity]
    if only_exploitable:
        findings = [f for f in findings if f.get("exploit_available")]
    return len(findings) > 0


def _match_on_tech_changed(node: WorkflowNode, event_data: dict) -> bool:
    """Fires when an asset's tech stack changes (e.g., version bump).

    Config fields:
      - tech_filter: list[str] — only fire if one of these tech names appears
        in new_tech. Empty list = match any tech change.
    """
    config = node.config or {}
    watched = {t.lower() for t in (config.get("tech_filter") or [])}
    if not watched:
        return True
    new_tech = event_data.get("new_tech") or {}
    # new_tech can be dict {name: version} or list[str]
    if isinstance(new_tech, dict):
        changed_names = {k.lower() for k in new_tech.keys()}
    else:
        changed_names = {str(t).lower() for t in new_tech}
    return bool(watched & changed_names)


def _match_on_port_changed(node: WorkflowNode, event_data: dict) -> bool:
    """Fires when an asset's open port set changes.

    Config fields:
      - port_filter: list[int] — only fire if one of these ports appears in
        new_ports. Empty list = match any port change.
      - direction: 'added' | 'removed' | 'any' (default 'any')
    """
    config = node.config or {}
    watched = {int(p) for p in (config.get("port_filter") or []) if str(p).isdigit()}
    direction = config.get("direction", "any")

    new_ports = [int(p) for p in (event_data.get("new_ports") or []) if str(p).isdigit()]
    removed_ports = [int(p) for p in (event_data.get("removed_ports") or []) if str(p).isdigit()]

    if direction == "added":
        candidates = new_ports
    elif direction == "removed":
        candidates = removed_ports
    else:
        candidates = new_ports + removed_ports

    if not candidates:
        return False
    if not watched:
        return True
    return bool(watched & set(candidates))


def _match_on_ip_changed(node: WorkflowNode, event_data: dict) -> bool:
    """Fires when an asset's IP changes. No config filter — always matches
    if the event has old_ip and new_ip."""
    return bool(event_data.get("old_ip") and event_data.get("new_ip"))


def _match_on_cert_expiring(node: WorkflowNode, event_data: dict) -> bool:
    """Fires when a TLS cert is approaching expiry.

    Config fields:
      - max_days_remaining: int — only fire if days_remaining <= this value.
        Default: no filter (match all cert_expiring events).
    """
    config = node.config or {}
    threshold = config.get("max_days_remaining")
    if threshold is None:
        return True
    try:
        days = int(event_data.get("days_remaining", 999))
    except (TypeError, ValueError):
        return True
    return days <= int(threshold)


def _match_on_asset_gone(node: WorkflowNode, event_data: dict) -> bool:
    """Fires when an asset has not been seen in recent scans. No config."""
    return True


_TRIGGER_MATCHERS: dict[str, callable] = {
    "on_upload": _match_on_upload,
    "on_integration_execution": _match_on_integration_execution,
    "on_new_threat_intel": _match_on_new_threat_intel,
    "on_new_asset": _match_on_new_asset,
    "on_new_finding": _match_on_new_finding,
    # ── Scanner-driven (via services.scanner_event_bridge) ──
    "on_tech_changed": _match_on_tech_changed,
    "on_port_changed": _match_on_port_changed,
    "on_ip_changed": _match_on_ip_changed,
    "on_cert_expiring": _match_on_cert_expiring,
    "on_asset_gone": _match_on_asset_gone,
}


def _trigger_matches_event(node: WorkflowNode, event_type: str, event_data: dict) -> bool:
    """Check if a trigger node's config matches the incoming event data."""
    matcher = _TRIGGER_MATCHERS.get(event_type)
    if matcher:
        return matcher(node, event_data)
    return True  # unknown event types pass through
