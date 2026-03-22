"""
Bidirectional ticket sync — polls Jira/ServiceNow for status updates
and maps external ticket statuses back to Hakuna workflow_status.
"""
import logging
from datetime import datetime

import requests
from sqlalchemy import func
from sqlalchemy.orm import Session

from models.models import FindingTicket, Finding
from services.integrations import get_integration_config

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Status mappings
# ─────────────────────────────────────────────

# Jira uses statusCategory.key which is reliable across custom workflows
JIRA_CATEGORY_MAP = {
    "new": "open",
    "undefined": "open",
    "indeterminate": "in_progress",
    "done": "resolved",
}

# Fallback: map common Jira status names directly
JIRA_STATUS_MAP = {
    "to do": "open",
    "open": "open",
    "backlog": "open",
    "in progress": "in_progress",
    "in review": "in_progress",
    "done": "resolved",
    "closed": "resolved",
    "resolved": "resolved",
    "won't do": "accepted_risk",
    "won't fix": "accepted_risk",
    "rejected": "false_positive",
}

# ServiceNow incident state integers
SERVICENOW_STATE_MAP = {
    "1": "open",          # New
    "2": "in_progress",   # In Progress
    "3": "in_progress",   # On Hold
    "6": "resolved",      # Resolved
    "7": "resolved",      # Closed
    "8": "accepted_risk", # Canceled
}


def _map_jira_status(status_name: str, status_category_key: str | None = None) -> str:
    """Map a Jira status to Hakuna workflow_status. Prefer statusCategory for reliability."""
    if status_category_key:
        mapped = JIRA_CATEGORY_MAP.get(status_category_key.lower())
        if mapped:
            return mapped
    return JIRA_STATUS_MAP.get(status_name.lower(), "in_progress")


def _map_servicenow_state(state: str) -> str:
    return SERVICENOW_STATE_MAP.get(str(state), "in_progress")


# ─────────────────────────────────────────────
# Batch fetchers
# ─────────────────────────────────────────────

def _fetch_jira_statuses(ticket_keys: list[str], int_cfg: dict) -> dict:
    """Batch-fetch Jira issue statuses via JQL.

    Returns: {ticket_key: {"status": name, "category_key": key}}
    """
    base_url = int_cfg["base_url"].rstrip("/")
    auth = (int_cfg["email"], int_cfg["api_token"])

    results = {}
    # JQL IN clause has a practical limit; batch in groups of 50
    for i in range(0, len(ticket_keys), 50):
        batch = ticket_keys[i:i + 50]
        jql = f"key in ({','.join(batch)})"
        try:
            r = requests.get(
                f"{base_url}/rest/api/3/search",
                auth=auth,
                params={"jql": jql, "fields": "status", "maxResults": len(batch)},
                timeout=20,
            )
            r.raise_for_status()
            for issue in r.json().get("issues", []):
                key = issue["key"]
                status = issue["fields"]["status"]
                results[key] = {
                    "status": status["name"],
                    "category_key": status.get("statusCategory", {}).get("key"),
                }
        except requests.RequestException as e:
            logger.error("Jira status fetch failed for batch: %s", e)

    return results


def _fetch_servicenow_statuses(sys_ids: list[str], int_cfg: dict) -> dict:
    """Batch-fetch ServiceNow incident states.

    Returns: {sys_id: {"state": str, "number": str}}
    """
    instance_url = int_cfg["instance_url"].rstrip("/")
    auth = (int_cfg["username"], int_cfg["password"])
    headers = {"Accept": "application/json"}

    results = {}
    # ServiceNow sysparm_query IN supports large lists, but batch for safety
    for i in range(0, len(sys_ids), 50):
        batch = sys_ids[i:i + 50]
        query = "sys_idIN" + ",".join(batch)
        try:
            r = requests.get(
                f"{instance_url}/api/now/table/incident",
                auth=auth, headers=headers,
                params={"sysparm_query": query, "sysparm_fields": "sys_id,state,number"},
                timeout=20,
            )
            r.raise_for_status()
            for record in r.json().get("result", []):
                results[record["sys_id"]] = {
                    "state": record.get("state", ""),
                    "number": record.get("number", ""),
                }
        except requests.RequestException as e:
            logger.error("ServiceNow status fetch failed for batch: %s", e)

    return results


# ─────────────────────────────────────────────
# Core sync logic
# ─────────────────────────────────────────────

def sync_all_tickets(db: Session) -> dict:
    """Poll all active tickets and update statuses. Returns summary stats."""
    # Get all tickets that are not already resolved
    active_tickets = db.query(FindingTicket).filter(
        FindingTicket.mapped_status.notin_(["resolved"])
        | FindingTicket.mapped_status.is_(None)
    ).all()

    if not active_tickets:
        return {"synced": 0, "updated": 0, "errors": 0}

    # Group by ticket system and deduplicate by ticket_key/ticket_id
    jira_tickets = {}    # ticket_key -> [FindingTicket, ...]
    snow_tickets = {}    # ticket_id (sys_id) -> [FindingTicket, ...]

    for t in active_tickets:
        if t.ticket_system == "jira" and t.ticket_key:
            jira_tickets.setdefault(t.ticket_key, []).append(t)
        elif t.ticket_system == "servicenow" and t.ticket_id:
            snow_tickets.setdefault(t.ticket_id, []).append(t)

    updated = 0
    errors = 0

    # Sync Jira tickets
    if jira_tickets:
        jira_cfg = get_integration_config(db, "jira")
        if jira_cfg:
            statuses = _fetch_jira_statuses(list(jira_tickets.keys()), jira_cfg)
            for key, ticket_list in jira_tickets.items():
                status_info = statuses.get(key)
                if status_info:
                    mapped = _map_jira_status(status_info["status"], status_info.get("category_key"))
                    for ft in ticket_list:
                        old_mapped = ft.mapped_status
                        ft.external_status = status_info["status"]
                        ft.mapped_status = mapped
                        ft.last_synced_at = datetime.utcnow()
                        ft.sync_error = None
                        if old_mapped != mapped:
                            updated += 1
                            _maybe_update_finding_status(db, ft)
                else:
                    for ft in ticket_list:
                        ft.sync_error = "Ticket not found in Jira"
                        ft.last_synced_at = datetime.utcnow()
                        errors += 1
        else:
            logger.warning("Jira not configured, skipping %d ticket(s)", len(jira_tickets))

    # Sync ServiceNow tickets
    if snow_tickets:
        snow_cfg = get_integration_config(db, "servicenow")
        if snow_cfg:
            statuses = _fetch_servicenow_statuses(list(snow_tickets.keys()), snow_cfg)
            for sys_id, ticket_list in snow_tickets.items():
                status_info = statuses.get(sys_id)
                if status_info:
                    mapped = _map_servicenow_state(status_info["state"])
                    for ft in ticket_list:
                        old_mapped = ft.mapped_status
                        ft.external_status = f"state={status_info['state']}"
                        ft.mapped_status = mapped
                        ft.last_synced_at = datetime.utcnow()
                        ft.sync_error = None
                        if old_mapped != mapped:
                            updated += 1
                            _maybe_update_finding_status(db, ft)
                else:
                    for ft in ticket_list:
                        ft.sync_error = "Incident not found in ServiceNow"
                        ft.last_synced_at = datetime.utcnow()
                        errors += 1
        else:
            logger.warning("ServiceNow not configured, skipping %d ticket(s)", len(snow_tickets))

    db.commit()

    total = len(jira_tickets) + len(snow_tickets)
    logger.info("Ticket sync: %d polled, %d updated, %d errors", total, updated, errors)
    return {"synced": total, "updated": updated, "errors": errors}


def sync_tickets_for_finding(db: Session, finding_id: int) -> dict:
    """Sync tickets linked to a specific finding. Returns updated ticket data."""
    tickets = db.query(FindingTicket).filter(FindingTicket.finding_id == finding_id).all()
    if not tickets:
        return {"tickets": [], "message": "No linked tickets"}

    jira_keys = [t.ticket_key for t in tickets if t.ticket_system == "jira" and t.ticket_key]
    snow_ids = [t.ticket_id for t in tickets if t.ticket_system == "servicenow" and t.ticket_id]

    jira_statuses = {}
    snow_statuses = {}

    if jira_keys:
        jira_cfg = get_integration_config(db, "jira")
        if jira_cfg:
            jira_statuses = _fetch_jira_statuses(jira_keys, jira_cfg)

    if snow_ids:
        snow_cfg = get_integration_config(db, "servicenow")
        if snow_cfg:
            snow_statuses = _fetch_servicenow_statuses(snow_ids, snow_cfg)

    for t in tickets:
        if t.ticket_system == "jira" and t.ticket_key in jira_statuses:
            info = jira_statuses[t.ticket_key]
            t.external_status = info["status"]
            t.mapped_status = _map_jira_status(info["status"], info.get("category_key"))
            t.last_synced_at = datetime.utcnow()
            t.sync_error = None
            _maybe_update_finding_status(db, t)
        elif t.ticket_system == "servicenow" and t.ticket_id in snow_statuses:
            info = snow_statuses[t.ticket_id]
            t.external_status = f"state={info['state']}"
            t.mapped_status = _map_servicenow_state(info["state"])
            t.last_synced_at = datetime.utcnow()
            t.sync_error = None
            _maybe_update_finding_status(db, t)

    db.commit()
    return {"tickets": [_ticket_to_dict(t) for t in tickets]}


def _maybe_update_finding_status(db: Session, ft: FindingTicket):
    """Update the Finding's workflow_status if the ticket status changed to resolved.

    Only auto-updates if the finding hasn't been manually changed more recently.
    """
    if not ft.mapped_status:
        return

    finding = db.query(Finding).filter(Finding.id == ft.finding_id).first()
    if not finding:
        return

    # Don't downgrade resolved findings or override manual changes
    if finding.workflow_status == ft.mapped_status:
        return

    # If the finding was manually changed after the ticket was created, don't override
    if finding.status_changed_at and ft.created_at and finding.status_changed_at > ft.created_at:
        # Only override if the ticket is moving to resolved (definitive external signal)
        if ft.mapped_status != "resolved":
            return

    finding.workflow_status = ft.mapped_status
    finding.status_changed_at = datetime.utcnow()
    logger.info("Finding %d status updated to '%s' from %s ticket %s",
                finding.id, ft.mapped_status, ft.ticket_system, ft.ticket_key)


def _ticket_to_dict(t: FindingTicket) -> dict:
    return {
        "id": t.id,
        "finding_id": t.finding_id,
        "ticket_system": t.ticket_system,
        "ticket_id": t.ticket_id,
        "ticket_key": t.ticket_key,
        "ticket_url": t.ticket_url,
        "external_status": t.external_status,
        "mapped_status": t.mapped_status,
        "last_synced_at": t.last_synced_at.isoformat() if t.last_synced_at else None,
        "sync_error": t.sync_error,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }
