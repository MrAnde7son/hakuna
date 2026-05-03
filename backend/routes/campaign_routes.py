"""
Campaign endpoints — CRUD, query preview, execution, ticket tracking, Slack integration.
"""
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy import desc

from core.database import get_db
from core.auth import (
    get_current_user, get_accessible_org_ids, apply_org_filter,
)
from core.subscription import check_campaign_limit
from core.audit import log_audit, diff as _diff
from core.time_utils import iso_utc
from models.models import (
    User, Scan, Asset, Finding, FindingTicket,
    Campaign, CampaignFinding, AssetOwnership,
)
import services.campaign_query as cq
import services.tags as tag_engine
import services.rule_engine as rule_engine
import services.workflow_engine as workflow_engine
import services.integrations as integ_module
import services.ownership_inference as ownership_inference
from services.nlp_to_rules import nlp_to_conditions

router = APIRouter()


# ─── Pydantic schemas ───


class AutoTicketConfig(BaseModel):
    integration: str = "jira"         # jira | servicenow
    project: Optional[str] = None     # Jira project key or ServiceNow assignment group
    issue_type: str = "task"          # bug | task | story | incident
    group_by: str = "one_per_asset"   # one_per_finding | one_per_asset | one_for_all
    priority: Optional[str] = None    # highest | high | medium | low | lowest
    labels: Optional[str] = None      # comma-separated


class CampaignCreateBody(BaseModel):
    name: str
    description: Optional[str] = None
    scan_id: Optional[int] = None
    query: list = []
    query_logic: str = "AND"
    owner_id: Optional[int] = None
    auto_ticket: Optional[AutoTicketConfig] = None


class CampaignUpdateBody(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    query: Optional[list] = None
    query_logic: Optional[str] = None
    owner_id: Optional[int] = None


class CampaignFindingUpdateBody(BaseModel):
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_role: Optional[str] = None
    team: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None
    exception_type: Optional[str] = None  # accepted_risk / false_positive / compensating_control


class AdvancedSearchBody(BaseModel):
    query: list = []
    query_logic: str = "AND"
    scan_id: Optional[int] = None
    type: str = "finding"   # "finding" | "asset"
    page: int = 1
    page_size: int = 50


# ─── Helpers ───


def _serialize_finding(f: Finding, asset: Asset = None) -> dict:
    """Minimal finding dict for campaign results."""
    return {
        "id": f.id,
        "plugin_id": f.plugin_id,
        "plugin_name": f.plugin_name,
        "plugin_family": f.plugin_family,
        "severity": f.severity,
        "severity_label": f.severity_label,
        "cvss2_score": f.cvss2_score,
        "cvss3_score": f.cvss3_score,
        "vpr_score": f.vpr_score,
        "priority_score": f.priority_score,
        "owner_suggestion": f.owner_suggestion,
        "synopsis": f.synopsis,
        "remediation_steps": f.remediation_steps,
        "cves": f.cves or [],
        "exploit_available": f.exploit_available,
        "exploit_maturity": f.exploit_maturity,
        "zero_day": f.zero_day,
        "is_kev": f.is_kev or False,
        "epss_score": f.epss_score,
        "ransomware_linked": f.ransomware_linked or False,
        "trending_in_news": f.trending_in_news or False,
        "port": f.port,
        "asset_ip": asset.ip if asset else None,
        "asset_hostname": (asset.hostname or asset.fqdn or asset.ip) if asset else None,
    }


def _group_findings_by_owner(campaign_findings: list) -> list:
    """
    Group campaign findings by effective owner.
    Resolution: campaign override > finding ownership > asset ownership > inferred > plugin family.
    Returns list of {owner_key, owner_name, owner_role, team, findings[]}.
    """
    groups = {}
    for cf in campaign_findings:
        f = cf.finding
        if f is None:
            continue  # skip orphaned campaign findings whose finding was deleted
        asset = f.asset if f else None

        # Campaign-level override always wins
        if cf.owner_role:
            owner_key = cf.owner_role
            owner_name = cf.owner_name or cf.owner_role
            owner_role = cf.owner_role
            team = cf.team
        elif f:
            # Use the full resolution chain from ownership_inference
            resolved = ownership_inference.resolve_finding_owner(f, asset, None)
            owner_role = resolved["owner_role"] or "Unassigned"
            owner_name = resolved["owner_name"] or owner_role
            owner_key = owner_role
            team = resolved["owner_team"]
        else:
            owner_key = "Unassigned"
            owner_name = "Unassigned"
            owner_role = "Unassigned"
            team = None

        if owner_key not in groups:
            groups[owner_key] = {
                "owner_key": owner_key,
                "owner_name": owner_name,
                "owner_role": owner_role,
                "team": team,
                "findings": [],
                "critical_count": 0,
                "high_count": 0,
                "exploit_count": 0,
            }

        fd = _serialize_finding(f, asset)
        fd["campaign_status"] = cf.status
        fd["campaign_finding_id"] = cf.id
        fd["campaign_owner"] = {
            "owner_name": cf.owner_name,
            "owner_email": cf.owner_email,
            "owner_role": cf.owner_role,
            "team": cf.team,
            "notes": cf.notes,
        }
        groups[owner_key]["findings"].append(fd)
        if f:
            if f.severity >= 4:
                groups[owner_key]["critical_count"] += 1
            elif f.severity >= 3:
                groups[owner_key]["high_count"] += 1
            if f.exploit_available:
                groups[owner_key]["exploit_count"] += 1

    # Sort findings within each group by priority_score desc
    for g in groups.values():
        g["findings"].sort(key=lambda x: x.get("priority_score") or 0, reverse=True)

    # Sort groups: critical first
    return sorted(groups.values(), key=lambda g: (g["critical_count"] + g["high_count"]), reverse=True)


# ─── Route handlers ───


@router.get("/api/rule-engine/catalog")
def get_rule_engine_catalog(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return the unified condition catalog used by all rule systems."""
    return rule_engine.get_condition_catalog(db, org_ids)


@router.get("/api/campaigns/condition-catalog")
def get_condition_catalog(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return condition catalog for campaign queries (proxies to unified catalog)."""
    return rule_engine.get_condition_catalog(db, org_ids)


class NLPToConditionsBody(BaseModel):
    q: str
    scan_id: Optional[int] = None


@router.post("/api/campaigns/nlp-to-conditions")
def nlp_to_campaign_conditions(
    body: NLPToConditionsBody,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Translate a natural-language query into rule-engine conditions + run a
    live preview so the UI can show finding/asset counts before the user commits.
    """
    translated = nlp_to_conditions(body.q)
    conditions = translated["conditions"]
    asset_count = finding_count = 0
    if conditions:
        try:
            results = cq.run_query(
                db, conditions, translated["query_logic"], body.scan_id, org_ids=org_ids,
            )
            asset_count = len(results)
            finding_count = sum(len(r["findings"]) for r in results)
        except Exception:
            # Translator may emit a condition the rule engine can't evaluate
            # against the current schema (e.g. unknown enum). Fail soft so the
            # user still gets the conditions to edit.
            pass
    return {
        "conditions": conditions,
        "query_logic": translated["query_logic"],
        "chips": translated["chips"],
        "asset_count": asset_count,
        "finding_count": finding_count,
        "original_query": translated["original_query"],
    }


@router.post("/api/campaigns/preview")
def preview_campaign_query(
    body: CampaignCreateBody,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Run a query and return matching assets + finding counts without saving."""
    results = cq.run_query(db, body.query, body.query_logic, body.scan_id, org_ids=org_ids)
    return {
        "asset_count": len(results),
        "finding_count": sum(len(r["findings"]) for r in results),
        "assets": [
            {
                "asset_id": r["asset"].id,
                "ip": r["asset"].ip,
                "hostname": r["asset"].hostname or r["asset"].fqdn,
                "criticality": r["asset"].criticality,
                "environment_tag": r["asset"].environment_tag,
                "risk_score": r["asset"].risk_score,
                "finding_count": len(r["findings"]),
                "critical_count": sum(1 for f in r["findings"] if f.severity >= 4),
                "matched_conditions": r["matched_conditions"],
            }
            for r in results
        ]
    }


@router.post("/api/search/advanced")
def advanced_search(
    body: AdvancedSearchBody,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Run a rule-engine query and return findings or assets in table format."""
    from routes.asset_routes import _asset_to_dict
    from routes.finding_routes import _finding_to_dict
    from services.blast_radius import resolve_dc_asset_ids as _resolve_dc_asset_ids
    results = cq.run_query(db, body.query, body.query_logic, body.scan_id, org_ids=org_ids)

    if body.type == "asset":
        asset_ids = [r["asset"].id for r in results]
        tag_map = tag_engine.get_asset_tags(asset_ids, db)
        dc_asset_ids = _resolve_dc_asset_ids(db, restrict_to_asset_ids=asset_ids) if asset_ids else set()
        assets_out = []
        for r in results:
            a = r["asset"]
            d = _asset_to_dict(a)
            d["tags"] = tag_map.get(a.id, [])
            d["is_domain_controller"] = a.id in dc_asset_ids
            assets_out.append(d)
        total = len(assets_out)
        start = (body.page - 1) * body.page_size
        return {"total": total, "page": body.page, "page_size": body.page_size, "assets": assets_out[start:start + body.page_size]}

    # findings mode — flatten all findings from all matched assets
    all_findings = []
    for r in results:
        all_findings.extend(r["findings"])
    # deduplicate (same finding can only appear once since each asset is unique)
    all_findings.sort(key=lambda f: f.priority_score or 0, reverse=True)
    total = len(all_findings)
    start = (body.page - 1) * body.page_size
    page_findings = all_findings[start:start + body.page_size]

    finding_ids = [f.id for f in page_findings]
    tag_map = tag_engine.get_finding_tags(finding_ids, db)
    findings_out = []
    for f in page_findings:
        d = _finding_to_dict(f, db)
        d["tags"] = tag_map.get(f.id, [])
        findings_out.append(d)
    return {"total": total, "page": body.page, "page_size": body.page_size, "findings": findings_out}


@router.post("/api/campaigns", dependencies=[Depends(check_campaign_limit)])
def create_campaign(body: CampaignCreateBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Create a new remediation campaign."""
    campaign = Campaign(
        org_id=user.org_id if user else None,
        name=body.name,
        description=body.description,
        scan_id=body.scan_id,
        query=body.query,
        query_logic=body.query_logic,
        owner_id=body.owner_id,
        status="draft",
    )
    db.add(campaign)
    db.flush()
    log_audit(db, "create", "campaign", campaign.id,
              entity_name=campaign.name,
              changes={"name": campaign.name, "description": campaign.description, "status": campaign.status},
              actor=user)

    # Auto-create ticket workflow if requested
    workflow_id = None
    if body.auto_ticket:
        tc = body.auto_ticket
        wf = workflow_engine.create_ticket_workflow(
            db,
            campaign_id=campaign.id,
            campaign_name=campaign.name,
            integration=tc.integration,
            project=tc.project,
            issue_type=tc.issue_type,
            group_by=tc.group_by,
            priority=tc.priority,
            labels=tc.labels,
        )
        workflow_id = wf.id

    db.commit()
    db.refresh(campaign)
    return {"id": campaign.id, "name": campaign.name, "status": campaign.status, "workflow_id": workflow_id}


@router.get("/api/campaigns")
def list_campaigns(scan_id: Optional[int] = None, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """List all campaigns, optionally filtered by scan."""
    q = apply_org_filter(db.query(Campaign), Campaign, org_ids)
    if scan_id:
        q = q.filter((Campaign.scan_id == scan_id) | (Campaign.scan_id == None))
    campaigns = q.order_by(Campaign.created_at.desc()).all()
    # Batch-load owners
    owner_ids = {c.owner_id for c in campaigns if c.owner_id}
    owners = {u.id: u for u in db.query(User).filter(User.id.in_(owner_ids)).all()} if owner_ids else {}
    return [
        {
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "status": c.status,
            "scan_id": c.scan_id,
            "query": c.query,
            "query_logic": c.query_logic,
            "finding_count": c.finding_count,
            "created_at": iso_utc(c.created_at),
            "last_run_at": iso_utc(c.last_run_at),
            "owner_id": c.owner_id,
            "owner_name": owners[c.owner_id].display_name or owners[c.owner_id].email if c.owner_id and c.owner_id in owners else None,
        }
        for c in campaigns
    ]


@router.get("/api/campaigns/{campaign_id}")
def get_campaign(campaign_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Get a campaign with its findings grouped by owner."""
    query = db.query(Campaign).options(
        selectinload(Campaign.findings)
        .joinedload(CampaignFinding.finding)
        .options(
            joinedload(Finding.asset).selectinload(Asset.ownership),
            selectinload(Finding.ownership),
        )
    ).filter(Campaign.id == campaign_id)
    query = apply_org_filter(query, Campaign, org_ids)
    campaign = query.first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    owner_groups = _group_findings_by_owner(campaign.findings)
    total_findings = sum(len(g["findings"]) for g in owner_groups)
    total_critical = sum(g["critical_count"] for g in owner_groups)
    total_exploit = sum(g["exploit_count"] for g in owner_groups)

    # Status breakdown across all campaign findings
    status_counts = {"open": 0, "in_progress": 0, "resolved": 0, "wont_fix": 0}
    for cf in campaign.findings:
        s = cf.status or "open"
        if s in status_counts:
            status_counts[s] += 1
        else:
            status_counts["open"] += 1

    owner = db.query(User).filter(User.id == campaign.owner_id).first() if campaign.owner_id else None
    return {
        "id": campaign.id,
        "name": campaign.name,
        "description": campaign.description,
        "status": campaign.status,
        "scan_id": campaign.scan_id,
        "query": campaign.query,
        "query_logic": campaign.query_logic,
        "created_at": iso_utc(campaign.created_at),
        "last_run_at": iso_utc(campaign.last_run_at),
        "finding_count": total_findings,
        "critical_count": total_critical,
        "exploit_count": total_exploit,
        "status_counts": status_counts,
        "owner_id": campaign.owner_id,
        "owner_name": (owner.display_name or owner.email) if owner else None,
        "owner_groups": owner_groups,
        "slack_channel_id": campaign.slack_channel_id,
        "slack_channel_name": campaign.slack_channel_name,
    }


@router.patch("/api/campaigns/{campaign_id}")
def update_campaign(campaign_id: int, body: CampaignUpdateBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Update campaign metadata or query."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    _old_c = {"name": campaign.name, "status": campaign.status, "description": campaign.description}
    if body.name is not None:
        campaign.name = body.name
    if body.description is not None:
        campaign.description = body.description
    if body.status is not None:
        campaign.status = body.status
    if body.query is not None:
        campaign.query = body.query
    if body.query_logic is not None:
        campaign.query_logic = body.query_logic
    if body.owner_id is not None:
        campaign.owner_id = body.owner_id
    _new_c = {"name": campaign.name, "status": campaign.status, "description": campaign.description}
    log_audit(db, "update", "campaign", campaign.id,
              entity_name=campaign.name, changes=_diff(_old_c, _new_c), actor=user)
    db.commit()
    return {"ok": True, "id": campaign.id}


@router.delete("/api/campaigns/{campaign_id}")
def delete_campaign(campaign_id: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Delete a campaign and its finding associations."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    _c_name, _c_org = campaign.name, campaign.org_id
    db.delete(campaign)
    log_audit(db, "delete", "campaign", campaign_id, entity_name=_c_name, actor=user, org_id=_c_org)
    db.commit()
    return {"ok": True}


@router.post("/api/campaigns/{campaign_id}/run", status_code=202)
def run_campaign(campaign_id: int, db: Session = Depends(get_db)):
    """Dispatch campaign execution as a background job. Returns job_id immediately."""
    from services.job_manager import dispatch
    from core.database import SessionLocal

    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    def _run_campaign():
        db2 = SessionLocal()
        try:
            camp = db2.query(Campaign).filter(Campaign.id == campaign_id).first()
            if not camp:
                return {"error": "Campaign not found"}

            db2.query(CampaignFinding).filter(CampaignFinding.campaign_id == campaign_id).delete()

            scan_id = camp.scan_id
            if scan_id and not db2.query(Scan).filter(Scan.id == scan_id).first():
                camp.scan_id = None
                scan_id = None

            # Scope to the campaign's own org so cross-tenant assets/findings can't leak in.
            camp_org_ids = [camp.org_id] if camp.org_id is not None else None
            results = cq.run_query(db2, camp.query or [], camp.query_logic or "AND", scan_id, org_ids=camp_org_ids)

            added = 0
            for r in results:
                for finding in r["findings"]:
                    cf = CampaignFinding(campaign_id=campaign_id, finding_id=finding.id)
                    db2.add(cf)
                    added += 1

            camp.finding_count = added
            camp.last_run_at = datetime.utcnow()
            if camp.status == "draft":
                camp.status = "active"

            if added > 0:
                from services.notifications import create_notification
                create_notification(db2, camp.org_id, "campaign_findings",
                    f"{added} findings matched in campaign '{camp.name}'",
                    link=f"/campaigns/{campaign_id}",
                    entity_type="campaign", entity_id=campaign_id,
                    metadata={"count": added, "campaign_name": camp.name})

            db2.commit()
            return {"ok": True, "finding_count": added, "asset_count": len(results)}
        finally:
            db2.close()

    job = dispatch(f"campaign_run_{campaign_id}", _run_campaign)
    return {"job_id": job.id, "status": job.status.value, "poll_url": f"/api/jobs/{job.id}/status"}


@router.patch("/api/campaigns/{campaign_id}/findings/{cf_id}")
def update_campaign_finding(
    campaign_id: int, cf_id: int, body: CampaignFindingUpdateBody, db: Session = Depends(get_db)
):
    """Update ownership or status for a finding within a campaign."""
    cf = db.query(CampaignFinding).filter(
        CampaignFinding.id == cf_id,
        CampaignFinding.campaign_id == campaign_id
    ).first()
    if not cf:
        raise HTTPException(404, "Campaign finding not found")
    if body.owner_name is not None:
        cf.owner_name = body.owner_name
    if body.owner_email is not None:
        cf.owner_email = body.owner_email
    if body.owner_role is not None:
        cf.owner_role = body.owner_role
    if body.team is not None:
        cf.team = body.team
    if body.notes is not None:
        cf.notes = body.notes
    if body.status is not None:
        cf.status = body.status
        # Sync campaign status to the underlying finding's workflow_status
        _STATUS_TO_WORKFLOW = {
            "resolved": "resolved",
            "in_progress": "in_progress",
            "open": "open",
            "wont_fix": "accepted_risk",
        }
        if cf.finding and body.status in _STATUS_TO_WORKFLOW:
            cf.finding.workflow_status = _STATUS_TO_WORKFLOW[body.status]
            cf.finding.status_changed_at = datetime.utcnow()
    if body.exception_type is not None and cf.finding:
        # Also set the more specific workflow_status from exception type
        cf.finding.workflow_status = body.exception_type
        cf.finding.status_changed_at = datetime.utcnow()
    db.commit()
    return {"ok": True}


@router.get("/api/campaigns/{campaign_id}/tickets")
def get_campaign_tickets(campaign_id: int, db: Session = Depends(get_db)):
    """Return all tickets linked to findings in this campaign."""
    from services.ticket_sync import _ticket_to_dict
    # Get finding IDs from campaign
    finding_ids = [
        r[0] for r in db.query(CampaignFinding.finding_id)
        .filter(CampaignFinding.campaign_id == campaign_id).all()
    ]
    if not finding_ids:
        return {"tickets": [], "total": 0}

    tickets = db.query(FindingTicket).filter(
        FindingTicket.finding_id.in_(finding_ids)
    ).order_by(desc(FindingTicket.created_at)).all()

    # Enrich with finding info
    findings_map = {}
    if tickets:
        rows = db.query(Finding.id, Finding.plugin_name, Finding.severity_label, Finding.asset_id).filter(
            Finding.id.in_({t.finding_id for t in tickets})
        ).all()
        for r in rows:
            findings_map[r.id] = {"plugin_name": r.plugin_name, "severity_label": r.severity_label}

    result = []
    for t in tickets:
        d = _ticket_to_dict(t)
        fi = findings_map.get(t.finding_id, {})
        d["finding_plugin_name"] = fi.get("plugin_name")
        d["finding_severity_label"] = fi.get("severity_label")
        result.append(d)

    return {"tickets": result, "total": len(result)}


@router.post("/api/campaigns/{campaign_id}/slack-channel")
def create_campaign_slack_channel(campaign_id: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Create a Slack channel for a campaign and invite all collaborators."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    # Collect collaborator emails from campaign findings owner groups
    owner_groups = _group_findings_by_owner(campaign.findings)
    emails = list({
        g["owner_email"]
        for g in owner_groups
        if g.get("owner_email")
    })

    try:
        result = integ_module.create_slack_campaign_channel(
            db,
            campaign_name=campaign.name,
            collaborator_emails=emails,
            campaign_description=campaign.description,
        )
    except ConnectionError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(502, str(e))

    # Persist channel info on the campaign
    campaign.slack_channel_id = result["channel_id"]
    campaign.slack_channel_name = result["channel_name"]
    db.commit()

    return {
        "channel_id": result["channel_id"],
        "channel_name": result["channel_name"],
        "invited": result["invited"],
    }
