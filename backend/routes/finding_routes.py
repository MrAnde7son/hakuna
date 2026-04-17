"""
Findings — FastAPI routes
Extracted from app.py: Findings section + Finding Workflow Status section.
"""
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, or_, cast, Text, func

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids, apply_scan_org_filter
from core.builtin_team_roles import user_owner_scopes, apply_owner_scope_to_findings
from core.audit import log_audit, diff as _diff
from models.models import (
    User, Scan, Asset, Finding, FindingTicket, FindingException,
    InventorySecurityControl, InventoryLoggedOn, AggregatedSolution,
    SLAConfig,
)
import services.tags as tag_engine
import services.ownership_inference as ownership_inference
import services.patch_reliability as patch_reliability
from services.sla_engine import compute_sla_status as _compute_sla_status

router = APIRouter()


def _json_text_at(col, key: str):
    """Portable JSON string extraction: json_extract on SQLite, ->> on Postgres."""
    from core.database import engine as _engine
    if _engine.dialect.name == "postgresql":
        return col.op("->>")(key)
    return func.json_extract(col, f"$.{key}")


# ─────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────

@router.get("/api/findings")
def list_findings(
    request: Request,
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    severity: Optional[str] = None,
    plugin_family: Optional[str] = None,
    has_exploit: Optional[bool] = None,
    is_kev: Optional[bool] = None,
    ransomware_linked: Optional[bool] = None,
    trending_in_news: Optional[bool] = None,
    min_epss: Optional[float] = None,
    sla_status: Optional[str] = None,
    effort_level: Optional[str] = None,
    auto_resolved: Optional[bool] = None,
    cve: Optional[str] = None,
    search: Optional[str] = None,
    source: Optional[str] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    expand_children: bool = False,
    # Product / CPE filters (join through SBOMVulnerability → SBOMComponent)
    product: Optional[str] = None,
    cpe: Optional[str] = None,
    # ATT&CK / threat-intel filters
    has_ttps: Optional[bool] = None,
    tactic: Optional[str] = None,
    technique_id: Optional[str] = None,
    threat_group_id: Optional[int] = None,
    created_after: Optional[str] = None,
    sort_by: str = "priority_score",
    order: str = "desc",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    # Team-scoped RBAC: if the user's access comes entirely through built-in team
    # roles, narrow results to the teams they're assigned to.
    q = apply_owner_scope_to_findings(q, user_owner_scopes(db, current_user.id))
    if created_after:
        try:
            q = q.filter(Scan.created_at > datetime.fromisoformat(created_after))
        except ValueError:
            pass
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if asset_id:
        q = q.filter(Finding.asset_id == asset_id)
    if severity is not None:
        sev_parts = [int(s) for s in severity.split(",") if s.strip().lstrip("-").isdigit()]
        if len(sev_parts) == 1:
            q = q.filter(Finding.severity == sev_parts[0])
        elif sev_parts:
            q = q.filter(Finding.severity.in_(sev_parts))
    if plugin_family:
        q = q.filter(Finding.plugin_family == plugin_family)
    if has_exploit is not None:
        q = q.filter(Finding.exploit_available == has_exploit)
    if is_kev is not None:
        q = q.filter(Finding.is_kev == is_kev)
    if ransomware_linked is not None:
        q = q.filter(Finding.ransomware_linked == ransomware_linked)
    if trending_in_news is not None:
        q = q.filter(Finding.trending_in_news == trending_in_news)
    if min_epss is not None:
        q = q.filter(Finding.epss_score >= min_epss)
    if sla_status:
        q = q.filter(Finding.sla_status == sla_status)
    if request.query_params.get("workflow_status"):
        ws = request.query_params["workflow_status"]
        if ws == "excepted":
            q = q.filter(Finding.workflow_status.in_(["accepted_risk", "false_positive", "compensating_control"]))
        else:
            q = q.filter(Finding.workflow_status == ws)
    if request.query_params.get("has_exception") == "true":
        q = q.filter(Finding.exception_id != None)
    elif request.query_params.get("has_exception") == "false":
        q = q.filter(Finding.exception_id == None)
    # Ticket filter: has_ticket, ticket_status
    if request.query_params.get("has_ticket") == "true":
        q = q.filter(Finding.tickets.any())
    elif request.query_params.get("has_ticket") == "false":
        q = q.filter(~Finding.tickets.any())
    _ticket_status = request.query_params.get("ticket_status")
    if _ticket_status:
        q = q.filter(Finding.tickets.any(FindingTicket.mapped_status == _ticket_status))
    _control_status = request.query_params.get("control_mitigation_status")
    if _control_status:
        q = q.filter(Finding.control_mitigation_status == _control_status)
    if effort_level:
        q = q.filter(Finding.effort_level == effort_level)
    if auto_resolved is not None:
        q = q.filter(Finding.auto_resolved == auto_resolved)
    if cve:
        # Partial match within JSON-serialized cves array (case-insensitive)
        q = q.filter(Finding.cves.ilike(f"%{cve}%"))
    if request.query_params.get("port"):
        q = q.filter(Finding.port == request.query_params["port"])
    if request.query_params.get("min_priority"):
        q = q.filter(Finding.priority_score >= float(request.query_params["min_priority"]))
    if search:
        q = q.filter(
            Finding.plugin_name.ilike(f"%{search}%") |
            Finding.synopsis.ilike(f"%{search}%") |
            Finding.plugin_id.ilike(f"%{search}%")
        )
    if source:
        q = q.filter(cast(Finding.source_systems, Text).ilike(f'%"{source}"%'))
    # ── AI validation filter ──
    # validation={true_positive|false_positive|needs_review|not_validated|validated}
    # Also controls FP auto-hide via `hide_validated_fps` (default true — FPs are noise).
    _validation = request.query_params.get("validation")
    if _validation:
        from sqlalchemy import func as _sql_func
        _verdict_expr = _json_text_at(Finding.llm_validation, "verdict")
        if _validation == "not_validated":
            q = q.filter(or_(Finding.llm_validation.is_(None), _verdict_expr.is_(None)))
        elif _validation == "validated":
            q = q.filter(Finding.llm_validation.isnot(None), _verdict_expr.isnot(None))
        else:
            q = q.filter(_verdict_expr == _validation)

    # Default hide validated false_positives unless the user opts in or explicitly
    # selected `validation=false_positive`. This matches the existing behavior for
    # manually-marked false_positive workflow_status (analysts want noise reduction).
    _hide_fps_raw = request.query_params.get("hide_validated_fps")
    _hide_fps = _hide_fps_raw is None or _hide_fps_raw.lower() not in ("false", "0", "no")
    if _hide_fps and _validation != "false_positive":
        _verdict_expr = _json_text_at(Finding.llm_validation, "verdict")
        q = q.filter(or_(_verdict_expr.is_(None), _verdict_expr != "false_positive"))

    # ── Corroboration filter ── findings confirmed by ≥ 2 scanners
    # (custom_fields.corroboration.corroborated=true set by finding_correlator)
    if request.query_params.get("corroborated") == "true":
        _corr_expr = _json_text_at(Finding.custom_fields, "corroboration")
        q = q.filter(
            Finding.custom_fields.isnot(None),
            _corr_expr.isnot(None),
            _corr_expr != "null",
        )

    # Custom field filters: ?cf_<key>=<value>
    for _cf_param, _cf_value in request.query_params.multi_items():
        if _cf_param.startswith("cf_") and _cf_value:
            _cf_key = _cf_param[3:]
            if _cf_key:
                q = q.filter(_json_text_at(Finding.custom_fields, _cf_key).ilike(f"%{_cf_value}%"))
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, expand_children, db)
        q = tag_engine.apply_finding_tag_filter(q, id_sets, tag_logic, db)
    # Product / CPE filters — join through SBOM to find findings linked to a product or CPE
    if product or cpe:
        from models.models import SBOMComponent, SBOMVulnerability
        _sbom_join = (
            db.query(SBOMVulnerability.finding_id)
            .join(SBOMComponent, SBOMVulnerability.component_id == SBOMComponent.id)
        )
        if product:
            _sbom_join = _sbom_join.filter(SBOMComponent.name.ilike(f"%{product}%"))
        if cpe:
            _sbom_join = _sbom_join.filter(SBOMComponent.cpe.ilike(f"%{cpe}%"))
        _sbom_join = _sbom_join.filter(SBOMVulnerability.finding_id.isnot(None))
        _matching_finding_ids = _sbom_join.subquery()
        q = q.filter(Finding.id.in_(db.query(_matching_finding_ids.c.finding_id)))

    # ATT&CK / threat-intel filters — matched_ttps is a JSON column; cast to Text for string ops
    _ttps_as_text = cast(Finding.matched_ttps, Text)
    if has_ttps is True:
        q = q.filter(Finding.matched_ttps.isnot(None), _ttps_as_text != "[]", _ttps_as_text != "null")
    elif has_ttps is False:
        q = q.filter(or_(Finding.matched_ttps == None, _ttps_as_text == "[]", _ttps_as_text == "null"))
    if tactic:
        q = q.filter(_ttps_as_text.ilike(f'%"tactic": "{tactic}"%'))
    if technique_id:
        q = q.filter(_ttps_as_text.ilike(f'%"{technique_id}"%'))
    if threat_group_id:
        # Resolve TTPs linked to this group, then filter findings with any of those technique_ids
        from models.threat_intel_models import ThreatGroupTTP as _TGTTP, TTP as _TTP
        group_ttps = (
            db.query(_TTP.technique_id)
            .join(_TGTTP, _TTP.id == _TGTTP.ttp_id)
            .filter(_TGTTP.group_id == threat_group_id)
            .all()
        )
        group_technique_ids = [row.technique_id for row in group_ttps]
        if group_technique_ids:
            q = q.filter(or_(*[_ttps_as_text.ilike(f'%"{tid}"%') for tid in group_technique_ids]))
        else:
            # Group has no TTPs — return empty
            q = q.filter(False)

    # Sort (supports custom_fields.<key>)
    if sort_by and sort_by.startswith("custom_fields."):
        _cf_key = sort_by.split(".", 1)[1]
        sort_col = _json_text_at(Finding.custom_fields, _cf_key) if _cf_key else Finding.priority_score
    else:
        sort_col = getattr(Finding, sort_by, Finding.priority_score)
    if order == "desc":
        q = q.order_by(desc(sort_col))
    else:
        q = q.order_by(sort_col)

    total = q.count()
    findings = q.options(joinedload(Finding.ownership)).offset((page - 1) * page_size).limit(page_size).all()

    finding_ids = [f.id for f in findings]
    tag_map = tag_engine.get_finding_tags(finding_ids, db)

    # Batch-fetch assets for all findings on this page (avoids N+1 per-finding query)
    asset_ids_needed = {f.asset_id for f in findings if f.asset_id}
    asset_map = {}
    if asset_ids_needed:
        fetched = db.query(Asset).options(joinedload(Asset.ownership)).filter(Asset.id.in_(asset_ids_needed)).all()
        asset_map = {a.id: a for a in fetched}

    result = []
    for f in findings:
        d = _finding_to_dict(f, db, asset=asset_map.get(f.asset_id))
        d["tags"] = tag_map.get(f.id, [])
        result.append(d)

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "findings": result,
    }


@router.get("/api/findings/products")
def list_finding_products(
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return distinct product names from SBOM components linked to findings."""
    from models.models import SBOMComponent, SBOMVulnerability
    q = (
        db.query(SBOMComponent.name)
        .join(SBOMVulnerability, SBOMVulnerability.component_id == SBOMComponent.id)
        .filter(SBOMVulnerability.finding_id.isnot(None))
        .filter(SBOMComponent.name.isnot(None))
        .distinct()
    )
    rows = q.all()
    return {"products": sorted(set(r[0] for r in rows if r[0]))}


@router.get("/api/findings/cpes")
def list_finding_cpes(
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return distinct CPE strings from SBOM components linked to findings."""
    from models.models import SBOMComponent, SBOMVulnerability
    q = (
        db.query(SBOMComponent.cpe)
        .join(SBOMVulnerability, SBOMVulnerability.component_id == SBOMComponent.id)
        .filter(SBOMVulnerability.finding_id.isnot(None))
        .filter(SBOMComponent.cpe.isnot(None))
        .distinct()
    )
    rows = q.all()
    return {"cpes": sorted(set(r[0] for r in rows if r[0]))}


@router.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    query = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == finding_id)
    query = apply_scan_org_filter(query, org_ids)
    finding = query.first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    return _finding_to_dict(finding, db, include_full=True)


# ── Ticket sync endpoints ──

@router.get("/api/findings/{finding_id}/tickets")
def get_finding_tickets(finding_id: int, db: Session = Depends(get_db)):
    """Return all linked external tickets for a finding."""
    from services.ticket_sync import _ticket_to_dict
    tickets = db.query(FindingTicket).filter(FindingTicket.finding_id == finding_id).all()
    return [_ticket_to_dict(t) for t in tickets]


@router.post("/api/findings/{finding_id}/tickets/sync")
def sync_finding_tickets(finding_id: int, db: Session = Depends(get_db)):
    """Manually trigger ticket status sync for a specific finding."""
    from services.ticket_sync import sync_tickets_for_finding
    return sync_tickets_for_finding(db, finding_id)


@router.post("/api/ticket-sync")
def trigger_ticket_sync(db: Session = Depends(get_db)):
    """Manually trigger global ticket status sync."""
    from services.ticket_sync import sync_all_tickets
    return sync_all_tickets(db)


@router.get("/api/tickets")
def list_tickets(
    ticket_system: Optional[str] = None,
    mapped_status: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    order: str = "desc",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
):
    """List all linked external tickets with filtering."""
    from services.ticket_sync import _ticket_to_dict
    q = db.query(FindingTicket)
    if ticket_system:
        q = q.filter(FindingTicket.ticket_system == ticket_system)
    if mapped_status:
        q = q.filter(FindingTicket.mapped_status == mapped_status)
    if search:
        q = q.filter(
            FindingTicket.ticket_key.ilike(f"%{search}%") |
            FindingTicket.ticket_url.ilike(f"%{search}%")
        )
    sort_col = getattr(FindingTicket, sort_by, FindingTicket.created_at)
    if order == "desc":
        q = q.order_by(desc(sort_col))
    else:
        q = q.order_by(sort_col)
    total = q.count()
    tickets = q.offset((page - 1) * page_size).limit(page_size).all()

    # Enrich with finding info
    finding_ids = {t.finding_id for t in tickets}
    findings_map = {}
    if finding_ids:
        rows = db.query(Finding.id, Finding.plugin_name, Finding.severity_label, Finding.asset_id).filter(Finding.id.in_(finding_ids)).all()
        for r in rows:
            findings_map[r.id] = {"plugin_name": r.plugin_name, "severity_label": r.severity_label, "asset_id": r.asset_id}

    result = []
    for t in tickets:
        d = _ticket_to_dict(t)
        fi = findings_map.get(t.finding_id, {})
        d["finding_plugin_name"] = fi.get("plugin_name")
        d["finding_severity_label"] = fi.get("severity_label")
        d["finding_asset_id"] = fi.get("asset_id")
        result.append(d)

    return {"total": total, "page": page, "page_size": page_size, "tickets": result}


def _review_status(review_by) -> Optional[str]:
    if not review_by:
        return None
    days_until = (review_by - datetime.utcnow()).days
    if days_until < 0:
        return "overdue"
    elif days_until <= 30:
        return "upcoming"
    return "ok"


def _infer_finding_context(f: Finding, asset: Optional[Asset], db: Session) -> dict:
    """Auto-infer validated context + business context from existing data."""
    inferred = {}

    # ── Reachability ──
    if asset:
        inferred["ctx_reachability"] = "internet_facing" if asset.is_internet_facing else "internal_only"

    # ── Exploitability ──
    if f.exploit_available:
        mat = (f.exploit_maturity or "").lower()
        if mat in ("weaponized", "functional", "high"):
            inferred["ctx_exploitability"] = "easily_exploitable"
        else:
            inferred["ctx_exploitability"] = "requires_conditions"
    elif f.epss_score is not None:
        inferred["ctx_exploitability"] = "easily_exploitable" if f.epss_score >= 0.5 else (
            "requires_conditions" if f.epss_score >= 0.1 else "not_exploitable"
        )
    else:
        inferred["ctx_exploitability"] = "unknown"

    # ── Accessibility ──
    port_str = str(f.port or "")
    public_ports = {"80", "443", "8080", "8443"}
    auth_families = {"Windows", "Databases", "RPC", "SMB"}
    family = f.plugin_family or ""
    if port_str in public_ports:
        inferred["ctx_accessibility"] = "public"
    elif any(af in family for af in auth_families):
        inferred["ctx_accessibility"] = "authenticated_only"
    else:
        inferred["ctx_accessibility"] = "unknown"

    # ── Compensating Control (from exception detail + security controls on asset) ──
    cc_parts = []
    if f.exception_id:
        exc = db.query(FindingException).filter(FindingException.id == f.exception_id).first()
        if exc and exc.compensating_control_detail:
            cc_parts.append(exc.compensating_control_detail)
    if asset:
        controls = db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == asset.id,
            InventorySecurityControl.scan_id == f.scan_id,
            InventorySecurityControl.is_enabled == True,
        ).all()
        if controls:
            lines = []
            for ctrl in controls:
                desc_str = ctrl.control_type.upper()
                if ctrl.product_name:
                    desc_str += f": {ctrl.product_name}"
                if ctrl.vendor:
                    desc_str += f" ({ctrl.vendor})"
                if ctrl.is_up_to_date is False:
                    desc_str += " [outdated]"
                lines.append(desc_str)
            cc_parts.append("Active security controls on host: " + "; ".join(lines))
    if cc_parts:
        inferred["ctx_compensating_control"] = "\n".join(cc_parts)

    # ── Business context (from asset-level fields) ──
    if asset:
        if asset.business_context:
            inferred["biz_function"] = asset.business_context
        # No. of Users: use asset.biz_num_users if set, else infer from InventoryLoggedOn
        if asset.biz_num_users is not None:
            inferred["biz_num_users"] = asset.biz_num_users
        else:
            user_count = db.query(InventoryLoggedOn).filter(
                InventoryLoggedOn.asset_id == asset.id,
                InventoryLoggedOn.scan_id == f.scan_id,
            ).count()
            if user_count:
                inferred["biz_num_users"] = user_count
        # Revenue Impact: use asset.biz_revenue_impact if set, else infer from criticality
        if asset.biz_revenue_impact:
            inferred["biz_revenue_impact"] = asset.biz_revenue_impact
        elif asset.criticality:
            c = asset.criticality
            inferred["biz_revenue_impact"] = (
                "critical" if c >= 9 else
                "high" if c >= 7 else
                "medium" if c >= 5 else
                "low" if c >= 3 else
                "none"
            )

    return inferred


def _finding_to_dict(f: Finding, db: Session, include_full: bool = False, asset: Asset = None) -> dict:
    if asset is None and f.asset_id:
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
    # Resolve effective owner through the full chain
    resolved = ownership_inference.resolve_finding_owner(f, asset, db)
    base = {
        "id": f.id,
        "scan_id": f.scan_id,
        "asset_id": f.asset_id,
        "asset_ip": asset.ip if asset else None,
        "asset_hostname": asset.hostname if asset else None,
        "asset_os": asset.os if asset else None,
        "plugin_id": f.plugin_id,
        "plugin_name": f.plugin_name,
        "plugin_family": f.plugin_family,
        # Multi-source provenance
        "source_type": f.source_type or "nessus",
        "source_systems": f.source_systems or [],
        "source_vuln_id": f.source_vuln_id,
        "normalized_id": f.normalized_id,
        "severity": f.severity,
        "severity_label": f.severity_label,
        "risk_factor": f.risk_factor,
        "cvss2_score": f.cvss2_score,
        "cvss3_score": f.cvss3_score,
        "cvss4_score": f.cvss4_score,
        "vpr_score": f.vpr_score,
        "cves": f.cves or [],
        "synopsis": f.synopsis,
        "port": f.port,
        "protocol": f.protocol,
        "vulnerability_state": f.vulnerability_state,
        "exploit_available": f.exploit_available,
        "exploit_maturity": f.exploit_maturity,
        "zero_day": f.zero_day,
        "is_kev": f.is_kev or False,
        "epss_score": f.epss_score,
        "epss_percentile": f.epss_percentile,
        "ransomware_linked": f.ransomware_linked or False,
        "trending_in_news": f.trending_in_news or False,
        "matched_ttps": f.matched_ttps or [],
        "control_mitigation_status": f.control_mitigation_status,
        "control_mitigation_summary": f.control_mitigation_summary,
        "priority_score": f.priority_score,
        "effort_level": f.effort_level,
        "owner_suggestion": f.owner_suggestion,
        # Resolved ownership (full chain)
        "resolved_owner": resolved,
        # SLA tracking
        "sla_due_date": f.sla_due_date.isoformat() if f.sla_due_date else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "sla_status": f.sla_status or "n/a",
        # When the vulnerability was observed (from scanner, not upload time)
        "sla_observed_date": asset.scan_start if asset else None,
        # Workflow status
        "workflow_status": f.workflow_status or "open",
        "workflow_assigned_to": f.workflow_assigned_to,
        "workflow_notes": f.workflow_notes,
        "status_changed_at": f.status_changed_at.isoformat() if f.status_changed_at else None,
        "exception_id": f.exception_id,
        # Aggregated solution
        "aggregated_solution_id": f.aggregated_solution_id,
        # Temporal tracking
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "times_seen": f.times_seen or 1,
        "is_regression": f.is_regression or False,
        # Delta tracking
        "auto_resolved": f.auto_resolved or False,
        "auto_resolved_at": f.auto_resolved_at.isoformat() if f.auto_resolved_at else None,
        "auto_resolved_by_scan_id": f.auto_resolved_by_scan_id,
        # Ticket tracking (lightweight for list view)
        "has_ticket": len(f.tickets) > 0 if f.tickets else False,
        # User-defined custom fields
        "custom_fields": f.custom_fields or {},
        "user_edited_fields": f.user_edited_fields or [],
        # AI validation (from services.llm_vuln_validator and the validator agent).
        # Shape: {verdict, confidence, reasoning, validated_at, validator}
        "llm_validation": f.llm_validation or None,
        # Validated context (analyst- or agent-confirmed assessment).
        "ctx_reachability": f.ctx_reachability,
        "ctx_exploitability": f.ctx_exploitability,
        # Cross-scanner corroboration flag derived from custom_fields.corroboration
        # (set by services.finding_correlator when ≥ 2 scanners report the same CVE).
        "corroborated": bool((f.custom_fields or {}).get("corroboration", {}).get("corroborated")),
    }
    if include_full:
        base.update({
            "description": f.description,
            "solution": f.solution,
            "see_also": f.see_also or [],
            "references": f.references or {},
            "plugin_output": f.plugin_output,
            "cvss2_vector": f.cvss2_vector,
            "cvss3_vector": f.cvss3_vector,
            "cvss4_vector": f.cvss4_vector,
            "plugin_pub_date": f.plugin_pub_date,
            "plugin_mod_date": f.plugin_mod_date,
            "remediation_steps": f.remediation_steps,
            # Linked external tickets
            "tickets": [{
                "id": t.id,
                "ticket_system": t.ticket_system,
                "ticket_key": t.ticket_key,
                "ticket_url": t.ticket_url,
                "external_status": t.external_status,
                "mapped_status": t.mapped_status,
                "last_synced_at": t.last_synced_at.isoformat() if t.last_synced_at else None,
                "sync_error": t.sync_error,
                "created_at": t.created_at.isoformat() if t.created_at else None,
            } for t in (f.tickets or [])],
        })
        # Validated + Business context (with auto-inference)
        inferred = _infer_finding_context(f, asset, db)
        context = {}
        # Validated context fields — manual override stored on finding
        for field in ["ctx_reachability", "ctx_exploitability", "ctx_accessibility", "ctx_compensating_control"]:
            manual = getattr(f, field)
            auto = inferred.get(field)
            context[field] = {
                "value": manual if manual is not None else auto,
                "source": "manual" if manual is not None else ("inferred" if auto is not None else None),
                "inferred": auto,
            }
        # Business context fields — manual values stored on asset, inference from scan data
        biz_manual_map = {
            "biz_function": asset.business_context if asset else None,
            "biz_num_users": asset.biz_num_users if asset else None,
            "biz_revenue_impact": asset.biz_revenue_impact if asset else None,
        }
        biz_confirmed = bool(asset.business_context_confirmed) if asset else False
        for field in ["biz_function", "biz_num_users", "biz_revenue_impact"]:
            manual = biz_manual_map[field]
            auto = inferred.get(field)
            # For biz_function: manual only if confirmed; otherwise treat as inferred
            if field == "biz_function" and manual and not biz_confirmed:
                context[field] = {"value": manual, "source": "inferred", "inferred": manual}
            elif manual is not None:
                context[field] = {"value": manual, "source": "manual", "inferred": auto}
            else:
                context[field] = {"value": auto, "source": "inferred" if auto is not None else None, "inferred": auto}
        base["context"] = context
        base["asset_id_for_biz"] = f.asset_id  # frontend needs this to PATCH the asset
        # Include aggregated solution summary if present
        if f.aggregated_solution_id:
            agg = db.query(AggregatedSolution).filter(AggregatedSolution.id == f.aggregated_solution_id).first()
            if agg:
                base["aggregated_solution"] = {
                    "id": agg.id,
                    "category": agg.category,
                    "title": agg.title,
                    "description": agg.description,
                    "finding_count": agg.finding_count,
                    "effort_level": agg.effort_level,
                }
        # Include technical debt info if this finding's exception is a tech debt
        if f.exception_id:
            exc = db.query(FindingException).filter(FindingException.id == f.exception_id).first()
            if exc and exc.exception_type == "technical_debt":
                base["technical_debt"] = {
                    "title": exc.plugin_name or f"Technical Debt #{exc.id}",
                    "reason": exc.reason,
                    "debt_category": exc.debt_category,
                    "mitigation_plan": exc.mitigation_plan,
                    "review_by": exc.review_by.isoformat() if exc.review_by else None,
                    "review_status": _review_status(exc.review_by),
                }
    return base


# ─────────────────────────────────────────────
# Finding Workflow Status
# ─────────────────────────────────────────────

class FindingStatusUpdate(BaseModel):
    status: str  # open / in_progress / resolved / accepted_risk / false_positive
    assigned_to: Optional[str] = None
    notes: Optional[str] = None

VALID_WORKFLOW_STATUSES = {"open", "in_progress", "resolved", "accepted_risk", "false_positive"}


@router.patch("/api/findings/{finding_id}/status")
def update_finding_status(finding_id: int, body: FindingStatusUpdate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Update finding workflow status."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if body.status not in VALID_WORKFLOW_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {', '.join(VALID_WORKFLOW_STATUSES)}")
    _old_status = {"status": finding.workflow_status, "assigned_to": finding.workflow_assigned_to}
    # Capture the prior resolved_at so we can detect a resolved→open reopen
    # after we've already mutated the finding. Used for the patch rollback hook.
    _prior_resolved_at = finding.resolved_at
    finding.workflow_status = body.status
    finding.status_changed_at = datetime.utcnow()
    if body.assigned_to is not None:
        finding.workflow_assigned_to = body.assigned_to
    if body.notes is not None:
        finding.workflow_notes = body.notes
    # Sync resolved state with SLA system
    if body.status == "resolved" and not finding.resolved_at:
        finding.resolved_at = datetime.utcnow()
        finding.sla_status = "resolved"
    elif body.status == "open" and finding.resolved_at:
        finding.resolved_at = None
        configs = db.query(SLAConfig).all()
        cfg_map = {c.severity: c for c in configs}
        cfg = cfg_map.get(finding.severity)
        warn = cfg.warn_days_before if cfg else 7
        finding.sla_status = _compute_sla_status(finding.sla_due_date, None, warn)
    _new_status = {"status": finding.workflow_status, "assigned_to": finding.workflow_assigned_to}
    log_audit(db, "update", "finding_status", finding_id,
              entity_name=finding.plugin_name,
              changes=_diff(_old_status, _new_status), actor=user)
    db.commit()

    # After commit: if this was a resolved→open transition inside the rollback
    # window, emit reliability signals against the patches that were supposed
    # to fix this finding. Failures here must not break the status update, so
    # we swallow exceptions and log.
    if body.status == "open" and _prior_resolved_at is not None:
        try:
            asset = db.query(Asset).filter(Asset.id == finding.asset_id).first() if finding.asset_id else None
            patch_reliability.handle_finding_reopened(
                db,
                finding_id=finding.id,
                cves=list(finding.cves or []),
                asset_os=asset.os if asset else None,
                asset_id=finding.asset_id,
                org_id=finding.org_id,
                resolved_at=_prior_resolved_at,
            )
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "patch_reliability rollback hook failed for finding %s", finding_id
            )

    return {
        "ok": True, "finding_id": finding_id,
        "workflow_status": finding.workflow_status,
        "assigned_to": finding.workflow_assigned_to,
    }


class FindingContextUpdate(BaseModel):
    ctx_reachability: Optional[str] = None       # unreachable / internal_only / internet_facing / unknown
    ctx_exploitability: Optional[str] = None     # not_exploitable / requires_conditions / easily_exploitable / unknown
    ctx_accessibility: Optional[str] = None      # restricted / authenticated_only / public / unknown
    ctx_compensating_control: Optional[str] = None
    biz_function: Optional[str] = None           # saved to asset.business_context
    biz_num_users: Optional[int] = None          # saved to asset.biz_num_users
    biz_revenue_impact: Optional[str] = None     # saved to asset.biz_revenue_impact


@router.patch("/api/findings/{finding_id}/context")
def update_finding_context(finding_id: int, body: FindingContextUpdate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Update validated context (on finding) and business context (on asset)."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    changes = {}
    # Validated context → stored on finding
    for field in ["ctx_reachability", "ctx_exploitability", "ctx_accessibility", "ctx_compensating_control"]:
        val = getattr(body, field)
        if val is not None:
            old = getattr(finding, field)
            setattr(finding, field, val)
            changes[field] = {"old": old, "new": val}
    # Business context → stored on asset (shared across all findings on the asset)
    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
    if asset:
        if body.biz_function is not None:
            old = asset.business_context
            asset.business_context = body.biz_function
            asset.business_context_confirmed = True
            changes["biz_function"] = {"old": old, "new": body.biz_function}
        if body.biz_num_users is not None:
            old = asset.biz_num_users
            asset.biz_num_users = body.biz_num_users
            changes["biz_num_users"] = {"old": old, "new": body.biz_num_users}
        if body.biz_revenue_impact is not None:
            old = asset.biz_revenue_impact
            asset.biz_revenue_impact = body.biz_revenue_impact
            changes["biz_revenue_impact"] = {"old": old, "new": body.biz_revenue_impact}
    if changes:
        log_audit(db, "update", "finding_context", finding_id,
                  entity_name=finding.plugin_name, changes=changes, actor=user)
    db.commit()
    return _finding_to_dict(finding, db, include_full=True)


@router.patch("/api/findings/{finding_id}/custom-fields")
def update_finding_custom_fields(
    finding_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Set manual custom field values on a finding.

    Rejects attempts to set computed (mapping/formula) fields — those come
    from ingest only. Unknown keys raise 400.
    """
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == finding_id)
    q = apply_scan_org_filter(q, org_ids)
    finding = q.first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    from models.models import CustomFieldDefinition
    from services.custom_field_resolver import _coerce_value

    scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    org_id = scan.org_id if scan else None
    if not org_id:
        raise HTTPException(400, "Finding has no org context")

    defs = db.query(CustomFieldDefinition).filter(
        CustomFieldDefinition.org_id == org_id,
        CustomFieldDefinition.entity_type == "finding",
        CustomFieldDefinition.is_active.is_(True),
    ).all()
    def_map = {d.key: d for d in defs}

    current = dict(finding.custom_fields or {})
    edited = list(finding.user_edited_fields or [])
    for key, raw_value in (payload or {}).items():
        definition = def_map.get(key)
        if not definition:
            raise HTTPException(400, f"Unknown custom field '{key}'")
        if definition.source_type != "manual":
            raise HTTPException(400, f"custom field '{key}' is computed and cannot be set manually")
        if raw_value is None:
            current.pop(key, None)
        else:
            current[key] = _coerce_value(raw_value, definition.data_type)
        marker = f"custom_fields.{key}"
        if marker not in edited:
            edited.append(marker)

    finding.custom_fields = current
    finding.user_edited_fields = edited
    db.commit()
    return _finding_to_dict(finding, db, include_full=True)


@router.post("/api/findings/bulk-status")
def bulk_update_finding_status(
    body: dict,
    db: Session = Depends(get_db),
):
    """Bulk update workflow status for multiple findings."""
    finding_ids = body.get("finding_ids", [])
    status = body.get("status", "open")
    assigned_to = body.get("assigned_to")
    if status not in VALID_WORKFLOW_STATUSES:
        raise HTTPException(400, f"Invalid status: {status}")
    updated = 0
    for fid in finding_ids:
        f = db.query(Finding).filter(Finding.id == fid).first()
        if f:
            f.workflow_status = status
            f.status_changed_at = datetime.utcnow()
            if assigned_to is not None:
                f.workflow_assigned_to = assigned_to
            if status == "resolved" and not f.resolved_at:
                f.resolved_at = datetime.utcnow()
                f.sla_status = "resolved"
            updated += 1
    db.commit()
    return {"ok": True, "updated": updated}
