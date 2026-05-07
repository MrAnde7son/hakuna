"""Compliance API — frameworks, controls, subscriptions, compensating
controls. All endpoints require ``page_compliance`` permission, which
ships off-by-default for analyst/viewer/team roles. Reports endpoints
land in PR 5.

Prefix: ``/api/compliance``
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from core.audit import log_audit
from core.auth import (
    apply_org_filter,
    get_accessible_org_ids,
    get_current_user,
    require_permission,
)
from core.database import get_db
from core.time_utils import iso_utc
from models.models import (
    Asset,
    Campaign,
    CampaignComplianceControl,
    CampaignFinding,
    ComplianceCompensatingControl,
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceControlStatus,
    ComplianceFindingStatus,
    ComplianceFramework,
    ComplianceFrameworkRelease,
    ComplianceReportRun,
    Finding,
    FindingException,
    OrgFrameworkSubscription,
    Scan,
    User,
)
from services.compliance_evaluator import (
    apply_compensating_control,
    evaluate as evaluate_compliance,
    revoke_compensating_control,
)
from services.compliance_export import framework_to_yaml
from services.compliance_loader import load_framework_from_yaml_text
from services.compliance_report import (
    SUPPORTED_FORMATS as REPORT_SUPPORTED_FORMATS,
    generate_report,
    serialize_run,
)


router = APIRouter()


# ─────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────


class SubscriptionCreate(BaseModel):
    scope_rule: Optional[dict] = None      # rule_engine condition list
    scope_tag_expr: Optional[str] = None   # UI mirror, e.g. "env:prod,cde:yes"


class ScopeUpdate(BaseModel):
    scope_rule: Optional[dict] = None
    scope_tag_expr: Optional[str] = None
    enabled: Optional[bool] = None


class CompensatingControlCreate(BaseModel):
    rationale: str = Field(min_length=4)
    scope_rule: Optional[dict] = None
    valid_until: Optional[datetime] = None
    linked_exception_id: Optional[int] = None
    linked_ticket_ids: Optional[List[dict]] = None


class ReportCreate(BaseModel):
    framework_slug: str
    format: str = "csv"  # csv | json (pdf deferred — see services/compliance_report)


class CampaignFromControlCreate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    owner_id: Optional[int] = None
    also_include_control_ids: Optional[List[int]] = None  # bundle multiple controls


class CampaignFromFrameworkCreate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    owner_id: Optional[int] = None
    only_failing: bool = True  # if False, include compensating-control verdicts too


# ─────────────────────────────────────────────
# Serializers
# ─────────────────────────────────────────────


def _framework_to_dict(
    fw: ComplianceFramework,
    *,
    subscribed: Optional[bool] = None,
    scope_tag_expr: Optional[str] = None,
) -> dict:
    return {
        "id": fw.id,
        "slug": fw.slug,
        "name": fw.name,
        "version": fw.version,
        "authority": fw.authority,
        "published_at": iso_utc(fw.published_at),
        "description": fw.description,
        "categories": fw.categories or [],
        "mapping_schema_version": fw.mapping_schema_version,
        "org_id": fw.org_id,
        "source": fw.source or "builtin",
        "created_by": fw.created_by,
        "subscribed": subscribed,
        "scope_tag_expr": scope_tag_expr,
    }


def _control_to_dict(
    ctrl: ComplianceControl,
    *,
    status: Optional[ComplianceControlStatus] = None,
    mapping_count: Optional[int] = None,
) -> dict:
    out = {
        "id": ctrl.id,
        "framework_id": ctrl.framework_id,
        "ref": ctrl.ref,
        "title": ctrl.title,
        "description": ctrl.description,
        "parent_ref": ctrl.parent_ref,
        "domain": ctrl.domain,
        "testability": ctrl.testability,
        "default_severity_floor": ctrl.default_severity_floor,
        "canonical_guidance": ctrl.canonical_guidance,
        "mapping_count": mapping_count,
    }
    if status is not None:
        out["state"] = status.state
        out["in_scope_asset_count"] = status.in_scope_asset_count
        out["failing_finding_count"] = status.failing_finding_count
        out["failing_asset_count"] = status.failing_asset_count
        out["last_evaluated_at"] = iso_utc(status.last_evaluated_at)
        out["first_failed_at"] = iso_utc(status.first_failed_at)
    else:
        out["state"] = "not_evaluated"
        out["in_scope_asset_count"] = None
        out["failing_finding_count"] = None
        out["failing_asset_count"] = None
        out["last_evaluated_at"] = None
        out["first_failed_at"] = None
    return out


def _subscription_to_dict(sub: OrgFrameworkSubscription) -> dict:
    return {
        "id": sub.id,
        "org_id": sub.org_id,
        "framework_id": sub.framework_id,
        "enabled": sub.enabled,
        "scope_rule": sub.scope_rule,
        "scope_tag_expr": sub.scope_tag_expr,
        "activated_at": iso_utc(sub.activated_at),
        "activated_by": sub.activated_by,
    }


def _compensating_to_dict(cc: ComplianceCompensatingControl) -> dict:
    return {
        "id": cc.id,
        "org_id": cc.org_id,
        "control_id": cc.control_id,
        "rationale": cc.rationale,
        "scope_rule": cc.scope_rule,
        "linked_exception_id": cc.linked_exception_id,
        "linked_ticket_ids": cc.linked_ticket_ids or [],
        "valid_until": iso_utc(cc.valid_until),
        "created_by": cc.created_by,
        "approved_by": cc.approved_by,
        "created_at": iso_utc(cc.created_at),
    }


def _finding_status_to_dict(s: ComplianceFindingStatus, finding: Optional[Finding]) -> dict:
    return {
        "id": s.id,
        "finding_id": s.finding_id,
        "control_id": s.control_id,
        "mapping_key": s.mapping_key,
        "verdict": s.verdict,
        "matched_via": s.matched_via,
        "match_signal": s.match_signal or {},
        "scored_at": iso_utc(s.scored_at),
        "finding": None if finding is None else {
            "id": finding.id,
            "plugin_id": finding.plugin_id,
            "plugin_name": finding.plugin_name,
            "plugin_family": finding.plugin_family,
            "severity": finding.severity,
            "severity_label": finding.severity_label,
            "workflow_status": finding.workflow_status,
            "asset_id": finding.asset_id,
            "cves": finding.cves or [],
            "cwe_ids": finding.cwe_ids or [],
            "is_kev": finding.is_kev or False,
        },
    }


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────


def _resolve_org_id(user: User, x_org_context: Optional[str] = None) -> int:
    """Pick the org we're acting on. Per CLAUDE.md, X-Org-Context narrows
    the action's org for MSSP users; otherwise default to user.org_id.
    Validation against accessible_org_ids happens at the dependency level
    via apply_org_filter / require_permission."""
    if x_org_context:
        try:
            return int(x_org_context)
        except (TypeError, ValueError):
            raise HTTPException(400, "X-Org-Context must be an integer")
    return user.org_id


def _get_framework_or_404(
    db: Session,
    slug: str,
    *,
    org_id: Optional[int] = None,
) -> ComplianceFramework:
    """Resolve a framework by slug for the caller's org.

    A tenant may have imported a private framework that shares a slug with a
    global builtin (e.g. their own "iso_27001_2022" with extra controls).
    Prefer the tenant copy when present; otherwise fall back to the global
    pack. Tenant-private frameworks belonging to other orgs are never
    returned.
    """
    if org_id is not None:
        tenant_fw = (
            db.query(ComplianceFramework)
            .filter(ComplianceFramework.slug == slug,
                    ComplianceFramework.org_id == org_id)
            .first()
        )
        if tenant_fw is not None:
            return tenant_fw
    fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.slug == slug,
                ComplianceFramework.org_id.is_(None))
        .first()
    )
    if fw is None:
        raise HTTPException(404, f"Framework {slug!r} not found")
    return fw


# ─────────────────────────────────────────────
# Frameworks
# ─────────────────────────────────────────────


@router.get("/api/compliance/frameworks")
def list_frameworks(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """List frameworks visible to the caller's org.

    Visible = built-in global packs (org_id IS NULL) + this org's imported
    private packs. Other tenants' private packs are filtered out at the
    query level. The per-org subscription layer adds the ``subscribed``
    boolean for the caller's primary org.
    """
    org_id = user.org_id
    fw_q = db.query(ComplianceFramework)
    if org_id is not None:
        fw_q = fw_q.filter(or_(
            ComplianceFramework.org_id.is_(None),
            ComplianceFramework.org_id == org_id,
        ))
    else:
        fw_q = fw_q.filter(ComplianceFramework.org_id.is_(None))
    frameworks = fw_q.order_by(ComplianceFramework.name).all()
    sub_by_fw: dict[int, OrgFrameworkSubscription] = {}
    if org_id:
        sub_by_fw = {
            s.framework_id: s for s in
            db.query(OrgFrameworkSubscription)
            .filter_by(org_id=org_id, enabled=True)
            .all()
        }
    return [
        _framework_to_dict(
            fw,
            subscribed=fw.id in sub_by_fw,
            scope_tag_expr=sub_by_fw[fw.id].scope_tag_expr if fw.id in sub_by_fw else None,
        )
        for fw in frameworks
    ]


@router.post("/api/compliance/frameworks/{slug}/subscribe")
def subscribe_to_framework(
    slug: str,
    body: SubscriptionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """Enable a framework for the user's org. Idempotent — re-calling with
    a new scope_rule updates the existing subscription rather than failing."""
    fw = _get_framework_or_404(db, slug, org_id=user.org_id)
    org_id = user.org_id
    if not org_id:
        raise HTTPException(400, "user has no org_id")

    sub = (
        db.query(OrgFrameworkSubscription)
        .filter_by(org_id=org_id, framework_id=fw.id)
        .first()
    )
    if sub is None:
        sub = OrgFrameworkSubscription(
            org_id=org_id,
            framework_id=fw.id,
            enabled=True,
            scope_rule=body.scope_rule,
            scope_tag_expr=body.scope_tag_expr,
            activated_by=user.id,
        )
        db.add(sub)
        db.flush()
        log_audit(db, "create", "compliance_subscription", sub.id,
                  entity_name=slug, changes={"scope_rule": body.scope_rule},
                  actor=user)
    else:
        sub.enabled = True
        sub.scope_rule = body.scope_rule
        sub.scope_tag_expr = body.scope_tag_expr
        log_audit(db, "update", "compliance_subscription", sub.id,
                  entity_name=slug, changes={"scope_rule": body.scope_rule},
                  actor=user)
    db.commit()
    return _subscription_to_dict(sub)


@router.delete("/api/compliance/frameworks/{slug}/subscribe")
def unsubscribe_from_framework(
    slug: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    fw = _get_framework_or_404(db, slug, org_id=user.org_id)
    org_id = user.org_id
    sub = (
        db.query(OrgFrameworkSubscription)
        .filter_by(org_id=org_id, framework_id=fw.id)
        .first()
    )
    if sub is None:
        return {"status": "not_subscribed"}
    sub.enabled = False
    log_audit(db, "disable", "compliance_subscription", sub.id,
              entity_name=slug, actor=user)
    db.commit()
    return {"status": "unsubscribed"}


@router.patch("/api/compliance/frameworks/{slug}/scope")
def update_scope(
    slug: str,
    body: ScopeUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    fw = _get_framework_or_404(db, slug, org_id=user.org_id)
    org_id = user.org_id
    sub = (
        db.query(OrgFrameworkSubscription)
        .filter_by(org_id=org_id, framework_id=fw.id)
        .first()
    )
    if sub is None:
        raise HTTPException(404, f"No subscription for {slug!r}")
    if body.scope_rule is not None:
        sub.scope_rule = body.scope_rule
    if body.scope_tag_expr is not None:
        sub.scope_tag_expr = body.scope_tag_expr
    if body.enabled is not None:
        sub.enabled = body.enabled
    log_audit(db, "update", "compliance_subscription", sub.id,
              entity_name=slug,
              changes={"scope_rule": body.scope_rule, "enabled": body.enabled},
              actor=user)
    db.commit()
    return _subscription_to_dict(sub)


# ─────────────────────────────────────────────
# Import / Export — tenant-private framework packs
# ─────────────────────────────────────────────


class FrameworkImport(BaseModel):
    """Body for POST /import. We accept the YAML as a string in JSON rather
    than multipart so the same endpoint works from API clients without a
    file picker. Frontend file uploads should read the file and POST the
    contents here."""
    yaml_text: str = Field(min_length=10)


@router.get("/api/compliance/frameworks/{slug}/export")
def export_framework(
    slug: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """Serialize a framework + controls + mappings back to YAML.

    Round-trips through POST /api/compliance/frameworks/import. Visible to
    any caller with page_compliance — exporting the global packs is by
    design (auditors often want to inspect the rules), and tenant-private
    packs are already org-scoped via _get_framework_or_404.
    """
    fw = _get_framework_or_404(db, slug, org_id=user.org_id)
    yaml_body = framework_to_yaml(db, fw)
    filename = f"compliance_{fw.slug}_{fw.version}.yaml".replace(" ", "_")
    return PlainTextResponse(
        content=yaml_body,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/api/compliance/frameworks/import")
def import_framework(
    body: FrameworkImport,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """Load a tenant-private framework from YAML.

    Imports always land at org_id=user.org_id; never as a global builtin.
    Re-importing the same YAML (same SHA) under the same tenant is a
    no-op and returns status="skipped". Validation errors return 400 with
    the exact mapping/field that failed so the uploader can fix it.
    """
    org_id = user.org_id
    if not org_id:
        raise HTTPException(400, "user has no org_id")

    result = load_framework_from_yaml_text(
        db, body.yaml_text, org_id=org_id, created_by=user.id,
    )

    status = result.get("status")
    if status in ("parse_error", "schema_error", "validation_error"):
        raise HTTPException(400, result.get("error") or status)
    if status not in ("loaded", "updated", "skipped"):
        raise HTTPException(500, f"unexpected loader status: {status!r}")

    log_audit(
        db, "import", "compliance_framework",
        result.get("framework_id"),
        entity_name=result.get("framework_slug"),
        changes={
            "status": status,
            "release_tag": result.get("release_tag"),
            "controls_loaded": result.get("controls_loaded"),
        },
        actor=user,
    )
    db.commit()
    return result


@router.delete("/api/compliance/frameworks/{slug}/imported")
def delete_imported_framework(
    slug: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """Delete a tenant-imported framework.

    Refuses to touch builtin packs even if the slug matches — those live in
    YAML on disk and the on-boot loader would re-create them anyway. The
    cascade on framework_id removes controls, mappings, releases, and via
    the tenant-tables' cascades the per-org status / report rows.
    """
    org_id = user.org_id
    if not org_id:
        raise HTTPException(400, "user has no org_id")

    fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.slug == slug,
                ComplianceFramework.org_id == org_id)
        .first()
    )
    if fw is None:
        raise HTTPException(
            404,
            f"No imported framework {slug!r} for this org "
            "(builtin packs cannot be deleted via the API)",
        )
    fw_id = fw.id
    db.delete(fw)
    log_audit(db, "delete", "compliance_framework", fw_id,
              entity_name=slug, actor=user)
    db.commit()
    return {"status": "deleted", "framework_slug": slug}


# ─────────────────────────────────────────────
# Controls
# ─────────────────────────────────────────────


@router.get("/api/compliance/frameworks/{slug}/controls")
def list_controls(
    slug: str,
    domain: Optional[str] = None,
    state: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """List controls under a framework with the caller-org's status per row."""
    fw = _get_framework_or_404(db, slug, org_id=user.org_id)
    org_id = user.org_id

    q = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw.id)
    if domain:
        q = q.filter(ComplianceControl.domain == domain)
    if search:
        like = f"%{search}%"
        q = q.filter(
            (ComplianceControl.ref.ilike(like))
            | (ComplianceControl.title.ilike(like))
        )
    q = q.order_by(ComplianceControl.ref)

    # Pre-fetch status per (org, control) so we don't N+1.
    status_map: dict[int, ComplianceControlStatus] = {}
    mapping_count_map: dict[int, int] = {}
    if org_id:
        for s in (
            db.query(ComplianceControlStatus)
            .filter_by(org_id=org_id)
            .all()
        ):
            status_map[s.control_id] = s
    from sqlalchemy import func as sqla_func
    for cid, cnt in (
        db.query(ComplianceControlMapping.control_id,
                 sqla_func.count(ComplianceControlMapping.id))
        .group_by(ComplianceControlMapping.control_id)
        .all()
    ):
        mapping_count_map[cid] = cnt

    total = q.count()
    rows = q.offset((page - 1) * page_size).limit(page_size).all()
    items = [
        _control_to_dict(
            c,
            status=status_map.get(c.id),
            mapping_count=mapping_count_map.get(c.id, 0),
        )
        for c in rows
    ]

    if state:
        items = [i for i in items if i["state"] == state]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "framework": _framework_to_dict(fw),
    }


@router.get("/api/compliance/controls/{control_id}")
def get_control(
    control_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    ctrl = db.query(ComplianceControl).filter_by(id=control_id).first()
    if ctrl is None:
        raise HTTPException(404, "control not found")
    org_id = user.org_id
    status = (
        db.query(ComplianceControlStatus)
        .filter_by(org_id=org_id, control_id=control_id)
        .first() if org_id else None
    )
    mapping_count = (
        db.query(ComplianceControlMapping)
        .filter_by(control_id=control_id)
        .count()
    )
    out = _control_to_dict(ctrl, status=status, mapping_count=mapping_count)
    out["mappings"] = [
        {
            "id": m.id,
            "mapping_key": m.mapping_key,
            "rule": m.rule,
            "rule_version": m.rule_version,
            "testability": m.testability,
        }
        for m in (
            db.query(ComplianceControlMapping)
            .filter_by(control_id=control_id)
            .all()
        )
    ]
    out["compensating_controls"] = [
        _compensating_to_dict(cc)
        for cc in (
            db.query(ComplianceCompensatingControl)
            .filter_by(org_id=org_id, control_id=control_id)
            .order_by(ComplianceCompensatingControl.created_at.desc())
            .all()
        )
    ] if org_id else []
    return out


@router.get("/api/compliance/controls/{control_id}/findings")
def list_findings_under_control(
    control_id: int,
    verdict: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    ctrl = db.query(ComplianceControl).filter_by(id=control_id).first()
    if ctrl is None:
        raise HTTPException(404, "control not found")

    q = (
        db.query(ComplianceFindingStatus)
        .filter(ComplianceFindingStatus.control_id == control_id)
        .order_by(ComplianceFindingStatus.scored_at.desc())
    )
    if org_ids is not None:
        q = q.filter(ComplianceFindingStatus.org_id.in_(org_ids))
    if verdict:
        q = q.filter(ComplianceFindingStatus.verdict == verdict)
    total = q.count()
    rows = q.offset((page - 1) * page_size).limit(page_size).all()

    finding_ids = [r.finding_id for r in rows]
    findings_by_id = {
        f.id: f for f in (
            db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
            if finding_ids else []
        )
    }
    return {
        "items": [
            _finding_status_to_dict(r, findings_by_id.get(r.finding_id))
            for r in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


# ─────────────────────────────────────────────
# Spin up a remediation Campaign from compliance controls
# ─────────────────────────────────────────────


def _materialize_campaign_from_controls(
    db: Session,
    org_id: int,
    control_ids: List[int],
    only_failing: bool,
) -> tuple[list[dict], int]:
    """Build the Campaign.query JSON and pre-compute the finding set from
    ComplianceFindingStatus. Returns (query_conditions, finding_id_count).

    The query is the union of the selected controls' mapping rules — used as
    a stored snapshot so the campaign survives a YAML re-release that
    renumbers mappings. The finding set is materialised now (option a:
    point-in-time) by pulling failing rows from compliance_finding_status.
    """
    mappings = (
        db.query(ComplianceControlMapping)
        .filter(ComplianceControlMapping.control_id.in_(control_ids))
        .all()
    )

    flat: list[dict] = []
    for m in mappings:
        rule = m.rule or {}
        conds = rule.get("conditions") if isinstance(rule, dict) else None
        if isinstance(conds, list):
            flat.extend(conds)
        elif isinstance(rule, list):
            flat.extend(rule)

    verdicts = ["failing"] if only_failing else [
        "failing", "satisfied_by_compensating",
    ]
    finding_ids = [
        row.finding_id
        for row in (
            db.query(ComplianceFindingStatus.finding_id)
            .filter(
                ComplianceFindingStatus.org_id == org_id,
                ComplianceFindingStatus.control_id.in_(control_ids),
                ComplianceFindingStatus.verdict.in_(verdicts),
            )
            .distinct()
            .all()
        )
    ]
    return flat, finding_ids


def _create_campaign_for_controls(
    db: Session,
    user: User,
    org_id: int,
    controls: List[ComplianceControl],
    name: Optional[str],
    description: Optional[str],
    owner_id: Optional[int],
    only_failing: bool = True,
) -> Campaign:
    if not controls:
        raise HTTPException(400, "no controls provided")

    control_ids = [c.id for c in controls]
    query_conds, finding_ids = _materialize_campaign_from_controls(
        db, org_id, control_ids, only_failing,
    )

    framework = (
        db.query(ComplianceFramework)
        .filter_by(id=controls[0].framework_id)
        .first()
    )
    if not name:
        if len(controls) == 1:
            name = f"{framework.name} {controls[0].ref} — {controls[0].title}"
        else:
            refs = ", ".join(c.ref for c in controls[:4])
            more = f" +{len(controls) - 4}" if len(controls) > 4 else ""
            name = f"{framework.name} compliance — {refs}{more}"
    name = name[:240]

    campaign = Campaign(
        org_id=org_id,
        name=name,
        description=description,
        query=query_conds,
        query_logic="OR",  # mappings are alternative detection signals — any match qualifies
        owner_id=owner_id,
        status="draft",
        finding_count=len(finding_ids),
    )
    db.add(campaign)
    db.flush()

    for ctrl in controls:
        db.add(CampaignComplianceControl(
            campaign_id=campaign.id,
            control_id=ctrl.id,
            org_id=org_id,
        ))

    for fid in finding_ids:
        db.add(CampaignFinding(campaign_id=campaign.id, finding_id=fid))

    log_audit(
        db, "create", "campaign", campaign.id,
        entity_name=campaign.name,
        changes={
            "name": campaign.name,
            "compliance_control_ids": control_ids,
            "compliance_framework": framework.slug if framework else None,
            "finding_count": len(finding_ids),
            "source": "compliance",
        },
        actor=user,
    )
    db.commit()
    db.refresh(campaign)
    return campaign


@router.post("/api/compliance/controls/{control_id}/campaign")
def create_campaign_from_control(
    control_id: int,
    body: CampaignFromControlCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """Spin up a remediation campaign scoped to one compliance control —
    optionally bundling sibling controls via ``also_include_control_ids``.
    The campaign's finding set is frozen at creation time (point-in-time
    snapshot) from ``compliance_finding_status``."""
    org_id = user.org_id
    if not org_id:
        raise HTTPException(400, "user has no org_id")

    primary = db.query(ComplianceControl).filter_by(id=control_id).first()
    if primary is None:
        raise HTTPException(404, "control not found")

    extra_ids = list(body.also_include_control_ids or [])
    all_ids = [control_id] + [i for i in extra_ids if i != control_id]

    controls = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.id.in_(all_ids))
        .all()
    )
    found_ids = {c.id for c in controls}
    missing = [i for i in all_ids if i not in found_ids]
    if missing:
        raise HTTPException(404, f"controls not found: {missing}")

    # Cross-framework bundling is rejected — confuses both the audit story
    # and the campaign-name auto-generation.
    framework_ids = {c.framework_id for c in controls}
    if len(framework_ids) > 1:
        raise HTTPException(
            400, "all bundled controls must belong to the same framework",
        )

    # Order the primary control first so name/description default uses it.
    controls.sort(key=lambda c: 0 if c.id == control_id else 1)

    campaign = _create_campaign_for_controls(
        db, user, org_id, controls,
        name=body.name, description=body.description, owner_id=body.owner_id,
    )
    return {
        "id": campaign.id,
        "name": campaign.name,
        "status": campaign.status,
        "finding_count": campaign.finding_count,
        "control_ids": [c.id for c in controls],
    }


@router.post("/api/compliance/frameworks/{slug}/campaign")
def create_campaign_from_framework(
    slug: str,
    body: CampaignFromFrameworkCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """Bundle every failing control of a framework into a single campaign.
    Useful for "remediate all of HIPAA" style audit pushes."""
    org_id = user.org_id
    if not org_id:
        raise HTTPException(400, "user has no org_id")

    fw = _get_framework_or_404(db, slug, org_id=org_id)

    failing_states = ["failing", "partial"]
    statuses = (
        db.query(ComplianceControlStatus.control_id)
        .filter(
            ComplianceControlStatus.org_id == org_id,
            ComplianceControlStatus.state.in_(failing_states),
        )
        .all()
    )
    failing_control_ids = {row.control_id for row in statuses}
    if not failing_control_ids:
        raise HTTPException(
            400, "no failing controls in this framework for this org",
        )

    controls = (
        db.query(ComplianceControl)
        .filter(
            ComplianceControl.framework_id == fw.id,
            ComplianceControl.id.in_(failing_control_ids),
        )
        .order_by(ComplianceControl.ref)
        .all()
    )
    if not controls:
        raise HTTPException(400, "no failing controls match this framework")

    name = body.name or f"{fw.name} — failing controls remediation"
    campaign = _create_campaign_for_controls(
        db, user, org_id, controls,
        name=name, description=body.description, owner_id=body.owner_id,
        only_failing=body.only_failing,
    )
    return {
        "id": campaign.id,
        "name": campaign.name,
        "status": campaign.status,
        "finding_count": campaign.finding_count,
        "control_ids": [c.id for c in controls],
        "control_count": len(controls),
    }


# ─────────────────────────────────────────────
# Compensating controls
# ─────────────────────────────────────────────


@router.post("/api/compliance/controls/{control_id}/compensating-controls")
def create_compensating_control(
    control_id: int,
    body: CompensatingControlCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """Document a compensating control for a compliance control. Optionally
    bridges to an existing FindingException of type compensating_control —
    the canonical risk-acceptance record stays the source of truth, this
    table adds the auditor-relevant scope + approval metadata."""
    ctrl = db.query(ComplianceControl).filter_by(id=control_id).first()
    if ctrl is None:
        raise HTTPException(404, "control not found")
    org_id = user.org_id
    if not org_id:
        raise HTTPException(400, "user has no org_id")

    if body.linked_exception_id is not None:
        exc = (
            db.query(FindingException)
            .filter_by(id=body.linked_exception_id, org_id=org_id)
            .first()
        )
        if exc is None:
            raise HTTPException(
                404,
                f"FindingException {body.linked_exception_id} not found in this org",
            )

    cc = ComplianceCompensatingControl(
        org_id=org_id,
        control_id=control_id,
        scope_rule=body.scope_rule,
        rationale=body.rationale,
        linked_exception_id=body.linked_exception_id,
        linked_ticket_ids=body.linked_ticket_ids or [],
        valid_until=body.valid_until,
        created_by=user.id,
    )
    db.add(cc)
    db.flush()

    flipped = apply_compensating_control(db, cc)

    log_audit(db, "create", "compliance_compensating_control", cc.id,
              entity_name=f"{ctrl.ref}",
              changes={
                  "control_id": control_id,
                  "linked_exception_id": body.linked_exception_id,
                  "rows_flipped": flipped,
              },
              actor=user)
    db.commit()
    out = _compensating_to_dict(cc)
    out["rows_flipped"] = flipped
    return out


@router.delete("/api/compliance/compensating-controls/{cc_id}")
def delete_compensating_control(
    cc_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    org_id = user.org_id
    cc = (
        db.query(ComplianceCompensatingControl)
        .filter_by(id=cc_id, org_id=org_id)
        .first()
    )
    if cc is None:
        raise HTTPException(404, "compensating control not found")
    control_id = cc.control_id
    db.delete(cc)
    db.flush()
    flipped = revoke_compensating_control(db, org_id=org_id, control_id=control_id)
    log_audit(db, "delete", "compliance_compensating_control", cc_id,
              changes={"rows_flipped_back": flipped}, actor=user)
    db.commit()
    return {"status": "deleted", "rows_flipped_back": flipped}


# ─────────────────────────────────────────────
# Reverse lookup: which controls does this finding fail?
# ─────────────────────────────────────────────


@router.get("/api/compliance/findings/{finding_id}/satisfies-controls")
def satisfies_controls(
    finding_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return every (framework, control, verdict) triple this finding contributes
    to, scoped to orgs the caller can read. Used by the Finding Detail drawer."""
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if f is None:
        raise HTTPException(404, "finding not found")

    # Tenant-scope via the finding's scan.org_id (Finding has no org_id column).
    scan = db.query(Scan).filter(Scan.id == f.scan_id).first()
    if scan and org_ids is not None and scan.org_id not in (org_ids or []):
        raise HTTPException(403, "no access to this finding's tenant")

    rows = (
        db.query(ComplianceFindingStatus, ComplianceControl, ComplianceFramework)
        .join(ComplianceControl,
              ComplianceControl.id == ComplianceFindingStatus.control_id)
        .join(ComplianceFramework,
              ComplianceFramework.id == ComplianceControl.framework_id)
        .filter(ComplianceFindingStatus.finding_id == finding_id)
        .all()
    )
    return [
        {
            "framework_slug": fw.slug,
            "framework_name": fw.name,
            "control_id": ctrl.id,
            "control_ref": ctrl.ref,
            "control_title": ctrl.title,
            "verdict": status.verdict,
            "matched_via": status.matched_via,
            "mapping_key": status.mapping_key,
        }
        for status, ctrl, fw in rows
    ]


# ─────────────────────────────────────────────
# Reports
# ─────────────────────────────────────────────


def _report_run_to_dict(run: ComplianceReportRun, fw_slug: Optional[str] = None) -> dict:
    return {
        "id": run.id,
        "org_id": run.org_id,
        "framework_id": run.framework_id,
        "framework_slug": fw_slug,
        "format": run.format,
        "status": run.status,
        "error": run.error,
        "sha256": run.sha256,
        "generated_by": run.generated_by,
        "generated_at": iso_utc(run.generated_at),
        "created_at": iso_utc(run.created_at),
        # Summary fields lifted from the snapshot for list-view rendering.
        "framework_name": (run.snapshot or {}).get("framework", {}).get("name"),
        "framework_version": (run.snapshot or {}).get("framework", {}).get("version"),
        "rollup": (run.snapshot or {}).get("rollup"),
    }


@router.post("/api/compliance/reports")
def create_report(
    body: ReportCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
):
    """Generate a compliance report. v1 supports csv | json.

    The snapshot is frozen at request time and stored on the row, so a
    follow-up download returns identical bytes regardless of how compliance
    state has shifted in the meantime.
    """
    fmt = (body.format or "csv").lower()
    if fmt == "pdf":
        # Wired but not implemented — surface explicitly so the UI can
        # disable the PDF button and link to docs once the renderer ships.
        raise HTTPException(
            501,
            "PDF reports are not implemented in v1; use format=csv or format=json. "
            "PDF will reuse services/report_renderer once a /compliance/report/{id} "
            "React route is added.",
        )
    if fmt not in REPORT_SUPPORTED_FORMATS:
        raise HTTPException(
            400,
            f"Unsupported format {fmt!r}; expected one of {sorted(REPORT_SUPPORTED_FORMATS)}",
        )
    org_id = user.org_id
    if not org_id:
        raise HTTPException(400, "user has no org_id")
    fw = _get_framework_or_404(db, body.framework_slug, org_id=org_id)

    # Confirm the org actually subscribes to the framework — generating a
    # report for a framework you don't run would be misleading (zero data).
    sub = (
        db.query(OrgFrameworkSubscription)
        .filter_by(org_id=org_id, framework_id=fw.id)
        .first()
    )
    if sub is None or not sub.enabled:
        raise HTTPException(
            400,
            f"Org is not subscribed to framework {body.framework_slug!r}; "
            "subscribe first via POST /api/compliance/frameworks/{slug}/subscribe.",
        )

    try:
        run = generate_report(db, org_id=org_id, framework=fw, fmt=fmt, user_id=user.id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    log_audit(db, "create", "compliance_report_run", run.id,
              entity_name=fw.slug,
              changes={"format": fmt, "sha256": run.sha256[:16] if run.sha256 else None},
              actor=user)
    db.commit()
    return _report_run_to_dict(run, fw_slug=fw.slug)


@router.get("/api/compliance/reports")
def list_reports(
    framework_slug: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """List recent report runs for the caller's accessible orgs, newest first."""
    q = (
        db.query(ComplianceReportRun, ComplianceFramework)
        .join(ComplianceFramework, ComplianceFramework.id == ComplianceReportRun.framework_id)
    )
    if org_ids is not None:
        q = q.filter(ComplianceReportRun.org_id.in_(org_ids))
    if framework_slug:
        q = q.filter(ComplianceFramework.slug == framework_slug)
    q = q.order_by(ComplianceReportRun.created_at.desc()).limit(limit)
    rows = q.all()
    return [_report_run_to_dict(r, fw_slug=fw.slug) for r, fw in rows]


@router.get("/api/compliance/reports/{run_id}")
def get_report(
    run_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return report metadata + the embedded snapshot. Use the /download
    endpoint when you want the raw artifact bytes instead."""
    q = db.query(ComplianceReportRun).filter(ComplianceReportRun.id == run_id)
    if org_ids is not None:
        q = q.filter(ComplianceReportRun.org_id.in_(org_ids))
    run = q.first()
    if run is None:
        raise HTTPException(404, "report not found")
    fw = db.query(ComplianceFramework).filter_by(id=run.framework_id).first()
    out = _report_run_to_dict(run, fw_slug=fw.slug if fw else None)
    out["snapshot"] = run.snapshot
    return out


@router.get("/api/compliance/reports/{run_id}/download")
def download_report(
    run_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("page_compliance")),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Stream the artifact bytes. Re-serializes from the stored snapshot so
    every download returns identical bytes — the run.sha256 covers the
    serialized output, not the raw snapshot dict."""
    q = db.query(ComplianceReportRun).filter(ComplianceReportRun.id == run_id)
    if org_ids is not None:
        q = q.filter(ComplianceReportRun.org_id.in_(org_ids))
    run = q.first()
    if run is None:
        raise HTTPException(404, "report not found")
    if run.status != "succeeded":
        raise HTTPException(409, f"report status={run.status}; cannot download")

    fw = db.query(ComplianceFramework).filter_by(id=run.framework_id).first()
    fw_slug = fw.slug if fw else "framework"
    try:
        body = serialize_run(run)
    except ValueError as exc:
        raise HTTPException(500, f"failed to serialize report: {exc}")

    media_type = "text/csv" if run.format == "csv" else "application/json"
    extension = run.format
    filename = f"compliance_{fw_slug}_{run.id}.{extension}"

    return StreamingResponse(
        iter([body]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
