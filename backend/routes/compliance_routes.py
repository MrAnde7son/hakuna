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
from pydantic import BaseModel, Field
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


# ─────────────────────────────────────────────
# Serializers
# ─────────────────────────────────────────────


def _framework_to_dict(fw: ComplianceFramework, *, subscribed: Optional[bool] = None) -> dict:
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
        "subscribed": subscribed,
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


def _get_framework_or_404(db: Session, slug: str) -> ComplianceFramework:
    fw = db.query(ComplianceFramework).filter_by(slug=slug).first()
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
    """List every canonical framework, with each org's current subscription state.

    Frameworks themselves are global (no org_id) — the per-org subscription
    layer adds the ``subscribed`` boolean for the caller's primary org.
    """
    frameworks = (
        db.query(ComplianceFramework)
        .order_by(ComplianceFramework.name)
        .all()
    )
    org_id = user.org_id
    sub_ids = set()
    if org_id:
        sub_ids = {
            s.framework_id for s in
            db.query(OrgFrameworkSubscription)
            .filter_by(org_id=org_id, enabled=True)
            .all()
        }
    return [
        _framework_to_dict(fw, subscribed=fw.id in sub_ids)
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
    fw = _get_framework_or_404(db, slug)
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
    fw = _get_framework_or_404(db, slug)
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
    fw = _get_framework_or_404(db, slug)
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
    fw = _get_framework_or_404(db, slug)
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
):
    ctrl = db.query(ComplianceControl).filter_by(id=control_id).first()
    if ctrl is None:
        raise HTTPException(404, "control not found")
    org_id = user.org_id
    if not org_id:
        raise HTTPException(400, "user has no org_id")

    q = (
        db.query(ComplianceFindingStatus)
        .filter(
            ComplianceFindingStatus.org_id == org_id,
            ComplianceFindingStatus.control_id == control_id,
        )
        .order_by(ComplianceFindingStatus.scored_at.desc())
    )
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
