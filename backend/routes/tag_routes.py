"""
Tag routes — CRUD for tags, tag assignment/unassignment, OS/software summary,
and auto-tag rule management.
Prefix: /api/tags, /api/auto-tag-rules
"""
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import (
    get_current_user, get_accessible_org_ids, apply_org_filter, apply_scan_org_filter,
    resolve_active_org_id,
)
from core.audit import log_audit, diff as _diff
from core.time_utils import iso_utc
from models.models import (
    User, Scan, Asset, Finding, Tag, TagAssignment, AutoTagRule,
    InventorySoftware, SBOMComponent,
)
import services.tags as tag_engine
import services.rule_engine as rule_engine

router = APIRouter()


# ─────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────

class TagCreate(BaseModel):
    category: str
    value: str
    parent_id: Optional[int] = None
    color: Optional[str] = "#6366f1"
    description: Optional[str] = None


class TagUpdate(BaseModel):
    category: Optional[str] = None
    value: Optional[str] = None
    parent_id: Optional[int] = None
    color: Optional[str] = None
    description: Optional[str] = None


class TagAssignBody(BaseModel):
    tag_ids: list
    asset_ids: Optional[list] = None
    finding_ids: Optional[list] = None


class AutoTagRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tag_id: Optional[int] = None
    target_type: str = "asset"
    conditions: list = []
    condition_logic: str = "AND"
    is_enabled: bool = True


class AutoTagRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tag_id: Optional[int] = None
    target_type: Optional[str] = None
    conditions: Optional[list] = None
    condition_logic: Optional[str] = None
    is_enabled: Optional[bool] = None


# ─────────────────────────────────────────────
# Tags
# ─────────────────────────────────────────────

@router.post("/api/tags")
def create_tag(
    body: TagCreate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    target_org = resolve_active_org_id(user, org_ids) if user else None
    dup_q = db.query(Tag).filter(Tag.category == body.category, Tag.value == body.value)
    if target_org is not None:
        dup_q = dup_q.filter(Tag.org_id == target_org)
    if dup_q.first():
        raise HTTPException(409, f"Tag '{body.category}:{body.value}' already exists")
    if body.parent_id:
        parent_q = db.query(Tag).filter(Tag.id == body.parent_id)
        if org_ids is not None:
            parent_q = parent_q.filter(Tag.org_id.in_(org_ids))
        if not parent_q.first():
            raise HTTPException(404, "Parent tag not found")
    tag = Tag(
        org_id=target_org,
        category=body.category,
        value=body.value,
        parent_id=body.parent_id,
        color=body.color or "#6366f1",
        description=body.description,
    )
    db.add(tag)
    db.flush()
    log_audit(db, "create", "tag", tag.id,
              entity_name=f"{tag.category}:{tag.value}",
              changes={"category": tag.category, "value": tag.value, "color": tag.color},
              actor=user)
    db.commit()
    db.refresh(tag)
    return tag_engine._tag_to_dict(tag, db=db, include_counts=True)


@router.get("/api/tags")
def list_tags(
    category: Optional[str] = None,
    tree: bool = False,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = apply_org_filter(db.query(Tag), Tag, org_ids)
    if category:
        q = q.filter(Tag.category == category)
    q = q.order_by(Tag.category, Tag.value)
    tags = q.all()
    if tree:
        return tag_engine.build_tree(tags, db=db)
    return [tag_engine._tag_to_dict(t, db=db, include_counts=True) for t in tags]


@router.get("/api/tags/os-software-summary")
def get_os_software_summary(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return OS distribution and top software products with asset counts."""
    from sqlalchemy import func as sqla_func

    # OS distribution from assets
    os_q = db.query(Asset.os, sqla_func.count(Asset.id).label("count")).join(
        Scan, Asset.scan_id == Scan.id
    )
    os_q = apply_scan_org_filter(os_q, org_ids)
    if scan_id:
        os_q = os_q.filter(Asset.scan_id == scan_id)
    os_q = os_q.filter(Asset.os.isnot(None), Asset.os != "").group_by(Asset.os).order_by(sqla_func.count(Asset.id).desc())
    os_rows = os_q.all()

    # Classify into families
    from services.os_software_tags import classify_os_family
    family_counts: dict[str, int] = {}
    os_detail = []
    for os_str, count in os_rows:
        family = classify_os_family(os_str) or "Other"
        family_counts[family] = family_counts.get(family, 0) + count
        os_detail.append({"os": os_str, "family": family, "count": count})

    os_families = sorted(
        [{"name": k, "count": v} for k, v in family_counts.items()],
        key=lambda x: x["count"], reverse=True,
    )

    # Software distribution from InventorySoftware
    sw_q = db.query(
        InventorySoftware.name,
        InventorySoftware.vendor,
        sqla_func.count(sqla_func.distinct(InventorySoftware.asset_id)).label("asset_count"),
        sqla_func.count(InventorySoftware.id).label("install_count"),
    ).join(Scan, InventorySoftware.scan_id == Scan.id)
    sw_q = apply_scan_org_filter(sw_q, org_ids)
    if scan_id:
        sw_q = sw_q.filter(InventorySoftware.scan_id == scan_id)
    sw_q = (
        sw_q.filter(InventorySoftware.name.isnot(None))
        .group_by(InventorySoftware.name, InventorySoftware.vendor)
        .order_by(sqla_func.count(sqla_func.distinct(InventorySoftware.asset_id)).desc())
        .limit(100)
    )
    sw_rows = sw_q.all()
    software = [
        {"name": r.name, "vendor": r.vendor, "asset_count": r.asset_count, "install_count": r.install_count}
        for r in sw_rows
    ]

    # Software category breakdown
    cat_q = db.query(
        InventorySoftware.category,
        sqla_func.count(sqla_func.distinct(InventorySoftware.asset_id)).label("asset_count"),
    ).join(Scan, InventorySoftware.scan_id == Scan.id)
    cat_q = apply_scan_org_filter(cat_q, org_ids)
    if scan_id:
        cat_q = cat_q.filter(InventorySoftware.scan_id == scan_id)
    cat_q = cat_q.group_by(InventorySoftware.category).order_by(
        sqla_func.count(sqla_func.distinct(InventorySoftware.asset_id)).desc()
    )
    cat_rows = cat_q.all()
    software_categories = [
        {"name": r.category or "Uncategorized", "count": r.asset_count}
        for r in cat_rows
    ]

    # Device type breakdown
    dt_q = db.query(Asset.device_type, sqla_func.count(Asset.id).label("count")).join(
        Scan, Asset.scan_id == Scan.id
    )
    dt_q = apply_scan_org_filter(dt_q, org_ids)
    if scan_id:
        dt_q = dt_q.filter(Asset.scan_id == scan_id)
    dt_q = dt_q.filter(Asset.device_type.isnot(None)).group_by(Asset.device_type).order_by(sqla_func.count(Asset.id).desc())
    device_types = [{"name": r.device_type, "count": r.count} for r in dt_q.all()]

    # Asset type distribution
    at_q = db.query(Asset.asset_type, sqla_func.count(Asset.id).label("count")).join(
        Scan, Asset.scan_id == Scan.id
    )
    at_q = apply_scan_org_filter(at_q, org_ids)
    if scan_id:
        at_q = at_q.filter(Asset.scan_id == scan_id)
    at_q = at_q.group_by(Asset.asset_type).order_by(sqla_func.count(Asset.id).desc())
    asset_types = [{"name": r.asset_type or "host", "count": r.count} for r in at_q.all()]

    # ── Riskiest OS families (OS → assets → findings severity rollup) ──
    from sqlalchemy import case as sa_case2
    os_risk_q = (
        db.query(
            Asset.os,
            sqla_func.count(sqla_func.distinct(Finding.id)).label("vuln_count"),
            sqla_func.sum(sa_case2((Finding.severity == 4, 1), else_=0)).label("critical"),
            sqla_func.sum(sa_case2((Finding.severity == 3, 1), else_=0)).label("high"),
            sqla_func.sum(sa_case2((Finding.severity == 2, 1), else_=0)).label("medium"),
            sqla_func.count(sqla_func.distinct(Asset.id)).label("asset_count"),
        )
        .join(Scan, Asset.scan_id == Scan.id)
        .join(Finding, (Finding.asset_id == Asset.id) & (Finding.scan_id == Asset.scan_id))
        .filter(Asset.os.isnot(None), Asset.os != "", Finding.severity >= 1)
    )
    os_risk_q = apply_scan_org_filter(os_risk_q, org_ids)
    if scan_id:
        os_risk_q = os_risk_q.filter(Asset.scan_id == scan_id)
    os_risk_q = os_risk_q.group_by(Asset.os)
    os_risk_rows = os_risk_q.all()

    # Roll up by family
    os_risk_map: dict[str, dict] = {}
    for row in os_risk_rows:
        fam = classify_os_family(row.os) or "Other"
        entry = os_risk_map.setdefault(fam, {"name": fam, "vuln_count": 0, "critical": 0, "high": 0, "medium": 0, "asset_count": 0})
        entry["vuln_count"] += row.vuln_count
        entry["critical"] += row.critical or 0
        entry["high"] += row.high or 0
        entry["medium"] += row.medium or 0
        entry["asset_count"] += row.asset_count
    os_risk = sorted(os_risk_map.values(), key=lambda x: (x["critical"], x["high"], x["vuln_count"]), reverse=True)[:15]

    # ── Riskiest software (SBOMComponent aggregated CVE stats) ──
    sw_risk_q = (
        db.query(
            SBOMComponent.name,
            SBOMComponent.vendor,
            sqla_func.sum(SBOMComponent.cve_count).label("vuln_count"),
            sqla_func.max(SBOMComponent.max_severity).label("max_severity"),
            sqla_func.max(SBOMComponent.max_cvss).label("max_cvss"),
            sqla_func.count(sqla_func.distinct(SBOMComponent.asset_id)).label("asset_count"),
        )
        .join(Scan, SBOMComponent.scan_id == Scan.id)
        .filter(SBOMComponent.cve_count > 0)
    )
    sw_risk_q = apply_scan_org_filter(sw_risk_q, org_ids)
    if scan_id:
        sw_risk_q = sw_risk_q.filter(SBOMComponent.scan_id == scan_id)
    sw_risk_q = (
        sw_risk_q.group_by(SBOMComponent.name, SBOMComponent.vendor)
        .order_by(sqla_func.sum(SBOMComponent.cve_count).desc())
        .limit(20)
    )
    sw_risk = [
        {"name": r.name, "vendor": r.vendor, "vuln_count": r.vuln_count, "max_severity": r.max_severity, "max_cvss": float(r.max_cvss) if r.max_cvss else None, "asset_count": r.asset_count}
        for r in sw_risk_q.all()
    ]

    # ── Riskiest plugin families (findings grouped by plugin_family) ──
    fam_risk_q = (
        db.query(
            Finding.plugin_family,
            sqla_func.count(Finding.id).label("vuln_count"),
            sqla_func.sum(sa_case2((Finding.severity == 4, 1), else_=0)).label("critical"),
            sqla_func.sum(sa_case2((Finding.severity == 3, 1), else_=0)).label("high"),
            sqla_func.sum(sa_case2((Finding.severity == 2, 1), else_=0)).label("medium"),
            sqla_func.count(sqla_func.distinct(Finding.asset_id)).label("asset_count"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.severity >= 1, Finding.plugin_family.isnot(None))
    )
    fam_risk_q = apply_scan_org_filter(fam_risk_q, org_ids)
    if scan_id:
        fam_risk_q = fam_risk_q.filter(Finding.scan_id == scan_id)
    fam_risk_q = fam_risk_q.group_by(Finding.plugin_family).order_by(sqla_func.count(Finding.id).desc()).limit(15)
    family_risk = [
        {"name": r.plugin_family, "vuln_count": r.vuln_count, "critical": r.critical or 0, "high": r.high or 0, "medium": r.medium or 0, "asset_count": r.asset_count}
        for r in fam_risk_q.all()
    ]

    return {
        "os_families": os_families,
        "os_detail": os_detail[:50],
        "software": software,
        "software_categories": software_categories,
        "device_types": device_types,
        "asset_types": asset_types,
        "os_risk": os_risk,
        "software_risk": sw_risk,
        "family_risk": family_risk,
    }


def _get_tag_in_orgs(db, tag_id, org_ids):
    q = db.query(Tag).filter(Tag.id == tag_id)
    if org_ids is not None:
        q = q.filter(Tag.org_id.in_(org_ids))
    tag = q.first()
    if not tag:
        raise HTTPException(404, "Tag not found")
    return tag


@router.get("/api/tags/{tag_id}")
def get_tag(
    tag_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    tag = _get_tag_in_orgs(db, tag_id, org_ids)
    d = tag_engine._tag_to_dict(tag, db=db, include_counts=True)
    d["ancestors"] = tag_engine.get_ancestors(tag_id, db)
    descendant_ids = tag_engine.get_descendant_ids(tag_id, db)
    d["descendant_count"] = len(descendant_ids)
    return d


@router.patch("/api/tags/{tag_id}")
def update_tag(
    tag_id: int, body: TagUpdate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    tag = _get_tag_in_orgs(db, tag_id, org_ids)
    _old_tag = {"category": tag.category, "value": tag.value, "color": tag.color}
    if body.category is not None or body.value is not None:
        new_cat = body.category or tag.category
        new_val = body.value or tag.value
        # Conflict check is scoped to the tag's own org so two tenants can
        # have the same category:value without colliding.
        conflict = db.query(Tag).filter(
            Tag.category == new_cat, Tag.value == new_val,
            Tag.id != tag_id, Tag.org_id == tag.org_id,
        ).first()
        if conflict:
            raise HTTPException(409, f"Tag '{new_cat}:{new_val}' already exists")
        tag.category = new_cat
        tag.value = new_val
    if body.parent_id is not None:
        if body.parent_id == tag_id:
            raise HTTPException(400, "Tag cannot be its own parent")
        tag.parent_id = body.parent_id
    if body.color is not None:
        tag.color = body.color
    if body.description is not None:
        tag.description = body.description
    _new_tag = {"category": tag.category, "value": tag.value, "color": tag.color}
    log_audit(db, "update", "tag", tag_id,
              entity_name=f"{tag.category}:{tag.value}",
              changes=_diff(_old_tag, _new_tag), actor=user)
    db.commit()
    return tag_engine._tag_to_dict(tag, db=db, include_counts=True)


@router.delete("/api/tags/{tag_id}")
def delete_tag(
    tag_id: int,
    strategy: str = "reparent",  # "reparent" | "cascade"
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    tag = _get_tag_in_orgs(db, tag_id, org_ids)
    _tag_name = f"{tag.category}:{tag.value}"
    _tag_org = tag.org_id

    children = db.query(Tag).filter(Tag.parent_id == tag_id).all()
    if strategy == "cascade":
        # Delete all descendants recursively
        all_desc_ids = tag_engine.get_descendant_ids(tag_id, db)
        for did in all_desc_ids:
            db.query(TagAssignment).filter(TagAssignment.tag_id == did).delete(synchronize_session=False)
            db.query(Tag).filter(Tag.id == did).delete(synchronize_session=False)
    else:
        # Reparent children to grandparent
        grandparent_id = tag.parent_id
        for child in children:
            child.parent_id = grandparent_id

    db.query(TagAssignment).filter(TagAssignment.tag_id == tag_id).delete(synchronize_session=False)
    db.delete(tag)
    log_audit(db, "delete", "tag", tag_id, entity_name=_tag_name, actor=user, org_id=_tag_org)
    db.commit()
    return {"message": "Tag deleted", "strategy": strategy}


@router.post("/api/tags/assign")
def assign_tags(body: TagAssignBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    from core.auth import has_tag_permission
    assigned = 0
    for tag_id in (body.tag_ids or []):
        tag = db.query(Tag).filter(Tag.id == tag_id).first()
        if not tag:
            continue
        if user and not has_tag_permission(user, tag_id, "write", db):
            raise HTTPException(status_code=403, detail=f"No write permission on tag '{tag.category}:{tag.value}'")
        for aid in (body.asset_ids or []):
            exists = db.query(TagAssignment).filter(
                TagAssignment.tag_id == tag_id,
                TagAssignment.asset_id == aid,
            ).first()
            if not exists:
                db.add(TagAssignment(tag_id=tag_id, asset_id=aid, assigned_by="user"))
                assigned += 1
        for fid in (body.finding_ids or []):
            exists = db.query(TagAssignment).filter(
                TagAssignment.tag_id == tag_id,
                TagAssignment.finding_id == fid,
            ).first()
            if not exists:
                db.add(TagAssignment(tag_id=tag_id, finding_id=fid, assigned_by="user"))
                assigned += 1
    db.commit()
    return {"assigned": assigned}


@router.post("/api/tags/unassign")
def unassign_tags(body: TagAssignBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    from core.auth import has_tag_permission
    removed = 0
    for tag_id in (body.tag_ids or []):
        if user and not has_tag_permission(user, tag_id, "write", db):
            tag = db.query(Tag).filter(Tag.id == tag_id).first()
            label = f"{tag.category}:{tag.value}" if tag else str(tag_id)
            raise HTTPException(status_code=403, detail=f"No write permission on tag '{label}'")
        for aid in (body.asset_ids or []):
            n = db.query(TagAssignment).filter(
                TagAssignment.tag_id == tag_id,
                TagAssignment.asset_id == aid,
            ).delete(synchronize_session=False)
            removed += n
        for fid in (body.finding_ids or []):
            n = db.query(TagAssignment).filter(
                TagAssignment.tag_id == tag_id,
                TagAssignment.finding_id == fid,
            ).delete(synchronize_session=False)
            removed += n
    db.commit()
    return {"removed": removed}


# ─────────────────────────────────────────────
# Auto-tag rules
# ─────────────────────────────────────────────

@router.get("/api/auto-tag-rules/condition-catalog")
def get_tag_condition_catalog(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return condition catalog for auto-tag rules (proxies to unified catalog)."""
    return rule_engine.get_condition_catalog(db, org_ids)


@router.get("/api/auto-tag-rules")
def list_auto_tag_rules(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = db.query(AutoTagRule)
    if org_ids is not None:
        q = q.filter(AutoTagRule.org_id.in_(org_ids))
    rules = q.order_by(AutoTagRule.id).all()
    return [_rule_to_dict(r) for r in rules]


def _get_auto_tag_rule_in_orgs(db, rule_id, org_ids):
    q = db.query(AutoTagRule).filter(AutoTagRule.id == rule_id)
    if org_ids is not None:
        q = q.filter(AutoTagRule.org_id.in_(org_ids))
    rule = q.first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule


@router.post("/api/auto-tag-rules")
def create_auto_tag_rule(
    body: AutoTagRuleCreate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    target_org = resolve_active_org_id(user, org_ids) if user else None
    is_passthrough = any(c.get("op") == "passthrough" for c in (body.conditions or []))
    if body.tag_id is not None:
        tag_q = db.query(Tag).filter(Tag.id == body.tag_id)
        if org_ids is not None:
            tag_q = tag_q.filter(Tag.org_id.in_(org_ids))
        if not tag_q.first():
            raise HTTPException(404, "Tag not found")
    elif not is_passthrough:
        raise HTTPException(400, "tag_id is required for non-passthrough rules")
    rule = AutoTagRule(
        org_id=target_org,
        name=body.name,
        description=body.description,
        tag_id=body.tag_id,
        target_type=body.target_type,
        conditions=body.conditions,
        condition_logic=body.condition_logic,
        is_enabled=body.is_enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _rule_to_dict(rule)


@router.patch("/api/auto-tag-rules/{rule_id}")
def update_auto_tag_rule(
    rule_id: int, body: AutoTagRuleUpdate,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = _get_auto_tag_rule_in_orgs(db, rule_id, org_ids)
    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.tag_id is not None:
        tag_q = db.query(Tag).filter(Tag.id == body.tag_id)
        if org_ids is not None:
            tag_q = tag_q.filter(Tag.org_id.in_(org_ids))
        if not tag_q.first():
            raise HTTPException(404, "Tag not found")
        rule.tag_id = body.tag_id
    if body.target_type is not None:
        rule.target_type = body.target_type
    if body.conditions is not None:
        rule.conditions = body.conditions
    if body.condition_logic is not None:
        rule.condition_logic = body.condition_logic
    if body.is_enabled is not None:
        rule.is_enabled = body.is_enabled
    db.commit()
    return _rule_to_dict(rule)


@router.delete("/api/auto-tag-rules/{rule_id}")
def delete_auto_tag_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = _get_auto_tag_rule_in_orgs(db, rule_id, org_ids)
    db.delete(rule)
    db.commit()
    return {"message": "Rule deleted"}


@router.post("/api/auto-tag-rules/run-all")
def run_all_auto_tag_rules_endpoint(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    results = tag_engine.run_all_auto_tag_rules(db, scan_id=scan_id, org_ids=org_ids)
    return {"results": results, "total_tagged": sum(results.values())}


@router.post("/api/auto-tag-rules/{rule_id}/run")
def run_auto_tag_rule(
    rule_id: int,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = db.query(AutoTagRule).filter(AutoTagRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    matched = tag_engine.run_auto_tag_rule(rule, db, scan_id=scan_id, org_ids=org_ids)
    return {"tagged": matched, "rule_id": rule_id}


def _rule_to_dict(rule: AutoTagRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "tag_id": rule.tag_id,
        "tag_label": f"{rule.tag.category}:{rule.tag.value}" if rule.tag else None,
        "tag_color": rule.tag.color if rule.tag else None,
        "target_type": rule.target_type,
        "conditions": rule_engine.migrate_conditions(rule.conditions or [], mode="autotag"),
        "condition_logic": rule.condition_logic,
        "is_enabled": rule.is_enabled,
        "created_at": iso_utc(rule.created_at),
        "last_run_at": iso_utc(rule.last_run_at),
        "last_run_count": rule.last_run_count,
    }
