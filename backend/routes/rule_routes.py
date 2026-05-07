"""
Rule-related routes: Ownership Endpoints, Asset Type Rules, Ownership Rules, External Tag Sources.
"""
from typing import Optional, List

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids, resolve_active_org_id
from core.audit import log_audit, diff as _diff
from core.time_utils import iso_utc
from models.models import (
    Asset, Finding, Scan,
    AssetOwnership, FindingOwnership,
    AssetTypeRule, OwnershipRule,
    ExternalTagSource, ExternalTagMap, Tag,
    User,
)
import services.ownership_inference as ownership_inference
import services.asset_type_rules as asset_type_rule_engine
import services.rule_engine as rule_engine
import services.tags as tag_engine

router = APIRouter()


# ─────────────────────────────────────────────
# Ownership Endpoints
# ─────────────────────────────────────────────

class OwnershipBody(BaseModel):
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_role: Optional[str] = None
    team: Optional[str] = None
    notes: Optional[str] = None


@router.patch("/api/assets/{asset_id}/ownership")
def set_asset_ownership(asset_id: int, body: OwnershipBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Set or update ownership for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    own = db.query(AssetOwnership).filter(AssetOwnership.asset_id == asset_id).first()
    _old_own = {"owner_name": own.owner_name if own else None, "owner_email": own.owner_email if own else None, "owner_role": own.owner_role if own else None, "team": own.team if own else None}
    if not own:
        own = AssetOwnership(asset_id=asset_id)
        db.add(own)
    own.owner_name = body.owner_name
    own.owner_email = body.owner_email
    own.owner_role = body.owner_role
    own.team = body.team
    own.notes = body.notes
    _new_own = {"owner_name": own.owner_name, "owner_email": own.owner_email, "owner_role": own.owner_role, "team": own.team}
    log_audit(db, "update", "asset_ownership", asset_id,
              entity_name=asset.ip or asset.hostname,
              changes=_diff(_old_own, _new_own), actor=user)
    db.commit()
    return {"ok": True, "asset_id": asset_id, "owner_name": own.owner_name}


@router.patch("/api/findings/{finding_id}/ownership")
def set_finding_ownership(finding_id: int, body: OwnershipBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Set or update ownership for a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    own = db.query(FindingOwnership).filter(FindingOwnership.finding_id == finding_id).first()
    _old_fown = {"owner_name": own.owner_name if own else None, "owner_role": own.owner_role if own else None, "team": own.team if own else None}
    if not own:
        own = FindingOwnership(finding_id=finding_id)
        db.add(own)
    own.owner_name = body.owner_name
    own.owner_email = body.owner_email
    own.owner_role = body.owner_role
    own.team = body.team
    own.notes = body.notes
    _new_fown = {"owner_name": own.owner_name, "owner_role": own.owner_role, "team": own.team}
    log_audit(db, "update", "finding_ownership", finding_id,
              entity_name=finding.plugin_name,
              changes=_diff(_old_fown, _new_fown), actor=user)
    db.commit()
    return {"ok": True, "finding_id": finding_id, "owner_name": own.owner_name}


@router.post("/api/scans/{scan_id}/infer-ownership")
def rerun_ownership_inference(scan_id: int, db: Session = Depends(get_db)):
    """Re-run ownership inference for a scan (e.g. after inventory update)."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    stats = ownership_inference.infer_asset_ownership(db, scan_id)
    return stats


@router.post("/api/assets/{asset_id}/confirm-owner")
def confirm_inferred_owner(asset_id: int, db: Session = Depends(get_db)):
    """Promote inferred ownership to a manual AssetOwnership record."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    if not asset.inferred_primary_user and not asset.inferred_team:
        raise HTTPException(400, "No inferred ownership to confirm")

    own = db.query(AssetOwnership).filter(AssetOwnership.asset_id == asset_id).first()
    if not own:
        own = AssetOwnership(asset_id=asset_id)
        db.add(own)
    own.owner_name = own.owner_name or asset.inferred_primary_user
    own.owner_role = own.owner_role or asset.inferred_team
    own.team = own.team or asset.inferred_team
    db.commit()
    return {"ok": True, "asset_id": asset_id, "owner_name": own.owner_name, "owner_role": own.owner_role}


@router.get("/api/scans/{scan_id}/ownership-summary")
def get_ownership_summary(scan_id: int, db: Session = Depends(get_db)):
    """Summary of ownership coverage for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    total = len(assets)
    manual = 0
    inferred_high = 0
    inferred_medium = 0
    inferred_low = 0
    team_counts = {}

    for a in assets:
        own = a.ownership[0] if a.ownership else None
        if own and (own.owner_name or own.owner_role):
            manual += 1
            team = own.team or own.owner_role or "Unknown"
        elif a.inferred_team or a.inferred_primary_user:
            conf = a.owner_confidence or "low"
            if conf == "high":
                inferred_high += 1
            elif conf == "medium":
                inferred_medium += 1
            else:
                inferred_low += 1
            team = a.inferred_team or "Unknown"
        else:
            inferred_low += 1
            team = "Unassigned"
        team_counts[team] = team_counts.get(team, 0) + 1

    return {
        "total_assets": total,
        "manual_ownership": manual,
        "inferred_high": inferred_high,
        "inferred_medium": inferred_medium,
        "inferred_low": inferred_low,
        "unassigned": total - manual - inferred_high - inferred_medium,
        "team_breakdown": [{"team": k, "count": v} for k, v in sorted(team_counts.items(), key=lambda x: -x[1])],
    }


# ─────────────────────────────────────────────
# Asset Type Rules (low-code classification)
# ─────────────────────────────────────────────

class AssetTypeRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    conditions: list = []
    condition_logic: str = "AND"
    target_asset_type: str
    identity_mapping: dict = {}
    default_attributes: dict = {}
    priority: int = 100
    source_filter: Optional[str] = None
    is_enabled: bool = True


class AssetTypeRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[list] = None
    condition_logic: Optional[str] = None
    target_asset_type: Optional[str] = None
    identity_mapping: Optional[dict] = None
    default_attributes: Optional[dict] = None
    priority: Optional[int] = None
    source_filter: Optional[str] = None
    is_enabled: Optional[bool] = None


def _asset_type_rule_to_dict(rule: AssetTypeRule) -> dict:
    return {
        "id": rule.id,
        "org_id": rule.org_id,
        "name": rule.name,
        "description": rule.description,
        "conditions": rule.conditions,
        "condition_logic": rule.condition_logic,
        "target_asset_type": rule.target_asset_type,
        "identity_mapping": rule.identity_mapping,
        "default_attributes": rule.default_attributes,
        "priority": rule.priority,
        "source_filter": rule.source_filter,
        "is_enabled": rule.is_enabled,
        "created_at": iso_utc(rule.created_at),
        "updated_at": iso_utc(rule.updated_at),
    }


@router.get("/api/asset-type-rules/condition-catalog")
def asset_type_rules_condition_catalog():
    """Return available conditions for asset-type classification rules."""
    return asset_type_rule_engine.get_condition_catalog()


@router.get("/api/asset-type-rules")
def list_asset_type_rules(
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(AssetTypeRule)
    if org_ids is not None:
        q = q.filter(AssetTypeRule.org_id.in_(org_ids))
    rules = q.order_by(AssetTypeRule.priority, AssetTypeRule.id).all()
    return [_asset_type_rule_to_dict(r) for r in rules]


@router.post("/api/asset-type-rules")
def create_asset_type_rule(
    body: AssetTypeRuleCreate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = AssetTypeRule(
        org_id=resolve_active_org_id(user, org_ids) if user else None,
        name=body.name,
        description=body.description,
        conditions=body.conditions,
        condition_logic=body.condition_logic,
        target_asset_type=body.target_asset_type,
        identity_mapping=body.identity_mapping,
        default_attributes=body.default_attributes,
        priority=body.priority,
        source_filter=body.source_filter,
        is_enabled=body.is_enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    log_audit(db, "create", "asset_type_rule", rule.id,
              entity_name=rule.name,
              changes={"target_asset_type": rule.target_asset_type, "conditions": rule.conditions},
              actor=user)
    db.commit()
    return _asset_type_rule_to_dict(rule)


def _get_asset_type_rule_in_orgs(db, rule_id, org_ids):
    q = db.query(AssetTypeRule).filter(AssetTypeRule.id == rule_id)
    if org_ids is not None:
        q = q.filter(AssetTypeRule.org_id.in_(org_ids))
    rule = q.first()
    if not rule:
        raise HTTPException(404, "Asset type rule not found")
    return rule


@router.get("/api/asset-type-rules/{rule_id}")
def get_asset_type_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    return _asset_type_rule_to_dict(_get_asset_type_rule_in_orgs(db, rule_id, org_ids))


@router.patch("/api/asset-type-rules/{rule_id}")
def update_asset_type_rule(
    rule_id: int,
    body: AssetTypeRuleUpdate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = _get_asset_type_rule_in_orgs(db, rule_id, org_ids)
    changes = {}
    for field in body.model_fields_set:
        val = getattr(body, field)
        changes[field] = val
        setattr(rule, field, val)
    log_audit(db, "update", "asset_type_rule", rule.id,
              entity_name=rule.name, changes=changes, actor=user)
    db.commit()
    db.refresh(rule)
    return _asset_type_rule_to_dict(rule)


@router.delete("/api/asset-type-rules/{rule_id}")
def delete_asset_type_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = _get_asset_type_rule_in_orgs(db, rule_id, org_ids)
    log_audit(db, "delete", "asset_type_rule", rule.id,
              entity_name=rule.name, actor=user)
    db.delete(rule)
    db.commit()
    return {"message": "Asset type rule deleted"}


@router.post("/api/asset-type-rules/test")
def test_asset_type_rule(
    body: dict,
    db: Session = Depends(get_db),
):
    """Dry-run: test a rule's conditions against sample asset data.

    Body: {"conditions": [...], "condition_logic": "AND",
           "identity_mapping": {...}, "target_asset_type": "web_app",
           "sample_asset": {"hostname": "http://...", "ip": "10.0.0.1", ...}}
    """
    sample = body.get("sample_asset", {})
    conditions = body.get("conditions", [])
    logic = body.get("condition_logic", "AND")
    mapping = body.get("identity_mapping", {})
    target = body.get("target_asset_type", "host")

    matched = rule_engine.evaluate_conditions(
        conditions=conditions,
        logic=logic,
        asset_dict=sample,
    )
    identity = asset_type_rule_engine.resolve_identity(mapping, sample) if matched else {}
    return {
        "matched": matched,
        "result_asset_type": target if matched else None,
        "result_identity": identity if matched else None,
    }


# ─────────────────────────────────────────────
# Ownership Rules
# ─────────────────────────────────────────────

class OwnershipRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    target_type: str = "asset"
    conditions: list = []
    condition_logic: str = "AND"
    priority: int = 100
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_role: Optional[str] = None
    team: Optional[str] = None
    notes: Optional[str] = None
    overwrite_existing: bool = False
    is_enabled: bool = True


class OwnershipRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target_type: Optional[str] = None
    conditions: Optional[list] = None
    condition_logic: Optional[str] = None
    priority: Optional[int] = None
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_role: Optional[str] = None
    team: Optional[str] = None
    notes: Optional[str] = None
    overwrite_existing: Optional[bool] = None
    is_enabled: Optional[bool] = None


def _ownership_rule_to_dict(rule: OwnershipRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "target_type": rule.target_type,
        "conditions": rule_engine.migrate_conditions(rule.conditions or [], mode="autotag"),
        "condition_logic": rule.condition_logic,
        "priority": rule.priority,
        "owner_name": rule.owner_name,
        "owner_email": rule.owner_email,
        "owner_role": rule.owner_role,
        "team": rule.team,
        "notes": rule.notes,
        "overwrite_existing": rule.overwrite_existing,
        "is_enabled": rule.is_enabled,
        "created_at": iso_utc(rule.created_at),
        "last_run_at": iso_utc(rule.last_run_at),
        "last_run_count": rule.last_run_count,
    }


@router.get("/api/ownership-rules")
def list_ownership_rules(
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(OwnershipRule)
    if org_ids is not None:
        q = q.filter(OwnershipRule.org_id.in_(org_ids))
    rules = q.order_by(OwnershipRule.priority, OwnershipRule.id).all()
    return [_ownership_rule_to_dict(r) for r in rules]


def _get_ownership_rule_in_orgs(db, rule_id, org_ids):
    q = db.query(OwnershipRule).filter(OwnershipRule.id == rule_id)
    if org_ids is not None:
        q = q.filter(OwnershipRule.org_id.in_(org_ids))
    rule = q.first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule


@router.post("/api/ownership-rules")
def create_ownership_rule(
    body: OwnershipRuleCreate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = OwnershipRule(
        org_id=resolve_active_org_id(user, org_ids) if user else None,
        name=body.name,
        description=body.description,
        target_type=body.target_type,
        conditions=body.conditions,
        condition_logic=body.condition_logic,
        priority=body.priority,
        owner_name=body.owner_name,
        owner_email=body.owner_email,
        owner_role=body.owner_role,
        team=body.team,
        notes=body.notes,
        overwrite_existing=body.overwrite_existing,
        is_enabled=body.is_enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _ownership_rule_to_dict(rule)


@router.patch("/api/ownership-rules/{rule_id}")
def update_ownership_rule(
    rule_id: int, body: OwnershipRuleUpdate,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = _get_ownership_rule_in_orgs(db, rule_id, org_ids)
    for field in ("name", "description", "target_type", "conditions", "condition_logic",
                  "priority", "owner_name", "owner_email", "owner_role", "team",
                  "notes", "overwrite_existing", "is_enabled"):
        val = getattr(body, field)
        if val is not None:
            setattr(rule, field, val)
    db.commit()
    return _ownership_rule_to_dict(rule)


@router.delete("/api/ownership-rules/{rule_id}")
def delete_ownership_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = _get_ownership_rule_in_orgs(db, rule_id, org_ids)
    db.delete(rule)
    db.commit()
    return {"message": "Rule deleted"}


@router.post("/api/ownership-rules/{rule_id}/run")
def run_ownership_rule_endpoint(
    rule_id: int,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    rule = _get_ownership_rule_in_orgs(db, rule_id, org_ids)
    count = tag_engine.run_ownership_rule(rule, db, scan_id=scan_id)
    return {"updated": count, "rule_id": rule_id}


@router.post("/api/ownership-rules/run-all")
def run_all_ownership_rules_endpoint(
    scan_id: Optional[int] = None,
    overwrite: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    results = tag_engine.run_all_ownership_rules(db, scan_id=scan_id, overwrite=overwrite)
    return {"results": results, "total_updated": sum(results.values())}


# ─────────────────────────────────────────────
# External Tag Sources
# ─────────────────────────────────────────────

class ExternalTagSourceCreate(BaseModel):
    name: str
    source_type: str = "csv"          # csv | servicenow | api
    match_field: str = "any"          # ip | hostname | fqdn | any
    api_url: Optional[str] = None
    api_config: dict = {}
    auto_create_tags: bool = True


class ExternalTagSourceUpdate(BaseModel):
    name: Optional[str] = None
    source_type: Optional[str] = None
    match_field: Optional[str] = None
    api_url: Optional[str] = None
    api_config: Optional[dict] = None
    auto_create_tags: Optional[bool] = None


class ExternalTagMapCreate(BaseModel):
    external_tag: str
    internal_tag_id: Optional[int] = None   # null = auto-create from external_tag string


class ExternalTagMapUpdate(BaseModel):
    external_tag: Optional[str] = None
    internal_tag_id: Optional[int] = None


def _ext_source_to_dict(src: ExternalTagSource) -> dict:
    return {
        "id": src.id,
        "name": src.name,
        "source_type": src.source_type,
        "match_field": src.match_field,
        "api_url": src.api_url,
        "api_config": {k: v for k, v in (src.api_config or {}).items() if k not in ("password", "token")},
        "auto_create_tags": src.auto_create_tags,
        "created_at": iso_utc(src.created_at),
        "last_synced_at": iso_utc(src.last_synced_at),
        "last_sync_count": src.last_sync_count,
        "last_sync_error": src.last_sync_error,
        "maps": [
            {
                "id": m.id,
                "external_tag": m.external_tag,
                "internal_tag_id": m.internal_tag_id,
                "internal_tag_label": f"{m.internal_tag.category}:{m.internal_tag.value}" if m.internal_tag else None,
                "internal_tag_color": m.internal_tag.color if m.internal_tag else None,
            }
            for m in (src.maps or [])
        ],
    }


@router.get("/api/external-tag-sources")
def list_external_tag_sources(
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(ExternalTagSource)
    if org_ids is not None:
        q = q.filter(ExternalTagSource.org_id.in_(org_ids))
    sources = q.order_by(ExternalTagSource.id).all()
    return [_ext_source_to_dict(s) for s in sources]


def _get_ext_source_in_orgs(db, source_id, org_ids):
    q = db.query(ExternalTagSource).filter(ExternalTagSource.id == source_id)
    if org_ids is not None:
        q = q.filter(ExternalTagSource.org_id.in_(org_ids))
    src = q.first()
    if not src:
        raise HTTPException(404, "Source not found")
    return src


@router.post("/api/external-tag-sources")
def create_external_tag_source(
    body: ExternalTagSourceCreate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    src = ExternalTagSource(
        org_id=resolve_active_org_id(user, org_ids) if user else None,
        name=body.name,
        source_type=body.source_type,
        match_field=body.match_field,
        api_url=body.api_url,
        api_config=body.api_config,
        auto_create_tags=body.auto_create_tags,
    )
    db.add(src)
    db.commit()
    db.refresh(src)
    return _ext_source_to_dict(src)


@router.patch("/api/external-tag-sources/{source_id}")
def update_external_tag_source(
    source_id: int, body: ExternalTagSourceUpdate,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    src = _get_ext_source_in_orgs(db, source_id, org_ids)
    for field in ("name", "source_type", "match_field", "api_url", "api_config", "auto_create_tags"):
        val = getattr(body, field)
        if val is not None:
            setattr(src, field, val)
    db.commit()
    return _ext_source_to_dict(src)


@router.delete("/api/external-tag-sources/{source_id}")
def delete_external_tag_source(
    source_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    src = _get_ext_source_in_orgs(db, source_id, org_ids)
    db.delete(src)
    db.commit()
    return {"message": "Deleted"}


# ── Tag maps per source ───────────────────────────────────

@router.post("/api/external-tag-sources/{source_id}/maps")
def upsert_external_tag_map(
    source_id: int, body: ExternalTagMapCreate,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    src = _get_ext_source_in_orgs(db, source_id, org_ids)
    if body.internal_tag_id:
        if not db.query(Tag).filter(Tag.id == body.internal_tag_id).first():
            raise HTTPException(404, "Internal tag not found")
    existing = db.query(ExternalTagMap).filter(
        ExternalTagMap.source_id == source_id,
        ExternalTagMap.external_tag == body.external_tag,
    ).first()
    if existing:
        existing.internal_tag_id = body.internal_tag_id
    else:
        existing = ExternalTagMap(source_id=source_id, external_tag=body.external_tag, internal_tag_id=body.internal_tag_id)
        db.add(existing)
    db.commit()
    db.refresh(existing)
    tag = db.query(Tag).filter(Tag.id == existing.internal_tag_id).first() if existing.internal_tag_id else None
    return {
        "id": existing.id,
        "external_tag": existing.external_tag,
        "internal_tag_id": existing.internal_tag_id,
        "internal_tag_label": f"{tag.category}:{tag.value}" if tag else None,
        "internal_tag_color": tag.color if tag else None,
    }


@router.delete("/api/external-tag-sources/{source_id}/maps/{map_id}")
def delete_external_tag_map(
    source_id: int, map_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    _get_ext_source_in_orgs(db, source_id, org_ids)
    m = db.query(ExternalTagMap).filter(ExternalTagMap.id == map_id, ExternalTagMap.source_id == source_id).first()
    if not m:
        raise HTTPException(404, "Map not found")
    db.delete(m)
    db.commit()
    return {"message": "Deleted"}


# ── Import / Sync ─────────────────────────────────────────

@router.post("/api/external-tag-sources/{source_id}/import")
async def import_external_tags(
    source_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Upload a CSV file to apply external tags. Expected columns: identifier, tags."""
    src = _get_ext_source_in_orgs(db, source_id, org_ids)
    try:
        content = (await file.read()).decode("utf-8-sig")  # strip BOM
        rows = tag_engine.parse_csv_rows(content)
        stats = tag_engine.apply_external_tags(src, rows, db)
        return stats
    except Exception as e:
        src.last_sync_error = str(e)
        db.commit()
        raise HTTPException(400, f"Import failed: {e}")


@router.post("/api/external-tag-sources/{source_id}/sync")
def sync_external_tag_source(
    source_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Pull tags from a remote API source (ServiceNow, etc.) and apply them."""
    src = _get_ext_source_in_orgs(db, source_id, org_ids)
    if src.source_type == "servicenow":
        try:
            stats = tag_engine.sync_servicenow_source(src, db)
            return stats
        except Exception as e:
            src.last_sync_error = str(e)
            db.commit()
            raise HTTPException(400, f"Sync failed: {e}")
    raise HTTPException(400, f"API sync not supported for source type '{src.source_type}'. Use /import for CSV.")
