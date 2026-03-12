"""
Tag system helpers: hierarchy traversal, auto-tag engine, filtering utilities.
Auto-tag rule evaluation is delegated to rule_engine (unified condition engine).
"""
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

import csv
import io
import re
import requests as _requests
from typing import List, Dict, Any
from models.models import Tag, TagAssignment, AutoTagRule, Asset, Finding, OwnershipRule, AssetOwnership, FindingOwnership, ExternalTagSource, ExternalTagMap
import services.rule_engine as engine


# ─────────────────────────────────────────────────────────
# Serialization
# ─────────────────────────────────────────────────────────

def _tag_to_dict(tag: Tag, db: Session = None, include_counts: bool = False) -> dict:
    d = {
        "id": tag.id,
        "category": tag.category,
        "value": tag.value,
        "label": f"{tag.category}:{tag.value}",
        "parent_id": tag.parent_id,
        "color": tag.color or "#6366f1",
        "description": tag.description,
        "created_at": tag.created_at.isoformat() if tag.created_at else None,
    }
    if include_counts and db:
        d["asset_count"] = db.query(TagAssignment).filter(
            TagAssignment.tag_id == tag.id,
            TagAssignment.asset_id.isnot(None),
        ).count()
        d["finding_count"] = db.query(TagAssignment).filter(
            TagAssignment.tag_id == tag.id,
            TagAssignment.finding_id.isnot(None),
        ).count()
    return d


def tag_assignment_info(ta: TagAssignment) -> dict:
    return {
        "tag_id": ta.tag_id,
        "label": f"{ta.tag.category}:{ta.tag.value}",
        "category": ta.tag.category,
        "value": ta.tag.value,
        "color": ta.tag.color or "#6366f1",
        "assigned_by": ta.assigned_by,
        "assigned_at": ta.assigned_at.isoformat() if ta.assigned_at else None,
    }


# ─────────────────────────────────────────────────────────
# Hierarchy
# ─────────────────────────────────────────────────────────

def get_ancestors(tag_id: int, db: Session) -> list:
    """Return ancestor tags from root → parent (excluding the tag itself)."""
    ancestors = []
    current_id = tag_id
    visited = set()
    while True:
        if current_id in visited:
            break
        visited.add(current_id)
        tag = db.query(Tag).filter(Tag.id == current_id).first()
        if not tag or not tag.parent_id:
            break
        parent = db.query(Tag).filter(Tag.id == tag.parent_id).first()
        if not parent:
            break
        ancestors.insert(0, _tag_to_dict(parent))
        current_id = parent.id
    return ancestors


def get_descendant_ids(tag_id: int, db: Session) -> list:
    """Return all descendant tag IDs (children, grandchildren, …)."""
    result = []
    queue = [tag_id]
    visited = set()
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        children = db.query(Tag).filter(Tag.parent_id == current).all()
        for child in children:
            result.append(child.id)
            queue.append(child.id)
    return result


def build_tree(tags: list, db: Session = None) -> list:
    """Build hierarchical tree dict from flat Tag list."""
    tag_dicts = {}
    for t in tags:
        d = _tag_to_dict(t, db=db, include_counts=(db is not None))
        d["children"] = []
        tag_dicts[t.id] = d

    roots = []
    for td in tag_dicts.values():
        pid = td["parent_id"]
        if pid and pid in tag_dicts:
            tag_dicts[pid]["children"].append(td)
        else:
            roots.append(td)

    def _sort(node):
        node["children"].sort(key=lambda x: (x["category"], x["value"]))
        for child in node["children"]:
            _sort(child)

    for r in roots:
        _sort(r)
    roots.sort(key=lambda x: (x["category"], x["value"]))
    return roots


# ─────────────────────────────────────────────────────────
# Tag filtering helpers (used in /api/assets and /api/findings)
# ─────────────────────────────────────────────────────────

def parse_tag_filter(tags_str: str) -> list:
    """
    Parse 'network:dmz,env:prod' → [('network','dmz'), ('env','prod')]
    """
    pairs = []
    for part in tags_str.split(","):
        part = part.strip()
        if ":" in part:
            cat, val = part.split(":", 1)
            pairs.append((cat.strip(), val.strip()))
    return pairs


def resolve_tag_ids(pairs: list, expand_children: bool, db: Session) -> list:
    """
    For each (category, value) pair resolve matching tag IDs (optionally
    including descendant IDs). Returns a list-of-lists, one per pair.
    Missing tags result in an empty inner list (→ AND logic: zero results).
    """
    result = []
    for cat, val in pairs:
        tag = db.query(Tag).filter(Tag.category == cat, Tag.value == val).first()
        if tag:
            ids = [tag.id]
            if expand_children:
                ids += get_descendant_ids(tag.id, db)
            result.append(ids)
        else:
            result.append([])  # tag not found → no matches for AND
    return result


def apply_asset_tag_filter(query, tag_id_sets: list, tag_logic: str, db: Session):
    """Apply tag filter to an Asset SQLAlchemy query."""
    from sqlalchemy import or_
    from models.models import Asset  # avoid circular at module level

    if not tag_id_sets:
        return query

    if tag_logic.upper() == "AND":
        for ids in tag_id_sets:
            if not ids:
                # no matching tag → return empty
                return query.filter(Asset.id == -1)
            subq = db.query(TagAssignment.asset_id).filter(
                TagAssignment.tag_id.in_(ids),
                TagAssignment.asset_id.isnot(None),
            ).subquery()
            query = query.filter(Asset.id.in_(subq))
    else:  # OR
        all_ids = [i for ids in tag_id_sets for i in ids]
        if not all_ids:
            return query.filter(Asset.id == -1)
        subq = db.query(TagAssignment.asset_id).filter(
            TagAssignment.tag_id.in_(all_ids),
            TagAssignment.asset_id.isnot(None),
        ).subquery()
        query = query.filter(Asset.id.in_(subq))

    return query


def apply_finding_tag_filter(query, tag_id_sets: list, tag_logic: str, db: Session):
    """Apply tag filter to a Finding SQLAlchemy query.
    A finding matches if it is directly tagged OR its parent asset is tagged.
    """
    from sqlalchemy import or_
    from models.models import Finding

    if not tag_id_sets:
        return query

    def _finding_ids_for_tag_ids(ids):
        """Return a subquery of finding IDs matched by a set of tag IDs (direct or via asset)."""
        direct_subq = db.query(TagAssignment.finding_id).filter(
            TagAssignment.tag_id.in_(ids),
            TagAssignment.finding_id.isnot(None),
        )
        asset_subq = db.query(TagAssignment.asset_id).filter(
            TagAssignment.tag_id.in_(ids),
            TagAssignment.asset_id.isnot(None),
        )
        return db.query(Finding.id).filter(
            or_(
                Finding.id.in_(direct_subq),
                Finding.asset_id.in_(asset_subq),
            )
        ).subquery()

    if tag_logic.upper() == "AND":
        for ids in tag_id_sets:
            if not ids:
                return query.filter(Finding.id == -1)
            query = query.filter(Finding.id.in_(_finding_ids_for_tag_ids(ids)))
    else:
        all_ids = [i for ids in tag_id_sets for i in ids]
        if not all_ids:
            return query.filter(Finding.id == -1)
        query = query.filter(Finding.id.in_(_finding_ids_for_tag_ids(all_ids)))

    return query


def get_asset_tags(asset_ids: list, db: Session) -> dict:
    """Bulk-fetch tags for a list of asset IDs. Returns {asset_id: [tag_info, …]}."""
    if not asset_ids:
        return {}
    rows = (
        db.query(TagAssignment)
        .filter(
            TagAssignment.asset_id.in_(asset_ids),
            TagAssignment.asset_id.isnot(None),
        )
        .all()
    )
    result = {aid: [] for aid in asset_ids}
    for ta in rows:
        result[ta.asset_id].append(tag_assignment_info(ta))
    return result


def get_finding_tags(finding_ids: list, db: Session) -> dict:
    """Bulk-fetch tags for a list of finding IDs. Returns {finding_id: [tag_info, …]}."""
    if not finding_ids:
        return {}
    rows = (
        db.query(TagAssignment)
        .filter(
            TagAssignment.finding_id.in_(finding_ids),
            TagAssignment.finding_id.isnot(None),
        )
        .all()
    )
    result = {fid: [] for fid in finding_ids}
    for ta in rows:
        result[ta.finding_id].append(tag_assignment_info(ta))
    return result


# ─────────────────────────────────────────────────────────
# Auto-tag runner (delegates to unified rule_engine)
# ─────────────────────────────────────────────────────────

def _asset_dict(asset: Asset) -> dict:
    return {
        "ip": asset.ip, "hostname": asset.hostname, "fqdn": asset.fqdn,
        "os": asset.os, "netbios_name": asset.netbios_name,
        "environment_tag": asset.environment_tag,
        "criticality": asset.criticality or 5,
        "risk_score": asset.risk_score or 0.0,
        "critical_count": asset.critical_count or 0,
        "high_count": asset.high_count or 0,
        "medium_count": asset.medium_count or 0,
        "low_count": asset.low_count or 0,
        "info_count": asset.info_count or 0,
    }


def _get_or_create_tag(label: str, org_id, db: Session) -> Optional[Tag]:
    """Find or create a tag by category:value label. label may be 'cat:val' or just 'val'."""
    if not label:
        return None
    if ":" in label:
        category, value = label.split(":", 1)
    else:
        category, value = "auto", label
    tag = db.query(Tag).filter(Tag.category == category, Tag.value == value).first()
    if not tag:
        tag = Tag(category=category, value=value, color="#6366f1", org_id=org_id)
        db.add(tag)
        db.flush()
    return tag


def run_auto_tag_rule(rule: AutoTagRule, db: Session, scan_id: Optional[int] = None) -> int:
    """Execute one auto-tag rule. Returns number of new assignments created."""
    conditions = engine.migrate_conditions(rule.conditions or [], mode="autotag")
    logic = rule.condition_logic or "AND"
    count = 0

    # ── Passthrough mode: read field value → auto-create tag from value ────────
    cond0 = (rule.conditions or [{}])[0]
    if cond0.get("op") == "passthrough":
        field = cond0.get("field", "")
        prefix = cond0.get("value", "") or ""

        # Remove previous assignments made by this rule so stale tags are cleaned up
        db.query(TagAssignment).filter(
            TagAssignment.assigned_by == f"rule:{rule.id}"
        ).delete(synchronize_session=False)
        db.flush()

        if rule.target_type in ("asset", "both"):
            aq = db.query(Asset)
            if scan_id:
                aq = aq.filter(Asset.scan_id == scan_id)
            for asset in aq.all():
                raw = _asset_dict(asset).get(field)
                if raw is None:
                    continue
                label = f"{prefix}:{raw}" if prefix else str(raw)
                tag = _get_or_create_tag(label, rule.org_id, db)
                if not tag:
                    continue
                db.add(TagAssignment(tag_id=tag.id, asset_id=asset.id, assigned_by=f"rule:{rule.id}"))
                count += 1

        if rule.target_type in ("finding", "both"):
            fq = db.query(Finding)
            if scan_id:
                fq = fq.filter(Finding.scan_id == scan_id)
            for finding in fq.all():
                raw = getattr(finding, field, None)
                if raw is None:
                    continue
                label = f"{prefix}:{raw}" if prefix else str(raw)
                tag = _get_or_create_tag(label, rule.org_id, db)
                if not tag:
                    continue
                db.add(TagAssignment(tag_id=tag.id, finding_id=finding.id, assigned_by=f"rule:{rule.id}"))
                count += 1

        db.commit()
        rule.last_run_at = datetime.utcnow()
        rule.last_run_count = count
        db.commit()
        return count

    # ── Standard condition matching ────────────────────────────────────────────
    if rule.target_type in ("asset", "both"):
        aq = db.query(Asset)
        if scan_id:
            aq = aq.filter(Asset.scan_id == scan_id)
        for asset in aq.all():
            if engine.evaluate_conditions(
                conditions, logic,
                asset_dict=_asset_dict(asset),
                db=db, asset_id=asset.id, scan_id=scan_id,
            ):
                exists = db.query(TagAssignment).filter(
                    TagAssignment.tag_id == rule.tag_id,
                    TagAssignment.asset_id == asset.id,
                ).first()
                if not exists:
                    db.add(TagAssignment(
                        tag_id=rule.tag_id,
                        asset_id=asset.id,
                        assigned_by=f"rule:{rule.id}",
                    ))
                    count += 1

    if rule.target_type in ("finding", "both"):
        fq = db.query(Finding)
        if scan_id:
            fq = fq.filter(Finding.scan_id == scan_id)
        for finding in fq.all():
            parent_asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
            ad = _asset_dict(parent_asset) if parent_asset else {}
            if engine.evaluate_conditions_for_finding(conditions, logic, finding, asset_dict=ad):
                exists = db.query(TagAssignment).filter(
                    TagAssignment.tag_id == rule.tag_id,
                    TagAssignment.finding_id == finding.id,
                ).first()
                if not exists:
                    db.add(TagAssignment(
                        tag_id=rule.tag_id,
                        finding_id=finding.id,
                        assigned_by=f"rule:{rule.id}",
                    ))
                    count += 1

    db.commit()
    rule.last_run_at = datetime.utcnow()
    rule.last_run_count = count
    db.commit()
    return count


def run_all_auto_tag_rules(db: Session, scan_id: Optional[int] = None) -> dict:
    """Run all enabled auto-tag rules. Returns {rule_id: tagged_count}."""
    rules = db.query(AutoTagRule).filter(AutoTagRule.is_enabled == True).all()
    return {r.id: run_auto_tag_rule(r, db, scan_id=scan_id) for r in rules}


# ─────────────────────────────────────────────────────────
# Ownership Rule Engine
# ─────────────────────────────────────────────────────────

def run_ownership_rule(rule: OwnershipRule, db: Session, scan_id: Optional[int] = None, overwrite: Optional[bool] = None) -> int:
    """Execute one ownership rule. Returns number of assets/findings updated."""
    conditions = engine.migrate_conditions(rule.conditions or [], mode="autotag")
    logic = rule.condition_logic or "AND"
    count = 0

    # ── Passthrough mode: read field value → use as ownership attribute ────────
    cond0 = (rule.conditions or [{}])[0]
    if cond0.get("op") == "passthrough":
        field = cond0.get("field", "")
        assign_to = cond0.get("value", "owner_name")  # which ownership attr to set

        should_overwrite = overwrite if overwrite is not None else True  # passthrough always overwrites by default

        if rule.target_type in ("asset", "both"):
            aq = db.query(Asset)
            if scan_id:
                aq = aq.filter(Asset.scan_id == scan_id)
            for asset in aq.all():
                raw = _asset_dict(asset).get(field) or getattr(asset, field, None)
                if raw is None:
                    continue
                ownership = db.query(AssetOwnership).filter(AssetOwnership.asset_id == asset.id).first()
                if ownership and not should_overwrite:
                    continue
                if not ownership:
                    ownership = AssetOwnership(asset_id=asset.id)
                    db.add(ownership)
                setattr(ownership, assign_to, str(raw))
                count += 1

        if rule.target_type in ("finding", "both"):
            fq = db.query(Finding)
            if scan_id:
                fq = fq.filter(Finding.scan_id == scan_id)
            for finding in fq.all():
                parent_asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
                ad = _asset_dict(parent_asset) if parent_asset else {}
                raw = ad.get(field) or getattr(finding, field, None)
                if raw is None:
                    continue
                ownership = db.query(FindingOwnership).filter(FindingOwnership.finding_id == finding.id).first()
                if ownership and not should_overwrite:
                    continue
                if not ownership:
                    ownership = FindingOwnership(finding_id=finding.id)
                    db.add(ownership)
                setattr(ownership, assign_to, str(raw))
                count += 1

        db.commit()
        rule.last_run_at = datetime.utcnow()
        rule.last_run_count = count
        db.commit()
        return count

    # ── Standard condition matching ────────────────────────────────────────────
    action = {k: v for k, v in {
        "owner_name": rule.owner_name,
        "owner_email": rule.owner_email,
        "owner_role": rule.owner_role,
        "team": rule.team,
        "notes": rule.notes,
    }.items() if v is not None}

    if not action:
        return 0

    should_overwrite = overwrite if overwrite is not None else rule.overwrite_existing

    if rule.target_type in ("asset", "both"):
        aq = db.query(Asset)
        if scan_id:
            aq = aq.filter(Asset.scan_id == scan_id)
        for asset in aq.all():
            if not engine.evaluate_conditions(
                conditions, logic,
                asset_dict=_asset_dict(asset),
                db=db, asset_id=asset.id, scan_id=scan_id,
            ):
                continue
            ownership = db.query(AssetOwnership).filter(AssetOwnership.asset_id == asset.id).first()
            if ownership and not should_overwrite:
                continue
            if not ownership:
                ownership = AssetOwnership(asset_id=asset.id)
                db.add(ownership)
            for k, v in action.items():
                setattr(ownership, k, v)
            count += 1

    if rule.target_type in ("finding", "both"):
        fq = db.query(Finding)
        if scan_id:
            fq = fq.filter(Finding.scan_id == scan_id)
        for finding in fq.all():
            parent_asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
            ad = _asset_dict(parent_asset) if parent_asset else {}
            if not engine.evaluate_conditions_for_finding(conditions, logic, finding, asset_dict=ad):
                continue
            ownership = db.query(FindingOwnership).filter(FindingOwnership.finding_id == finding.id).first()
            if ownership and not should_overwrite:
                continue
            if not ownership:
                ownership = FindingOwnership(finding_id=finding.id)
                db.add(ownership)
            for k, v in action.items():
                setattr(ownership, k, v)
            count += 1

    db.commit()
    rule.last_run_at = datetime.utcnow()
    rule.last_run_count = count
    db.commit()
    return count


def run_all_ownership_rules(db: Session, scan_id: Optional[int] = None, overwrite: Optional[bool] = None) -> dict:
    """Run all enabled ownership rules ordered by priority. Returns {rule_id: count}."""
    rules = (
        db.query(OwnershipRule)
        .filter(OwnershipRule.is_enabled == True)
        .order_by(OwnershipRule.priority)
        .all()
    )
    return {r.id: run_ownership_rule(r, db, scan_id=scan_id, overwrite=overwrite) for r in rules}


# ─────────────────────────────────────────────────────────
# External Tag Sync Engine
# ─────────────────────────────────────────────────────────

def parse_csv_rows(content: str) -> List[Dict[str, Any]]:
    """Parse CSV into list of {identifier, tags[]}.

    Supported formats:
      identifier,tag1|tag2|tag3          (pipe-separated tags in one column)
      identifier,tag1,tag2,tag3          (one tag per extra column)
      ip_address,hostname,tag1|tag2      (two identifier columns)
    The first row that is NOT a valid IP and NOT 'identifier'/'ip'/'hostname'
    is treated as a header. Header detection is automatic.
    """
    rows = []
    reader = csv.reader(io.StringIO(content.strip()))
    headers = None
    for raw in reader:
        if not raw or all(c.strip() == '' for c in raw):
            continue
        cells = [c.strip() for c in raw]
        # Auto-detect header row
        if headers is None:
            lower = [h.lower() for h in cells]
            if any(h in ('identifier', 'ip', 'ip_address', 'hostname', 'fqdn', 'name', 'host') for h in lower):
                headers = lower
                continue
            else:
                # No header — assume col0=identifier, rest=tags
                headers = []

        if not headers:
            # Headerless: col0=identifier, remaining cols are tag values (or pipe-sep in col1)
            identifier = cells[0]
            raw_tags = cells[1:] if len(cells) > 1 else []
        else:
            # Try to find identifier column
            id_col = next((i for i, h in enumerate(headers)
                           if h in ('identifier', 'ip', 'ip_address', 'fqdn', 'hostname', 'name', 'host')), 0)
            identifier = cells[id_col] if id_col < len(cells) else cells[0]
            # Remaining columns or a 'tags'/'tag' column
            tag_col = next((i for i, h in enumerate(headers) if h in ('tags', 'tag', 'labels', 'label')), None)
            if tag_col is not None and tag_col < len(cells):
                raw_tags = [cells[tag_col]]
            else:
                raw_tags = [cells[i] for i in range(len(cells)) if i != id_col]

        # Split pipe/comma separated tags, strip empty
        tags = []
        for rt in raw_tags:
            tags.extend(t.strip() for t in re.split(r'[|,;]', rt) if t.strip())

        if identifier and tags:
            rows.append({"identifier": identifier, "tags": tags})
    return rows


def _resolve_internal_tag(external_tag: str, source: ExternalTagSource, db: Session) -> Optional[Tag]:
    """Find or create the internal Tag for a given external_tag string."""
    # Check for an explicit mapping first
    mapping = db.query(ExternalTagMap).filter(
        ExternalTagMap.source_id == source.id,
        ExternalTagMap.external_tag == external_tag,
    ).first()
    if mapping and mapping.internal_tag_id:
        return db.query(Tag).filter(Tag.id == mapping.internal_tag_id).first()
    if mapping and not mapping.internal_tag_id and not source.auto_create_tags:
        return None  # Mapping exists but says "skip"

    # Auto-create: parse "category:value" or use "external" as category
    if ':' in external_tag:
        category, value = external_tag.split(':', 1)
    else:
        category, value = 'external', external_tag

    category = category.strip().lower()
    value = value.strip().lower()

    tag = db.query(Tag).filter(Tag.category == category, Tag.value == value).first()
    if not tag and source.auto_create_tags:
        tag = Tag(category=category, value=value, color='#6366f1')
        db.add(tag)
        db.flush()
        # Record the auto-created mapping
        if not mapping:
            db.add(ExternalTagMap(source_id=source.id, external_tag=external_tag, internal_tag_id=tag.id))
        elif not mapping.internal_tag_id:
            mapping.internal_tag_id = tag.id
    return tag


def _find_assets_by_identifier(identifier: str, match_field: str, db: Session) -> List[Asset]:
    """Find assets matching the identifier by IP, hostname, FQDN, or all three."""
    identifier = identifier.strip().lower()
    fields = {
        'ip': [Asset.ip],
        'hostname': [Asset.hostname, Asset.netbios_name],
        'fqdn': [Asset.fqdn],
        'any': [Asset.ip, Asset.hostname, Asset.fqdn, Asset.netbios_name],
    }.get(match_field, [Asset.ip, Asset.hostname, Asset.fqdn, Asset.netbios_name])

    from sqlalchemy import or_, func
    conditions = [func.lower(f) == identifier for f in fields if f is not None]
    if not conditions:
        return []
    return db.query(Asset).filter(or_(*conditions)).all()


def apply_external_tags(
    source: ExternalTagSource,
    rows: List[Dict[str, Any]],
    db: Session,
) -> Dict[str, int]:
    """Apply external tag rows to matching assets. Returns stats dict."""
    stats = {"assets_matched": 0, "tags_applied": 0, "tags_created": 0, "unmatched": 0}
    matched_asset_ids = set()

    for row in rows:
        identifier = row.get("identifier", "")
        external_tags = row.get("tags", [])
        assets = _find_assets_by_identifier(identifier, source.match_field, db)

        if not assets:
            stats["unmatched"] += 1
            continue

        for asset in assets:
            matched_asset_ids.add(asset.id)
            for ext_tag in external_tags:
                tag = _resolve_internal_tag(ext_tag, source, db)
                if not tag:
                    continue
                is_new = tag.id is None  # freshly flushed but not yet in db
                db.flush()
                if is_new or not db.query(Tag).filter(Tag.id == tag.id).first():
                    stats["tags_created"] += 1
                existing = db.query(TagAssignment).filter(
                    TagAssignment.tag_id == tag.id,
                    TagAssignment.asset_id == asset.id,
                ).first()
                if not existing:
                    db.add(TagAssignment(
                        tag_id=tag.id,
                        asset_id=asset.id,
                        assigned_by=f"external:{source.id}",
                    ))
                    stats["tags_applied"] += 1

    stats["assets_matched"] = len(matched_asset_ids)
    db.commit()

    source.last_synced_at = datetime.utcnow()
    source.last_sync_count = stats["assets_matched"]
    source.last_sync_error = None
    db.commit()
    return stats


def sync_servicenow_source(source: ExternalTagSource, db: Session) -> Dict[str, int]:
    """Pull CMDB data from ServiceNow and apply tags."""
    cfg = source.api_config or {}
    instance_url = (source.api_url or "").rstrip("/")
    if not instance_url:
        raise ValueError("ServiceNow instance URL not configured")

    auth_type = cfg.get("auth_type", "basic")
    id_field  = cfg.get("id_field", "ip_address")   # ServiceNow field for asset identifier
    tag_field = cfg.get("tag_field", "sys_tags")     # ServiceNow field containing tags
    table     = cfg.get("table", "cmdb_ci_computer")

    headers_map = {"Accept": "application/json", "Content-Type": "application/json"}
    auth = None
    if auth_type == "basic":
        auth = (cfg.get("username", ""), cfg.get("password", ""))
    elif auth_type == "token":
        headers_map["Authorization"] = f"Bearer {cfg.get('token', '')}"

    url = f"{instance_url}/api/now/table/{table}"
    params = {
        "sysparm_fields": f"{id_field},{tag_field}",
        "sysparm_limit": 10000,
    }
    resp = _requests.get(url, params=params, headers=headers_map, auth=auth, timeout=30)
    resp.raise_for_status()
    records = resp.json().get("result", [])

    rows = []
    for rec in records:
        identifier = rec.get(id_field, "")
        raw_tags   = rec.get(tag_field, "")
        if not identifier:
            continue
        tags = [t.strip() for t in re.split(r'[,|;]', str(raw_tags)) if t.strip()]
        if tags:
            rows.append({"identifier": identifier, "tags": tags})

    return apply_external_tags(source, rows, db)


# ─────────────────────────────────────────────────────────
# Condition catalog — proxies to unified rule_engine catalog
# ─────────────────────────────────────────────────────────

CONDITION_CATALOG = engine.CONDITION_CATALOG
