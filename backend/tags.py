"""
Tag system helpers: hierarchy traversal, auto-tag engine, filtering utilities.
Auto-tag rule evaluation is delegated to rule_engine (unified condition engine).
"""
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from models import Tag, TagAssignment, AutoTagRule, Asset, Finding
import rule_engine as engine


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
    from models import Asset  # avoid circular at module level

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
    """Apply tag filter to a Finding SQLAlchemy query."""
    from models import Finding

    if not tag_id_sets:
        return query

    if tag_logic.upper() == "AND":
        for ids in tag_id_sets:
            if not ids:
                return query.filter(Finding.id == -1)
            subq = db.query(TagAssignment.finding_id).filter(
                TagAssignment.tag_id.in_(ids),
                TagAssignment.finding_id.isnot(None),
            ).subquery()
            query = query.filter(Finding.id.in_(subq))
    else:
        all_ids = [i for ids in tag_id_sets for i in ids]
        if not all_ids:
            return query.filter(Finding.id == -1)
        subq = db.query(TagAssignment.finding_id).filter(
            TagAssignment.tag_id.in_(all_ids),
            TagAssignment.finding_id.isnot(None),
        ).subquery()
        query = query.filter(Finding.id.in_(subq))

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
        "criticality": asset.criticality or 3,
        "risk_score": asset.risk_score or 0.0,
        "critical_count": asset.critical_count or 0,
        "high_count": asset.high_count or 0,
        "medium_count": asset.medium_count or 0,
        "low_count": asset.low_count or 0,
        "info_count": asset.info_count or 0,
    }


def run_auto_tag_rule(rule: AutoTagRule, db: Session, scan_id: Optional[int] = None) -> int:
    """Execute one auto-tag rule. Returns number of new assignments created."""
    # Migrate any old-format conditions to the unified format
    conditions = engine.migrate_conditions(rule.conditions or [], mode="autotag")
    logic = rule.condition_logic or "AND"
    count = 0

    # ── Asset-level tagging ────────────────────────────────────────────────────
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

    # ── Finding-level tagging ──────────────────────────────────────────────────
    if rule.target_type in ("finding", "both"):
        fq = db.query(Finding)
        if scan_id:
            fq = fq.filter(Finding.scan_id == scan_id)
        for finding in fq.all():
            # Evaluate finding conditions against the finding itself,
            # asset conditions against its parent asset
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
# Condition catalog — proxies to unified rule_engine catalog
# ─────────────────────────────────────────────────────────

CONDITION_CATALOG = engine.CONDITION_CATALOG
