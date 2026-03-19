"""
Configurable deduplication engine for Hakuna Remediation Platform.

Supports three strategies per entity type:
  keep_first  — on duplicate key, keep the record already in DB / seen first
  keep_last   — on duplicate key, replace with the newer record
  merge       — union of list fields, OR of bool fields, first non-null for scalars
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import or_

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent / "config" / "dedup_config.json"

# ─────────────────────────────────────────────
# Key field options per entity type
# ─────────────────────────────────────────────

KEY_FIELD_OPTIONS: dict[str, list[str]] = {
    "assets": ["ip", "hostname", "fqdn", "netbios_name"],
    "findings": ["plugin_id", "asset_id", "port", "protocol", "cve"],
    "users": ["username", "domain", "sid"],
    "groups": ["group_name", "domain", "sid"],
    "computers": ["computer_name", "sid", "dns_hostname"],
    "services": ["service_name", "asset_id"],
    "software": ["name", "version", "asset_id"],
    "shares": ["share_name", "asset_id"],
    "netconns": ["local_addr", "local_port", "remote_addr", "remote_port", "asset_id"],
    "patches": ["kb_id", "asset_id"],
    "security_controls": ["control_type", "asset_id"],
    "password_policies": ["domain"],
    "logged_on": ["username", "domain", "asset_id"],
    "scheduled_tasks": ["task_uri", "asset_id"],
    "env_vars": ["name", "asset_id"],
    "processes": ["process_name", "pid", "asset_id"],
    "certificates": ["subject_cn", "serial_number", "asset_id"],
    "database_instances": ["db_type", "instance_name", "port", "asset_id"],
}

# ─────────────────────────────────────────────
# Default configuration
# ─────────────────────────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "apply_on_upload": True,
    "assets": {
        "enabled": True,
        "key_fields": ["ip"],
        "key_mode": "or",
        "strategy": "merge",
        "scope": "cross_scan",
    },
    "findings": {
        "enabled": False,
        "key_fields": ["plugin_id", "asset_id", "port"],
        "strategy": "keep_last",
        "scope": "cross_scan",
    },
    "inventory": {
        "users": {
            "enabled": True,
            "key_fields": ["username", "domain"],
            "strategy": "merge",
        },
        "groups": {
            "enabled": True,
            "key_fields": ["group_name", "domain"],
            "strategy": "merge",
        },
        "computers": {
            "enabled": True,
            "key_fields": ["computer_name", "sid"],
            "strategy": "merge",
        },
        "services": {
            "enabled": True,
            "key_fields": ["service_name", "asset_id"],
            "strategy": "merge",
        },
        "software": {
            "enabled": True,
            "key_fields": ["name", "version", "asset_id"],
            "strategy": "keep_first",
        },
        "shares": {
            "enabled": True,
            "key_fields": ["share_name", "asset_id"],
            "strategy": "merge",
        },
        "netconns": {
            "enabled": False,
            "key_fields": ["local_addr", "local_port", "remote_addr", "remote_port", "asset_id"],
            "strategy": "keep_first",
        },
        "patches": {
            "enabled": True,
            "key_fields": ["kb_id", "asset_id"],
            "strategy": "keep_last",
        },
        "security_controls": {
            "enabled": True,
            "key_fields": ["control_type", "asset_id"],
            "strategy": "merge",
        },
        "password_policies": {
            "enabled": True,
            "key_fields": ["domain"],
            "strategy": "merge",
        },
        "logged_on": {
            "enabled": True,
            "key_fields": ["username", "domain", "asset_id"],
            "strategy": "keep_last",
        },
        "scheduled_tasks": {
            "enabled": True,
            "key_fields": ["task_uri", "asset_id"],
            "strategy": "merge",
        },
        "env_vars": {
            "enabled": True,
            "key_fields": ["name", "asset_id"],
            "strategy": "keep_last",
        },
        "processes": {
            "enabled": False,
            "key_fields": ["process_name", "pid", "asset_id"],
            "strategy": "keep_last",
        },
        "certificates": {
            "enabled": True,
            "key_fields": ["subject_cn", "serial_number", "asset_id"],
            "strategy": "keep_last",
        },
        "database_instances": {
            "enabled": True,
            "key_fields": ["db_type", "instance_name", "port", "asset_id"],
            "strategy": "keep_last",
        },
    },
}


# ─────────────────────────────────────────────
# Config I/O
# ─────────────────────────────────────────────

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning new dict."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config() -> dict:
    """Load dedup config from disk, deep-merged with defaults."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                on_disk = json.load(f)
            return _deep_merge(DEFAULT_CONFIG, on_disk)
        except Exception as e:
            logger.warning(f"Failed to load dedup config: {e}; using defaults")
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    """Persist dedup config to disk."""
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


# ─────────────────────────────────────────────
# Core dedup logic
# ─────────────────────────────────────────────

# Fields that expand into per-element matching (list field → singular config name)
_LIST_EXPAND_FIELDS: dict[str, str] = {
    "cve": "cves",  # key_field "cve" expands each element of the "cves" list column
}


def _make_keys(record: dict, key_fields: list[str], key_mode: str = "and") -> list[tuple]:
    """Build hashable key(s) from selected fields.

    key_mode="or" (OR-style):
        Each non-null scalar key field produces its own key so that records
        matching on *any* field are considered duplicates.  Good for assets
        where same IP = same asset regardless of FQDN.

    key_mode="and" (AND-style / composite):
        All key fields together form a single composite key.  Records must
        match on ALL fields to be considered duplicates.  Good for inventory
        entities like users (username + domain together identify a user).

    List-expand fields (e.g. "cve" → "cves") produce one key per element.
    Returns [] only if ALL key fields are missing/None.
    """
    if key_mode == "or":
        # OR-style: each field is its own key
        keys: list[tuple] = []
        for field in key_fields:
            col_name = _LIST_EXPAND_FIELDS.get(field)
            if col_name:
                vals = record.get(col_name)
                if vals and isinstance(vals, list):
                    for v in vals:
                        keys.append((field, str(v)))
            else:
                val = record.get(field)
                if val is not None and val != "":
                    keys.append((field, str(val)))
        return keys
    else:
        # AND-style: all fields form a single composite key
        parts = []
        has_any = False
        for field in key_fields:
            col_name = _LIST_EXPAND_FIELDS.get(field)
            if col_name:
                vals = record.get(col_name)
                if vals and isinstance(vals, list):
                    parts.append((field, tuple(sorted(str(v) for v in vals))))
                    has_any = True
                else:
                    parts.append((field, ()))
            else:
                val = record.get(field)
                if val is not None and val != "":
                    parts.append((field, str(val)))
                    has_any = True
                else:
                    parts.append((field, None))
        return [tuple(parts)] if has_any else []


def _is_ip_like(val: str) -> bool:
    """Check if a string looks like an IP address."""
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val))


def _merge_dicts(first: dict, second: dict) -> dict:
    """
    Merge two records using the merge strategy:
      - list fields → union (deduplicated)
      - bool fields → OR
      - scalar fields → first non-null value wins, but prefer
        richer values (e.g. real hostname over IP-as-hostname)
    """
    result = dict(first)
    for k, v in second.items():
        existing = result.get(k)
        if existing is None:
            result[k] = v
        elif isinstance(existing, list) and isinstance(v, list):
            # Union preserving order
            seen = set()
            merged_list = []
            for item in existing + v:
                key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                if key not in seen:
                    seen.add(key)
                    merged_list.append(item)
            result[k] = merged_list
        elif isinstance(existing, bool) and isinstance(v, bool):
            result[k] = existing or v
        elif k == "hostname" and isinstance(existing, str) and isinstance(v, str):
            # Prefer a real hostname over an IP-as-hostname
            if _is_ip_like(existing) and not _is_ip_like(v):
                result[k] = v
        # else: first non-null wins (already set)
    return result


def dedup_records(records: list[dict], key_fields: list[str], strategy: str, key_mode: str = "and") -> list[dict]:
    """
    Deduplicate a list of in-memory dicts.

    key_mode: "and" = composite key (all fields must match), "or" = any field match.
    Returns a new list with duplicates resolved per strategy.
    """
    if not records or not key_fields:
        return records

    seen: dict[tuple, dict] = {}  # key → record
    no_key: list[dict] = []       # records with None key (always kept)
    kept: dict[int, dict] = {}    # id(rec) → rec, to avoid adding duplicates to result

    for rec in records:
        keys = _make_keys(rec, key_fields, key_mode=key_mode)
        if not keys:
            no_key.append(rec)
            continue

        # Check if any key already maps to an existing record
        existing = None
        for k in keys:
            if k in seen:
                existing = seen[k]
                break

        if existing is None:
            # New record — register all its keys
            for k in keys:
                seen[k] = rec
            kept[id(rec)] = rec
        else:
            # Duplicate — apply strategy
            if strategy == "keep_last":
                # Replace: point all old keys to new rec, add new keys
                for k in keys:
                    seen[k] = rec
                # Remove old from kept, add new
                kept.pop(id(existing), None)
                kept[id(rec)] = rec
            elif strategy == "merge":
                merged = _merge_dicts(existing, rec)
                # Update all keys (old + new) to point to merged
                for k in keys:
                    seen[k] = merged
                # Also update any keys that pointed to existing
                for k, v in seen.items():
                    if v is existing:
                        seen[k] = merged
                kept.pop(id(existing), None)
                kept[id(merged)] = merged
            # keep_first: do nothing

    return list(kept.values()) + no_key


def dedup_inventory(inventory: dict, cfg: dict) -> dict:
    """
    Apply dedup to the full inventory dict returned by extract_inventory_from_findings.

    cfg is the full loaded config (from load_config()).
    Returns a new inventory dict with duplicates removed/merged.
    """
    if not cfg.get("enabled") or not cfg.get("apply_on_upload"):
        return inventory

    inv_cfg = cfg.get("inventory", {})
    result = {}

    # Map inventory_extractor keys → dedup config keys
    KEY_MAP = {
        "users": "users",
        "groups": "groups",
        "services": "services",
        "netconns": "netconns",
        "scheduled_tasks": "scheduled_tasks",
        "patches": "patches",
        "logged_on": "logged_on",
        "shares": "shares",
        "software": "software",
        "security_controls": "security_controls",
        "computers": "computers",
        "password_policies": "password_policies",
        "env_vars": "env_vars",
        "processes": "processes",
        "certificates": "certificates",
        "ai_tools": "ai_tools",
        "database_instances": "database_instances",
    }

    for inv_key, dedup_key in KEY_MAP.items():
        records = inventory.get(inv_key, [])
        entity_cfg = inv_cfg.get(dedup_key, {})
        if records and entity_cfg.get("enabled", True):
            before = len(records)
            records = dedup_records(
                records,
                entity_cfg.get("key_fields", []),
                entity_cfg.get("strategy", "keep_first"),
                key_mode=entity_cfg.get("key_mode", "and"),
            )
            after = len(records)
            if before != after:
                logger.info(f"Dedup {inv_key}: {before} → {after} records")
        result[inv_key] = records

    return result


# ─────────────────────────────────────────────
# DB-level dedup (on-demand)
# ─────────────────────────────────────────────

def _merge_model_row(existing, incoming, strategy: str, list_fields: set[str], bool_fields: set[str]):
    """Apply merge strategy to two SQLAlchemy model instances (in-place on existing)."""
    if strategy == "keep_first":
        return  # nothing to do
    for col in incoming.__table__.columns:
        attr = col.name
        if attr in ("id", "scan_id", "asset_id"):
            continue
        new_val = getattr(incoming, attr, None)
        old_val = getattr(existing, attr, None)
        if strategy == "keep_last":
            if new_val is not None:
                setattr(existing, attr, new_val)
        elif strategy == "merge":
            if attr in list_fields and isinstance(old_val, list) and isinstance(new_val, list):
                merged = list(old_val)
                seen_set = {json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x) for x in merged}
                for item in new_val:
                    key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                    if key not in seen_set:
                        merged.append(item)
                        seen_set.add(key)
                setattr(existing, attr, merged)
            elif attr in bool_fields and isinstance(old_val, bool) and isinstance(new_val, bool):
                setattr(existing, attr, old_val or new_val)
            elif old_val is None and new_val is not None:
                setattr(existing, attr, new_val)
            elif attr == "hostname" and isinstance(old_val, str) and isinstance(new_val, str):
                # Prefer a real hostname over an IP-as-hostname
                if _is_ip_like(old_val) and not _is_ip_like(new_val):
                    setattr(existing, attr, new_val)


def _merge_source_systems(survivor, donor) -> None:
    """Merge source_systems lists from donor into survivor (union, preserving order)."""
    current = survivor.source_systems or []
    donor_sources = donor.source_systems or []
    merged = list(current)
    for src in donor_sources:
        if src and src not in merged:
            merged.append(src)
    if merged != current:
        survivor.source_systems = merged


def _reassign_asset_children(db, old_asset_id: int, new_asset_id: int, ENTITY_MODEL_MAP: dict) -> None:
    """
    Before deleting a duplicate asset, reassign all its child records
    (findings + all inventory types + ownership) to the surviving asset.
    This prevents cascade-deletion of findings and inventory orphaning.
    """
    from models.models import Finding, AssetOwnership, TagAssignment
    db.query(Finding).filter(Finding.asset_id == old_asset_id).update(
        {"asset_id": new_asset_id}, synchronize_session=False
    )
    # Reassign or delete ownership records (unique constraint on asset_id)
    if db.query(AssetOwnership).filter(AssetOwnership.asset_id == new_asset_id).first():
        db.query(AssetOwnership).filter(AssetOwnership.asset_id == old_asset_id).delete(synchronize_session=False)
    else:
        db.query(AssetOwnership).filter(AssetOwnership.asset_id == old_asset_id).update(
            {"asset_id": new_asset_id}, synchronize_session=False
        )
    # Reassign tag assignments (delete dupes to avoid unique violations)
    existing_tags = {
        ta.tag_id for ta in
        db.query(TagAssignment).filter(TagAssignment.asset_id == new_asset_id).all()
    }
    for ta in db.query(TagAssignment).filter(TagAssignment.asset_id == old_asset_id).all():
        if ta.tag_id in existing_tags:
            db.delete(ta)
        else:
            ta.asset_id = new_asset_id
    for entity_type, (Model, _, _) in ENTITY_MODEL_MAP.items():
        if entity_type in ("assets", "findings"):
            continue
        if getattr(Model, "asset_id", None) is not None:
            db.query(Model).filter(Model.asset_id == old_asset_id).update(
                {"asset_id": new_asset_id}, synchronize_session=False
            )


def _dedup_inventory_on_assets(db, asset_ids: set, cfg: dict, ENTITY_MODEL_MAP: dict) -> int:
    """
    After cross-scan asset merge, dedup inventory records on survivor assets.
    Records from different scans may have the same key (e.g. same username+domain)
    and need to be collapsed.
    """
    inv_cfg = cfg.get("inventory", {})
    total_removed = 0

    for entity_type, (Model, list_fields_list, bool_fields_list) in ENTITY_MODEL_MAP.items():
        if entity_type in ("assets", "findings"):
            continue
        if not hasattr(Model, "asset_id"):
            continue

        entity_cfg = inv_cfg.get(entity_type, {})
        if not entity_cfg.get("enabled", True):
            continue
        key_fields = entity_cfg.get("key_fields", [])
        if not key_fields:
            continue
        strategy = entity_cfg.get("strategy", "keep_first")
        list_fields = set(list_fields_list)
        bool_fields = set(bool_fields_list)

        for asset_id in asset_ids:
            asset_id_col = getattr(Model, "asset_id", None)
            if asset_id_col is None:
                continue
            rows = db.query(Model).filter(asset_id_col == asset_id).order_by(Model.id).all()
            if len(rows) < 2:
                continue

            seen: dict[tuple, Any] = {}
            for row in rows:
                parts = []
                skip = False
                for field in key_fields:
                    if field == "asset_id":
                        parts.append(str(asset_id))
                        continue
                    val = getattr(row, field, None)
                    if val is None or val == "":
                        skip = True
                        break
                    parts.append(str(val))
                if skip:
                    continue
                key = tuple(parts)
                if key in seen:
                    survivor = seen[key]
                    if strategy == "merge":
                        _merge_model_row(survivor, row, strategy, list_fields, bool_fields)
                    elif strategy == "keep_last":
                        _merge_model_row(survivor, row, strategy, list_fields, bool_fields)
                    db.delete(row)
                    total_removed += 1
                else:
                    seen[key] = row

    return total_removed


def run_cross_scan_asset_dedup(db, org_id, cfg: dict, ENTITY_MODEL_MAP: dict) -> dict:
    """
    Cross-scan asset dedup: within each org, find duplicate assets (same key_fields
    across different scans) and merge them into the most-recent scan's asset.

    - org_id: restrict to one org; None = all orgs (superadmin / on-demand run)
    - Survivor: asset from the highest scan_id (most recent upload)
    - Older duplicates: findings + inventory reassigned to survivor, then deleted
    """
    from models.models import Asset, Scan

    asset_cfg = cfg.get("assets", {})
    if not asset_cfg.get("enabled", True):
        return {"skipped": True, "reason": "asset dedup disabled in config"}

    key_fields: list[str] = asset_cfg.get("key_fields", ["ip"])
    strategy: str = asset_cfg.get("strategy", "merge")

    if not key_fields:
        return {"skipped": True, "reason": "no key_fields configured"}

    _, list_fields_list, bool_fields_list = ENTITY_MODEL_MAP.get("assets", (None, [], []))
    list_fields = set(list_fields_list)
    bool_fields = set(bool_fields_list)

    # Load all assets joined with their scan, oldest scan first so the latest
    # scan's asset ends up as the final value in `seen` (the survivor).
    q = (
        db.query(Asset, Scan.org_id.label("scan_org_id"))
        .join(Scan, Asset.scan_id == Scan.id)
        .order_by(Scan.id.asc(), Asset.id.asc())
    )
    if org_id is not None:
        # Include scans with matching org_id AND scans with no org (dev/legacy uploads)
        q = q.filter(or_(Scan.org_id == org_id, Scan.org_id.is_(None)))

    rows = q.all()  # list of (Asset, scan_org_id)

    # group_key → current survivor Asset (the most-recent-scan asset seen so far)
    seen: dict[tuple, Asset] = {}
    to_delete: list[tuple] = []  # (old_asset, survivor_asset)

    for asset, scan_org_id in rows:
        # Build OR-style keys: one per non-null key field, namespaced by org.
        # When caller passes org_id, use it as the namespace (treats None-org scans as same).
        # When caller passes org_id=None (dev/no-auth), treat all scans as same org.
        effective_org = str(org_id) if org_id is not None else "0"
        asset_keys = []
        for field in key_fields:
            val = getattr(asset, field, None)
            if val is not None and val != "":
                asset_keys.append((effective_org, field, str(val)))
        if not asset_keys:
            continue

        # Check if any key matches an existing survivor
        existing = None
        for k in asset_keys:
            if k in seen:
                existing = seen[k]
                break

        if existing is None:
            # New asset — register all its keys
            for k in asset_keys:
                seen[k] = asset
        else:
            # Duplicate — apply strategy
            if strategy == "keep_first":
                to_delete.append((asset, existing))
                # Point new keys to existing survivor too
                for k in asset_keys:
                    seen[k] = existing
            elif strategy == "keep_last":
                to_delete.append((existing, asset))
                # Re-point all keys that referenced old survivor to new one
                for k, v in list(seen.items()):
                    if v is existing:
                        seen[k] = asset
                for k in asset_keys:
                    seen[k] = asset
            else:  # merge
                _merge_model_row(asset, existing, "merge", list_fields, bool_fields)
                to_delete.append((existing, asset))
                for k, v in list(seen.items()):
                    if v is existing:
                        seen[k] = asset
                for k in asset_keys:
                    seen[k] = asset

    removed = len(to_delete)
    survivor_ids = set()
    for old_asset, survivor in to_delete:
        # Merge source_systems from the deleted asset into the survivor
        _merge_source_systems(survivor, old_asset)
        _reassign_asset_children(db, old_asset.id, survivor.id, ENTITY_MODEL_MAP)
        survivor_ids.add(survivor.id)
        db.expire(old_asset)
        db.delete(old_asset)

    if removed:
        db.flush()
        # After reassigning children, dedup inventory on survivor assets
        # to eliminate duplicates created by merging records from multiple scans
        inv_removed = _dedup_inventory_on_assets(db, survivor_ids, cfg, ENTITY_MODEL_MAP)
        db.commit()
        logger.info(f"Cross-scan asset dedup: removed {removed} duplicate assets, {inv_removed} duplicate inventory records (org_id={org_id!r})")

    return {"removed": removed, "entity_type": "assets", "scope": "cross_scan"}


def run_db_dedup(db, entity_type: str, scan_id: int | None, cfg: dict, ENTITY_MODEL_MAP: dict) -> dict:
    """
    Run dedup against existing DB rows for a given entity_type.

    entity_type: one of "users", "groups", "software", etc.
    scan_id: if provided, restrict to that scan; None = cross-scan.
    Returns {"removed": N, "merged": N} stats.
    """
    if entity_type not in ENTITY_MODEL_MAP:
        return {"error": f"Unknown entity type: {entity_type}"}

    # Cross-scan asset dedup requires org-aware grouping — delegate to dedicated function
    if entity_type == "assets" and not scan_id:
        asset_cfg = cfg.get("assets", {})
        if asset_cfg.get("scope", "cross_scan") == "cross_scan":
            return run_cross_scan_asset_dedup(db, org_id=None, cfg=cfg, ENTITY_MODEL_MAP=ENTITY_MODEL_MAP)

    # assets and findings live at the root config level; inventory types live under "inventory"
    if entity_type in ("assets", "findings"):
        entity_cfg = cfg.get(entity_type, {})
    else:
        inv_cfg = cfg.get("inventory", {})
        entity_cfg = inv_cfg.get(entity_type, {})
    if not entity_cfg.get("enabled", True):
        return {"skipped": True, "reason": "disabled in config"}

    Model, list_fields, bool_fields = ENTITY_MODEL_MAP[entity_type]
    key_fields: list[str] = entity_cfg.get("key_fields", [])
    strategy: str = entity_cfg.get("strategy", "keep_first")

    if not key_fields:
        return {"skipped": True, "reason": "no key_fields configured"}

    q = db.query(Model)
    if scan_id:
        scan_id_col = getattr(Model, "scan_id", None)
        if scan_id_col is not None:
            q = q.filter(scan_id_col == scan_id)

    rows = q.order_by(Model.id).all()

    seen: dict[tuple, Any] = {}       # key → surviving row
    to_delete: list[tuple] = []       # (duplicate_row, survivor_row)

    for row in rows:
        # Build key(s) — list-expand fields produce multiple keys per row
        scalar_parts = []
        expand_values = None
        skip = False
        for field in key_fields:
            col_name = _LIST_EXPAND_FIELDS.get(field)
            if col_name:
                vals = getattr(row, col_name, None)
                if not vals or not isinstance(vals, list):
                    skip = True
                    break
                expand_values = [str(v) for v in vals]
            else:
                val = getattr(row, field, None)
                if val is None or val == "":
                    skip = True
                    break
                scalar_parts.append(str(val))
        if skip:
            continue

        keys = [tuple(scalar_parts + [ev]) for ev in expand_values] if expand_values else [tuple(scalar_parts)]

        # Check if any key matches an existing survivor
        existing = None
        for k in keys:
            if k in seen:
                existing = seen[k]
                break

        if existing is None:
            for k in keys:
                seen[k] = row
        else:
            if strategy == "merge":
                _merge_model_row(existing, row, strategy, set(list_fields), set(bool_fields))
            elif strategy == "keep_last":
                _merge_model_row(existing, row, strategy, set(list_fields), set(bool_fields))
            # Point all new keys to the survivor too
            for k in keys:
                seen[k] = existing
            to_delete.append((row, existing))

    removed = len(to_delete)
    for row, survivor in to_delete:
        if entity_type == "assets":
            # Reassign all findings and inventory records to the survivor before
            # deleting the duplicate — prevents cascade-deletion of findings
            # and leaves no orphaned inventory rows.
            _reassign_asset_children(db, row.id, survivor.id, ENTITY_MODEL_MAP)
            db.expire(row)  # force SQLAlchemy to reload relationship collections
        db.delete(row)

    if removed:
        db.commit()
        logger.info(f"DB dedup {entity_type}: removed {removed} duplicates")

    return {"removed": removed, "entity_type": entity_type}
