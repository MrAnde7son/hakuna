"""
Configurable deduplication engine for Nessus Remediation Platform.

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

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent / "config" / "dedup_config.json"

# ─────────────────────────────────────────────
# Key field options per entity type
# ─────────────────────────────────────────────

KEY_FIELD_OPTIONS: dict[str, list[str]] = {
    "assets": ["ip", "hostname", "fqdn", "netbios_name"],
    "findings": ["plugin_id", "asset_id", "port", "protocol"],
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

def _make_key(record: dict, key_fields: list[str]) -> tuple | None:
    """Build a hashable key from selected fields. Returns None if any key field is missing/None."""
    parts = []
    for field in key_fields:
        val = record.get(field)
        if val is None or val == "":
            return None
        parts.append(str(val))
    return tuple(parts)


def _merge_dicts(first: dict, second: dict) -> dict:
    """
    Merge two records using the merge strategy:
      - list fields → union (deduplicated)
      - bool fields → OR
      - scalar fields → first non-null value wins
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
        # else: first non-null wins (already set)
    return result


def dedup_records(records: list[dict], key_fields: list[str], strategy: str) -> list[dict]:
    """
    Deduplicate a list of in-memory dicts.

    Returns a new list with duplicates resolved per strategy.
    """
    if not records or not key_fields:
        return records

    seen: dict[tuple, dict] = {}  # key → record
    no_key: list[dict] = []       # records with None key (always kept)

    for rec in records:
        key = _make_key(rec, key_fields)
        if key is None:
            no_key.append(rec)
            continue

        if key not in seen:
            seen[key] = rec
        elif strategy == "keep_last":
            seen[key] = rec
        elif strategy == "merge":
            seen[key] = _merge_dicts(seen[key], rec)
        # keep_first: do nothing

    return list(seen.values()) + no_key


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


def _reassign_asset_children(db, old_asset_id: int, new_asset_id: int, ENTITY_MODEL_MAP: dict) -> None:
    """
    Before deleting a duplicate asset, reassign all its child records
    (findings + all inventory types) to the surviving asset.
    This prevents cascade-deletion of findings and inventory orphaning.
    """
    from models.models import Finding
    db.query(Finding).filter(Finding.asset_id == old_asset_id).update(
        {"asset_id": new_asset_id}, synchronize_session=False
    )
    for entity_type, (Model, _, _) in ENTITY_MODEL_MAP.items():
        if entity_type in ("assets", "findings"):
            continue
        if getattr(Model, "asset_id", None) is not None:
            db.query(Model).filter(Model.asset_id == old_asset_id).update(
                {"asset_id": new_asset_id}, synchronize_session=False
            )


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
        q = q.filter(Scan.org_id == org_id)

    rows = q.all()  # list of (Asset, scan_org_id)

    # group_key → current survivor Asset (the most-recent-scan asset seen so far)
    seen: dict[tuple, Asset] = {}
    to_delete: list[tuple] = []  # (old_asset, survivor_asset)

    for asset, scan_org_id in rows:
        # Namespace by org so different orgs with the same IP never collide
        key_parts = [str(scan_org_id if scan_org_id is not None else 0)]
        skip = False
        for field in key_fields:
            val = getattr(asset, field, None)
            if val is None or val == "":
                skip = True
                break
            key_parts.append(str(val))
        if skip:
            continue

        group_key = tuple(key_parts)

        if group_key not in seen:
            seen[group_key] = asset
        else:
            old_survivor = seen[group_key]
            # Current asset is from a later scan (ASC order) → it becomes the new survivor
            if strategy == "keep_first":
                # Keep the oldest asset; mark the newer one for deletion
                to_delete.append((asset, old_survivor))
                # seen[group_key] stays as old_survivor
            elif strategy == "keep_last":
                # New asset wins; old asset is discarded
                to_delete.append((old_survivor, asset))
                seen[group_key] = asset
            else:  # merge
                # Fill gaps in new asset from old asset (list union, bool OR, null fallback)
                _merge_model_row(asset, old_survivor, "merge", list_fields, bool_fields)
                to_delete.append((old_survivor, asset))
                seen[group_key] = asset

    removed = len(to_delete)
    for old_asset, survivor in to_delete:
        _reassign_asset_children(db, old_asset.id, survivor.id, ENTITY_MODEL_MAP)
        db.expire(old_asset)
        db.delete(old_asset)

    if removed:
        db.commit()
        logger.info(f"Cross-scan asset dedup: removed {removed} duplicates (org_id={org_id!r})")

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
        key_parts = []
        skip = False
        for field in key_fields:
            val = getattr(row, field, None)
            if val is None or val == "":
                skip = True
                break
            key_parts.append(str(val))
        if skip:
            continue
        key = tuple(key_parts)

        if key not in seen:
            seen[key] = row
        else:
            existing = seen[key]
            if strategy == "merge":
                _merge_model_row(existing, row, strategy, set(list_fields), set(bool_fields))
            elif strategy == "keep_last":
                _merge_model_row(existing, row, strategy, set(list_fields), set(bool_fields))
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
