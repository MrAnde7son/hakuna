"""
Configurable deduplication engine for Hakuna Exposure Management Platform.

Supports three strategies per entity type:
  keep_first  — on duplicate key, keep the record already in DB / seen first
  keep_last   — on duplicate key, replace with the newer record
  merge       — union of list fields, OR of bool fields, first non-null for scalars
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent / "config" / "dedup_config.json"


def _unpack_entity_map(entry: tuple) -> tuple:
    """Unpack ENTITY_MODEL_MAP entry into (Model, list_fields, bool_fields, dict_fields).
    Handles both 3-element (legacy) and 4-element tuples."""
    if len(entry) == 4:
        return entry[0], entry[1], entry[2], entry[3]
    return entry[0], entry[1], entry[2], []

# ─────────────────────────────────────────────
# Key field options per entity type
# ─────────────────────────────────────────────

KEY_FIELD_OPTIONS: dict[str, list[str]] = {
    # Per-asset-type key field options (keys inside asset_identity for non-host types)
    "assets.host": ["ip", "hostname", "fqdn", "netbios_name"],
    "assets.web_app": ["url", "domain"],
    "assets.cloud_instance": ["cloud_provider", "instance_id", "account_id", "region"],
    "assets.api_endpoint": ["method", "url"],
    "assets.identity": ["provider", "principal_id", "tenant_id"],
    "assets.container_image": ["registry", "repository", "tag", "digest"],
    "assets.code_repo": ["provider", "org", "repo"],
    "assets.k8s_workload": ["cluster", "namespace", "kind", "name"],
    # Legacy flat key (backward compat for old UI / config references)
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
        "host": {
            "enabled": True,
            "key_fields": ["ip", "fqdn"],
            "key_mode": "or",
            "strategy": "merge",
            "scope": "cross_scan",
        },
        "web_app": {
            "enabled": True,
            "key_fields": ["url"],
            "key_mode": "and",
            "strategy": "keep_last",
            "scope": "cross_scan",
        },
        "cloud_instance": {
            "enabled": True,
            "key_fields": ["cloud_provider", "instance_id"],
            "key_mode": "and",
            "strategy": "merge",
            "scope": "cross_scan",
        },
        "api_endpoint": {
            "enabled": True,
            "key_fields": ["method", "url"],
            "key_mode": "and",
            "strategy": "keep_last",
            "scope": "cross_scan",
        },
        "identity": {
            "enabled": True,
            "key_fields": ["provider", "principal_id"],
            "key_mode": "and",
            "strategy": "merge",
            "scope": "cross_scan",
        },
        "container_image": {
            "enabled": True,
            "key_fields": ["registry", "repository", "digest"],
            "key_mode": "and",
            "strategy": "keep_last",
            "scope": "cross_scan",
        },
        "code_repo": {
            "enabled": True,
            "key_fields": ["provider", "org", "repo"],
            "key_mode": "and",
            "strategy": "merge",
            "scope": "cross_scan",
        },
        "k8s_workload": {
            "enabled": True,
            "key_fields": ["cluster", "namespace", "kind", "name"],
            "key_mode": "and",
            "strategy": "merge",
            "scope": "cross_scan",
        },
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
# Org-aware Config I/O (per-tenant overrides)
# ─────────────────────────────────────────────
#
# Mirrors the pattern in core/risk_config.py — global config lives in the
# file system; per-org overrides live in Organization.settings["dedup_config"]
# and are deep-merged on top of the global at read time.

_ORG_SETTINGS_KEY = "dedup_config"


def load_config_for_org(db, org_id):
    """Load dedup config with per-org overrides deep-merged on top of the global.

    Falls back to the global file-based config when no org override exists,
    or when org_id is None.
    """
    global_cfg = load_config()
    if org_id is None:
        return global_cfg

    from models.models import Organization
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return global_cfg

    settings = org.settings or {}
    org_override = settings.get(_ORG_SETTINGS_KEY)
    if not org_override:
        return global_cfg

    return _deep_merge(global_cfg, org_override)


def load_org_override(db, org_id):
    """Return the raw sparse override for this org (no merge), or {} if none."""
    if org_id is None:
        return {}
    from models.models import Organization
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return {}
    return (org.settings or {}).get(_ORG_SETTINGS_KEY) or {}


def save_config_for_org(db, org_id, cfg: dict) -> None:
    """Save dedup config. If org_id is provided, stores as an org-level override
    in Organization.settings. If org_id is None, saves to the global file.

    The caller is responsible for passing a sparse override — whatever fields
    are present will override the global at read time; absent fields fall
    back to the global.
    """
    if org_id is None:
        save_config(cfg)
        return

    import copy
    from models.models import Organization
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise ValueError(f"Organization {org_id} not found")

    settings = copy.deepcopy(org.settings or {})
    settings[_ORG_SETTINGS_KEY] = cfg
    org.settings = settings
    db.commit()


def delete_config_for_org(db, org_id) -> bool:
    """Remove the org-level dedup config override, reverting to global.

    Returns True if an override was removed, False if none existed.
    """
    if org_id is None:
        return False
    import copy
    from models.models import Organization
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return False
    settings = copy.deepcopy(org.settings or {})
    if _ORG_SETTINGS_KEY not in settings:
        return False
    del settings[_ORG_SETTINGS_KEY]
    org.settings = settings
    db.commit()
    return True


def has_org_override(db, org_id) -> bool:
    """Check whether an org has a custom dedup config override."""
    if org_id is None:
        return False
    from models.models import Organization
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return False
    return bool((org.settings or {}).get(_ORG_SETTINGS_KEY))


# ─────────────────────────────────────────────
# Per-asset-type config helpers
# ─────────────────────────────────────────────

_LEGACY_FLAT_ASSET_CONFIG = {"enabled", "key_fields", "key_mode", "strategy", "scope"}


def _is_legacy_asset_config(assets_cfg: dict) -> bool:
    """Detect old flat config format (pre per-type): has key_fields at top level."""
    return bool(assets_cfg and _LEGACY_FLAT_ASSET_CONFIG & set(assets_cfg.keys()))


def get_asset_type_config(cfg: dict, asset_type: str) -> dict:
    """Get dedup config for a specific asset type, with fallback chain:
    1. cfg["assets"][asset_type]  (per-type config)
    2. cfg["assets"]["host"]     (host fallback for unknown types)
    3. Legacy flat cfg["assets"] (backward compat for old config files)
    """
    assets_cfg = cfg.get("assets", {})
    # Legacy flat config (pre per-type migration)
    if _is_legacy_asset_config(assets_cfg):
        return assets_cfg
    # Per-type lookup
    if asset_type in assets_cfg:
        return assets_cfg[asset_type]
    # Unknown custom type — use reasonable defaults
    return {
        "enabled": True,
        "key_fields": list((cfg.get("assets", {}).get(asset_type) or {}).get("key_fields", [])),
        "key_mode": "and",
        "strategy": "merge",
        "scope": "cross_scan",
    }


def _get_asset_field(asset_or_dict, field: str):
    """Resolve a field value from an asset: try model column first, then asset_identity dict.
    For host-type fields (ip, hostname, fqdn, netbios_name) the column is authoritative.
    For non-host type fields (url, instance_id, etc.) they live inside asset_identity.
    """
    if isinstance(asset_or_dict, dict):
        val = asset_or_dict.get(field)
        if val is None:
            val = (asset_or_dict.get("asset_identity") or {}).get(field)
        return val
    else:
        # SQLAlchemy model
        val = getattr(asset_or_dict, field, None)
        if val is None:
            identity = asset_or_dict.asset_identity or {}
            val = identity.get(field)
        return val


_HOST_COLUMN_FIELDS = {"ip", "hostname", "fqdn", "netbios_name", "mac_address", "os"}


def resolve_asset_by_dedup_keys(db, asset_data: dict, org_id: int | None,
                                 asset_type: str = "host"):
    """Find an existing asset using the same dedup config as the cross-scan engine.

    Translates the in-memory key_fields + key_mode logic into a SQLAlchemy query
    so that finding→asset resolution uses the same rules as asset dedup.

    Returns the matching Asset or None.
    """
    from models.models import Asset, Scan
    from sqlalchemy import and_, func

    cfg = load_config()
    type_cfg = get_asset_type_config(cfg, asset_type)
    if not type_cfg.get("enabled", True):
        return None

    key_fields = type_cfg.get("key_fields", ["ip"] if asset_type == "host" else [])
    key_mode = type_cfg.get("key_mode", "or" if asset_type == "host" else "and")

    if not key_fields:
        return None

    # Resolve values for each key_field from the asset_data dict
    field_values = {}
    for field in key_fields:
        val = _get_asset_field(asset_data, field)
        if val is not None and val != "":
            field_values[field] = str(val)

    if not field_values:
        # No key fields have values — fall back to hostname for host type
        if asset_type == "host":
            hostname = asset_data.get("hostname", "")
            if hostname:
                field_values["hostname"] = str(hostname)
            else:
                return None
        else:
            return None

    # Build the query with org scoping
    base_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    if org_id is not None:
        base_q = base_q.filter(or_(Scan.org_id == org_id, Scan.org_id.is_(None)))

    # Filter by asset_type for non-host types
    if asset_type != "host":
        base_q = base_q.filter(Asset.asset_type == asset_type)

    # Build field match clauses
    def _field_clause(field: str, value: str):
        """Build a SQLAlchemy filter for a single key field."""
        if field in _HOST_COLUMN_FIELDS and hasattr(Asset, field):
            return getattr(Asset, field) == value
        # Non-host key field — lives in asset_identity JSON
        # Use func.json_extract for SQLite, ->> for PostgreSQL (both work via SA)
        return Asset.asset_identity[field].as_string() == value

    if key_mode == "or":
        # OR-style: match on ANY key field
        clauses = [_field_clause(f, v) for f, v in field_values.items()]
        result = base_q.filter(or_(*clauses)).first()
    else:
        # AND-style: ALL key fields must match
        clauses = [_field_clause(f, v) for f, v in field_values.items()]
        result = base_q.filter(and_(*clauses)).first()

    if result:
        return result

    # Fallback for host type: try hostname even if not in key_fields
    if asset_type == "host" and "hostname" not in field_values:
        hostname = asset_data.get("hostname", "")
        if hostname:
            return base_q.filter(Asset.hostname == str(hostname)).first()

    return None


def dedup_asset_records(records: list[dict], cfg: dict) -> list[dict]:
    """Deduplicate asset records using per-type config.
    Groups records by asset_type, applies type-specific dedup settings, returns merged list.
    """
    if not records:
        return records

    from collections import defaultdict
    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_type[r.get("asset_type", "host")].append(r)

    result = []
    for atype, recs in by_type.items():
        type_cfg = get_asset_type_config(cfg, atype)
        if not type_cfg.get("enabled", True):
            result.extend(recs)
            continue
        key_fields = type_cfg.get("key_fields", [])
        if not key_fields:
            result.extend(recs)
            continue

        # For non-host types, key fields reference asset_identity keys.
        # Lift them to top-level dict so _make_keys can find them.
        if atype != "host":
            for r in recs:
                identity = r.get("asset_identity") or {}
                for kf in key_fields:
                    if kf not in r and kf in identity:
                        r[kf] = identity[kf]

        deduped = dedup_records(
            recs, key_fields, type_cfg.get("strategy", "merge"),
            key_mode=type_cfg.get("key_mode", "and"),
        )
        result.extend(deduped)
    return result


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

    Inventory keys are discovered from the config + any dynamically registered
    types (via entity_registry.register_inventory_type) — no hardcoded KEY_MAP.
    """
    if not cfg.get("enabled") or not cfg.get("apply_on_upload"):
        return inventory

    inv_cfg = cfg.get("inventory", {})

    # Merge dynamic defaults from registry (registered types that aren't in the
    # JSON config yet still get deduped with their declared defaults).
    from models.entity_registry import get_dedup_defaults
    dynamic_defaults = get_dedup_defaults()

    # Process every key present in the inventory dict — covers both config-file
    # entries and dynamically registered types.
    result = {}
    for inv_key, records in inventory.items():
        if not records:
            result[inv_key] = records
            continue

        # Config-file entry takes precedence; fall back to registered defaults.
        entity_cfg = inv_cfg.get(inv_key) or dynamic_defaults.get(inv_key, {})

        if entity_cfg.get("enabled", True):
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

def _merge_model_row(existing, incoming, strategy: str, list_fields: set[str], bool_fields: set[str],
                     dict_fields: set[str] | None = None):
    """Apply merge strategy to two SQLAlchemy model instances (in-place on existing)."""
    dict_fields = dict_fields or set()
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
            elif attr in dict_fields and isinstance(old_val, dict) and isinstance(new_val, dict):
                # Deep merge: existing keys preserved, new keys added, new values win on conflict
                merged = {**old_val, **new_val}
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
    # Use "evaluate" so SQLAlchemy updates in-memory Finding objects too.
    # With synchronize_session=False, stale session objects still reference old_asset_id,
    # and the "delete-orphan" cascade on Asset.findings then incorrectly deletes them
    # when old_asset is deleted — even though the DB rows were already reassigned.
    db.query(Finding).filter(Finding.asset_id == old_asset_id).update(
        {"asset_id": new_asset_id}, synchronize_session="evaluate"
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
    # Reassign per-source observations (merge if same source exists on both sides)
    from services.asset_observations import reassign_observations
    reassign_observations(db, old_asset_id, new_asset_id)

    from services.asset_relationship_engine import reassign_relationships
    reassign_relationships(db, old_asset_id, new_asset_id)

    for entity_type, entry in ENTITY_MODEL_MAP.items():
        if entity_type in ("assets", "findings"):
            continue
        Model = entry[0]
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

    for entity_type, entry in ENTITY_MODEL_MAP.items():
        if entity_type in ("assets", "findings"):
            continue
        Model, list_fields_list, bool_fields_list, dict_fields_list = _unpack_entity_map(entry)
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
        dict_fields = set(dict_fields_list)

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
                        _merge_model_row(survivor, row, strategy, list_fields, bool_fields, dict_fields)
                    elif strategy == "keep_last":
                        _merge_model_row(survivor, row, strategy, list_fields, bool_fields, dict_fields)
                    db.delete(row)
                    total_removed += 1
                else:
                    seen[key] = row

    return total_removed


def _asset_cdn_provider(asset) -> str | None:
    """Return the CDN provider for an asset, or None. Checks the ``easm_data``
    JSON blob (where the EASM pipeline writes it) with a fallback to a top-level
    ``cdn_provider`` attribute in case some other source attaches it directly.

    Assets fronted by a CDN share IPs with thousands of other hostnames
    (Cloudflare, Fastly, Cloudfront, Akamai) — dedup on IP alone produces
    false-positive merges. When this returns a non-empty value, the cross-scan
    dedup layer excludes IP from the key set for that asset.
    """
    # Direct column first (future-proof in case we promote it)
    direct = getattr(asset, "cdn_provider", None)
    if direct:
        return direct
    # EASM nested blob
    easm = getattr(asset, "easm_data", None) or {}
    if isinstance(easm, dict):
        return easm.get("cdn_provider") or None
    return None


def run_cross_scan_finding_dedup(db, org_id, cfg: dict) -> dict:
    """Cross-scan finding dedup scoped to a single org.

    Groups all of the org's findings by the configured `findings.key_fields`
    and applies the configured strategy (keep_first / keep_last / merge) to
    every group with more than one row. The surviving row is keyed by
    `last_seen` (fallback `created_at`, fallback id) so fresh data wins.

    Returns ``{"removed": N, "merged": N}`` or ``{"skipped": True, ...}``.

    This function is the single source of truth for finding dedup. Scanners
    (Nessus parser, VM scanner, EASM) emit raw findings; post_ingest.
    finalize_scan calls this after every ingest so the resolved per-org
    rule is enforced uniformly.
    """
    from models.models import Finding, Scan

    findings_cfg = cfg.get("findings", {}) or {}
    if not findings_cfg.get("enabled", False):
        return {"skipped": True, "reason": "findings dedup disabled for this org"}

    key_fields: list[str] = findings_cfg.get("key_fields") or []
    if not key_fields:
        return {"skipped": True, "reason": "no key_fields configured"}

    strategy: str = findings_cfg.get("strategy", "keep_last")

    # Only fields that make sense on the Finding model. Silently drop unknowns.
    supported = {"plugin_id", "asset_id", "port", "protocol", "cve",
                 "source_type", "source_system", "normalized_id", "severity"}
    effective_fields = [f for f in key_fields if f in supported]
    # Always scope by asset_id as a safety floor so findings can't dedup
    # across unrelated assets even if the config is sparse.
    if "asset_id" not in effective_fields:
        effective_fields = ["asset_id", *effective_fields]
    if not effective_fields:
        return {"skipped": True, "reason": "no supported key_fields for findings"}

    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    if org_id is not None:
        q = q.filter(Scan.org_id == org_id)
    rows = q.all()

    def _sort_key(f):
        # Fresh > stale: later last_seen wins under keep_last / merge.
        ls = getattr(f, "last_seen", None) or getattr(f, "created_at", None)
        return (ls or datetime.min, f.id or 0)

    groups: dict[tuple, list] = {}
    for row in rows:
        key_parts = []
        skip = False
        for field in effective_fields:
            val = getattr(row, field, None)
            # Special-case for cve since Finding stores a list in `cves`.
            if field == "cve":
                cves = getattr(row, "cves", None) or []
                if not cves:
                    skip = True
                    break
                val = str(cves[0])
            if val is None or val == "":
                skip = True
                break
            key_parts.append(str(val))
        if skip:
            continue
        groups.setdefault(tuple(key_parts), []).append(row)

    removed = 0
    merged = 0
    for group_rows in groups.values():
        if len(group_rows) < 2:
            continue

        group_rows.sort(key=_sort_key)
        # Under keep_first, the oldest survives; under keep_last / merge, the newest.
        if strategy == "keep_first":
            survivor = group_rows[0]
            losers = group_rows[1:]
        else:
            survivor = group_rows[-1]
            losers = group_rows[:-1]

        if strategy == "merge":
            for loser in losers:
                _merge_finding_lists(survivor, loser)
            merged += len(losers)

        for loser in losers:
            db.delete(loser)
        removed += len(losers)

    if removed or merged:
        db.flush()

    return {"removed": removed, "merged": merged, "strategy": strategy, "key_fields": effective_fields}


def _merge_finding_lists(survivor, loser) -> None:
    """For merge strategy — union list/JSON fields from loser into survivor."""
    for field in ("cves", "references", "source_systems", "matched_ttps"):
        s_val = getattr(survivor, field, None)
        l_val = getattr(loser, field, None)
        if isinstance(s_val, list) and isinstance(l_val, list):
            seen = {json.dumps(x, sort_keys=True, default=str) for x in s_val}
            for item in l_val:
                k = json.dumps(item, sort_keys=True, default=str)
                if k not in seen:
                    s_val.append(item)
                    seen.add(k)
            setattr(survivor, field, s_val)
    # times_seen aggregates across duplicates.
    if hasattr(survivor, "times_seen") and hasattr(loser, "times_seen"):
        survivor.times_seen = (survivor.times_seen or 1) + (loser.times_seen or 1)


def run_cross_scan_asset_dedup(db, org_id, cfg: dict, ENTITY_MODEL_MAP: dict) -> dict:
    """
    Cross-scan asset dedup: within each org, find duplicate assets (same key_fields
    across different scans) and merge them into the most-recent scan's asset.

    Partitions assets by asset_type and applies per-type dedup config.

    - org_id: restrict to one org; None = all orgs (superadmin / on-demand run)
    - Survivor: asset with the most-recent ``last_seen`` (not the highest scan_id).
      Using scan_id as the tiebreaker was wrong: scan_id is an autoincrement, so a
      one-off integration sync (e.g. Cloudflare DNS import) could outrank a fresh
      EASM scan just because it had a higher row id, silently siphoning newly-
      discovered EASM assets into a stale integration scan.
    - Older duplicates: findings + inventory reassigned to survivor, then deleted
    - CDN-fronted assets (cdn_provider set) are excluded from IP-based key matching
      because CDN IPs are shared across unrelated hostnames.
    """
    from models.models import Asset, Scan

    _, list_fields_list, bool_fields_list, dict_fields_list = _unpack_entity_map(
        ENTITY_MODEL_MAP.get("assets", (None, [], [], []))
    )
    list_fields = set(list_fields_list)
    bool_fields = set(bool_fields_list)
    dict_fields = set(dict_fields_list)

    # Load all assets joined with their scan. Sort so the most recently-seen
    # asset is processed LAST — it becomes the survivor via the merge/keep_last
    # logic below. Tiebreakers (scan.id, asset.id) keep the ordering deterministic.
    #
    # NULL last_seen (legacy rows, never-run integration syncs) must sort FIRST
    # so they get overwritten by anything with real data. SQLite and PostgreSQL
    # disagree on the default NULL ordering with ASC, and SQLite rejects the
    # explicit ``NULLS FIRST`` clause — so we use COALESCE to a constant epoch
    # date, which is portable across both dialects.
    _NULL_EPOCH = datetime(1970, 1, 1)
    last_seen_sort = func.coalesce(Asset.last_seen, _NULL_EPOCH)
    q = (
        db.query(Asset, Scan.org_id.label("scan_org_id"))
        .join(Scan, Asset.scan_id == Scan.id)
        .order_by(
            last_seen_sort.asc(),
            Scan.id.asc(),
            Asset.id.asc(),
        )
    )
    if org_id is not None:
        # Include scans with matching org_id AND scans with no org (dev/legacy uploads)
        q = q.filter(or_(Scan.org_id == org_id, Scan.org_id.is_(None)))

    rows = q.all()  # list of (Asset, scan_org_id)

    # Partition by asset_type
    from collections import defaultdict
    by_type: dict[str, list] = defaultdict(list)
    for asset, scan_org_id in rows:
        atype = asset.asset_type or "host"
        by_type[atype].append((asset, scan_org_id))

    # group_key → current survivor Asset (the most-recent-scan asset seen so far)
    seen: dict[tuple, Asset] = {}
    to_delete: list[tuple] = []  # (old_asset, survivor_asset)

    for atype, type_rows in by_type.items():
        type_cfg = get_asset_type_config(cfg, atype)
        if not type_cfg.get("enabled", True):
            continue
        key_fields = type_cfg.get("key_fields", ["ip"] if atype == "host" else [])
        strategy = type_cfg.get("strategy", "merge")
        key_mode = type_cfg.get("key_mode", "or" if atype == "host" else "and")
        if not key_fields:
            continue

        type_seen: dict[tuple, Asset] = {}

        for asset, scan_org_id in type_rows:
            effective_org = str(org_id) if org_id is not None else "0"
            asset_keys = []

            # CDN-fronted assets share IPs across unrelated hostnames
            # (Cloudflare, Fastly, Cloudfront, Akamai). Skip the "ip" key
            # field for these — require a hostname/fqdn match instead.
            #
            # Without this: every EASM-discovered host on Cloudflare would
            # dedup-merge into the first Cloudflare-IP asset the engine saw,
            # silently losing distinct hostnames (the original bug).
            is_cdn = _asset_cdn_provider(asset) is not None
            effective_key_fields = (
                [f for f in key_fields if f != "ip"] if is_cdn else key_fields
            )

            if key_mode == "or":
                # OR-style: each non-null field is its own key
                for field in effective_key_fields:
                    val = _get_asset_field(asset, field)
                    if val is not None and val != "":
                        asset_keys.append((effective_org, atype, field, str(val)))
            else:
                # AND-style: composite key from all fields
                parts = [effective_org, atype]
                has_any = False
                for field in effective_key_fields:
                    val = _get_asset_field(asset, field)
                    if val is not None and val != "":
                        parts.append(str(val))
                        has_any = True
                    else:
                        parts.append("")
                if has_any:
                    asset_keys = [tuple(parts)]

            if not asset_keys:
                continue

            # Check if any key matches an existing survivor
            existing = None
            for k in asset_keys:
                if k in type_seen:
                    existing = type_seen[k]
                    break

            if existing is None:
                for k in asset_keys:
                    type_seen[k] = asset
            else:
                if strategy == "keep_first":
                    to_delete.append((asset, existing))
                    for k in asset_keys:
                        type_seen[k] = existing
                elif strategy == "keep_last":
                    to_delete.append((existing, asset))
                    for k, v in list(type_seen.items()):
                        if v is existing:
                            type_seen[k] = asset
                    for k in asset_keys:
                        type_seen[k] = asset
                else:  # merge
                    _merge_model_row(asset, existing, "merge", list_fields, bool_fields, dict_fields)
                    to_delete.append((existing, asset))
                    for k, v in list(type_seen.items()):
                        if v is existing:
                            type_seen[k] = asset
                    for k in asset_keys:
                        type_seen[k] = asset

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

        # Re-rollup survivor assets using source priority (if configured)
        _rollup_survivors(db, survivor_ids, cfg)

        db.commit()
        logger.info(f"Cross-scan asset dedup: removed {removed} duplicate assets, {inv_removed} duplicate inventory records (org_id={org_id!r})")

    return {"removed": removed, "entity_type": "assets", "scope": "cross_scan"}


def _rollup_survivors(db, survivor_ids: set, cfg: dict) -> None:
    """Apply source_priority rollup to survivor assets after dedup merge."""
    # Collect source_priority from all asset type configs
    from services.asset_observations import rollup_asset
    assets_cfg = cfg.get("assets", {})
    for aid in survivor_ids:
        from models.models import Asset
        asset = db.query(Asset).filter(Asset.id == aid).first()
        if not asset:
            continue
        atype = asset.asset_type or "host"
        type_cfg = get_asset_type_config(cfg, atype)
        sp = type_cfg.get("source_priority")
        if sp and any(sp.values()):
            rollup_asset(db, aid, sp)


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
        return run_cross_scan_asset_dedup(db, org_id=None, cfg=cfg, ENTITY_MODEL_MAP=ENTITY_MODEL_MAP)

    # assets and findings live at the root config level; inventory types live under "inventory"
    if entity_type == "assets":
        # Per-type asset config — for within-scan dedup, use host config as default
        entity_cfg = get_asset_type_config(cfg, "host")
    elif entity_type == "findings":
        entity_cfg = cfg.get(entity_type, {})
    else:
        inv_cfg = cfg.get("inventory", {})
        entity_cfg = inv_cfg.get(entity_type, {})
    if not entity_cfg.get("enabled", True):
        return {"skipped": True, "reason": "disabled in config"}

    Model, list_fields, bool_fields, dict_fields = _unpack_entity_map(ENTITY_MODEL_MAP[entity_type])
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
                _merge_model_row(existing, row, strategy, set(list_fields), set(bool_fields), set(dict_fields))
            elif strategy == "keep_last":
                _merge_model_row(existing, row, strategy, set(list_fields), set(bool_fields), set(dict_fields))
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
        elif entity_type == "findings":
            from services.asset_observations import reassign_finding_observations
            reassign_finding_observations(db, row.id, survivor.id)
        db.delete(row)

    if removed:
        db.commit()
        logger.info(f"DB dedup {entity_type}: removed {removed} duplicates")

    return {"removed": removed, "entity_type": entity_type}
