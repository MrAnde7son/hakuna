"""Model registry — makes SQLAlchemy models available as integration builder targets.

Decorate any model with @importable(...) to register it as a valid destination
for the integration builder's field mapping and upsert engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import String, Text, Integer, Float, Boolean, DateTime, JSON

logger = logging.getLogger(__name__)

_REGISTRY: dict[str, "ImportableModel"] = {}

# Columns that are auto-managed and should not appear as mapping targets
_AUTO_COLUMNS = frozenset([
    "id", "created_at", "updated_at",
    "org_id", "scan_id",  # Set by the upsert engine, not user-mapped
])

# JSON columns that support dot-notation sub-key mapping (e.g. "asset_attributes.dns_record_type")
# Each entry lists suggested sub-keys shown in the UI, but users can add custom ones.
_EXPANDABLE_JSON_HINTS: dict[str, list[dict]] = {
    "asset_attributes": [
        {"name": "dns_record_type", "type": "string", "description": "DNS record type (A, AAAA, CNAME, MX, TXT)"},
        {"name": "cloud_provider", "type": "string", "description": "Cloud provider (aws, azure, gcp)"},
        {"name": "cloud_region", "type": "string", "description": "Cloud region or location"},
        {"name": "cloud_account_id", "type": "string", "description": "Cloud account or subscription ID"},
        {"name": "cdn_provider", "type": "string", "description": "CDN provider name"},
        {"name": "origin_ip", "type": "string", "description": "Origin IP behind CDN/proxy"},
        {"name": "proxied", "type": "boolean", "description": "Whether traffic is proxied (e.g. Cloudflare)"},
        {"name": "ttl", "type": "integer", "description": "DNS TTL value"},
        {"name": "cname_target", "type": "string", "description": "CNAME target hostname"},
        {"name": "service_name", "type": "string", "description": "Service or application name"},
    ],
    "easm_data": [
        {"name": "http_url", "type": "string", "description": "HTTP URL observed"},
        {"name": "http_status", "type": "integer", "description": "HTTP response status code"},
        {"name": "http_title", "type": "string", "description": "HTML page title"},
        {"name": "cdn_provider", "type": "string", "description": "CDN provider detected"},
        {"name": "waf", "type": "string", "description": "WAF detected"},
    ],
    "asset_identity": [
        {"name": "hostname", "type": "string", "description": "Primary hostname"},
        {"name": "fqdn", "type": "string", "description": "Fully qualified domain name"},
        {"name": "ip", "type": "string", "description": "IP address"},
        {"name": "url", "type": "string", "description": "URL for web apps"},
        {"name": "display_name", "type": "string", "description": "Display name"},
        {"name": "instance_id", "type": "string", "description": "Cloud instance ID"},
    ],
}


@dataclass
class ParentHint:
    """Describes how to resolve a parent FK from mapped record data."""
    field: str              # FK column on this model, e.g. "asset_id"
    parent_slug: str        # Registry slug of the parent, e.g. "asset"
    resolve_by: list[str]   # Columns on parent to match against, e.g. ["ip", "hostname"]


@dataclass
class ImportableModel:
    model_class: type
    slug: str
    display_name: str
    category: str                   # "core", "threat_intel", "inventory", "sbom"
    dedup_keys: list[str]
    required_fields: list[str] = field(default_factory=list)
    parent_hint: Optional[ParentHint] = None
    description: str = ""
    writable_columns: list[dict] = field(default_factory=list)


def importable(
    slug: str,
    display_name: str,
    category: str,
    dedup_keys: list[str],
    required_fields: list[str] | None = None,
    parent_hint: dict | None = None,
    description: str = "",
):
    """Decorator to register a SQLAlchemy model as an importable target."""
    def wrapper(cls):
        hint = None
        if parent_hint:
            hint = ParentHint(**parent_hint)

        columns = _introspect_columns(cls, parent_fk=hint.field if hint else None)
        meta = ImportableModel(
            model_class=cls,
            slug=slug,
            display_name=display_name,
            category=category,
            dedup_keys=dedup_keys,
            required_fields=required_fields or [],
            parent_hint=hint,
            description=description,
            writable_columns=columns,
        )
        _REGISTRY[slug] = meta
        return cls
    return wrapper


# ── Introspection ────────────────────────────────────────

_TYPE_MAP = {
    String: "string",
    Text: "string",
    Integer: "integer",
    Float: "float",
    Boolean: "boolean",
    DateTime: "datetime",
    JSON: "json",
}


def _sqla_type_to_str(col_type) -> str:
    """Map a SQLAlchemy column type to a simple string label."""
    for sqla_cls, label in _TYPE_MAP.items():
        if isinstance(col_type, sqla_cls):
            return label
    return "string"


def _introspect_columns(model_cls, parent_fk: str | None = None) -> list[dict]:
    """Read writable column metadata from a SQLAlchemy model."""
    columns = []
    table = model_cls.__table__

    for col in table.columns:
        if col.name in _AUTO_COLUMNS:
            continue
        # Skip FK resolved via parent_hint (e.g. asset_id)
        if parent_fk and col.name == parent_fk:
            continue
        # Skip primary key (usually 'id', but just in case)
        if col.primary_key:
            continue

        col_type = _sqla_type_to_str(col.type)
        is_required = not col.nullable and col.default is None and col.server_default is None

        entry = {
            "name": col.name,
            "type": col_type,
            "required": is_required,
            "group": model_cls.__tablename__,
            "description": col.comment or "",
        }

        # Detect foreign keys
        if col.foreign_keys:
            fk = next(iter(col.foreign_keys))
            entry["foreign_key"] = str(fk.target_fullname)

        # Mark JSON columns that support dot-notation sub-key mapping
        if col_type == "json" and col.name in _EXPANDABLE_JSON_HINTS:
            entry["expandable"] = True
            entry["sub_fields"] = _EXPANDABLE_JSON_HINTS[col.name]

        columns.append(entry)

    return columns


# ── Public API ───────────────────────────────────────────

def get_registry() -> dict[str, ImportableModel]:
    return _REGISTRY


def get_model_meta(slug: str) -> ImportableModel | None:
    return _REGISTRY.get(slug)


def get_target_schema(slug: str) -> list[dict] | None:
    """Return the introspected field schema for a registered model."""
    meta = _REGISTRY.get(slug)
    if meta is None:
        return None
    return meta.writable_columns


def list_targets() -> list[dict]:
    """Return a summary list of all importable targets for the frontend."""
    targets = []
    for slug, meta in _REGISTRY.items():
        targets.append({
            "slug": meta.slug,
            "display_name": meta.display_name,
            "category": meta.category,
            "description": meta.description,
            "dedup_keys": meta.dedup_keys,
            "required_fields": meta.required_fields,
            "has_parent": meta.parent_hint is not None,
            "parent_slug": meta.parent_hint.parent_slug if meta.parent_hint else None,
        })
    return targets
