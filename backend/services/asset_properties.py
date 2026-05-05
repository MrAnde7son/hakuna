"""Asset property registry — single source of truth for the column picker,
filter builder, asset detail panels, and rule engine.

Every queryable property of `models.Asset` is declared here once. The
`/api/assets/schema` endpoint serves this registry to the frontend; the
filter executor consults it to translate `key` → SQL expression.

Add a new column to `Asset`? Add an entry here in the same commit.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Literal

from sqlalchemy.orm import Session

from models.models import CustomFieldDefinition


PropertyType = Literal[
    "string", "integer", "float", "boolean", "datetime",
    "enum", "string_array", "integer_array", "json",
]

PropertyGroup = Literal[
    "identity", "os", "network", "easm", "business",
    "ownership", "risk", "lifecycle", "provenance", "scan_plan", "custom",
]


@dataclass
class PropertySource:
    """Where to read the value from. `kind=column` → ORM attribute on Asset.
    `kind=json` → dotted path into a JSON column."""
    kind: Literal["column", "json"]
    path: List[str]


@dataclass
class AssetProperty:
    key: str
    label: str
    type: PropertyType
    source: PropertySource
    group: PropertyGroup
    filterable: bool = True
    sortable: bool = True
    default_visible: bool = False
    enum_values: Optional[List[str]] = None
    operators: Optional[List[str]] = None
    requires_permission: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d = {k: v for k, v in d.items() if v is not None}
        return d


_DEFAULT_OPERATORS: dict[PropertyType, list[str]] = {
    "string": ["eq", "neq", "contains", "regex", "starts_with", "is_null"],
    "integer": ["eq", "neq", "lt", "lte", "gt", "gte", "between", "is_null"],
    "float": ["eq", "neq", "lt", "lte", "gt", "gte", "between", "is_null"],
    "boolean": ["is_true", "is_false"],
    "datetime": ["before", "after", "between", "within_last", "is_null"],
    "enum": ["in", "not_in"],
    "string_array": ["contains", "contains_any", "contains_all", "length_eq", "is_empty"],
    "integer_array": ["contains", "contains_any", "contains_all", "length_eq", "is_empty"],
    "json": ["has_key", "path_eq", "path_contains"],
}


def operators_for(prop: AssetProperty) -> list[str]:
    return prop.operators or _DEFAULT_OPERATORS[prop.type]


def _col(name: str) -> PropertySource:
    return PropertySource(kind="column", path=[name])


def _json(column: str, *path: str) -> PropertySource:
    return PropertySource(kind="json", path=[column, *path])


# ─── Static registry ────────────────────────────────────────────────────────

_REGISTRY: List[AssetProperty] = [
    # Identity
    AssetProperty("hostname", "Hostname", "string", _col("hostname"), "identity", default_visible=True),
    AssetProperty("ip", "IP Address", "string", _col("ip"), "identity", default_visible=True),
    AssetProperty("fqdn", "FQDN", "string", _col("fqdn"), "identity"),
    AssetProperty("netbios_name", "NetBIOS Name", "string", _col("netbios_name"), "identity"),
    AssetProperty("mac_address", "MAC Address", "string", _col("mac_address"), "identity"),
    AssetProperty(
        "asset_type", "Asset Type", "enum", _col("asset_type"), "identity",
        enum_values=["host", "web_app", "cloud_instance", "api_endpoint", "identity",
                     "container_image", "code_repo", "github_org", "github_user",
                     "npm_package", "k8s_workload"],
        default_visible=True,
    ),
    AssetProperty("asset_identity", "Asset Identity", "json", _col("asset_identity"), "identity", sortable=False),
    AssetProperty("asset_attributes", "Asset Attributes", "json", _col("asset_attributes"), "identity", sortable=False),

    # OS / device
    AssetProperty("os", "Operating System", "string", _col("os"), "os", default_visible=True),
    AssetProperty(
        "device_type", "Device Type", "enum", _col("device_type"), "os",
        enum_values=["server", "workstation", "router", "switch", "firewall",
                     "printer", "hypervisor", "wap", "voip", "storage", "unknown"],
    ),
    AssetProperty("cpe", "CPE", "string_array", _col("cpe"), "os", sortable=False),
    AssetProperty("os_confidence", "OS Confidence", "integer", _col("os_confidence"), "os"),

    # Network exposure
    AssetProperty("is_internet_facing", "Internet-Facing", "boolean", _col("is_internet_facing"), "network", default_visible=True),
    AssetProperty(
        "internet_facing_confidence", "Internet-Facing Confidence", "enum",
        _col("internet_facing_confidence"), "network",
        enum_values=["confirmed", "high", "medium", "low"],
    ),
    AssetProperty("internet_facing_methods", "Internet-Facing Methods", "string_array",
                  _col("internet_facing_methods"), "network", sortable=False),
    AssetProperty("scanner_ip", "Scanner IP", "string", _col("scanner_ip"), "network"),
    AssetProperty("is_credentialed", "Credentialed Scan", "boolean", _col("is_credentialed"), "network"),
    AssetProperty("last_auth_run", "Last Authenticated Scan", "datetime", _col("last_auth_run"), "network"),
    AssetProperty("system_type", "System Type", "string", _col("system_type"), "network"),

    # EASM (from hakuna-scanner, stored under easm_data JSON)
    AssetProperty("easm.open_ports", "Open Ports", "integer_array",
                  _json("easm_data", "open_ports"), "easm", sortable=False, default_visible=True),
    AssetProperty("easm.tech_stack", "Tech Stack", "string_array",
                  _json("easm_data", "tech_stack"), "easm", sortable=False, default_visible=True),
    AssetProperty("easm.dns_records", "DNS Records", "json",
                  _json("easm_data", "dns_records"), "easm", sortable=False),
    AssetProperty("easm.tls_cert", "TLS Certificate", "json",
                  _json("easm_data", "tls_cert"), "easm", sortable=False),
    AssetProperty("easm.cdn_provider", "CDN Provider", "string",
                  _json("easm_data", "cdn_provider"), "easm"),
    AssetProperty("easm.waf", "WAF", "string", _json("easm_data", "waf"), "easm"),
    AssetProperty("easm.http_status", "HTTP Status", "integer",
                  _json("easm_data", "http_status"), "easm"),
    AssetProperty("easm.http_title", "HTTP Title", "string",
                  _json("easm_data", "http_title"), "easm"),
    AssetProperty("easm.http_url", "HTTP URL", "string",
                  _json("easm_data", "http_url"), "easm"),
    AssetProperty("easm.tags", "EASM Tags", "string_array",
                  _json("easm_data", "easm_tags"), "easm", sortable=False),
    AssetProperty("easm.source", "EASM Source", "string",
                  _json("easm_data", "easm_source"), "easm"),

    # Business context
    AssetProperty("business_context", "Business Context", "string", _col("business_context"), "business"),
    AssetProperty("business_context_confirmed", "Business Context Confirmed", "boolean",
                  _col("business_context_confirmed"), "business"),
    AssetProperty("biz_num_users", "Users on Asset", "integer", _col("biz_num_users"), "business"),
    AssetProperty(
        "biz_revenue_impact", "Revenue Impact", "enum", _col("biz_revenue_impact"), "business",
        enum_values=["none", "low", "medium", "high", "critical"],
    ),
    AssetProperty("criticality", "Criticality (1-10)", "integer", _col("criticality"), "business", default_visible=True),
    AssetProperty("environment_tag", "Environment", "enum", _col("environment_tag"), "business",
                  enum_values=["internal", "external", "production", "staging", "development", "dmz"],
                  default_visible=True),
    AssetProperty("environment_confirmed", "Environment Confirmed", "boolean",
                  _col("environment_confirmed"), "business"),

    # Ownership (sensitive — gate behind permission)
    AssetProperty("inferred_primary_user", "Primary User", "string", _col("inferred_primary_user"),
                  "ownership", requires_permission="asset:view_owners"),
    AssetProperty("inferred_admin_contacts", "Admin Contacts", "string_array",
                  _col("inferred_admin_contacts"), "ownership", sortable=False,
                  requires_permission="asset:view_owners"),
    AssetProperty("inferred_team", "Team", "string", _col("inferred_team"), "ownership",
                  requires_permission="asset:view_owners"),
    AssetProperty("owner_confidence", "Owner Confidence", "enum", _col("owner_confidence"), "ownership",
                  enum_values=["high", "medium", "low"], requires_permission="asset:view_owners"),

    # Risk / counts
    AssetProperty("risk_score", "Risk Score", "float", _col("risk_score"), "risk", default_visible=True),
    AssetProperty("critical_count", "Critical Findings", "integer", _col("critical_count"), "risk", default_visible=True),
    AssetProperty("high_count", "High Findings", "integer", _col("high_count"), "risk", default_visible=True),
    AssetProperty("medium_count", "Medium Findings", "integer", _col("medium_count"), "risk"),
    AssetProperty("low_count", "Low Findings", "integer", _col("low_count"), "risk"),
    AssetProperty("info_count", "Info Findings", "integer", _col("info_count"), "risk"),

    # Lifecycle
    AssetProperty("first_seen", "First Seen", "datetime", _col("first_seen"), "lifecycle"),
    AssetProperty("last_seen", "Last Seen", "datetime", _col("last_seen"), "lifecycle", default_visible=True),
    AssetProperty("times_seen", "Times Seen", "integer", _col("times_seen"), "lifecycle"),
    AssetProperty("asset_status", "Status", "enum", _col("asset_status"), "lifecycle",
                  enum_values=["active", "stale"]),
    AssetProperty("stale_since", "Stale Since", "datetime", _col("stale_since"), "lifecycle"),
    AssetProperty("last_enriched", "Last Enriched", "datetime", _col("last_enriched"), "lifecycle"),
    AssetProperty("last_js_fingerprinted", "Last JS Fingerprinted", "datetime",
                  _col("last_js_fingerprinted"), "lifecycle"),
    AssetProperty("scan_start", "Scan Start", "string", _col("scan_start"), "lifecycle"),
    AssetProperty("scan_end", "Scan End", "string", _col("scan_end"), "lifecycle"),

    # Provenance
    AssetProperty("source_system", "Source System", "string", _col("source_system"), "provenance"),
    AssetProperty("source_systems", "Source Systems", "string_array", _col("source_systems"),
                  "provenance", sortable=False),
    AssetProperty("source_id", "Source ID", "string", _col("source_id"), "provenance"),
    AssetProperty("user_edited_fields", "User-Edited Fields", "string_array",
                  _col("user_edited_fields"), "provenance", sortable=False, filterable=False),
    AssetProperty("scan_id", "Scan ID", "integer", _col("scan_id"), "provenance"),
    AssetProperty("scan_run_id", "Scan Run ID", "string", _col("scan_run_id"), "provenance"),

    # Scan plan
    AssetProperty("scan_plan_version", "Scan Plan Version", "integer",
                  _col("scan_plan_version"), "scan_plan"),
    AssetProperty("scan_plan_computed_at", "Scan Plan Computed At", "datetime",
                  _col("scan_plan_computed_at"), "scan_plan"),
    AssetProperty("scan_plan_signature", "Scan Plan Signature", "string",
                  _col("scan_plan_signature"), "scan_plan", filterable=False),
]


_GROUPS: dict[str, str] = {
    "identity": "Identity",
    "os": "OS / Device",
    "network": "Network Exposure",
    "easm": "EASM",
    "business": "Business Context",
    "ownership": "Ownership",
    "risk": "Risk",
    "lifecycle": "Lifecycle",
    "provenance": "Provenance",
    "scan_plan": "Scan Plan",
    "custom": "Custom Fields",
}


_CF_TYPE_MAP: dict[str, PropertyType] = {
    "string": "string",
    "number": "float",
    "boolean": "boolean",
    "date": "datetime",
    "enum": "enum",
}


def _custom_field_properties(db: Session, org_ids: list[int]) -> list[AssetProperty]:
    """Resolve per-org CustomFieldDefinitions into AssetProperty entries.

    Custom fields are dynamic and org-scoped, so they're materialized at
    request time rather than baked into the static registry.
    """
    if not org_ids:
        return []
    defs = (
        db.query(CustomFieldDefinition)
        .filter(
            CustomFieldDefinition.org_id.in_(org_ids),
            CustomFieldDefinition.entity_type == "asset",
            CustomFieldDefinition.is_active.is_(True),
        )
        .all()
    )
    seen: set[str] = set()
    out: list[AssetProperty] = []
    for d in defs:
        if d.key in seen:
            continue
        seen.add(d.key)
        out.append(AssetProperty(
            key=f"custom.{d.key}",
            label=d.label,
            type=_CF_TYPE_MAP.get(d.data_type, "string"),
            source=_json("custom_fields", d.key),
            group="custom",
            sortable=True,
            default_visible=bool(d.show_in_list),
            enum_values=d.enum_values if d.data_type == "enum" else None,
            description=d.description,
        ))
    return out


def list_properties(db: Session, org_ids: list[int]) -> list[AssetProperty]:
    """Static registry + per-org custom fields."""
    return list(_REGISTRY) + _custom_field_properties(db, org_ids)


def find_property(db: Session, org_ids: list[int], key: str) -> Optional[AssetProperty]:
    for p in list_properties(db, org_ids):
        if p.key == key:
            return p
    return None


def serialize_schema(db: Session, org_ids: list[int]) -> dict:
    props = list_properties(db, org_ids)
    return {
        "groups": [{"key": k, "label": v} for k, v in _GROUPS.items()],
        "properties": [
            {**p.to_dict(), "operators": operators_for(p)} for p in props
        ],
    }
