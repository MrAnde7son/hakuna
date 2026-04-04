"""
Asset Type Rule Engine
----------------------
Evaluates low-code rules to classify raw asset data into a target asset_type
with structured identity and attributes.  Rules reuse the unified rule-engine
condition format and are evaluated in priority order (lowest number first).

Data normalization:
  Before rule evaluation, raw asset data from any source (Nessus parser,
  EASM sync, VM scanner, integrations) is normalized into a flat dict with
  well-known keys.  This lets the same rule work regardless of source.

Identity mapping supports:
  - Direct field copy:      {"url": "hostname"}
  - Domain extraction:      {"domain": "@extract_domain(hostname)"}
  - Static value:           {"provider": "@static(nessus)"}
  - First non-empty:        {"url": "@coalesce(http_url,hostname)"}
"""
from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from services import rule_engine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known HTTP ports and web service fingerprints
# ---------------------------------------------------------------------------

_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443, 4443}

_WEB_SERVICE_NAMES = {
    "http", "https", "http-alt", "https-alt", "http-proxy",
    "ssl/http", "ssl/https",
}

_WEB_CPE_PATTERNS = re.compile(
    r"cpe:/[ao]:(apache|nginx|microsoft|tomcat|lighttpd|iis|"
    r"oracle:http_server|jetty|caddy|haproxy|openresty|"
    r"nodejs|express|django|flask|rails|spring|laravel|"
    r"wordpress|drupal|joomla|magento|shopify)", re.IGNORECASE
)

_WEB_TECH_KEYWORDS = re.compile(
    r"apache|nginx|iis|tomcat|node\.?js|express|react|angular|vue|"
    r"wordpress|drupal|joomla|django|flask|rails|laravel|spring|"
    r"php|asp\.net|next\.?js|nuxt|gatsby|webpack|vite", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Data normalization — flatten any source into a common evaluation dict
# ---------------------------------------------------------------------------

def normalize_asset_data(raw: dict) -> dict:
    """Normalize raw asset data from any source into a flat dict for rule evaluation.

    Merges scanner-level fields, EASM enrichment (easm_data blob), and
    integration-mapped fields into a consistent namespace.  All original
    fields are preserved; derived fields are added with well-known names.
    """
    d = dict(raw)  # shallow copy — don't mutate caller's dict

    # ── Flatten asset_attributes blob if present ─────────────────
    # This makes connector-specific fields (dns_record_type, proxied, etc.)
    # available to asset type rules without hardcoding field names.
    attrs = raw.get("asset_attributes") or {}
    if isinstance(attrs, dict):
        for key, val in attrs.items():
            if key not in d or not d[key]:
                d[key] = val

    # ── Flatten easm_data blob if present ────────────────────────
    easm = raw.get("easm_data") or {}
    if isinstance(easm, dict):
        # Promote enrichment fields to top level (don't overwrite existing)
        for key in ("tech_stack", "open_ports", "services", "cdn_provider",
                     "waf", "dns_records", "http_status", "http_title",
                     "http_url", "easm_tags", "liveness_state"):
            if key not in d or not d[key]:
                d[key] = easm.get(key)

    # ── Derived: has_http_port ────────────────────────────────────
    ports = d.get("open_ports") or []
    if isinstance(ports, list):
        d["has_http_port"] = any(_is_http_port(p) for p in ports)
    else:
        d["has_http_port"] = False

    # ── Derived: has_web_service ──────────────────────────────────
    services = d.get("services") or {}
    d["has_web_service"] = False
    if isinstance(services, dict):
        for port_str, svc in services.items():
            svc_name = ""
            if isinstance(svc, dict):
                svc_name = (svc.get("name") or svc.get("service_name") or "").lower()
            elif isinstance(svc, str):
                svc_name = svc.lower()
            if svc_name in _WEB_SERVICE_NAMES or _is_http_port(port_str):
                d["has_web_service"] = True
                break

    # ── Derived: has_web_tech ─────────────────────────────────────
    tech = d.get("tech_stack") or []
    d["has_web_tech"] = False
    if isinstance(tech, list):
        d["has_web_tech"] = any(_WEB_TECH_KEYWORDS.search(str(t)) for t in tech)

    # ── Derived: has_web_cpe ──────────────────────────────────────
    cpes = d.get("cpe") or []
    d["has_web_cpe"] = False
    if isinstance(cpes, list):
        d["has_web_cpe"] = any(_WEB_CPE_PATTERNS.search(str(c)) for c in cpes)

    # ── Derived: best_url — pick the best available URL ───────────
    d["best_url"] = (
        d.get("http_url")
        or (_url_from_hostname(d.get("hostname")) if _looks_like_url(d.get("hostname")) else None)
        or None
    )

    # ── Derived: best_domain ──────────────────────────────────────
    url_for_domain = d["best_url"] or d.get("fqdn") or d.get("hostname") or ""
    d["best_domain"] = _extract_domain(url_for_domain)

    return d


def _is_http_port(port) -> bool:
    try:
        return int(port) in _HTTP_PORTS
    except (TypeError, ValueError):
        return False


def _looks_like_url(val: Optional[str]) -> bool:
    return bool(val and re.match(r"^https?://", val))


def _url_from_hostname(hostname: str) -> Optional[str]:
    if _looks_like_url(hostname):
        return hostname
    return None


def _extract_domain(val: str) -> Optional[str]:
    if not val:
        return None
    try:
        parsed = urlparse(val if "://" in val else f"http://{val}")
        return parsed.hostname or val.split("/")[0]
    except Exception:
        return val.split("/")[0] if val else None


# ---------------------------------------------------------------------------
# Condition catalog — available conditions for the UI rule builder
# ---------------------------------------------------------------------------

ASSET_TYPE_CONDITION_CATALOG = [
    {
        "group": "Asset Properties",
        "conditions": [
            {"field": "hostname",     "label": "Hostname",      "ops": ["eq", "neq", "contains", "startswith", "endswith", "regex", "glob"], "value_type": "string", "placeholder": "http://*"},
            {"field": "ip",           "label": "IP Address",    "ops": ["eq", "neq", "contains", "startswith", "regex", "cidr"], "value_type": "string", "placeholder": "10.0.0.0/8"},
            {"field": "fqdn",         "label": "FQDN",          "ops": ["eq", "neq", "contains", "startswith", "endswith", "regex"], "value_type": "string"},
            {"field": "os",           "label": "Operating System", "ops": ["eq", "neq", "contains", "regex"], "value_type": "string", "placeholder": "Windows Server"},
            {"field": "netbios_name", "label": "NetBIOS Name",  "ops": ["eq", "neq", "contains", "regex"], "value_type": "string"},
        ],
    },
    {
        "group": "Service Fingerprint",
        "conditions": [
            {"field": "open_ports",      "label": "Open Ports",      "ops": ["has_item", "has_any", "has_all", "not_has_item"], "value_type": "string", "placeholder": "80,443,8080"},
            {"field": "tech_stack",      "label": "Tech Stack",      "ops": ["has_item", "has_any", "list_contains"], "value_type": "string", "placeholder": "Apache,nginx"},
            {"field": "cpe",             "label": "CPE",             "ops": ["has_item", "list_contains"], "value_type": "string", "placeholder": "cpe:/a:apache"},
            {"field": "has_http_port",   "label": "Has HTTP Port (auto-detected)", "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "has_web_service", "label": "Has Web Service (fingerprint)", "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "has_web_tech",    "label": "Has Web Tech Stack",            "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "has_web_cpe",     "label": "Has Web CPE",                   "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "http_url",        "label": "HTTP URL",        "ops": ["eq", "neq", "contains", "startswith", "regex"], "value_type": "string", "placeholder": "https://"},
            {"field": "http_status",     "label": "HTTP Status Code","ops": ["eq", "neq", "gte", "lte", "gt", "lt"], "value_type": "integer", "placeholder": "200"},
            {"field": "http_title",      "label": "HTTP Page Title", "ops": ["eq", "neq", "contains", "regex"], "value_type": "string"},
            {"field": "cdn_provider",    "label": "CDN Provider",    "ops": ["eq", "neq", "contains"], "value_type": "string", "placeholder": "Cloudflare"},
            {"field": "waf",             "label": "WAF",             "ops": ["eq", "neq", "contains"], "value_type": "string", "placeholder": "AWS WAF"},
        ],
    },
    {
        "group": "Source Context",
        "conditions": [
            {
                "field": "system_type", "label": "System Type (scanner-reported)",
                "ops": ["eq", "neq", "contains"],
                "value_type": "string", "placeholder": "web_application",
            },
            {
                "field": "scanner_type", "label": "Scanner Type",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Internal", "value": "internal"},
                    {"label": "External", "value": "external"},
                    {"label": "Cloud",    "value": "cloud"},
                    {"label": "Agent",    "value": "agent"},
                ],
            },
            {
                "field": "source_type", "label": "Source",
                "ops": ["eq", "neq"],
                "value_type": "enum",
                "options": [
                    {"label": "Nessus",      "value": "nessus"},
                    {"label": "Qualys",      "value": "qualys"},
                    {"label": "Rapid7",      "value": "rapid7"},
                    {"label": "OpenVAS",     "value": "openvas"},
                    {"label": "EASM",        "value": "easm"},
                    {"label": "VM Scanner",  "value": "vm_scanner"},
                    {"label": "Integration", "value": "integration"},
                ],
            },
        ],
    },
    {
        "group": "Connector Attributes",
        "conditions": [
            {"field": "dns_record_type", "label": "DNS Record Type", "ops": ["eq", "neq", "contains"], "value_type": "enum",
             "options": [
                 {"label": "A", "value": "A"}, {"label": "AAAA", "value": "AAAA"},
                 {"label": "CNAME", "value": "CNAME"}, {"label": "MX", "value": "MX"},
                 {"label": "TXT", "value": "TXT"}, {"label": "NS", "value": "NS"},
                 {"label": "SRV", "value": "SRV"}, {"label": "SOA", "value": "SOA"},
             ]},
            {"field": "proxied", "label": "Proxied (CDN/WAF)", "ops": ["is_true", "is_false"], "value_type": "none"},
            {"field": "cloud_provider", "label": "Cloud Provider", "ops": ["eq", "neq", "contains"], "value_type": "string", "placeholder": "aws, azure, gcp"},
            {"field": "cloud_region", "label": "Cloud Region", "ops": ["eq", "neq", "contains", "startswith"], "value_type": "string"},
            {"field": "cloud_account_id", "label": "Cloud Account ID", "ops": ["eq", "neq", "contains"], "value_type": "string"},
            {"field": "origin_ip", "label": "Origin IP", "ops": ["eq", "neq", "contains", "startswith", "cidr"], "value_type": "string"},
            {"field": "service_name", "label": "Service Name", "ops": ["eq", "neq", "contains", "regex"], "value_type": "string"},
            {"field": "cname_target", "label": "CNAME Target", "ops": ["eq", "neq", "contains", "endswith", "regex"], "value_type": "string", "placeholder": "*.amazonaws.com"},
            {"field": "ttl", "label": "DNS TTL", "ops": ["eq", "neq", "gt", "lt", "gte", "lte"], "value_type": "integer"},
        ],
    },
    {
        "group": "Derived (auto-computed)",
        "conditions": [
            {"field": "best_url",    "label": "Best URL (auto-resolved)", "ops": ["eq", "neq", "contains", "startswith", "regex"], "value_type": "string"},
            {"field": "best_domain", "label": "Best Domain (auto-resolved)", "ops": ["eq", "neq", "contains", "endswith", "regex"], "value_type": "string"},
            {"field": "is_credentialed", "label": "Credentialed Scan", "ops": ["is_true", "is_false"], "value_type": "none"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Identity mapping helpers
# ---------------------------------------------------------------------------

_EXTRACT_RE = re.compile(r"^@(\w+)\((.+)\)$")


def _resolve_identity_value(expr: str, asset_data: dict) -> Optional[str]:
    """Resolve a single identity mapping expression against normalized asset data.

    Expressions:
        "hostname"                        → asset_data["hostname"]
        "@extract_domain(hostname)"       → extract domain from URL in field
        "@static(nessus)"                 → literal "nessus"
        "@coalesce(http_url,hostname)"    → first non-empty field
    """
    m = _EXTRACT_RE.match(expr)
    if not m:
        # Direct field copy
        val = asset_data.get(expr)
        return str(val) if val is not None else None

    func_name, arg = m.group(1), m.group(2)

    if func_name == "static":
        return arg

    if func_name == "coalesce":
        for field_name in arg.split(","):
            val = asset_data.get(field_name.strip())
            if val:
                return str(val)
        return None

    if func_name == "extract_domain":
        raw = asset_data.get(arg) or ""
        return _extract_domain(raw)

    if func_name == "extract_path":
        raw = asset_data.get(arg) or ""
        try:
            parsed = urlparse(raw if "://" in raw else f"http://{raw}")
            return parsed.path or "/"
        except Exception:
            return "/"

    if func_name == "extract_port":
        raw = asset_data.get(arg) or ""
        try:
            parsed = urlparse(raw if "://" in raw else f"http://{raw}")
            return str(parsed.port) if parsed.port else None
        except Exception:
            return None

    if func_name == "lower":
        raw = asset_data.get(arg) or ""
        return str(raw).lower()

    if func_name == "upper":
        raw = asset_data.get(arg) or ""
        return str(raw).upper()

    logger.warning(f"Unknown identity mapping function: @{func_name}")
    return str(asset_data.get(arg) or "")


def resolve_identity(mapping: dict, asset_data: dict) -> dict:
    """Resolve a full identity mapping dict → concrete identity values."""
    result = {}
    for key, expr in mapping.items():
        val = _resolve_identity_value(str(expr), asset_data)
        if val is not None:
            result[key] = val
    return result


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------

def evaluate_asset_type_rules(
    asset_data: dict,
    db: Session,
    org_id: Optional[int] = None,
    source_type: Optional[str] = None,
) -> Optional[dict]:
    """Evaluate all enabled asset-type rules against raw asset data.

    Returns the first match as:
        {"asset_type": str, "asset_identity": dict, "asset_attributes": dict}
    or None if no rule matched (caller falls back to existing logic).

    The raw asset_data is normalized before evaluation so that the same
    rules work across Nessus uploads, EASM sync, VM scanner, and
    integrations.
    """
    from models.models import AssetTypeRule

    query = db.query(AssetTypeRule).filter(
        AssetTypeRule.is_enabled == True,  # noqa: E712
    ).order_by(AssetTypeRule.priority, AssetTypeRule.id)

    if org_id is not None:
        query = query.filter(
            (AssetTypeRule.org_id == org_id) | (AssetTypeRule.org_id.is_(None))
        )
    else:
        query = query.filter(AssetTypeRule.org_id.is_(None))

    rules = query.all()
    if not rules:
        return None

    # Normalize once, evaluate many
    normalized = normalize_asset_data(asset_data)

    for rule in rules:
        # Source filter: skip rule if it doesn't match the current source
        if rule.source_filter and source_type:
            if rule.source_filter.lower() != source_type.lower():
                continue

        # Evaluate conditions using the unified rule engine
        matched = rule_engine.evaluate_conditions(
            conditions=rule.conditions,
            logic=rule.condition_logic or "AND",
            asset_dict=normalized,
        )

        if matched:
            identity = resolve_identity(rule.identity_mapping or {}, normalized)
            attributes = dict(rule.default_attributes or {})
            logger.info(
                f"Asset type rule '{rule.name}' (id={rule.id}) matched → "
                f"type={rule.target_asset_type}, identity={identity}"
            )
            return {
                "asset_type": rule.target_asset_type,
                "asset_identity": identity,
                "asset_attributes": attributes,
            }

    return None


def get_condition_catalog() -> list:
    """Return the condition catalog for asset-type rule conditions."""
    return ASSET_TYPE_CONDITION_CATALOG
