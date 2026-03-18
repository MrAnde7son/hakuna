"""Pure-function field mapping engine for the Integration Builder.

Four public functions:
- detect_paths(record) → list of PathInfo dicts
- map(raw_record, field_map) → {mapped, errors}
- auto_suggest(source_paths, target_schema) → list of MappingRule dicts
- render_template(template, finding, asset) → rendered object
"""

import re
import copy
from datetime import datetime, timezone

MAX_DEPTH = 6
MAX_PATHS = 200

# ─────────────────────────────────────────────────────────
# detect_paths
# ─────────────────────────────────────────────────────────

def _infer_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        # epoch detection
        if value > 1_000_000_000:
            return "datetime"
        return "number"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, str):
        # datetime detection: ISO8601 patterns and common formats
        if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", value):
            return "datetime"
        if re.match(r"^\d{4}/\d{2}/\d{2}", value):
            return "datetime"
        # epoch as string
        if re.match(r"^\d{10,13}$", value):
            try:
                v = int(value)
                if v > 1_000_000_000:
                    return "datetime"
            except ValueError:
                pass
        return "string"
    return "string"


def _flatten(obj, prefix="", depth=0):
    """Recursively flatten a record into dot-path entries."""
    results = []
    if depth >= MAX_DEPTH:
        return results
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                results.append({"path": path, "sample_value": value, "inferred_type": "object"})
                results.extend(_flatten(value, path, depth + 1))
            elif isinstance(value, list):
                results.append({"path": path, "sample_value": value, "inferred_type": "array"})
                if value and depth + 1 < MAX_DEPTH:
                    first = value[0]
                    child_path = f"{path}[0]"
                    if isinstance(first, dict):
                        results.append({"path": child_path, "sample_value": first, "inferred_type": "object"})
                        results.extend(_flatten(first, child_path, depth + 2))
                    else:
                        results.append({"path": child_path, "sample_value": first, "inferred_type": _infer_type(first)})
            else:
                results.append({"path": path, "sample_value": value, "inferred_type": _infer_type(value)})
    return results


def detect_paths(record):
    """Flatten a record into every possible dot-path with type info."""
    paths = _flatten(record)
    if len(paths) > MAX_PATHS:
        paths = paths[:MAX_PATHS]
    return paths


# ─────────────────────────────────────────────────────────
# dot-path resolution
# ─────────────────────────────────────────────────────────

def _resolve_path(record, path):
    """Resolve a dot-path like 'asset.ip' or 'cve[0]' or 'tags[*].name' against a record."""
    if "[*]" in path:
        # Wildcard array: tags[*].name → [record.tags[0].name, record.tags[1].name, ...]
        before, after = path.split("[*]", 1)
        arr = _resolve_path(record, before)
        if not isinstance(arr, list):
            return None
        after = after.lstrip(".")
        if not after:
            return arr
        return [_resolve_path(item, after) for item in arr if item is not None]

    parts = re.split(r'\.(?![^\[]*\])', path)
    current = record
    for part in parts:
        if current is None:
            return None
        # Handle array index: field[0]
        match = re.match(r'^(.+?)\[(\d+)\]$', part)
        if match:
            key, idx = match.group(1), int(match.group(2))
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
            if isinstance(current, list) and idx < len(current):
                current = current[idx]
            else:
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _set_nested(obj, path, value):
    """Set a value at a nested dot-path, creating intermediate dicts as needed."""
    parts = path.split(".")
    for part in parts[:-1]:
        if part not in obj or not isinstance(obj[part], dict):
            obj[part] = {}
        obj = obj[part]
    obj[parts[-1]] = value


# ─────────────────────────────────────────────────────────
# transforms
# ─────────────────────────────────────────────────────────

def _apply_transform(value, transform, record):
    """Apply a transform to a value. Returns (transformed_value, error_or_None)."""
    if transform is None:
        return value, None

    t = transform.get("type")

    if t == "map":
        mapping = transform.get("mapping", {})
        str_val = str(value) if value is not None else ""
        if str_val in mapping:
            return mapping[str_val], None
        return value, f"Value '{str_val}' not in mapping"

    if t == "boolean":
        truthy = transform.get("truthy", ["true", "1", "yes", "True", "Yes", "TRUE"])
        str_val = str(value) if value is not None else ""
        return str_val in truthy, None

    if t == "float":
        try:
            return float(value), None
        except (ValueError, TypeError):
            return None, f"Cannot convert '{value}' to float"

    if t == "integer":
        try:
            return int(float(value)), None
        except (ValueError, TypeError):
            return None, f"Cannot convert '{value}' to integer"

    if t == "datetime":
        if value is None:
            return None, None
        if isinstance(value, (int, float)):
            # epoch
            if value > 1e12:
                value = value / 1000  # ms to seconds
            try:
                return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(), None
            except (OSError, ValueError) as e:
                return None, f"Invalid epoch: {e}"
        s = str(value)
        # Try ISO8601 first
        for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                     "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d",
                     "%a %b %d %H:%M:%S %Y"]:
            try:
                return datetime.strptime(s, fmt).isoformat(), None
            except ValueError:
                continue
        return s, f"Could not parse datetime: {s}"

    if t == "expression":
        expr = transform.get("expr", "")
        try:
            # Safe eval: only allow basic operations
            allowed_names = {"value": value, "record": record, "True": True, "False": False, "None": None}
            result = eval(expr, {"__builtins__": {}}, allowed_names)  # noqa: S307
            return result, None
        except Exception as e:
            return None, f"Expression error: {e}"

    return value, f"Unknown transform type: {t}"


# ─────────────────────────────────────────────────────────
# map
# ─────────────────────────────────────────────────────────

def map_record(raw_record, field_map):
    """Apply field_map to a raw record. Returns {mapped: dict, errors: list}."""
    mapped = {}
    errors = []

    for rule in field_map:
        source = rule.get("source")
        target = rule.get("target")
        transform = rule.get("transform")
        required = rule.get("required", False)

        value = _resolve_path(raw_record, source)

        if value is None and required:
            errors.append({"target": target, "source": source, "level": "error",
                           "message": f"Required field '{source}' is missing or null"})
            _set_nested(mapped, target, None)
            continue

        if value is None:
            errors.append({"target": target, "source": source, "level": "warning",
                           "message": f"Source path '{source}' not found"})
            _set_nested(mapped, target, None)
            continue

        transformed, err = _apply_transform(value, transform, raw_record)
        if err:
            errors.append({"target": target, "source": source, "level": "warning" if not required else "error",
                           "message": err})
        _set_nested(mapped, target, transformed)

    return {"mapped": mapped, "errors": errors}


# ─────────────────────────────────────────────────────────
# auto_suggest
# ─────────────────────────────────────────────────────────

ALIAS_TABLE = {
    "plugin_id": ["pluginID", "plugin_id", "checkId", "check_id", "findingId"],
    "title": ["pluginName", "name", "title", "finding_name", "checkName", "vulnerability_name", "issue_name"],
    "hostname": ["netbiosName", "hostname", "host", "hostName", "device_name", "computer_name", "asset_name", "name"],
    "ip_address": ["ip", "ip_address", "ipv4", "host_ip", "ipAddress", "ip4", "network_address"],
    "os": ["operatingSystem", "os", "platform", "system", "os_name"],
    "cve_id": ["cve", "cve_id", "cveId", "CVE", "cve_ids[0]", "vulnerability_id"],
    "cvss_score": ["cvss", "baseScore", "cvss_base", "cvss_score", "cvssV3", "risk_score", "base_score"],
    "exploit_available": ["exploitAvailable", "has_exploit", "exploitable", "exploit_exists", "is_exploitable"],
    "severity": ["severity", "risk", "risk_factor", "criticity", "priority", "impact", "threat_level"],
    "first_seen": ["firstSeen", "first_detected", "created_at", "created", "first_observed", "discovery_date"],
    "last_seen": ["lastSeen", "last_detected", "updated_at", "modified", "last_observed", "last_modified"],
    "solution": ["solution", "fix", "remediation", "recommendation", "mitigation", "how_to_fix"],
}


def _normalize(s):
    """Normalize a field name for comparison: lowercase, strip separators."""
    return re.sub(r'[_\-.\[\]0-9]', '', s.lower())


def _edit_distance(a, b):
    """Simple Levenshtein distance."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[len(b)]


def auto_suggest(source_paths, target_schema):
    """Suggest field mappings based on name similarity and alias table.

    source_paths: list of PathInfo dicts (from detect_paths)
    target_schema: list of {name, type, group, ...} dicts
    Returns: list of MappingRule dicts with confidence scores.
    """
    suggestions = []
    # Build lookup: last segment of source path → full path
    source_by_leaf = {}
    for p in source_paths:
        path = p["path"]
        leaf = path.rsplit(".", 1)[-1] if "." in path else path
        # Strip array index: cve[0] → cve
        leaf_clean = re.sub(r'\[\d+\]$', '', leaf)
        source_by_leaf[leaf_clean] = path
        source_by_leaf[path] = path

    for target_field in target_schema:
        target_name = target_field["name"]
        best_source = None
        best_confidence = 0.0

        # Check alias table first
        aliases = ALIAS_TABLE.get(target_name, [])
        for alias in aliases:
            if alias in source_by_leaf:
                best_source = source_by_leaf[alias]
                best_confidence = 0.95
                break
            # Check normalized match
            norm_alias = _normalize(alias)
            for leaf, path in source_by_leaf.items():
                if _normalize(leaf) == norm_alias:
                    best_source = path
                    best_confidence = 0.9
                    break
            if best_source:
                break

        # Fallback: edit distance on normalized names
        if not best_source:
            norm_target = _normalize(target_name)
            for leaf, path in source_by_leaf.items():
                norm_leaf = _normalize(leaf)
                if not norm_leaf:
                    continue
                max_len = max(len(norm_target), len(norm_leaf))
                if max_len == 0:
                    continue
                dist = _edit_distance(norm_target, norm_leaf)
                confidence = 1.0 - (dist / max_len)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_source = path

        if best_source and best_confidence > 0.7:
            suggestions.append({
                "source": best_source,
                "target": target_name,
                "confidence": round(best_confidence, 3),
            })

    return suggestions


# ─────────────────────────────────────────────────────────
# render_template (for push integrations)
# ─────────────────────────────────────────────────────────

_TEMPLATE_RE = re.compile(r'\{\{(\w+(?:\.\w+)*(?:\|[\w]+)?)\}\}')


def _apply_filter(value, filter_name):
    """Apply a template filter like upper, capitalize, lower."""
    s = str(value) if value is not None else ""
    if filter_name == "upper":
        return s.upper()
    if filter_name == "lower":
        return s.lower()
    if filter_name == "capitalize":
        return s.capitalize()
    return s


def _resolve_template_var(var_expr, context):
    """Resolve a template variable like 'finding.cve_id' or 'finding.severity|upper'."""
    parts = var_expr.split("|")
    var_path = parts[0]
    filters = parts[1:]

    value = _resolve_path(context, var_path)
    if value is None:
        value = ""

    for f in filters:
        value = _apply_filter(value, f)

    return value


def _render_value(value, context):
    """Recursively render {{}} templates in a value."""
    if isinstance(value, str):
        # Replace all {{...}} patterns
        def replacer(m):
            return str(_resolve_template_var(m.group(1), context))
        return _TEMPLATE_RE.sub(replacer, value)
    if isinstance(value, dict):
        return {k: _render_value(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_value(item, context) for item in value]
    return value


def render_template(template, finding, asset):
    """Render a push integration payload template with finding and asset data."""
    context = {"finding": finding, "asset": asset}
    return _render_value(copy.deepcopy(template), context)
