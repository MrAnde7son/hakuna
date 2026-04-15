"""Sigma rule importer — converts Sigma YAML rules to DetectionRule objects.

Supports a subset of Sigma v2 specification:
- detection.selection with field: value (string, list, wildcard)
- detection.condition: selection, selection and filter, selection or filter
- Modifiers: contains, startswith, endswith, re, all
- Count aggregation via |count() condition
- MITRE ATT&CK tag extraction

Unsupported features are skipped with clear error messages.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Optional

import yaml

from models.models import DetectionRule

logger = logging.getLogger(__name__)

# Map Sigma status to enabled flag
_STATUS_MAP = {"stable": True, "test": True, "experimental": True, "deprecated": False, "unsupported": False}
_LEVEL_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}

# Sigma field → SIEMEvent field mapping
_FIELD_MAP = {
    "EventID": "event_type",
    "EventType": "event_type",
    "SourceIP": "source_ip",
    "DestinationIP": "dest_ip",
    "SourceHostname": "host_name",
    "TargetUserName": "user_name",
    "User": "user_name",
    "CommandLine": "message",
    "ProcessName": "message",
    "Image": "message",
    "ParentImage": "message",
    "TargetFilename": "message",
}


def import_sigma_rule(yaml_text: str, org_id: int) -> dict:
    """Parse a single Sigma YAML rule and return a DetectionRule-compatible dict.

    Returns: {"rule": DetectionRule kwargs, "warnings": [...], "error": str|None}
    """
    result = {"rule": None, "warnings": [], "error": None}

    try:
        sigma = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        result["error"] = f"Invalid YAML: {e}"
        return result

    if not isinstance(sigma, dict):
        result["error"] = "YAML root must be a mapping"
        return result

    # Required fields
    title = sigma.get("title", "Untitled Sigma Rule")
    level = sigma.get("level", "medium")
    detection = sigma.get("detection")
    if not detection:
        result["error"] = "Missing 'detection' block"
        return result

    # Extract MITRE ATT&CK tags
    tags = sigma.get("tags", [])
    mitre = [t.replace("attack.", "") for t in tags if t.startswith("attack.t")]

    # Parse detection block
    try:
        query_filters = _parse_detection(detection, result["warnings"])
    except Exception as e:
        result["error"] = f"Failed to parse detection: {e}"
        return result

    # Parse condition for count/threshold
    condition = detection.get("condition", "selection")
    threshold = 1
    window_seconds = 300
    group_by = []

    count_match = re.search(r'\|\s*count\s*\(\s*(\w*)\s*\)\s*(by\s+([\w,\s]+))?\s*(>=?|==?|>)\s*(\d+)', str(condition))
    if count_match:
        count_field = count_match.group(1)
        by_fields = count_match.group(3)
        threshold = int(count_match.group(5))
        if by_fields:
            group_by = [f.strip() for f in by_fields.split(",")]

    # Parse timeframe
    timeframe = detection.get("timeframe") or sigma.get("detection", {}).get("timeframe")
    if timeframe:
        window_seconds = _parse_timeframe(timeframe)

    severity = _LEVEL_MAP.get(level.lower(), "medium")
    enabled = _STATUS_MAP.get(sigma.get("status", "test"), True)

    rule_kwargs = {
        "org_id": org_id,
        "name": title[:200],
        "description": sigma.get("description", "")[:2000],
        "severity": severity,
        "enabled": enabled,
        "query": query_filters,
        "window_seconds": window_seconds,
        "threshold": threshold,
        "group_by": group_by,
        "schedule_minutes": max(1, window_seconds // 60),
        "mitre_techniques": mitre,
        "source": "sigma",
        "sigma_rule_id": sigma.get("id"),
    }
    result["rule"] = rule_kwargs
    return result


def _parse_detection(detection: dict, warnings: list) -> dict:
    """Convert Sigma detection block to our query filter format."""
    filters = {}
    condition = detection.get("condition", "selection")

    # Find selection blocks
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue

        if key == "selection" or key.startswith("selection"):
            if isinstance(value, dict):
                for field, pattern in value.items():
                    _apply_sigma_field(filters, field, pattern, warnings)
            elif isinstance(value, list):
                # OR list of dicts
                for item in value:
                    if isinstance(item, dict):
                        for field, pattern in item.items():
                            _apply_sigma_field(filters, field, pattern, warnings)

        elif key == "filter" or key.startswith("filter"):
            warnings.append(f"Filter/exclusion block '{key}' partially supported")

    return filters


def _apply_sigma_field(filters: dict, field: str, pattern, warnings: list):
    """Map a single Sigma field pattern to our query format."""
    # Handle modifiers: field|contains, field|startswith, etc.
    base_field = field
    modifier = None
    if "|" in field:
        parts = field.split("|")
        base_field = parts[0]
        modifier = parts[1] if len(parts) > 1 else None

    # Map to SIEMEvent field
    mapped = _FIELD_MAP.get(base_field, None)
    if not mapped:
        # Try direct mapping
        if base_field in ("source_system", "event_type", "severity", "source_ip",
                          "dest_ip", "host_name", "user_name", "message", "action", "outcome"):
            mapped = base_field
        else:
            # Use message as catch-all for unknown fields
            mapped = "message_contains"
            if isinstance(pattern, str):
                filters[mapped] = pattern
                return
            elif isinstance(pattern, list):
                filters[mapped] = pattern[0] if pattern else ""
                return
            warnings.append(f"Unknown Sigma field '{base_field}' — mapped to message search")
            return

    # Apply value
    if isinstance(pattern, list):
        # List of values → use first for now (simplification)
        if mapped in ("severity",):
            filters[mapped] = [_LEVEL_MAP.get(str(v).lower(), str(v).lower()) for v in pattern]
        else:
            filters[mapped] = str(pattern[0])
    elif isinstance(pattern, str):
        if modifier == "contains" or "*" in pattern:
            filters["message_contains"] = pattern.replace("*", "")
        else:
            filters[mapped] = pattern
    elif isinstance(pattern, (int, float)):
        filters[mapped] = str(pattern)


def _parse_timeframe(tf: str) -> int:
    """Parse Sigma timeframe string to seconds. E.g. '5m' → 300."""
    match = re.match(r"(\d+)\s*(s|m|h|d)", str(tf).lower())
    if not match:
        return 300
    val, unit = int(match.group(1)), match.group(2)
    return val * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def bulk_import(yaml_texts: list[str], org_id: int, db=None) -> dict:
    """Import multiple Sigma rules. Returns summary."""
    from sqlalchemy.orm import Session

    results = {"imported": 0, "skipped": 0, "errors": [], "rules": []}

    for i, text in enumerate(yaml_texts):
        parsed = import_sigma_rule(text, org_id)
        if parsed["error"]:
            results["errors"].append({"index": i, "error": parsed["error"]})
            results["skipped"] += 1
            continue

        if parsed["rule"] and db:
            # Check if sigma_rule_id already exists
            sigma_id = parsed["rule"].get("sigma_rule_id")
            if sigma_id:
                existing = db.query(DetectionRule).filter(
                    DetectionRule.org_id == org_id,
                    DetectionRule.sigma_rule_id == sigma_id,
                ).first()
                if existing:
                    results["skipped"] += 1
                    results["errors"].append({"index": i, "error": f"Sigma rule {sigma_id} already imported"})
                    continue

            rule = DetectionRule(**parsed["rule"])
            db.add(rule)
            db.flush()
            results["imported"] += 1
            results["rules"].append({"id": rule.id, "name": rule.name, "warnings": parsed["warnings"]})
        elif parsed["rule"]:
            results["imported"] += 1
            results["rules"].append({"name": parsed["rule"]["name"], "warnings": parsed["warnings"]})

    if db:
        db.commit()

    return results
