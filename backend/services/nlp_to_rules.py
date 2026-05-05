"""
NLP → Rule Engine Conditions

Translates the structured filter dict produced by `services.nlp_search.parse_nlp_query`
into the condition list shape consumed by the campaign rule engine.

Used by the campaign creation flow so a user can describe what they want in plain
English ("critical Windows servers with exploits in DMZ") and get a starting set
of conditions they can then edit in the RuleBuilder.

Returns conditions that all use AND semantics (matching the default for new
campaigns). Filters that have no clean rule-engine analogue are silently dropped
— the chip list lets the UI show what was understood.
"""
from __future__ import annotations

from typing import Any

from services.nlp_search import parse_nlp_query


# NLP key → (rule-engine field, op, value transformer or None)
# Boolean-typed NLP filters: value is always True, op is "is_true"
_BOOL_FINDING_FIELDS = {
    "has_exploit":      "finding.exploit",
    "is_kev":           "finding.is_kev",
    "ransomware_linked":"finding.ransomware_linked",
    "trending_in_news": "finding.trending_in_news",
    "zero_day":         "finding.zero_day",
    "has_ttps":         "finding.has_ttps",
    "is_regression":    "finding.is_regression",
    "auto_resolved":    "finding.workflow_status",  # special: emits eq "resolved"
}

_BOOL_ASSET_FIELDS = {
    "is_internet_facing": "inventory.is_internet_facing",
}

# Enum-typed NLP filters: emit (field, "eq", value)
_ENUM_FINDING_FIELDS = {
    "exploit_maturity_level": "finding.exploit_maturity",
    "workflow_status":        "finding.workflow_status",
    "sla_status":             "finding.sla_status",
    "effort_level":           "finding.effort",
    "plugin_family":          "finding.plugin_family",
    "tactic":                 "finding.tactic",
    "technique_id":           "finding.technique_id",
    "cve":                    "finding.cve",
}

_ENUM_ASSET_FIELDS = {
    "environment": "environment_tag",
}

# Numeric-threshold NLP filters: emit (field, "gte", value)
_THRESHOLD_FINDING_FIELDS = {
    "min_cvss":  "finding.cvss3",
    "min_vpr":   "finding.vpr",
    "min_epss":  "finding.epss_score",
}

_THRESHOLD_ASSET_FIELDS = {
    "min_risk":      "risk_score",
    "min_critical":  "critical_count",
    "min_high":      "high_count",
    "criticality":   "criticality",
}


def _llm_verdict_value(raw: Any) -> str | None:
    """NLP uses 'any' for 'validated'; rule engine uses 'validated'."""
    if raw == "any":
        return "validated"
    if raw in ("true_positive", "false_positive", "needs_review"):
        return raw
    return None


def nlp_to_conditions(query: str) -> dict:
    """Parse an NLP query and translate it into rule-engine conditions.

    Returns:
        {
            "conditions": [{"field", "op", "value"}, ...],
            "query_logic": "AND",
            "chips": [...],         # passthrough from parse_nlp_query for UI display
            "asset_filters": {...}, # passthrough — caller can use for live preview
            "finding_filters": {...},
            "original_query": str,
        }
    """
    parsed = parse_nlp_query(query)
    af = parsed["asset_filters"]
    ff = parsed["finding_filters"]

    conditions: list[dict] = []

    # ── Finding-side ─────────────────────────────────────────────────────────
    for nlp_key, field in _BOOL_FINDING_FIELDS.items():
        if not ff.get(nlp_key):
            continue
        if nlp_key == "auto_resolved":
            conditions.append({"field": field, "op": "eq", "value": "resolved"})
        else:
            conditions.append({"field": field, "op": "is_true", "value": None})

    for nlp_key, field in _ENUM_FINDING_FIELDS.items():
        v = ff.get(nlp_key)
        if v is None:
            continue
        conditions.append({"field": field, "op": "eq", "value": v})

    for nlp_key, field in _THRESHOLD_FINDING_FIELDS.items():
        v = ff.get(nlp_key)
        if v is None:
            continue
        conditions.append({"field": field, "op": "gte", "value": v})

    # Severity — single value or list
    if "severity" in ff:
        conditions.append({"field": "finding.severity", "op": "eq", "value": ff["severity"]})
    elif "severity_list" in ff and ff["severity_list"]:
        # Mixed-severity query like "critical and high" → use min as gte
        conditions.append({
            "field": "finding.severity", "op": "gte",
            "value": min(ff["severity_list"]),
        })

    # LLM verdict
    if (verdict := _llm_verdict_value(ff.get("llm_verdict"))) is not None:
        conditions.append({"field": "finding.validation", "op": "eq", "value": verdict})

    # Free-text search → plugin_name contains (best-effort)
    if (search := ff.get("search")) and len(search) > 2:
        conditions.append({"field": "finding.plugin_name", "op": "contains", "value": search})

    # ── Asset-side ───────────────────────────────────────────────────────────
    for nlp_key, field in _BOOL_ASSET_FIELDS.items():
        if af.get(nlp_key):
            conditions.append({"field": field, "op": "is_true", "value": None})

    for nlp_key, field in _ENUM_ASSET_FIELDS.items():
        v = af.get(nlp_key)
        if v is None:
            continue
        conditions.append({"field": field, "op": "eq", "value": v})

    for nlp_key, field in _THRESHOLD_ASSET_FIELDS.items():
        v = af.get(nlp_key)
        if v is None:
            continue
        conditions.append({"field": field, "op": "gte", "value": v})

    # Tags — comma-separated list of tag names becomes one has_tag condition each
    raw_tags = af.get("tags") or ff.get("tags")
    if raw_tags:
        for tag in [t.strip() for t in str(raw_tags).split(",") if t.strip()]:
            conditions.append({"field": "tag", "op": "has_tag", "value": tag})

    # OS / hostname text search lands in asset_filters.search; if it didn't get
    # consumed by the finding side as plugin_name, route it to hostname.
    asset_search = af.get("search")
    if asset_search and len(asset_search) > 2 and not ff.get("search"):
        conditions.append({"field": "hostname", "op": "contains", "value": asset_search})

    return {
        "conditions": conditions,
        "query_logic": "AND",
        "chips": parsed.get("explanation", []),
        "asset_filters": af,
        "finding_filters": ff,
        "original_query": parsed.get("original_query", query),
    }
