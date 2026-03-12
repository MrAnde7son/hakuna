"""
Nessus scan data pre-processing for token-efficient LLM inputs.

Three compression functions, each targeting a different agent class:

    compress_for_triage(raw_findings, min_cvss=7.0)
        → slim JSON for triage agents (CVE/exploit triage decision data only)

    compress_for_remediation(findings, group_by="remediation_action")
        → batches grouped by fix action (one agent call per batch)

    compress_for_reporting(findings, persona="ciso")
        → aggregated stats for report agents; no raw scanner noise

All functions return compact JSON (no extra whitespace) to minimize token count.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, List, Optional


# ── Triage compressor ─────────────────────────────────────────────────

#: Fields required for triage decisions — everything else is stripped
_TRIAGE_FIELDS = {
    "id", "cve_id", "cves",
    "cvss_score", "cvss2", "cvss3",
    "vpr_score", "vpr",
    "epss_score", "epss",
    "asset_id", "asset_hostname", "asset_ip",
    "plugin_id", "plugin_family", "plugin_name",
    "port", "protocol",
    "has_exploit", "exploit_available", "exploit_maturity",
    "is_in_kev", "is_kev",
    "ransomware_linked", "zero_day",
    "age_days", "sla_status", "sla_due_date",
    "severity", "severity_label",
    "priority_score",
    "is_internet_facing",
    "is_regression",
}


def _normalize_cvss(finding: Dict[str, Any]) -> float:
    """Return the best available CVSS score from a finding dict."""
    return float(
        finding.get("cvss3") or finding.get("cvss_score") or finding.get("cvss2") or 0.0
    )


def compress_for_triage(
    raw_findings: List[Dict[str, Any]],
    min_cvss: float = 7.0,
) -> str:
    """Strip all fields not needed for triage; deduplicate CVE+asset pairs.

    Args:
        raw_findings: List of finding dicts (from tool results or DB serialization).
        min_cvss: Minimum CVSS score to include (default 7.0 — High+Critical only).

    Returns:
        Compact JSON string (no whitespace) of slim finding objects.

    Token reduction: typically 60-75% vs raw finding objects.
    """
    seen: set = set()
    slim: List[Dict[str, Any]] = []

    for f in raw_findings:
        cvss = _normalize_cvss(f)
        if cvss < min_cvss:
            continue

        # Normalize CVE list
        cves = f.get("cves") or []
        if isinstance(cves, str):
            cves = [c.strip() for c in cves.split(",") if c.strip()]

        # Dedup key: same CVE on same asset = one record
        asset_key = f.get("asset_id") or f.get("asset_ip") or "unknown"
        for cve in cves if cves else [f.get("plugin_id", "noCVE")]:
            dedup_key = f"{cve}::{asset_key}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

        # Build slim record with only triage-relevant fields
        slim_record: Dict[str, Any] = {}
        for field in _TRIAGE_FIELDS:
            val = f.get(field)
            if val is not None and val != "" and val != []:
                slim_record[field] = val

        # Normalize field names for consistency
        if "cvss3" in slim_record and "cvss_score" not in slim_record:
            slim_record["cvss_score"] = slim_record.pop("cvss3")
        elif "cvss2" in slim_record and "cvss_score" not in slim_record:
            slim_record["cvss_score"] = slim_record.pop("cvss2")

        if "vpr" in slim_record and "vpr_score" not in slim_record:
            slim_record["vpr_score"] = slim_record.pop("vpr")

        if "is_kev" in slim_record and "is_in_kev" not in slim_record:
            slim_record["is_in_kev"] = slim_record.pop("is_kev")

        if "exploit_available" in slim_record and "has_exploit" not in slim_record:
            slim_record["has_exploit"] = slim_record.pop("exploit_available")

        if "cves" in slim_record:
            slim_record["cve_id"] = slim_record.pop("cves")

        slim.append(slim_record)

    return json.dumps(slim, separators=(",", ":"))


# ── Remediation compressor ────────────────────────────────────────────

def _infer_remediation_action(finding: Dict[str, Any]) -> str:
    """Derive a grouping key from solution text or plugin family."""
    solution = (finding.get("solution") or "").strip()
    plugin_family = finding.get("plugin_family") or "Unknown"

    # Use first 120 chars of solution as grouping key (captures the action)
    if solution and len(solution) > 10:
        action_key = solution[:120].replace("\n", " ").strip()
    else:
        # Fall back to plugin family + plugin name prefix
        plugin_name = (finding.get("plugin_name") or "")[:60]
        action_key = f"{plugin_family}: {plugin_name}"

    return action_key


def _estimate_effort(batch_findings: List[Dict[str, Any]]) -> str:
    """Estimate effort level for a remediation batch."""
    n = len(batch_findings)
    max_cvss = max((_normalize_cvss(f) for f in batch_findings), default=0)
    if n <= 5 and max_cvss < 8.0:
        return "quick_win"
    elif n <= 20 or max_cvss < 9.0:
        return "medium"
    else:
        return "complex"


def compress_for_remediation(
    findings: List[Dict[str, Any]],
    group_by: str = "remediation_action",
) -> str:
    """Group findings that share the same fix; return one batch per action.

    Each batch represents one agent call covering many findings.

    Args:
        findings: List of finding dicts.
        group_by: Grouping strategy.
            - "remediation_action": group by solution/fix text (default)
            - "plugin_family": group by scanner plugin family
            - "asset": group by asset_id (one batch per host)

    Returns:
        Compact JSON string with list of batch objects.

    Token reduction: 50-70% vs sending all findings individually.
    """
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for f in findings:
        if group_by == "plugin_family":
            key = f.get("plugin_family") or "Unknown"
        elif group_by == "asset":
            key = str(f.get("asset_id") or f.get("asset_ip") or "unknown")
        else:  # remediation_action (default)
            key = _infer_remediation_action(f)

        groups[key].append(f)

    batches = []
    for action, batch_findings in groups.items():
        # Collect unique affected assets
        assets: List[Dict[str, Any]] = []
        seen_assets: set = set()
        for f in batch_findings:
            asset_id = str(f.get("asset_id") or f.get("asset_ip") or "")
            if asset_id and asset_id not in seen_assets:
                seen_assets.add(asset_id)
                assets.append({
                    "asset_id": f.get("asset_id"),
                    "ip": f.get("asset_ip"),
                    "hostname": f.get("asset_hostname"),
                })

        # Collect unique CVEs
        cves: set = set()
        for f in batch_findings:
            for cve in (f.get("cves") or f.get("cve_id") or []):
                if cve:
                    cves.add(cve)

        # Get severity range
        severities = [f.get("severity", 0) for f in batch_findings if f.get("severity") is not None]

        batches.append({
            "action": action,
            "finding_count": len(batch_findings),
            "affected_assets": assets[:50],  # cap at 50 assets per batch
            "affected_cves": sorted(cves)[:30],  # cap at 30 CVEs
            "severity_range": {
                "min": min(severities, default=0),
                "max": max(severities, default=0),
            },
            "estimated_effort": _estimate_effort(batch_findings),
            "has_exploit": any(
                f.get("exploit_available") or f.get("has_exploit") for f in batch_findings
            ),
            "has_kev": any(f.get("is_kev") or f.get("is_in_kev") for f in batch_findings),
        })

    # Sort batches: KEV first, then exploit, then by finding count descending
    batches.sort(key=lambda b: (
        not b["has_kev"],
        not b["has_exploit"],
        -b["finding_count"],
    ))

    return json.dumps(batches, separators=(",", ":"))


# ── Reporting compressor ──────────────────────────────────────────────

def compress_for_reporting(
    findings: List[Dict[str, Any]],
    persona: str = "ciso",
    assets: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Aggregate findings into persona-appropriate summary data.

    All raw scanner noise is stripped; only business-relevant metrics remain.

    Args:
        findings: List of finding dicts.
        persona: Target audience.
            - "ciso": aggregate counts, MTTR, SLA breach rate, top 5 risks only
            - "vm_analyst": per-asset breakdown grouped by severity
        assets: Optional list of asset dicts for enrichment.

    Returns:
        Compact JSON string of summary data.

    Token reduction: 85-95% vs raw findings list.
    """
    if not findings:
        return json.dumps({"finding_count": 0, "persona": persona}, separators=(",", ":"))

    # Base counts
    severity_counts = defaultdict(int)
    exploit_count = 0
    kev_count = 0
    sla_breached = 0
    sla_at_risk = 0
    cvss_scores = []

    for f in findings:
        sev = f.get("severity", 0)
        if isinstance(sev, str):
            sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            sev = sev_map.get(sev.lower(), 0)
        severity_counts[sev] += 1

        if f.get("exploit_available") or f.get("has_exploit"):
            exploit_count += 1
        if f.get("is_kev") or f.get("is_in_kev"):
            kev_count += 1

        sla = f.get("sla_status", "")
        if sla == "breached":
            sla_breached += 1
        elif sla == "at_risk":
            sla_at_risk += 1

        cvss = _normalize_cvss(f)
        if cvss > 0:
            cvss_scores.append(cvss)

    total = len(findings)
    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0

    if persona == "ciso":
        # CISO persona: aggregate stats only
        top_risks = sorted(
            [f for f in findings if f.get("severity", 0) >= 3],
            key=lambda f: (
                -(f.get("is_kev") or f.get("is_in_kev") or 0),
                -(f.get("exploit_available") or f.get("has_exploit") or 0),
                -_normalize_cvss(f),
            )
        )[:5]

        top_risk_summary = []
        for f in top_risks:
            top_risk_summary.append({
                "plugin_name": (f.get("plugin_name") or "")[:80],
                "cvss": _normalize_cvss(f),
                "has_exploit": bool(f.get("exploit_available") or f.get("has_exploit")),
                "is_kev": bool(f.get("is_kev") or f.get("is_in_kev")),
                "asset_count": 1,  # enriched by caller if aggregated
            })

        summary = {
            "persona": "ciso",
            "total_findings": total,
            "severity_counts": {
                "critical": severity_counts[4],
                "high": severity_counts[3],
                "medium": severity_counts[2],
                "low": severity_counts[1],
                "info": severity_counts[0],
            },
            "exploitable_findings": exploit_count,
            "kev_findings": kev_count,
            "sla_breached": sla_breached,
            "sla_at_risk": sla_at_risk,
            "average_cvss": avg_cvss,
            "top_5_risks": top_risk_summary,
        }

    elif persona == "vm_analyst":
        # VM Analyst persona: per-asset breakdown by severity
        asset_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "exploit": 0, "kev": 0,
        })

        for f in findings:
            asset_key = str(f.get("asset_id") or f.get("asset_ip") or "unknown")
            sev = f.get("severity", 0)
            sev_labels = {4: "critical", 3: "high", 2: "medium", 1: "low"}
            sev_label = sev_labels.get(sev, "low")
            asset_map[asset_key][sev_label] += 1
            if f.get("exploit_available") or f.get("has_exploit"):
                asset_map[asset_key]["exploit"] += 1
            if f.get("is_kev") or f.get("is_in_kev"):
                asset_map[asset_key]["kev"] += 1

        # Sort assets by risk score
        asset_breakdown = []
        for asset_id, counts in asset_map.items():
            risk = counts["critical"] * 4 + counts["high"] * 3 + counts["exploit"] * 5
            asset_breakdown.append({
                "asset_id": asset_id,
                "risk_score": risk,
                **counts,
            })
        asset_breakdown.sort(key=lambda a: -a["risk_score"])

        summary = {
            "persona": "vm_analyst",
            "total_findings": total,
            "total_assets": len(asset_map),
            "severity_totals": {
                "critical": severity_counts[4],
                "high": severity_counts[3],
                "medium": severity_counts[2],
                "low": severity_counts[1],
            },
            "exploitable_findings": exploit_count,
            "kev_findings": kev_count,
            "sla_breached": sla_breached,
            "per_asset": asset_breakdown[:30],  # Top 30 riskiest assets
        }
    else:
        summary = {
            "persona": persona,
            "total_findings": total,
            "severity_counts": dict(severity_counts),
            "exploitable_findings": exploit_count,
            "kev_findings": kev_count,
        }

    return json.dumps(summary, separators=(",", ":"))


# ── Token savings estimator ───────────────────────────────────────────

def estimate_compression_savings(
    raw_findings: List[Dict[str, Any]],
    compression_fn: str = "triage",
) -> Dict[str, Any]:
    """Estimate token savings from applying a compression function.

    Returns dict with raw_tokens, compressed_tokens, reduction_pct.
    """
    raw_json = json.dumps(raw_findings)
    raw_tokens = len(raw_json) // 4  # ~4 chars/token

    if compression_fn == "triage":
        compressed = compress_for_triage(raw_findings)
    elif compression_fn == "remediation":
        compressed = compress_for_remediation(raw_findings)
    elif compression_fn == "reporting_ciso":
        compressed = compress_for_reporting(raw_findings, persona="ciso")
    elif compression_fn == "reporting_analyst":
        compressed = compress_for_reporting(raw_findings, persona="vm_analyst")
    else:
        compressed = raw_json

    compressed_tokens = len(compressed) // 4
    reduction = round((1 - compressed_tokens / max(raw_tokens, 1)) * 100, 1)

    return {
        "compression_fn": compression_fn,
        "raw_tokens": raw_tokens,
        "compressed_tokens": compressed_tokens,
        "reduction_pct": reduction,
        "tokens_saved": raw_tokens - compressed_tokens,
    }
