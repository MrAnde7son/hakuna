"""Protocol-agnostic ``emit_finding`` — the write path every audit agent uses
to record an exposure it found.

Tracks the upstream backend schema (`backend/agents/tools/emit_finding.py`):

  - severity is a numeric 0–4 scale (matches ``Finding.severity`` column)
  - severity_label is a normalised "Info|Low|Medium|High|Critical"
  - plugin_id format: ``hakuna_{protocol}_audit_{mission}_{finding_type}``
  - plugin_family comes from ``_PROTOCOL_PLUGIN_FAMILIES`` so compliance
    aggregation has a stable taxonomy
  - cwe_ids + cves are normalised; missing both on Medium+ is logged
    and ``compliance_evaluable=False`` is stamped under custom_fields
  - references, ctx_reachability/exploitability/accessibility match
    the documented Finding columns

The OSS port differs from the backend's version in **one** way: instead
of writing to the SQLAlchemy ``Finding`` table, it appends a plain dict
(same shape) onto ``ctx.findings``. Backend ingest (the existing
``services.audit_runner._import_audit_findings`` path) reads that
list and constructs Finding rows.

Drift between this dict shape and the upstream Finding columns means
ingest needs to grow a translation step — keep them aligned.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from scanner.audit.agent_context import AuditContext
from scanner.audit.audit_engine import agent_tool

logger = logging.getLogger(__name__)


_SEVERITY_MAP = {
    "info": 0, "informational": 0,
    "low": 1,
    "medium": 2, "moderate": 2,
    "high": 3,
    "critical": 4, "crit": 4,
}

_SEVERITY_LABEL = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Closed plugin_family registry per protocol. Compliance mappings key
# off plugin_family as a stable taxonomy; freeform strings break
# aggregation. Adding a new audit protocol requires extending this map.
_PROTOCOL_PLUGIN_FAMILIES: dict[str, str] = {
    "wmi":      "Audit: Windows",
    "ldap":     "Audit: Active Directory",
    "smb":      "Audit: SMB",
    "kerberos": "Audit: Kerberos",
    "winrm":    "Audit: WinRM",
    "snmp":     "Audit: SNMP",
    "ssh":      "Audit: SSH",
    "aws":      "Audit: Cloud (AWS)",
    "azure":    "Audit: Cloud (Azure)",
    "gcp":      "Audit: Cloud (GCP)",
}

# ctx_* enums match the documented Finding column values. Anything
# off-list is dropped silently with a warning — soft-accept.
_CTX_REACHABILITY = {"unreachable", "internal_only", "internet_facing", "unknown"}
_CTX_EXPLOITABILITY = {"not_exploitable", "requires_conditions", "easily_exploitable", "unknown"}
_CTX_ACCESSIBILITY = {"restricted", "authenticated_only", "public", "unknown"}


def _normalize_str_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        return [v.strip() for v in raw.split(",") if v.strip()]
    return []


def _normalize_cwes(raw: Any) -> list[str]:
    """Uppercase + prefix-normalise (CWE-79, cwe-79, 79 → CWE-79). Skip
    anything that doesn't look like a CWE id."""
    out: list[str] = []
    seen: set[str] = set()
    for item in _normalize_str_list(raw):
        s = item.upper().replace(" ", "")
        if s.isdigit():
            s = f"CWE-{s}"
        elif not s.startswith("CWE-"):
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _normalize_cves(raw: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in _normalize_str_list(raw):
        s = item.upper().replace(" ", "")
        if not s.startswith("CVE-"):
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _coerce_ctx(value: Any, allowed: set[str]) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    return v if v in allowed else None


def _coerce_references(raw: Any) -> dict:
    """Persist references in the {urls, advisories, ...} shape used elsewhere."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {k: v for k, v in raw.items() if v}
    urls = _normalize_str_list(raw)
    return {"urls": urls} if urls else {}


def _format_evidence(evidence: dict) -> str:
    """Render structured evidence as readable text for the
    ``plugin_output`` column the backend writes."""
    if not evidence:
        return ""
    parts: list[str] = []
    for key, value in evidence.items():
        if key.startswith("_") or key in {"agent_id", "agent_run_id"}:
            continue
        if isinstance(value, (list, dict)):
            parts.append(f"{key}: {json.dumps(value, default=str)[:500]}")
        else:
            parts.append(f"{key}: {value}")
    return "\n".join(parts)


@agent_tool(
    "emit_finding",
    "Persist a vulnerability finding discovered by an audit agent. "
    "Every audit protocol (wmi, ldap, smb, kerberos, snmp, winrm, ssh, "
    "aws, azure, gcp) writes through this single tool so findings share "
    "one evidence format and one provenance tag. "
    "WHEN TO CALL: After you've probed enough to be confident an exposure "
    "exists. Include concrete evidence (tool calls + observed values) in "
    "the `evidence` field so a human reviewer can confirm without re-running "
    "you. For Medium severity or higher, include `cves` or `cwe_ids` so "
    "the finding is eligible for compliance evaluation; otherwise it still "
    "persists but is excluded from compliance framework status.",
    {
        "finding_type":   {"type": "string", "description": "Short machine-friendly type, e.g. 'weak_password_policy', 'kerberoastable_account'"},
        "severity":       {"type": "string", "description": "info | low | medium | high | critical"},
        "title":          {"type": "string", "description": "One-line human label"},
        "description":    {"type": "string", "description": "Detailed explanation of the exposure"},
        "evidence":       {"type": "object", "description": "Structured evidence — include tool_calls, observed values, reasoning"},
        "recommended_fix": {"type": "string", "description": "Concrete one-sentence remediation"},
        "cves":           {"type": "array", "description": "CVE IDs if the exposure maps to known CVEs (e.g. ['CVE-2021-44228'])", "items": {"type": "string"}},
        "cwe_ids":        {"type": "array", "description": "CWE weakness IDs (e.g. ['CWE-798','CWE-522']). Recommended for any non-Info finding so compliance frameworks can map to it.", "items": {"type": "string"}},
        "references":     {"type": "object", "description": "Reference URLs, e.g. {urls: ['https://nvd.nist.gov/...']}"},
        "ctx_reachability":   {"type": "string", "description": "unreachable | internal_only | internet_facing | unknown"},
        "ctx_exploitability": {"type": "string", "description": "not_exploitable | requires_conditions | easily_exploitable | unknown"},
        "ctx_accessibility":  {"type": "string", "description": "restricted | authenticated_only | public | unknown"},
    },
)
def emit_finding(ctx: AuditContext, params: dict[str, Any]) -> dict:
    finding_type = (params.get("finding_type") or "").strip()
    severity_label = (params.get("severity") or "medium").strip().lower()
    title = (params.get("title") or "").strip()
    description = (params.get("description") or "").strip()
    evidence = params.get("evidence") or {}
    recommended_fix = (params.get("recommended_fix") or "").strip()

    # Protocol + mission come from the run context — not the LLM. The
    # backend's version accepts them as params for legacy reasons; OSS
    # ties them to the actual run.
    protocol = (ctx.protocol or "").strip().lower()
    mission = (ctx.mission_key or "explore").strip().lower()
    asset_id = ctx.asset.get("id") if ctx.asset else None

    if not protocol or not asset_id or not finding_type or not title:
        return {"error": "finding_type and title are required, and run context must have protocol + asset"}

    cves = _normalize_cves(params.get("cves"))
    cwe_ids = _normalize_cwes(params.get("cwe_ids"))
    references = _coerce_references(params.get("references"))
    ctx_reachability = _coerce_ctx(params.get("ctx_reachability"), _CTX_REACHABILITY)
    ctx_exploitability = _coerce_ctx(params.get("ctx_exploitability"), _CTX_EXPLOITABILITY)
    ctx_accessibility = _coerce_ctx(params.get("ctx_accessibility"), _CTX_ACCESSIBILITY)

    severity = _SEVERITY_MAP.get(severity_label, 2)
    severity_label_norm = _SEVERITY_LABEL[severity]
    plugin_id = f"hakuna_{protocol}_audit_{mission}_{finding_type}"
    plugin_family = _PROTOCOL_PLUGIN_FAMILIES.get(protocol, f"Audit: {protocol.upper()}")

    compliance_evaluable = bool(cves or cwe_ids)
    if severity >= 2 and not compliance_evaluable:
        logger.info(
            "emit_finding: %s (sev=%s) emitted without CVE/CWE — marking "
            "compliance_evaluable=False",
            plugin_id, severity,
        )

    # Stamp run metadata into evidence so the agent-run viewer can
    # navigate from finding back to transcript.
    evidence_with_meta = dict(evidence)
    if "agent_id" not in evidence_with_meta:
        evidence_with_meta["agent_id"] = ctx.agent_id
    if "agent_run_id" not in evidence_with_meta:
        evidence_with_meta["agent_run_id"] = ctx.run_id

    custom_fields = {
        "finding_type": finding_type,
        "mission": mission,
        "protocol": protocol,
        "compliance_evaluable": compliance_evaluable,
    }

    finding = {
        "asset_id": asset_id,
        "org_id": ctx.org_id,
        "plugin_id": plugin_id,
        "plugin_name": title,
        "plugin_family": plugin_family,
        "synopsis": title,
        "description": description,
        "severity": severity,
        "severity_label": severity_label_norm,
        "source_type": f"{protocol}_audit",
        "source_systems": ["audit_agent"],
        "solution": recommended_fix,
        "cves": cves,
        "cwe_ids": cwe_ids,
        "references": references,
        "custom_fields": custom_fields,
        "llm_validation": {
            "verdict": "true_positive",
            "confidence": evidence.get("confidence", 0.8) if isinstance(evidence, dict) else 0.8,
            "reasoning": description,
            "validator": "agent",
            "validated_at": datetime.utcnow().isoformat(),
        },
        "plugin_output": _format_evidence(evidence_with_meta),
        "discovered_at": datetime.utcnow().isoformat(),
        "run_id": ctx.run_id,
    }
    if ctx_reachability:
        finding["ctx_reachability"] = ctx_reachability
    if ctx_exploitability:
        finding["ctx_exploitability"] = ctx_exploitability
    if ctx_accessibility:
        finding["ctx_accessibility"] = ctx_accessibility

    ctx.emit_finding(finding)

    logger.info(
        "emit_finding: protocol=%s mission=%s asset=%s severity=%s type=%s",
        protocol, mission, asset_id, severity, finding_type,
    )

    return {
        "plugin_id": plugin_id,
        "severity": severity,
        "compliance_evaluable": compliance_evaluable,
        "status": "emitted",
        "findings_emitted": len(ctx.findings),
    }
