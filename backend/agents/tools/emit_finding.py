"""Protocol-agnostic `emit_finding` — the write path every audit agent uses
to persist an exposure it found.

Lives in its own module so WMI/LDAP/SMB/Kerberos/SNMP/WinRM agents all call
one shared emitter. The `protocol` parameter is the discriminator; the
`source_plugin` column on the Finding ends up as `hakuna_{protocol}_audit_{mission}`
for easy filtering in the findings queue.

Design note (PR 0d): inputs are accepted permissively — missing CVE/CWE
on a Medium+ finding is logged and the finding is still persisted with
``compliance_evaluable: False`` recorded under custom_fields. The
compliance evaluator (PR 3) skips rows where neither cves nor cwe_ids is
populated; we surface "findings outside coverage" as a first-class count
in the Compliance tab so analysts can backfill the metadata or accept
that the finding sits outside framework scope.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from models.models import Asset, Finding
from agents.agent_tools import agent_tool

logger = logging.getLogger(__name__)


# Severity label mirrors the existing `Finding.severity` 0–4 scale used across
# the platform (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical). The agent sees
# the string form in the tool schema to reduce mis-typing.
_SEVERITY_MAP = {
    "info": 0, "informational": 0,
    "low": 1,
    "medium": 2, "moderate": 2,
    "high": 3,
    "critical": 4, "crit": 4,
}

# Closed plugin_family registry per protocol. Compliance mappings key off
# plugin_family as a stable taxonomy; freeform strings break aggregation.
# Adding a new audit protocol requires extending this map.
_PROTOCOL_PLUGIN_FAMILIES: dict[str, str] = {
    "wmi":                   "Audit: Windows",
    "ldap":                  "Audit: Active Directory",
    "smb":                   "Audit: SMB",
    "kerberos":              "Audit: Kerberos",
    "winrm":                 "Audit: WinRM",
    "snmp":                  "Audit: SNMP",
    "ssh":                   "Audit: SSH",
    "aws":                   "Audit: Cloud (AWS)",
    "azure":                 "Audit: Cloud (Azure)",
    "gcp":                   "Audit: Cloud (GCP)",
    "exposed_datastore":     "Audit: Exposed Datastore",
    "exposed_ai_service":    "Audit: Exposed AI Service",
    "exposed_anon_protocol": "Audit: Exposed Anonymous Protocol",
    "ipmi_bmc":              "Audit: IPMI / BMC",
    "netbios_local":         "Audit: NetBIOS / LLMNR / mDNS",
    "ot_protocol":           "Audit: OT (active read-only)",
    "ot_passive":            "Audit: OT (passive listen)",
    "managed_ai_saas":       "Audit: Managed AI (SaaS)",
}

# ctx_* enums match the documented Finding column values
# (see backend/models/models.py:597-599). Anything off-list is dropped
# silently with a warning — soft-accept; we never reject the finding.
_CTX_REACHABILITY = {"unreachable", "internal_only", "internet_facing", "unknown"}
_CTX_EXPLOITABILITY = {"not_exploitable", "requires_conditions", "easily_exploitable", "unknown"}
_CTX_ACCESSIBILITY = {"restricted", "authenticated_only", "public", "unknown"}


def _normalize_str_list(raw: Any) -> list[str]:
    """Accept either a list of strings or a comma-separated string."""
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        return [v.strip() for v in raw.split(",") if v.strip()]
    return []


def _normalize_cwes(raw: Any) -> list[str]:
    """Uppercase and prefix-normalize CWE IDs (CWE-79, cwe-79, 79 → CWE-79)."""
    out: list[str] = []
    seen: set[str] = set()
    for item in _normalize_str_list(raw):
        s = item.upper().replace(" ", "")
        if s.isdigit():
            s = f"CWE-{s}"
        elif not s.startswith("CWE-"):
            # Skip values that don't look like CWE IDs.
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _normalize_cves(raw: Any) -> list[str]:
    """Keep CVE-shaped strings, uppercased."""
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
    """Return the value if it's in the allowed set; else None (drop silently)."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v in allowed:
        return v
    return None


def _coerce_references(raw: Any) -> dict:
    """Persist references in the {urls, advisories, ...} shape used elsewhere.

    Accept either a list of URLs (most common — matches the Nuclei path)
    or a dict with already-namespaced keys. Always returns a dict.
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        # Trust the dict shape — caller has structured it.
        return {k: v for k, v in raw.items() if v}
    urls = _normalize_str_list(raw)
    return {"urls": urls} if urls else {}


@agent_tool(
    "emit_finding",
    "Persist a vulnerability finding discovered by an audit agent. "
    "Every audit protocol (wmi, ldap, smb, kerberos, snmp, winrm) writes "
    "through this single tool so findings share one evidence format and one "
    "provenance tag. "
    "WHEN TO CALL: After you've probed enough to be confident an exposure "
    "exists. Include concrete evidence (tool calls + observed values) in the "
    "`evidence` field so a human reviewer can confirm without re-running you. "
    "For Medium severity or higher, include `cves` or `cwe_ids` so the "
    "finding is eligible for compliance evaluation; otherwise it still "
    "persists but is excluded from compliance framework status.",
    {
        "protocol":       {"type": "string", "description": "Audit protocol (wmi|ldap|smb|kerberos|snmp|winrm|ssh|aws|azure|gcp)"},
        "mission":        {"type": "string", "description": "Mission key (identity|privesc|software_cve|network_hygiene|explore)"},
        "asset_id":       {"type": "integer", "description": "Asset this finding is about"},
        "finding_type":   {"type": "string", "description": "Short machine-friendly type, e.g. 'weak_password_policy', 'kerberoastable_account'"},
        "severity":       {"type": "string", "description": "info | low | medium | high | critical"},
        "title":          {"type": "string", "description": "One-line human label"},
        "description":    {"type": "string", "description": "Detailed explanation of the exposure"},
        "evidence":       {"type": "object", "description": "Structured evidence — include tool_calls, observed values, reasoning"},
        "recommended_fix": {"type": "string", "description": "Concrete one-sentence remediation"},
        "cves":           {"type": "array", "description": "CVE IDs if the exposure maps to known CVEs (e.g. ['CVE-2021-44228'])", "items": {"type": "string"}},
        "cwe_ids":        {"type": "array", "description": "CWE weakness IDs (e.g. ['CWE-798','CWE-522']). Recommended for any non-Info finding so compliance frameworks can map to it.", "items": {"type": "string"}},
        "references":     {"type": "object", "description": "Reference URLs, e.g. {urls: ['https://nvd.nist.gov/...']} — vendor advisories, NVD pages, exploit DBs."},
        "ctx_reachability":   {"type": "string", "description": "unreachable | internal_only | internet_facing | unknown — your assessment of network reachability"},
        "ctx_exploitability": {"type": "string", "description": "not_exploitable | requires_conditions | easily_exploitable | unknown"},
        "ctx_accessibility":  {"type": "string", "description": "restricted | authenticated_only | public | unknown"},
    },
)
def emit_finding_tool(db, params: dict) -> dict:
    protocol = (params.get("protocol") or "").strip().lower()
    mission = (params.get("mission") or "explore").strip().lower()
    asset_id = params.get("asset_id")
    finding_type = (params.get("finding_type") or "").strip()
    severity_label = (params.get("severity") or "medium").strip().lower()
    title = (params.get("title") or "").strip()
    description = (params.get("description") or "").strip()
    evidence = params.get("evidence") or {}
    recommended_fix = (params.get("recommended_fix") or "").strip()

    cves = _normalize_cves(params.get("cves"))
    cwe_ids = _normalize_cwes(params.get("cwe_ids"))
    references = _coerce_references(params.get("references"))
    ctx_reachability = _coerce_ctx(params.get("ctx_reachability"), _CTX_REACHABILITY)
    ctx_exploitability = _coerce_ctx(params.get("ctx_exploitability"), _CTX_EXPLOITABILITY)
    ctx_accessibility = _coerce_ctx(params.get("ctx_accessibility"), _CTX_ACCESSIBILITY)

    if not protocol or not asset_id or not finding_type or not title:
        return {
            "error": "protocol, asset_id, finding_type, and title are required",
        }

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return {"error": f"asset {asset_id} not found"}

    severity = _SEVERITY_MAP.get(severity_label, 2)
    severity_label_norm = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}[severity]
    plugin_id = f"hakuna_{protocol}_audit_{mission}_{finding_type}"
    plugin_family = _PROTOCOL_PLUGIN_FAMILIES.get(
        protocol, f"Audit: {protocol.upper()}"
    )

    # Soft-accept guardrail: a Medium+ finding without CVE *or* CWE can't be
    # mapped to compliance controls. Persist the finding (no rejection,
    # per side-effect analysis), but mark it ineligible so the evaluator
    # skips it cleanly and the UI can surface a "findings outside coverage"
    # count for analyst follow-up.
    compliance_evaluable = bool(cves or cwe_ids)
    if severity >= 2 and not compliance_evaluable:
        logger.info(
            "emit_finding: %s (sev=%s) emitted without CVE/CWE — marking "
            "compliance_evaluable=False",
            plugin_id, severity,
        )

    # Stamp the agent run id into evidence so a viewer can navigate back to
    # the transcript. The engine injects _agent_id / _org_id; _agent_run_id
    # is injected by the audit runner when it calls us (see agents/audit_runner.py).
    evidence = dict(evidence)
    if params.get("_agent_id") and "agent_id" not in evidence:
        evidence["agent_id"] = params["_agent_id"]
    if params.get("_agent_run_id") and "agent_run_id" not in evidence:
        evidence["agent_run_id"] = params["_agent_run_id"]

    custom_fields = {
        "finding_type": finding_type,
        "mission": mission,
        "protocol": protocol,
        "compliance_evaluable": compliance_evaluable,
    }

    finding_kwargs = dict(
        asset_id=asset.id,
        scan_id=asset.scan_id,                      # asset always has a scan_id FK
        plugin_id=plugin_id,                        # namespaced audit identifier
        plugin_name=title,
        plugin_family=plugin_family,
        synopsis=title,
        description=description,
        severity=severity,
        severity_label=severity_label_norm,
        source_type=f"{protocol}_audit",
        source_systems=["audit_agent"],
        solution=recommended_fix,
        cves=cves,
        cwe_ids=cwe_ids,
        references=references,
        custom_fields=custom_fields,
        llm_validation={
            "verdict": "true_positive",
            "confidence": evidence.get("confidence", 0.8),
            "reasoning": description,
            "validator": "agent",
            "validated_at": datetime.utcnow().isoformat(),
        },
        plugin_output=_format_evidence(evidence),
    )
    if ctx_reachability:
        finding_kwargs["ctx_reachability"] = ctx_reachability
    if ctx_exploitability:
        finding_kwargs["ctx_exploitability"] = ctx_exploitability
    if ctx_accessibility:
        finding_kwargs["ctx_accessibility"] = ctx_accessibility

    finding = Finding(**finding_kwargs)
    db.add(finding)
    db.flush()

    logger.info(
        "emit_finding: protocol=%s mission=%s asset=%s severity=%s type=%s → finding_id=%s",
        protocol, mission, asset_id, severity, finding_type, finding.id,
    )

    # Stream the new row through the incremental post-ingest pipeline so the
    # UI sees a real priority_score and the parent asset's severity counters
    # update immediately — otherwise audit findings sit at priority_score=0
    # and assets show no finding counts until the next full scan finalize.
    # Every other ingestion path (VM scanner, EASM, integrations) already
    # does this; audits were the only stream that skipped it.
    try:
        from services.post_ingest import finalize_batch
        finalize_batch(
            db,
            scan_id=asset.scan_id,
            org_id=params.get("_org_id"),
            new_finding_ids=[finding.id],
            new_asset_ids=None,
        )
    except Exception:
        logger.exception(
            "emit_finding: finalize_batch failed for finding_id=%s (non-fatal)",
            finding.id,
        )

    return {
        "finding_id": finding.id,
        "plugin_id": plugin_id,
        "severity": severity,
        "compliance_evaluable": compliance_evaluable,
        "status": "emitted",
    }


def _format_evidence(evidence: dict) -> str:
    """Render structured evidence as readable text for the plugin_output column.

    The JSON lives in finding.llm_validation.reasoning but plugin_output is
    shown prominently in the UI, so we render a compact text block there too.
    """
    if not evidence:
        return ""
    parts: list[str] = []
    for key, value in evidence.items():
        if key.startswith("_") or key in {"agent_id", "agent_run_id"}:
            continue
        if isinstance(value, (list, dict)):
            import json
            parts.append(f"{key}: {json.dumps(value, default=str)[:500]}")
        else:
            parts.append(f"{key}: {value}")
    return "\n".join(parts)
