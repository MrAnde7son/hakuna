"""Protocol-agnostic `emit_finding` — the write path every audit agent uses
to persist an exposure it found.

Lives in its own module so WMI/LDAP/SMB/Kerberos/SNMP/WinRM agents all call
one shared emitter. The `protocol` parameter is the discriminator; the
`source_plugin` column on the Finding ends up as `hakuna_{protocol}_audit_{mission}`
for easy filtering in the findings queue.
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


@agent_tool(
    "emit_finding",
    "Persist a vulnerability finding discovered by an audit agent. "
    "Every audit protocol (wmi, ldap, smb, kerberos, snmp, winrm) writes "
    "through this single tool so findings share one evidence format and one "
    "provenance tag. "
    "WHEN TO CALL: After you've probed enough to be confident an exposure "
    "exists. Include concrete evidence (tool calls + observed values) in the "
    "`evidence` field so a human reviewer can confirm without re-running you.",
    {
        "protocol":       {"type": "string", "description": "Audit protocol (wmi|ldap|smb|kerberos|snmp|winrm)"},
        "mission":        {"type": "string", "description": "Mission key (identity|privesc|software_cve|network_hygiene|explore)"},
        "asset_id":       {"type": "integer", "description": "Asset this finding is about"},
        "finding_type":   {"type": "string", "description": "Short machine-friendly type, e.g. 'weak_password_policy', 'kerberoastable_account'"},
        "severity":       {"type": "string", "description": "info | low | medium | high | critical"},
        "title":          {"type": "string", "description": "One-line human label"},
        "description":    {"type": "string", "description": "Detailed explanation of the exposure"},
        "evidence":       {"type": "object", "description": "Structured evidence — include tool_calls, observed values, reasoning"},
        "recommended_fix": {"type": "string", "description": "Concrete one-sentence remediation"},
        "cves":           {"type": "array", "description": "Optional CVE IDs if the exposure maps to known CVEs", "items": {"type": "string"}},
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
    cves = params.get("cves") or []

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

    # Stamp the agent run id into evidence so a viewer can navigate back to
    # the transcript. The engine injects _agent_id / _org_id; _agent_run_id
    # is injected by the audit runner when it calls us (see agents/audit_runner.py).
    evidence = dict(evidence)
    if params.get("_agent_id") and "agent_id" not in evidence:
        evidence["agent_id"] = params["_agent_id"]
    if params.get("_agent_run_id") and "agent_run_id" not in evidence:
        evidence["agent_run_id"] = params["_agent_run_id"]

    finding = Finding(
        asset_id=asset.id,
        scan_id=asset.scan_id,                      # asset always has a scan_id FK
        plugin_id=plugin_id,                        # namespaced audit identifier
        plugin_name=title,
        plugin_family=f"{protocol.upper()} Audit",
        synopsis=title,
        description=description,
        severity=severity,
        severity_label=severity_label_norm,
        source_type=f"{protocol}_audit",
        solution=recommended_fix,
        cves=cves if isinstance(cves, list) else [],
        custom_fields={"finding_type": finding_type, "mission": mission, "protocol": protocol},
        llm_validation={
            "verdict": "true_positive",
            "confidence": evidence.get("confidence", 0.8),
            "reasoning": description,
            "validator": "agent",
            "validated_at": datetime.utcnow().isoformat(),
        },
        plugin_output=_format_evidence(evidence),
    )
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
