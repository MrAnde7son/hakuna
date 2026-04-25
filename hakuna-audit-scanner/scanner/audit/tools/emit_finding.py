"""``emit_finding`` — the shared finding-capture tool.

Replaces ``backend/agents/tools/emit_finding.py``. The backend version
imports SQLAlchemy ``Asset`` and ``Finding`` and does direct ORM writes;
the OSS version appends a plain dict onto ``ctx.findings`` in the same
shape the VM scanner emits, so backend ingest
(``services.audit_runner._import_audit_findings`` /
``_import_nuclei_job_findings``) handles both with no special-casing.

Schema is intentionally narrow — every field listed here maps 1:1 to a
column on the backend's ``findings`` table. Drift means schema migration.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from scanner.audit.agent_context import AuditContext
from scanner.audit.audit_engine import agent_tool

logger = logging.getLogger(__name__)


_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@agent_tool(
    "emit_finding",
    "Emit a structured finding. Call this when you have evidence of a "
    "concrete misconfiguration or vulnerability. Use the most specific "
    "severity that fits the evidence (info < low < medium < high < critical). "
    "`evidence` is the literal command output / config snippet that supports "
    "the finding — keep it under 1500 chars; the worker truncates.",
    {
        "title": {
            "type": "string",
            "description": "One-line summary, e.g. 'sshd_config permits root password login'",
        },
        "severity": {
            "type": "string",
            "enum": ["info", "low", "medium", "high", "critical"],
        },
        "category": {
            "type": "string",
            "description": "hardening | identity | software_cve | network | privesc | other",
        },
        "evidence": {
            "type": "string",
            "description": "Raw command output / config snippet that proves the finding",
        },
        "remediation": {
            "type": "string",
            "description": "Concrete fix instruction, one or two sentences",
        },
        "cves": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional list of CVE IDs the finding maps to",
        },
        "plugin_id": {
            "type": "string",
            "description": "Stable identifier for this finding type, e.g. 'audit-ssh-permitrootlogin'. "
                           "Used by backend dedup to merge re-tests.",
        },
    },
)
def emit_finding(ctx: AuditContext, params: dict[str, Any]) -> dict:
    severity = (params.get("severity") or "info").lower()
    if severity not in _VALID_SEVERITIES:
        severity = "info"

    evidence = params.get("evidence") or ""
    if isinstance(evidence, str) and len(evidence) > 1500:
        evidence = evidence[:1500] + "...<truncated>"

    finding = {
        "asset_id": ctx.asset.get("id") if ctx.asset else None,
        "org_id": ctx.org_id,
        "plugin_id": params.get("plugin_id") or f"audit-{ctx.protocol}-generic",
        "plugin_name": params.get("title") or "audit finding",
        "severity": severity,
        "category": params.get("category") or "other",
        "evidence": evidence,
        "solution": params.get("remediation") or "",
        "cves": list(params.get("cves") or []),
        "source": "audit_agent",
        "protocol": ctx.protocol,
        "mission": ctx.mission_key,
        "discovered_at": datetime.utcnow().isoformat(),
        "run_id": ctx.run_id,
    }
    ctx.emit_finding(finding)
    return {"ok": True, "findings_emitted": len(ctx.findings)}
