"""LLM-powered vulnerability validation — detects false positives in Nuclei findings.

After Nuclei scanning, critical/high findings are batched and analyzed by an LLM
to determine if they are true positives, false positives, or need manual review.
Results are stored in the finding's llm_validation JSON column.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Cost control: max findings to validate per scan
MAX_FINDINGS_PER_SCAN = 50
# Findings per LLM API call (batched for efficiency)
BATCH_SIZE = 5

_SYSTEM_PROMPT = """You are a senior security analyst validating vulnerability scanner findings.

For each finding, determine if it is a TRUE POSITIVE, FALSE POSITIVE, or NEEDS MANUAL REVIEW.

Consider:
- Does the evidence (plugin_output) actually confirm the vulnerability?
- Does the affected software/version match what the scanner claims?
- Could this be a generic signature match that doesn't apply here?
- Is the technology actually present on this asset (check tech_stack)?
- Does the port/service make sense for this vulnerability?

Respond ONLY with a JSON array. Each element must have:
{
    "finding_id": <int>,
    "verdict": "true_positive" | "false_positive" | "needs_review",
    "confidence": <float 0.0-1.0>,
    "reasoning": "<brief explanation>"
}"""


def validate_findings(
    db: Session,
    org_id: int,
    scan_id: int | None = None,
    max_findings: int = MAX_FINDINGS_PER_SCAN,
) -> dict:
    """Validate critical/high Nuclei findings using LLM analysis.

    Returns {"validated": int, "true_positive": int, "false_positive": int, "needs_review": int}.
    """
    # Fast exit if no LLM provider is configured. Defer the check to
    # agent_engine.get_default_model which knows about Vertex / Gemini /
    # Ollama / Groq too — not just Anthropic/OpenAI env vars.
    try:
        from agents.agent_engine import get_default_model
        if not get_default_model(db):
            return {"validated": 0, "skipped": "no_llm_provider_configured"}
    except Exception:
        # If agent_engine can't resolve a provider, skip this cycle.
        return {"validated": 0, "skipped": "no_llm_provider_configured"}

    min_severity = int(os.environ.get("LLM_VALIDATION_MIN_SEVERITY", "3"))

    # Fetch candidate findings: critical/high from vm_scanner (Nuclei)
    params = {"org_id": org_id, "min_sev": min_severity, "limit": max_findings}
    scan_filter = ""
    if scan_id:
        scan_filter = "AND f.scan_id = :scan_id"
        params["scan_id"] = scan_id

    result = db.execute(
        text(f"""
            SELECT f.id, f.plugin_id, f.plugin_name, f.severity, f.severity_label,
                   f.description, f.plugin_output, f.port, f.protocol,
                   f.cves, f.exploit_available,
                   a.hostname, a.ip, a.os, a.easm_data
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE a.org_id = :org_id
              AND f.severity >= :min_sev
              AND f.source_type = 'vm_scanner'
              AND f.plugin_family = 'Nuclei'
              AND f.llm_validation IS NULL
              AND f.workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
              {scan_filter}
            ORDER BY f.severity DESC, f.priority_score DESC NULLS LAST
            LIMIT :limit
        """),
        params,
    )
    findings = result.fetchall()

    if not findings:
        return {"validated": 0, "no_candidates": True}

    stats = {"validated": 0, "true_positive": 0, "false_positive": 0, "needs_review": 0}

    # Process in batches
    for i in range(0, len(findings), BATCH_SIZE):
        batch = findings[i:i + BATCH_SIZE]
        verdicts = _validate_batch(batch, db=db)

        for verdict in verdicts:
            finding_id = verdict.get("finding_id")
            if not finding_id:
                continue

            verdict_type = verdict.get("verdict", "needs_review")
            confidence = max(0.0, min(1.0, float(verdict.get("confidence", 0.5))))
            reasoning = verdict.get("reasoning", "")[:1000]
            now = datetime.utcnow().isoformat()

            validation_data = {
                "verdict": verdict_type,
                "confidence": confidence,
                "reasoning": reasoning,
                "validated_at": now,
            }

            # Update finding
            update_sql = """
                UPDATE findings SET
                    llm_validation = :validation
                WHERE id = :id
            """
            update_params = {
                "id": finding_id,
                "validation": json.dumps(validation_data),
            }

            # For high-confidence false positives, also update ctx_exploitability
            if verdict_type == "false_positive" and confidence >= 0.8:
                update_sql = """
                    UPDATE findings SET
                        llm_validation = :validation,
                        ctx_exploitability = 'not_exploitable'
                    WHERE id = :id
                """

            db.execute(text(update_sql), update_params)
            stats["validated"] += 1
            stats[verdict_type] = stats.get(verdict_type, 0) + 1

    db.commit()
    logger.info(
        "org=%d LLM validation: validated=%d tp=%d fp=%d review=%d",
        org_id, stats["validated"], stats["true_positive"],
        stats["false_positive"], stats["needs_review"],
    )
    return stats


def _validate_batch(findings: list, db=None) -> list[dict]:
    """Send a batch of findings to the LLM for validation.

    Uses services.llm_provider.call_llm — honors whichever provider the
    system is configured for (Anthropic, OpenAI, Vertex AI, Gemini,
    Groq, Ollama).

    Returns list of verdict dicts.
    """
    # Build context for each finding
    finding_contexts = []
    for f in findings:
        easm = f.easm_data if isinstance(f.easm_data, dict) else {}
        tech_stack = easm.get("tech_stack", [])

        ctx = {
            "finding_id": f.id,
            "template_id": f.plugin_id,
            "name": f.plugin_name,
            "severity": f.severity_label,
            "description": (f.description or "")[:500],
            "evidence": (f.plugin_output or "")[:500],
            "port": f.port,
            "protocol": f.protocol,
            "cves": f.cves or [],
            "exploit_available": f.exploit_available,
            "asset": {
                "hostname": f.hostname,
                "ip": str(f.ip) if f.ip else None,
                "os": f.os,
                "tech_stack": tech_stack[:20] if tech_stack else [],
            },
        }
        finding_contexts.append(ctx)

    user_message = json.dumps(finding_contexts, indent=2)

    try:
        response_text = _call_llm(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_message,
            max_tokens=2048,
            db=db,
        )
    except Exception as e:
        logger.warning("LLM validation batch failed: %s", e)
        return []

    if not response_text:
        return []

    try:
        import re
        if response_text.strip().startswith("["):
            return json.loads(response_text.strip())

        match = re.search(r"\[.*\]", response_text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except (json.JSONDecodeError, ValueError):
        logger.debug("LLM validation: could not parse JSON from response")

    return []


def _call_llm(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 2048,
    db=None,
) -> str:
    """Multi-provider LLM call — delegates to services.llm_provider.

    Resolves the provider the same way the agent engine does (Vertex AI,
    Anthropic, OpenAI, Gemini, Groq, Ollama). LLM_VALIDATION_MODEL env
    var overrides the default model if set.
    """
    from services.llm_provider import call_llm
    return call_llm(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        max_tokens=max_tokens,
        model_env="LLM_VALIDATION_MODEL",
        db=db,
    )
