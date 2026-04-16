"""LLM triage for detection-rule alerts.

Ran once per alert, after threshold has been crossed and exposure enrichment
is complete, before notification fires. Produces:

- triage_verdict:    true_positive | false_positive | needs_review
- triage_confidence: 0.0 - 1.0
- triage_summary:    one-sentence rationale

Cost bounded — scales with alert volume, not event volume. A noisy rule that
fires once every few minutes costs ~1 LLM call every few minutes, not one per
event.

Optional auto-suppression: high-confidence false positives can be suppressed
in place (saving the pager). Off by default — enable with
ALERT_TRIAGE_AUTO_SUPPRESS_THRESHOLD=0.9.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Trim long messages so the prompt stays cheap.
_MAX_MESSAGE_CHARS = 400
# Sample only a handful of events — the LLM can infer volume from event_count.
_MAX_EVENTS_IN_PROMPT = 8

_VALID_VERDICTS = {"true_positive", "false_positive", "needs_review"}


_SYSTEM_PROMPT = """You are a senior SOC analyst triaging a newly-fired alert.

You will receive:
- The detection rule (intent, severity, filters).
- The events that crossed the threshold.
- Asset exposure context (criticality, internet exposure, open vulns, environment).

Decide whether this alert is a true positive that warrants paging a human.

Respond ONLY with a JSON object — no prose, no markdown:

{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": <float 0.0 - 1.0>,
  "summary": "<one sentence, max 200 chars>"
}

Guidelines:
- "true_positive"  — the events look like a real attack/misuse matching the rule's intent.
- "false_positive" — benign activity that incidentally matches the rule
  (scanners, health checks, admin maintenance, known-good automation, expected failures).
- "needs_review"   — genuinely ambiguous; a human should look.
- Confidence reflects how sure you are of the verdict, not severity.
- Weight the verdict by asset context: a login failure on an internet-facing
  critical asset with open vulns is far more likely to be a true positive than
  on an isolated dev box.
"""


def is_enabled() -> bool:
    """Triage is gated by env flag. Provider availability is checked at call time
    (since provider selection is per-org via IntegrationConfig, not env vars)."""
    return os.environ.get("ALERT_TRIAGE_ENABLED", "").lower() in ("1", "true", "yes")


def triage_alert(db: Session, alert, rule, events: list) -> Optional[dict]:
    """Run LLM triage on an alert in-place. Mutates the alert row.

    Returns the parsed verdict dict, or None if triage was skipped/failed.
    Safe to call unconditionally — internally checks `is_enabled()` and
    silently no-ops if no LLM provider is configured for the org.
    """
    if not is_enabled():
        return None

    try:
        from services.llm_dispatch import call_llm
        payload = _build_prompt_payload(alert, rule, events)
        response_text, model = call_llm(
            db, _SYSTEM_PROMPT, json.dumps(payload, default=str),
            max_tokens=512,
        )
    except Exception as e:
        logger.warning("Alert triage LLM call failed (alert=%s): %s", getattr(alert, "id", None), e)
        return None

    verdict = _parse_verdict(response_text)
    if not verdict:
        logger.warning("Alert triage returned unparseable verdict (alert=%s): %.200s",
                       getattr(alert, "id", None), response_text)
        return None

    # Write triage columns
    alert.triage_verdict = verdict["verdict"]
    alert.triage_confidence = verdict["confidence"]
    alert.triage_summary = verdict["summary"][:500]
    alert.triaged_at = datetime.utcnow()
    alert.triage_model = model

    # Optional auto-suppression of high-confidence FPs.
    threshold_raw = os.environ.get("ALERT_TRIAGE_AUTO_SUPPRESS_THRESHOLD")
    if threshold_raw:
        try:
            threshold = float(threshold_raw)
        except ValueError:
            threshold = None
        if (threshold is not None
                and verdict["verdict"] == "false_positive"
                and verdict["confidence"] >= threshold
                and not alert.suppressed):
            alert.suppressed = True
            alert.triage_reason = "llm_false_positive"
            logger.info(
                "Auto-suppressed alert %s (confidence=%.2f >= %.2f): %s",
                alert.id, verdict["confidence"], threshold, alert.triage_summary,
            )

    return verdict


# ─────────────────────────────────────────────────────────
# Prompt building
# ─────────────────────────────────────────────────────────

def _build_prompt_payload(alert, rule, events: list) -> dict:
    sample = []
    for ev in events[:_MAX_EVENTS_IN_PROMPT]:
        sample.append({
            "event_time": ev.event_time.isoformat() if getattr(ev, "event_time", None) else None,
            "source_system": ev.source_system,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "action": ev.action,
            "outcome": ev.outcome,
            "source_ip": ev.source_ip,
            "dest_ip": ev.dest_ip,
            "host_name": ev.host_name,
            "user_name": ev.user_name,
            "message": (ev.message or "")[:_MAX_MESSAGE_CHARS],
        })

    return {
        "rule": {
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity,
            "mitre_techniques": rule.mitre_techniques or [],
            "query": rule.query or {},
            "window_seconds": rule.window_seconds,
            "threshold": rule.threshold,
            "group_by": rule.group_by or [],
        },
        "alert": {
            "event_count": alert.event_count,
            "entity_type": alert.entity_type,
            "entity_value": alert.entity_value,
            "group_key": alert.group_key,
        },
        "exposure": alert.exposure_context or {},
        "events": sample,
    }


# ─────────────────────────────────────────────────────────
# Response parsing
# ─────────────────────────────────────────────────────────

def _parse_verdict(text: str) -> Optional[dict]:
    t = (text or "").strip()
    if t.startswith("```"):
        t = re.sub(r"^```\w*\n?", "", t)
        t = re.sub(r"\n?```$", "", t).strip()

    parsed = None
    try:
        parsed = json.loads(t)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", t, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group())
            except json.JSONDecodeError:
                pass
    if not isinstance(parsed, dict):
        return None

    verdict = str(parsed.get("verdict", "")).strip().lower()
    if verdict not in _VALID_VERDICTS:
        return None

    try:
        confidence = float(parsed.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    summary = str(parsed.get("summary", ""))[:500]

    return {"verdict": verdict, "confidence": confidence, "summary": summary}


