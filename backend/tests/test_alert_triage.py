"""Tests for services/alert_triage.

The LLM call itself is mocked — we verify the gating, parsing, DB-write, and
auto-suppression branches.
"""
import os, sys, hashlib
from datetime import datetime, timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

import pytest


def _make_events(db, org_id, count=3):
    from models.models import SIEMEvent
    evs = []
    for i in range(count):
        ev = SIEMEvent(
            org_id=org_id,
            event_time=datetime.utcnow() - timedelta(seconds=i * 10),
            source_system="test",
            event_type="authentication",
            severity="high",
            outcome="failure",
            source_ip=f"10.0.0.{i}",
            user_name="root",
            message=f"Failed password for root (test {i})",
            dedup_hash=hashlib.sha256(f"tr-{i}-{os.urandom(4).hex()}".encode()).hexdigest(),
        )
        db.add(ev)
        evs.append(ev)
    db.flush()
    return evs


def _make_rule_and_alert(db, org_id):
    from models.models import DetectionRule, Alert
    rule = DetectionRule(
        org_id=org_id, name="Failed logins", severity="high",
        query={"event_type": "authentication", "outcome": "failure"},
        window_seconds=600, threshold=3, schedule_minutes=1,
    )
    db.add(rule)
    db.flush()
    alert = Alert(
        org_id=org_id, rule_id=rule.id, severity="high",
        event_count=5, exposure_context={"is_internet_facing": True, "criticality": 9},
    )
    db.add(alert)
    db.flush()
    return rule, alert


# ── Gating ───────────────────────────────────────────────
#
# Gating is env-flag only. Provider availability is per-org (see
# IntegrationConfig + agents.agent_engine.get_default_model) and is resolved
# at call time — a missing provider causes triage_alert to log and return None,
# it doesn't flip is_enabled().

def test_is_enabled_false_without_env_flag(monkeypatch):
    from services import alert_triage
    monkeypatch.delenv("ALERT_TRIAGE_ENABLED", raising=False)
    assert alert_triage.is_enabled() is False


def test_is_enabled_true_with_env_flag(monkeypatch):
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")
    assert alert_triage.is_enabled() is True


def test_triage_noop_when_disabled(monkeypatch, db_session, test_org):
    from services import alert_triage
    monkeypatch.delenv("ALERT_TRIAGE_ENABLED", raising=False)
    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)
    result = alert_triage.triage_alert(db_session, alert, rule, events)
    assert result is None
    assert alert.triage_verdict is None


def test_triage_noop_when_no_provider_configured(monkeypatch, db_session, test_org):
    """If no LLM provider is configured for the org, triage logs and returns None."""
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")
    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)

    with patch("services.llm_dispatch.call_llm",
               side_effect=RuntimeError("No provider configured")):
        result = alert_triage.triage_alert(db_session, alert, rule, events)

    assert result is None
    assert alert.triage_verdict is None


# ── Happy path ───────────────────────────────────────────

def test_triage_writes_verdict_to_alert(monkeypatch, db_session, test_org):
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")

    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)

    fake_response = (
        '{"verdict": "true_positive", "confidence": 0.9, '
        '"summary": "Multiple SSH failures against exposed critical asset."}'
    )
    with patch("services.llm_dispatch.call_llm",
                      return_value=(fake_response, "claude-haiku-test")):
        result = alert_triage.triage_alert(db_session, alert, rule, events)

    assert result["verdict"] == "true_positive"
    assert alert.triage_verdict == "true_positive"
    assert alert.triage_confidence == 0.9
    assert alert.triage_summary.startswith("Multiple SSH failures")
    assert alert.triaged_at is not None
    assert alert.triage_model == "claude-haiku-test"
    # Must not auto-suppress without the threshold env var.
    assert alert.suppressed is False or alert.suppressed is None


def test_triage_tolerates_markdown_fenced_response(monkeypatch, db_session, test_org):
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")

    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)

    fake = '```json\n{"verdict":"needs_review","confidence":0.5,"summary":"idk"}\n```'
    with patch("services.llm_dispatch.call_llm", return_value=(fake, "m")):
        result = alert_triage.triage_alert(db_session, alert, rule, events)

    assert result["verdict"] == "needs_review"
    assert alert.triage_verdict == "needs_review"


def test_triage_returns_none_on_unparseable_response(monkeypatch, db_session, test_org):
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")

    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)

    with patch("services.llm_dispatch.call_llm", return_value=("complete garbage", "m")):
        result = alert_triage.triage_alert(db_session, alert, rule, events)

    assert result is None
    assert alert.triage_verdict is None


def test_triage_survives_llm_exception(monkeypatch, db_session, test_org):
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")

    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)

    with patch("services.llm_dispatch.call_llm", side_effect=RuntimeError("boom")):
        result = alert_triage.triage_alert(db_session, alert, rule, events)

    assert result is None
    assert alert.triage_verdict is None


# ── Verdict parsing edge cases ───────────────────────────

def test_parse_verdict_clamps_confidence():
    from services.alert_triage import _parse_verdict
    v = _parse_verdict('{"verdict":"true_positive","confidence":2.5,"summary":"x"}')
    assert v["confidence"] == 1.0
    v = _parse_verdict('{"verdict":"true_positive","confidence":-0.5,"summary":"x"}')
    assert v["confidence"] == 0.0


def test_parse_verdict_rejects_invalid_verdict_value():
    from services.alert_triage import _parse_verdict
    v = _parse_verdict('{"verdict":"maybe","confidence":0.5,"summary":"x"}')
    assert v is None


# ── Auto-suppression ─────────────────────────────────────

def test_auto_suppress_high_confidence_fp(monkeypatch, db_session, test_org):
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")
    monkeypatch.setenv("ALERT_TRIAGE_AUTO_SUPPRESS_THRESHOLD", "0.9")

    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)

    fake = '{"verdict":"false_positive","confidence":0.95,"summary":"Maintenance window."}'
    with patch("services.llm_dispatch.call_llm", return_value=(fake, "m")):
        alert_triage.triage_alert(db_session, alert, rule, events)

    assert alert.suppressed is True
    assert alert.triage_reason == "llm_false_positive"


def test_auto_suppress_does_not_fire_below_threshold(monkeypatch, db_session, test_org):
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")
    monkeypatch.setenv("ALERT_TRIAGE_AUTO_SUPPRESS_THRESHOLD", "0.9")

    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)

    fake = '{"verdict":"false_positive","confidence":0.7,"summary":"Unsure."}'
    with patch("services.llm_dispatch.call_llm", return_value=(fake, "m")):
        alert_triage.triage_alert(db_session, alert, rule, events)

    assert alert.triage_verdict == "false_positive"
    assert alert.suppressed is False or alert.suppressed is None


def test_auto_suppress_ignored_when_threshold_unset(monkeypatch, db_session, test_org):
    from services import alert_triage
    monkeypatch.setenv("ALERT_TRIAGE_ENABLED", "true")
    monkeypatch.delenv("ALERT_TRIAGE_AUTO_SUPPRESS_THRESHOLD", raising=False)

    rule, alert = _make_rule_and_alert(db_session, test_org.id)
    events = _make_events(db_session, test_org.id)

    fake = '{"verdict":"false_positive","confidence":0.99,"summary":"x"}'
    with patch("services.llm_dispatch.call_llm", return_value=(fake, "m")):
        alert_triage.triage_alert(db_session, alert, rule, events)

    assert alert.triage_verdict == "false_positive"
    assert alert.suppressed is False or alert.suppressed is None
