"""Tests for detection engine, Sigma importer, and alert management."""
import os, sys, hashlib, json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from conftest import create_user, make_auth_headers


# ── Helpers ─────────────────────────────────────────────

def _ingest_events(db, org_id, count=5, **overrides):
    from models.models import SIEMEvent
    events = []
    for i in range(count):
        ev = SIEMEvent(
            org_id=org_id,
            event_time=datetime.utcnow() - timedelta(seconds=i * 10),
            source_system=overrides.get("source_system", "test"),
            event_type=overrides.get("event_type", "authentication"),
            severity=overrides.get("severity", "medium"),
            outcome=overrides.get("outcome", "failure"),
            source_ip=overrides.get("source_ip", f"10.0.0.{i % 5}"),
            user_name=overrides.get("user_name", "admin"),
            message=overrides.get("message", f"test event {i}"),
            dedup_hash=hashlib.sha256(f"det-test-{i}-{os.urandom(4).hex()}".encode()).hexdigest(),
        )
        db.add(ev)
        events.append(ev)
    db.flush()
    return events


# ── Detection Engine ───────────────────────────────────

def test_simple_threshold_rule(db_session, test_org):
    from models.models import DetectionRule
    from services.detection_engine import run_rule

    _ingest_events(db_session, test_org.id, count=5, outcome="failure", event_type="authentication")

    rule = DetectionRule(
        org_id=test_org.id, name="Failed logins", severity="high",
        query={"event_type": "authentication", "outcome": "failure"},
        window_seconds=600, threshold=3, schedule_minutes=1,
    )
    db_session.add(rule)
    db_session.flush()

    alerts = run_rule(db_session, rule)
    assert len(alerts) == 1
    assert alerts[0].event_count >= 3
    assert alerts[0].severity == "high"


def test_threshold_not_met(db_session, test_org):
    from models.models import DetectionRule
    from services.detection_engine import run_rule

    _ingest_events(db_session, test_org.id, count=2, outcome="failure", event_type="authentication")

    rule = DetectionRule(
        org_id=test_org.id, name="High threshold", severity="medium",
        query={"event_type": "authentication", "outcome": "failure"},
        window_seconds=600, threshold=10, schedule_minutes=1,
    )
    db_session.add(rule)
    db_session.flush()

    alerts = run_rule(db_session, rule)
    assert len(alerts) == 0


def test_windowed_rule_grouping(db_session, test_org):
    from models.models import DetectionRule
    from services.detection_engine import run_rule

    # 5 events from IP A, 2 from IP B
    for i in range(5):
        _ingest_events(db_session, test_org.id, count=1, source_ip="10.0.0.1", outcome="failure", event_type="auth")
    for i in range(2):
        _ingest_events(db_session, test_org.id, count=1, source_ip="10.0.0.2", outcome="failure", event_type="auth")

    rule = DetectionRule(
        org_id=test_org.id, name="Grouped by IP", severity="high",
        query={"event_type": "auth", "outcome": "failure"},
        window_seconds=600, threshold=3,
        group_by=["source_ip"], schedule_minutes=1,
    )
    db_session.add(rule)
    db_session.flush()

    alerts = run_rule(db_session, rule)
    # Only IP A (5 events) should trigger, not IP B (2 events)
    assert len(alerts) == 1
    assert alerts[0].group_key == "10.0.0.1"


def test_rule_run_idempotent(db_session, test_org):
    from models.models import DetectionRule
    from services.detection_engine import run_rule

    _ingest_events(db_session, test_org.id, count=5, outcome="failure", event_type="auth")

    rule = DetectionRule(
        org_id=test_org.id, name="Idempotent test", severity="medium",
        query={"event_type": "auth"}, window_seconds=600, threshold=1,
    )
    db_session.add(rule)
    db_session.flush()

    alerts1 = run_rule(db_session, rule)
    alerts2 = run_rule(db_session, rule)
    # Second run should not create duplicate alert (dedup within window)
    assert len(alerts1) >= 1
    assert len(alerts2) == 0


# ── Sigma Importer ─────────────────────────────────────

def test_sigma_basic():
    from services.sigma_importer import import_sigma_rule

    yaml_text = """
title: Test Sigma Rule
id: test-sigma-001
status: stable
level: high
description: Test rule for unit tests
tags:
  - attack.t1110
detection:
  selection:
    event_type: authentication
    outcome: failure
  condition: selection
  timeframe: 5m
"""
    result = import_sigma_rule(yaml_text, org_id=1)
    assert result["error"] is None
    assert result["rule"] is not None
    assert result["rule"]["name"] == "Test Sigma Rule"
    assert result["rule"]["severity"] == "high"
    assert "t1110" in result["rule"]["mitre_techniques"]
    assert result["rule"]["source"] == "sigma"


def test_sigma_count_modifier():
    from services.sigma_importer import import_sigma_rule

    yaml_text = """
title: Count Rule
id: test-sigma-count
level: critical
detection:
  selection:
    event_type: authentication
  condition: selection | count(source_ip) by source_ip >= 10
  timeframe: 5m
"""
    result = import_sigma_rule(yaml_text, org_id=1)
    assert result["error"] is None
    assert result["rule"]["threshold"] == 10
    assert "source_ip" in result["rule"]["group_by"]


def test_sigma_unsupported_skipped():
    from services.sigma_importer import import_sigma_rule

    yaml_text = "not valid yaml: {"
    result = import_sigma_rule(yaml_text, org_id=1)
    assert result["error"] is not None


def test_sigma_missing_detection():
    from services.sigma_importer import import_sigma_rule

    yaml_text = """
title: No detection block
id: test-no-detect
level: low
"""
    result = import_sigma_rule(yaml_text, org_id=1)
    assert result["error"] is not None
    assert "detection" in result["error"].lower()


def test_sigma_bulk_import(db_session, test_org):
    from services.sigma_importer import bulk_import

    rules = [
        "title: Rule A\nid: bulk-a\nlevel: high\ndetection:\n  selection:\n    event_type: auth\n  condition: selection\n",
        "title: Rule B\nid: bulk-b\nlevel: low\ndetection:\n  selection:\n    event_type: network\n  condition: selection\n",
        "not valid yaml: {",
    ]
    result = bulk_import(rules, test_org.id, db_session)
    assert result["imported"] == 2
    assert result["skipped"] == 1
    assert len(result["errors"]) == 1


# ── Alert API ──────────────────────────────────────────

def test_alert_creation_via_rule(db_session, test_org):
    from models.models import DetectionRule, Alert
    from services.detection_engine import run_rule

    _ingest_events(db_session, test_org.id, count=3, event_type="network")

    rule = DetectionRule(
        org_id=test_org.id, name="Alert API test", severity="critical",
        query={"event_type": "network"}, window_seconds=600, threshold=1,
    )
    db_session.add(rule)
    db_session.flush()

    run_rule(db_session, rule)
    alerts = db_session.query(Alert).filter(Alert.rule_id == rule.id).all()
    assert len(alerts) >= 1
    assert alerts[0].context is not None
    assert "events_sample" in alerts[0].context


# ── Detection Rules API ────────────────────────────────

def test_rules_crud(authed_client):
    # Create
    resp = authed_client.post("/api/detection-rules", json={
        "name": "API Test Rule",
        "severity": "high",
        "query": {"event_type": "auth"},
        "threshold": 5,
        "window_seconds": 300,
    })
    assert resp.status_code == 200
    rule_id = resp.json()["id"]

    # Read
    resp = authed_client.get(f"/api/detection-rules/{rule_id}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "API Test Rule"

    # Update
    resp = authed_client.put(f"/api/detection-rules/{rule_id}", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False

    # List
    resp = authed_client.get("/api/detection-rules")
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # Delete
    resp = authed_client.delete(f"/api/detection-rules/{rule_id}")
    assert resp.status_code == 200


def test_alerts_list_and_triage(authed_client, db_session, test_org):
    from models.models import DetectionRule, Alert

    rule = DetectionRule(org_id=test_org.id, name="Alert triage test", severity="high",
                         query={}, window_seconds=300, threshold=1)
    db_session.add(rule)
    db_session.flush()

    alert = Alert(org_id=test_org.id, rule_id=rule.id, severity="high", event_count=5)
    db_session.add(alert)
    db_session.flush()

    # List
    resp = authed_client.get("/api/alerts")
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # Triage
    resp = authed_client.post(f"/api/alerts/{alert.id}/triage", json={"status": "triaged"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "triaged"


def test_seed_sigma_rules_parse():
    """Verify all seed Sigma rules parse without errors."""
    from services.sigma_importer import import_sigma_rule
    from pathlib import Path

    seeds_dir = Path(__file__).parent.parent / "seeds" / "sigma_rules"
    for yaml_file in seeds_dir.glob("*.yaml"):
        text = yaml_file.read_text()
        result = import_sigma_rule(text, org_id=1)
        assert result["error"] is None, f"Seed rule {yaml_file.name} failed: {result['error']}"
        assert result["rule"] is not None
