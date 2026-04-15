"""Tests for SIEM report endpoints and maintenance."""
import os, sys, hashlib
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

import pytest


def _seed_events_and_alerts(db, org_id):
    from models.models import SIEMEvent, DetectionRule, Alert

    for i in range(5):
        db.add(SIEMEvent(
            org_id=org_id,
            event_time=datetime.utcnow() - timedelta(hours=i),
            source_system="test_report",
            event_type="auth",
            severity="high",
            message=f"report event {i}",
            dedup_hash=hashlib.sha256(f"report-{i}-{os.urandom(4).hex()}".encode()).hexdigest(),
        ))

    rule = DetectionRule(org_id=org_id, name="Report Test Rule", severity="critical", query={})
    db.add(rule)
    db.flush()

    for i in range(3):
        alert = Alert(
            org_id=org_id, rule_id=rule.id, severity="critical", event_count=5,
            status="open" if i < 2 else "closed",
        )
        if i == 2:
            alert.updated_at = datetime.utcnow()
        db.add(alert)
    db.flush()


def test_siem_summary_endpoint(authed_client, db_session, test_org):
    _seed_events_and_alerts(db_session, test_org.id)

    resp = authed_client.get("/api/reports/siem-summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "events_24h" in data
    assert "alerts_open" in data
    assert "detection_rules_active" in data
    assert "mttr_minutes" in data
    assert data["events_24h"] >= 5
    assert data["alerts_open"] >= 2


def test_siem_event_volume_endpoint(authed_client, db_session, test_org):
    _seed_events_and_alerts(db_session, test_org.id)

    resp = authed_client.get("/api/reports/siem-event-volume", params={"hours": 24})
    assert resp.status_code == 200
    data = resp.json()
    assert "sources" in data
    assert len(data["sources"]) >= 1


def test_hot_retention_enforcement():
    from services.lake_maintenance import enforce_hot_retention
    result = enforce_hot_retention()
    assert "deleted" in result
    assert isinstance(result["deleted"], int)


def test_lake_maintenance_graceful_when_unavailable():
    from services.lake_maintenance import run_maintenance
    result = run_maintenance()
    assert isinstance(result, dict)
    assert "errors" in result
