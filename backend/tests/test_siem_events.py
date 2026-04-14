"""Tests for SIEM event hot-tier: ingest, dedup, search, org isolation."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest
from datetime import datetime, timedelta
from conftest import create_user, make_auth_headers


# ── Helpers ─────────────────────────────────────────────

def _make_event(overrides=None):
    """Return a minimal valid event payload."""
    base = {
        "event_time": "2026-04-14T10:30:00Z",
        "source_system": "palo_alto",
        "event_type": "network",
        "severity": "medium",
        "source_ip": "10.0.0.5",
        "dest_ip": "203.0.113.50",
        "message": "Outbound connection to suspicious IP blocked",
    }
    if overrides:
        base.update(overrides)
    return base


# ── Single ingest ───────────────────────────────────────

def test_ingest_single(authed_client):
    resp = authed_client.post("/api/siem/events", json=_make_event())
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "created"
    assert "id" in data
    assert "dedup_hash" in data


def test_ingest_invalid_severity(authed_client):
    resp = authed_client.post("/api/siem/events", json=_make_event({"severity": "banana"}))
    assert resp.status_code == 400


def test_ingest_missing_required_field(authed_client):
    event = _make_event()
    del event["event_type"]
    resp = authed_client.post("/api/siem/events", json=event)
    assert resp.status_code == 422


# ── Batch ingest ────────────────────────────────────────

def test_ingest_batch(authed_client):
    events = [
        _make_event({"source_ip": f"10.0.0.{i}", "message": f"event {i}"})
        for i in range(10)
    ]
    resp = authed_client.post("/api/siem/events/batch", json={"events": events})
    assert resp.status_code == 200
    data = resp.json()
    assert data["created"] == 10
    assert data["duplicates"] == 0
    assert data["total"] == 10


def test_ingest_batch_with_invalid_severity(authed_client):
    events = [
        _make_event({"message": "good event"}),
        _make_event({"severity": "invalid", "message": "bad event"}),
    ]
    resp = authed_client.post("/api/siem/events/batch", json={"events": events})
    assert resp.status_code == 200
    data = resp.json()
    assert data["created"] == 1
    assert len(data["errors"]) == 1


# ── Dedup by hash ───────────────────────────────────────

def test_dedup_by_hash(authed_client):
    event = _make_event({"message": "dedup test unique"})
    resp1 = authed_client.post("/api/siem/events", json=event)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "created"

    resp2 = authed_client.post("/api/siem/events", json=event)
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "duplicate"
    assert resp2.json()["id"] == resp1.json()["id"]


def test_dedup_batch(authed_client):
    event = _make_event({"message": "batch dedup unique"})
    # Ingest once
    authed_client.post("/api/siem/events", json=event)
    # Re-ingest in batch
    resp = authed_client.post("/api/siem/events/batch", json={"events": [event]})
    assert resp.status_code == 200
    assert resp.json()["duplicates"] == 1
    assert resp.json()["created"] == 0


# ── Search filters ──────────────────────────────────────

def test_search_returns_results(authed_client):
    # Ingest a few events first
    for i in range(3):
        authed_client.post("/api/siem/events", json=_make_event({
            "message": f"search test {i}",
            "source_ip": f"192.168.1.{i}",
        }))

    resp = authed_client.get("/api/siem/events/search")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 3


def test_search_filter_by_severity(authed_client):
    authed_client.post("/api/siem/events", json=_make_event({
        "severity": "critical",
        "message": "critical severity filter test",
    }))
    resp = authed_client.get("/api/siem/events/search", params={"severity": "critical"})
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["severity"] == "critical"


def test_search_filter_by_source_system(authed_client):
    authed_client.post("/api/siem/events", json=_make_event({
        "source_system": "crowdstrike",
        "message": "crowdstrike filter test",
    }))
    resp = authed_client.get("/api/siem/events/search", params={"source_system": "crowdstrike"})
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["source_system"] == "crowdstrike"


def test_search_filter_by_time_range(authed_client):
    authed_client.post("/api/siem/events", json=_make_event({
        "event_time": "2026-04-14T12:00:00Z",
        "message": "time range filter test",
    }))
    resp = authed_client.get("/api/siem/events/search", params={
        "time_from": "2026-04-14T11:00:00",
        "time_to": "2026-04-14T13:00:00",
    })
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


def test_search_fulltext_query(authed_client):
    authed_client.post("/api/siem/events", json=_make_event({
        "message": "XYZ_UNIQUE_FULLTEXT_TOKEN_123",
    }))
    resp = authed_client.get("/api/siem/events/search", params={"q": "XYZ_UNIQUE_FULLTEXT"})
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1
    assert "XYZ_UNIQUE_FULLTEXT" in resp.json()["items"][0]["message"]


def test_search_pagination(authed_client):
    resp = authed_client.get("/api/siem/events/search", params={"page": 1, "page_size": 2})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) <= 2
    assert "pages" in data


# ── Single event detail ────────────────────────────────

def test_get_event_by_id(authed_client):
    resp = authed_client.post("/api/siem/events", json=_make_event({"message": "detail test"}))
    event_id = resp.json()["id"]

    resp = authed_client.get(f"/api/siem/events/{event_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == event_id
    assert resp.json()["message"] == "detail test"


def test_get_event_not_found(authed_client):
    resp = authed_client.get("/api/siem/events/nonexistent-id")
    assert resp.status_code == 404


# ── Org isolation ───────────────────────────────────────

def test_org_isolation(authed_client, db_session, test_org):
    # Ingest event as org 1
    resp = authed_client.post("/api/siem/events", json=_make_event({"message": "org1 event isolation"}))
    event_id = resp.json()["id"]

    # Create second org + user
    from models.models import Organization
    org2 = Organization(name="Other Org", slug="other-org")
    db_session.add(org2)
    db_session.flush()

    user2 = create_user(db_session, org2, email="user2@other.com", role="org_admin")
    headers2 = make_auth_headers(user2, org2)

    # Second org cannot see the event
    from fastapi.testclient import TestClient
    from app import app as _app
    from core.database import get_db

    def _override():
        try:
            yield db_session
        finally:
            pass

    _app.dependency_overrides[get_db] = _override
    original_handlers = _app.router.on_startup.copy()
    _app.router.on_startup.clear()

    with TestClient(_app, raise_server_exceptions=False) as c:
        resp2 = c.get(f"/api/siem/events/{event_id}", headers=headers2)
        assert resp2.status_code == 404

        # Search also returns nothing for org2
        resp3 = c.get("/api/siem/events/search", headers=headers2)
        assert resp3.status_code == 200
        ids = [e["id"] for e in resp3.json()["items"]]
        assert event_id not in ids

    _app.dependency_overrides.clear()
    _app.router.on_startup = original_handlers


# ── Unauthorized ────────────────────────────────────────

def test_unauthorized_returns_401(client):
    resp = client.post("/api/siem/events", json=_make_event())
    assert resp.status_code in (401, 403)

    resp = client.get("/api/siem/events/search")
    assert resp.status_code in (401, 403)


# ── Retention cleanup ──────────────────────────────────

def test_retention_cleanup(authed_client):
    # Ingest an old event
    old_event = _make_event({
        "event_time": "2020-01-01T00:00:00Z",
        "message": "old retention cleanup event",
    })
    authed_client.post("/api/siem/events", json=old_event)

    # Run retention with 1h window
    resp = authed_client.delete("/api/siem/events/retention", params={"hours": 1})
    assert resp.status_code == 200
    assert resp.json()["deleted"] >= 1


def test_retention_non_admin_forbidden(db_session, test_org, client):
    analyst = create_user(db_session, test_org, email="analyst@test.com", role="analyst")
    headers = make_auth_headers(analyst, test_org)
    resp = client.delete("/api/siem/events/retention", headers=headers)
    assert resp.status_code == 403
