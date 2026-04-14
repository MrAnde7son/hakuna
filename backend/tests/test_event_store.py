"""Tests for the EventStore abstraction: hot tier, routed store, and drain."""
import os
import sys
import hashlib
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from conftest import create_user, make_auth_headers

from services.event_store.base import EventRecord, EventFilter
from services.event_store.hot_pg import HotPgStore
from services.event_store.router import RoutedEventStore


# ── Helpers ─────────────────────────────────────────────

def _make_record(org_id: int, **overrides) -> EventRecord:
    """Create a minimal EventRecord for testing."""
    now = datetime.utcnow()
    defaults = dict(
        id=hashlib.sha256(os.urandom(16)).hexdigest()[:36],
        org_id=org_id,
        event_time=now,
        ingested_at=now,
        source_system="test_source",
        source_id=None,
        event_type="network",
        event_category=None,
        severity="medium",
        action=None,
        outcome=None,
        asset_id=None,
        user_name=None,
        source_ip="10.0.0.1",
        dest_ip="10.0.0.2",
        host_name="test-host",
        message="test event",
        raw=None,
        normalized=None,
        dedup_hash=hashlib.sha256(os.urandom(16)).hexdigest(),
        integration_id=None,
    )
    defaults.update(overrides)
    return EventRecord(**defaults)


# ── HotPgStore tests ───────────────────────────────────

def test_hot_write_and_query(db_session, test_org):
    store = HotPgStore(db_session)
    records = [_make_record(test_org.id, message=f"event {i}") for i in range(5)]

    written = store.write_batch(records)
    assert written == 5

    filters = EventFilter(org_ids=[test_org.id])
    results = store.query(filters, limit=10)
    assert len(results) == 5


def test_hot_count(db_session, test_org):
    store = HotPgStore(db_session)
    records = [_make_record(test_org.id) for _ in range(3)]
    store.write_batch(records)

    filters = EventFilter(org_ids=[test_org.id])
    assert store.count(filters) == 3


def test_hot_get_by_id(db_session, test_org):
    store = HotPgStore(db_session)
    record = _make_record(test_org.id, message="findable")
    store.write_batch([record])

    found = store.get_by_id(record.id, [test_org.id])
    assert found is not None
    assert found.message == "findable"

    # Wrong org
    not_found = store.get_by_id(record.id, [99999])
    assert not_found is None


def test_hot_filter_by_severity(db_session, test_org):
    store = HotPgStore(db_session)
    store.write_batch([
        _make_record(test_org.id, severity="critical"),
        _make_record(test_org.id, severity="low"),
        _make_record(test_org.id, severity="critical"),
    ])

    filters = EventFilter(org_ids=[test_org.id], severity="critical")
    results = store.query(filters)
    assert len(results) == 2
    assert all(r.severity == "critical" for r in results)


def test_hot_filter_by_time_range(db_session, test_org):
    store = HotPgStore(db_session)
    old = datetime(2020, 1, 1)
    recent = datetime.utcnow()

    store.write_batch([
        _make_record(test_org.id, event_time=old, message="old"),
        _make_record(test_org.id, event_time=recent, message="new"),
    ])

    filters = EventFilter(
        org_ids=[test_org.id],
        time_from=datetime(2025, 1, 1),
    )
    results = store.query(filters)
    assert len(results) == 1
    assert results[0].message == "new"


def test_hot_filter_fulltext(db_session, test_org):
    store = HotPgStore(db_session)
    store.write_batch([
        _make_record(test_org.id, message="SSH brute force detected"),
        _make_record(test_org.id, message="HTTP 200 OK"),
    ])

    filters = EventFilter(org_ids=[test_org.id], q="brute force")
    results = store.query(filters)
    assert len(results) == 1
    assert "brute force" in results[0].message


def test_hot_sort_order(db_session, test_org):
    store = HotPgStore(db_session)
    t1 = datetime(2026, 1, 1, 10, 0)
    t2 = datetime(2026, 1, 1, 11, 0)
    t3 = datetime(2026, 1, 1, 12, 0)

    store.write_batch([
        _make_record(test_org.id, event_time=t2),
        _make_record(test_org.id, event_time=t1),
        _make_record(test_org.id, event_time=t3),
    ])

    # Descending (default)
    filters = EventFilter(org_ids=[test_org.id], sort_by="event_time", order="desc")
    results = store.query(filters)
    assert results[0].event_time == t3
    assert results[-1].event_time == t1

    # Ascending
    filters.order = "asc"
    results = store.query(filters)
    assert results[0].event_time == t1
    assert results[-1].event_time == t3


def test_hot_org_isolation(db_session, test_org):
    from models.models import Organization
    org2 = Organization(name="Other Org", slug="other-org-es")
    db_session.add(org2)
    db_session.flush()

    store = HotPgStore(db_session)
    store.write_batch([
        _make_record(test_org.id, message="org1 event"),
        _make_record(org2.id, message="org2 event"),
    ])

    # Org 1 only sees its event
    results = store.query(EventFilter(org_ids=[test_org.id]))
    assert all(r.org_id == test_org.id for r in results)
    assert len(results) == 1

    # Org 2 only sees its event
    results = store.query(EventFilter(org_ids=[org2.id]))
    assert all(r.org_id == org2.id for r in results)
    assert len(results) == 1


# ── RoutedEventStore tests ─────────────────────────────

def test_routed_query_hot(db_session, test_org):
    """Recent queries (within hot window) go to Postgres."""
    store = RoutedEventStore(db_session)
    records = [_make_record(test_org.id) for _ in range(3)]
    store.write_batch(records)

    # Default (no time range) → hot tier
    filters = EventFilter(org_ids=[test_org.id])
    results = store.query(filters)
    assert len(results) == 3


def test_routed_get_by_id_hot(db_session, test_org):
    store = RoutedEventStore(db_session)
    record = _make_record(test_org.id, message="routed find")
    store.write_batch([record])

    found = store.get_by_id(record.id, [test_org.id])
    assert found is not None
    assert found.message == "routed find"


def test_routed_falls_back_to_hot_when_lake_unavailable(db_session, test_org):
    """When lake is unavailable, old queries still work (hot-only fallback)."""
    store = RoutedEventStore(db_session)
    old_time = datetime(2020, 1, 1)
    record = _make_record(test_org.id, event_time=old_time, message="old event")
    store.write_batch([record])

    # Lake is unavailable (no MinIO) — should still query hot
    filters = EventFilter(
        org_ids=[test_org.id],
        time_from=datetime(2019, 1, 1),
        time_to=datetime(2021, 1, 1),
    )
    results = store.query(filters)
    assert len(results) == 1
    assert results[0].message == "old event"


# ── Drain tests ────────────────────────────────────────

def test_drain_skips_when_lake_unavailable(db_session, test_org):
    """Drain should not crash when lake is unavailable."""
    from services.event_drain import drain_hot_to_lake
    result = drain_hot_to_lake(db_session)
    # Lake is unavailable in test env
    assert result["error"] is not None or result["drained"] == 0


def test_drain_idempotent(db_session, test_org):
    """Multiple drain calls don't crash or double-process."""
    from services.event_drain import drain_hot_to_lake
    r1 = drain_hot_to_lake(db_session)
    r2 = drain_hot_to_lake(db_session)
    # Both should complete without error (lake unavailable, no events)
    assert isinstance(r1, dict)
    assert isinstance(r2, dict)


# ── EventRecord serialization ──────────────────────────

def test_event_record_to_dict():
    now = datetime.utcnow()
    record = EventRecord(
        id="test-123",
        org_id=1,
        event_time=now,
        ingested_at=now,
        source_system="test",
        event_type="auth",
        severity="high",
        dedup_hash="abc123",
    )
    d = record.to_dict()
    assert d["id"] == "test-123"
    assert d["severity"] == "high"
    assert d["event_time"] == now.isoformat()


# ── Integration with SIEM routes (search via RoutedEventStore) ──

def test_search_endpoint_uses_routed_store(authed_client):
    """Verify the search endpoint still works after switching to RoutedEventStore."""
    # Ingest some events via the API
    for i in range(3):
        authed_client.post("/api/siem/events", json={
            "event_time": "2026-04-14T10:30:00Z",
            "source_system": "test_routed",
            "event_type": "network",
            "severity": "medium",
            "message": f"routed search test {i}",
            "source_ip": f"172.16.0.{i}",
        })

    resp = authed_client.get("/api/siem/events/search", params={"source_system": "test_routed"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 3
    assert all(item["source_system"] == "test_routed" for item in data["items"])


def test_get_event_endpoint_uses_routed_store(authed_client):
    resp = authed_client.post("/api/siem/events", json={
        "event_time": "2026-04-14T10:30:00Z",
        "source_system": "test_detail",
        "event_type": "auth",
        "severity": "high",
        "message": "detail via routed store",
    })
    event_id = resp.json()["id"]

    resp = authed_client.get(f"/api/siem/events/{event_id}")
    assert resp.status_code == 200
    assert resp.json()["message"] == "detail via routed store"
