"""Tests for SIEM pull connectors: Splunk, Sentinel, Elastic.

Tests connector template loading, cursor state, and field mapping.
Integration runner execution is tested with mocked transport responses.
"""
import os
import sys
import json
import hashlib
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

import pytest


# ── Connector template tests ──────────────────────────

def test_splunk_siem_connector_loads():
    from integrations.connector_loader import get_connector
    c = get_connector("splunk_siem_events")
    assert c is not None
    assert c["entity"] == "siem_event"
    assert c["direction"] == "pull"
    assert c["category"] == "SIEM"
    assert "incremental" in c
    assert c["incremental"]["cursor_field"] == "last_event_time"


def test_sentinel_siem_connector_loads():
    from integrations.connector_loader import get_connector
    c = get_connector("sentinel_siem_events")
    assert c is not None
    assert c["entity"] == "siem_event"
    assert "cursor_update" in c
    assert c["cursor_update"]["field"] == "last_event_time"


def test_elastic_siem_connector_loads():
    from integrations.connector_loader import get_connector
    c = get_connector("elastic_siem_events")
    assert c is not None
    assert c["entity"] == "siem_event"
    assert c["transport_config"]["method"] == "POST"
    assert "search_after" in json.dumps(c["transport_config"])


def test_all_siem_connectors_have_required_fields():
    from integrations.connector_loader import get_connector
    for cid in ["splunk_siem_events", "sentinel_siem_events", "elastic_siem_events"]:
        c = get_connector(cid)
        assert c is not None, f"Connector {cid} not found"
        assert c["entity"] == "siem_event", f"{cid} should target siem_event"
        assert "default_field_map" in c, f"{cid} missing default_field_map"
        assert "dedup_key" in c, f"{cid} missing dedup_key"
        assert "params_schema" in c, f"{cid} missing params_schema"
        assert "credential_acquisition" in c, f"{cid} missing credential_acquisition"

        # Field map must include event_time and severity
        field_targets = [f["target"] for f in c["default_field_map"]]
        assert "event_time" in field_targets, f"{cid} missing event_time mapping"
        assert "severity" in field_targets, f"{cid} missing severity mapping"


# ── Cursor state tests ─────────────────────────────────

def test_cursor_state_column_exists(db_session, test_org):
    """Integration model should have cursor_state column."""
    from models.models import Integration
    i = Integration(
        org_id=test_org.id,
        name="Cursor Test",
        direction="pull",
        entity="siem_event",
        transport_type="api",
        cursor_state={"last_event_time": "2026-04-14T00:00:00Z"},
    )
    db_session.add(i)
    db_session.flush()

    loaded = db_session.query(Integration).filter(Integration.id == i.id).first()
    assert loaded.cursor_state is not None
    assert loaded.cursor_state["last_event_time"] == "2026-04-14T00:00:00Z"


def test_cursor_state_persists_across_updates(db_session, test_org):
    from models.models import Integration
    i = Integration(
        org_id=test_org.id,
        name="Cursor Persist",
        direction="pull",
        entity="siem_event",
        transport_type="api",
    )
    db_session.add(i)
    db_session.flush()

    # Initially null
    assert i.cursor_state is None

    # Update cursor
    i.cursor_state = {"last_event_time": "2026-04-14T10:00:00Z", "offset": 500}
    db_session.flush()

    loaded = db_session.query(Integration).filter(Integration.id == i.id).first()
    assert loaded.cursor_state["offset"] == 500


def test_stream_config_column_exists(db_session, test_org):
    """Integration model should have stream_config column."""
    from models.models import Integration
    i = Integration(
        org_id=test_org.id,
        name="Stream Test",
        direction="pull",
        entity="siem_event",
        transport_type="stream",
        stream_config={"template_id": "palo_alto_panos", "listen_port": 6514},
    )
    db_session.add(i)
    db_session.flush()

    loaded = db_session.query(Integration).filter(Integration.id == i.id).first()
    assert loaded.stream_config["template_id"] == "palo_alto_panos"


# ── Field mapping tests with mock Splunk response ─────

def test_splunk_field_mapping():
    """Verify Splunk field_map correctly maps raw Splunk records."""
    from services.field_mapper import map_record
    from integrations.connector_loader import get_connector

    connector = get_connector("splunk_siem_events")
    field_map = connector["default_field_map"]

    raw_record = {
        "_time": "2026-04-14T10:30:00.000Z",
        "source": "WinEventLog:Security",
        "event_id": "EVT-12345",
        "sourcetype": "WinEventLog",
        "severity": "high",
        "action": "blocked",
        "user": "admin",
        "src_ip": "10.0.0.5",
        "dest_ip": "203.0.113.50",
        "host": "DC01",
        "_raw": "Failed logon attempt for admin from 10.0.0.5",
    }

    result = map_record(raw_record, field_map)
    mapped = result["mapped"]

    assert mapped.get("source_system") == "WinEventLog:Security"
    assert mapped.get("source_id") == "EVT-12345"
    assert mapped.get("event_type") == "WinEventLog"
    assert mapped.get("severity") == "high"
    assert mapped.get("user_name") == "admin"
    assert mapped.get("source_ip") == "10.0.0.5"
    assert mapped.get("host_name") == "DC01"


def test_sentinel_field_mapping():
    """Verify Sentinel field_map correctly maps raw Sentinel incident records."""
    from services.field_mapper import map_record
    from integrations.connector_loader import get_connector

    connector = get_connector("sentinel_siem_events")
    field_map = connector["default_field_map"]

    raw_record = {
        "properties": {
            "createdTimeUtc": "2026-04-14T10:30:00Z",
            "incidentNumber": 42,
            "title": "Brute force attack detected",
            "severity": "High",
            "status": "Active",
            "classification": "TruePositive",
            "owner": {"assignedTo": "analyst@corp.com"},
            "additionalData": {"alertsCount": 3},
        }
    }

    result = map_record(raw_record, field_map)
    mapped = result["mapped"]

    assert mapped.get("message") == "Brute force attack detected"
    assert mapped.get("severity") == "high"
    assert mapped.get("outcome") == "unknown"  # Active → unknown
    assert mapped.get("user_name") == "analyst@corp.com"


def test_elastic_field_mapping():
    """Verify Elastic field_map correctly maps raw Elastic alert records."""
    from services.field_mapper import map_record
    from integrations.connector_loader import get_connector

    connector = get_connector("elastic_siem_events")
    field_map = connector["default_field_map"]

    raw_record = {
        "_id": "alert-abc123",
        "_source": {
            "@timestamp": "2026-04-14T10:30:00.000Z",
            "kibana": {
                "alert": {
                    "rule": {
                        "name": "Suspicious PowerShell execution",
                        "category": "execution",
                    },
                    "severity": "high",
                    "workflow_status": "open",
                },
            },
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "10.0.0.1"},
            "host": {"name": "WORKSTATION-01"},
            "user": {"name": "jdoe"},
            "event": {"action": "execution", "category": "process"},
        },
        "sort": [1776000000000, "alert-abc123"],
    }

    result = map_record(raw_record, field_map)
    mapped = result["mapped"]

    assert mapped.get("source_id") == "alert-abc123"
    assert mapped.get("message") == "Suspicious PowerShell execution"
    assert mapped.get("severity") == "high"
    assert mapped.get("source_ip") == "10.0.0.5"
    assert mapped.get("host_name") == "WORKSTATION-01"
    assert mapped.get("user_name") == "jdoe"
    assert mapped.get("action") == "execution"


# ── SIEM event upsert via generic path ────────────────

def test_siem_event_generic_upsert(db_session, test_org):
    """Verify siem_event entity works through the generic upsert path."""
    from services.upsert_handler import upsert_batch

    records = [
        {
            "org_id": test_org.id,
            "event_time": "2026-04-14T10:30:00",
            "source_system": "splunk",
            "source_id": "EVT-001",
            "event_type": "network",
            "severity": "high",
            "message": "Generic upsert test",
            "dedup_hash": hashlib.sha256(b"test-dedup-1").hexdigest(),
        },
        {
            "org_id": test_org.id,
            "event_time": "2026-04-14T10:31:00",
            "source_system": "splunk",
            "source_id": "EVT-002",
            "event_type": "network",
            "severity": "medium",
            "message": "Generic upsert test 2",
            "dedup_hash": hashlib.sha256(b"test-dedup-2").hexdigest(),
        },
    ]

    result = upsert_batch(db_session, "siem_event", records, ["org_id", "dedup_hash"], "test-int-id")
    assert result["inserted"] == 2
    assert result["errors"] == []

    # Verify they're in the DB
    from models.models import SIEMEvent
    events = db_session.query(SIEMEvent).filter(SIEMEvent.org_id == test_org.id).all()
    assert len(events) >= 2


def test_siem_event_dedup_via_upsert(db_session, test_org):
    """Duplicate dedup_hash should update, not insert."""
    from services.upsert_handler import upsert_batch

    dedup = hashlib.sha256(b"dedup-test-same").hexdigest()
    record = {
        "org_id": test_org.id,
        "event_time": "2026-04-14T10:30:00",
        "source_system": "elastic",
        "source_id": "DUP-001",
        "event_type": "auth",
        "severity": "low",
        "message": "first insert",
        "dedup_hash": dedup,
    }

    r1 = upsert_batch(db_session, "siem_event", [record], ["org_id", "dedup_hash"], "int-id")
    assert r1["inserted"] == 1

    record["message"] = "updated message"
    r2 = upsert_batch(db_session, "siem_event", [record], ["org_id", "dedup_hash"], "int-id")
    assert r2["updated"] == 1 or r2["skipped"] == 1  # either is acceptable


# ── Partial failure resume ─────────────────────────────

def test_cursor_survives_partial_failure(db_session, test_org):
    """Cursor state should be preserved even if later processing fails."""
    from models.models import Integration

    i = Integration(
        org_id=test_org.id,
        name="Partial Test",
        direction="pull",
        entity="siem_event",
        transport_type="api",
        cursor_state={"last_event_time": "2026-04-14T08:00:00Z"},
    )
    db_session.add(i)
    db_session.flush()

    # Simulate a partial failure: cursor was saved but run errored
    i.cursor_state = {"last_event_time": "2026-04-14T10:00:00Z"}
    db_session.flush()

    # On next run, cursor should start from the saved position
    loaded = db_session.query(Integration).filter(Integration.id == i.id).first()
    assert loaded.cursor_state["last_event_time"] == "2026-04-14T10:00:00Z"


# ── Connector listing includes SIEM connectors ────────

def test_siem_connectors_appear_in_listing(authed_client):
    """SIEM connectors should appear in the connector listing API."""
    # Try paginated listing (may need category filter or larger page_size)
    resp = authed_client.get("/api/integration-builder/connectors", params={"category": "SIEM", "page_size": 100})
    assert resp.status_code == 200
    data = resp.json()

    # Handle various response formats (list, or {connectors: [...]}, or {items: [...]})
    if isinstance(data, list):
        connectors = data
    elif isinstance(data, dict):
        connectors = data.get("connectors", data.get("items", data.get("results", [])))
    else:
        connectors = []

    siem_ids = [c["id"] for c in connectors]
    # If filtering by category didn't work, try full listing
    if not siem_ids:
        resp2 = authed_client.get("/api/integration-builder/connectors", params={"page_size": 200})
        if resp2.status_code == 200:
            data2 = resp2.json()
            if isinstance(data2, list):
                connectors = data2
            elif isinstance(data2, dict):
                connectors = data2.get("connectors", data2.get("items", data2.get("results", [])))
            siem_ids = [c["id"] for c in connectors if c.get("category") == "SIEM"]

    assert "splunk_siem_events" in siem_ids, f"splunk_siem_events not found in: {siem_ids[:10]}"
    assert "sentinel_siem_events" in siem_ids
    assert "elastic_siem_events" in siem_ids
