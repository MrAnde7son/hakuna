"""Tests for the Phase 4.0 transport-aware port_change emission in
``app.ingest.delta``.

The DB layer is mocked at the SQLAlchemy execute boundary. We verify the
shape of the emitted asset_event payload — specifically, that:

  * TCP port diffs emit ``payload.transport == "tcp"``
  * UDP port diffs emit ``payload.transport == "udp"``
  * Both can fire for the same asset in one detect_changes call
  * Snapshots without ``open_udp_ports`` are tolerated (back-compat)
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, call

import pytest


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _fake_db(current_row):
    """Build a mocked AsyncSession whose execute() returns ``current_row``
    for the SELECT and a no-op for the INSERTs we capture."""
    db = MagicMock()
    inserted: list[dict] = []

    async def _execute(stmt, params=None):
        result = MagicMock()
        sql = str(stmt)
        if "SELECT" in sql:
            result.fetchone = lambda: current_row
        elif "INSERT INTO asset_events" in sql:
            inserted.append(dict(params or {}))
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db._inserted = inserted  # expose for assertions
    return db


def _row(hostname="h", ip="10.0.0.1", open_ports=None, open_udp_ports=None,
         tech_stack=None, tls_cert=None):
    """Build a fake asset row matching the shape detect_changes selects."""
    r = MagicMock()
    r.hostname = hostname
    r.ip = ip
    r.open_ports = open_ports
    r.open_udp_ports = open_udp_ports
    r.tech_stack = tech_stack or {}
    r.tls_cert = tls_cert or {}
    return r


def _payload(inserted_call: dict) -> dict:
    """Strip the JSON-encoded payload arg out of the captured insert
    parameters."""
    import json
    return json.loads(inserted_call["payload"])


def test_detect_changes_emits_tcp_port_change_with_transport_tag():
    from app.ingest.delta import detect_changes

    asset_id = uuid.uuid4()
    org_id = uuid.uuid4()
    snapshot = [{
        "id": asset_id, "hostname": "h", "ip": "10.0.0.1",
        "open_ports": [80], "open_udp_ports": [],
        "tech_stack": {}, "tls_cert": {},
    }]
    current = _row(open_ports=[80, 443], open_udp_ports=[])

    db = _fake_db(current)
    n = _run(detect_changes(db, org_id, snapshot))

    assert n == 1
    assert len(db._inserted) == 1
    payload = _payload(db._inserted[0])
    assert payload["transport"] == "tcp"
    assert payload["new_ports"] == [443]
    assert payload["removed_ports"] == []


def test_detect_changes_emits_udp_port_change_with_transport_tag():
    from app.ingest.delta import detect_changes

    asset_id = uuid.uuid4()
    org_id = uuid.uuid4()
    snapshot = [{
        "id": asset_id, "hostname": "h", "ip": "10.0.0.1",
        "open_ports": [], "open_udp_ports": [],
        "tech_stack": {}, "tls_cert": {},
    }]
    # SNMP newly opens on UDP 161.
    current = _row(open_ports=[], open_udp_ports=[161])

    db = _fake_db(current)
    n = _run(detect_changes(db, org_id, snapshot))

    assert n == 1
    payload = _payload(db._inserted[0])
    assert payload["transport"] == "udp"
    assert payload["new_ports"] == [161]


def test_detect_changes_emits_both_tcp_and_udp_events_when_both_diff():
    """One asset with simultaneous TCP and UDP changes produces two
    distinct port_change events — one per transport."""
    from app.ingest.delta import detect_changes

    asset_id = uuid.uuid4()
    org_id = uuid.uuid4()
    snapshot = [{
        "id": asset_id, "hostname": "h", "ip": "10.0.0.1",
        "open_ports": [80], "open_udp_ports": [],
        "tech_stack": {}, "tls_cert": {},
    }]
    current = _row(open_ports=[80, 21], open_udp_ports=[623])

    db = _fake_db(current)
    n = _run(detect_changes(db, org_id, snapshot))

    assert n == 2
    transports = sorted(_payload(c)["transport"] for c in db._inserted)
    assert transports == ["tcp", "udp"]
    # IPMI BMC on UDP 623 must be reported as the UDP-side new port.
    udp_event = next(c for c in db._inserted if _payload(c)["transport"] == "udp")
    assert _payload(udp_event)["new_ports"] == [623]


def test_detect_changes_tolerates_legacy_snapshot_without_open_udp_ports():
    """A snapshot dict captured before Phase 4.0 (no ``open_udp_ports``
    key) must not crash — UDP diffs default to empty."""
    from app.ingest.delta import detect_changes

    asset_id = uuid.uuid4()
    org_id = uuid.uuid4()
    snapshot = [{
        "id": asset_id, "hostname": "h", "ip": "10.0.0.1",
        "open_ports": [80],
        # NO open_udp_ports key — pre-Phase-4.0 snapshot.
        "tech_stack": {}, "tls_cert": {},
    }]
    current = _row(open_ports=[80], open_udp_ports=[161])

    db = _fake_db(current)
    n = _run(detect_changes(db, org_id, snapshot))

    # The UDP diff (None → [161]) is detected; payload tags it udp.
    assert n == 1
    payload = _payload(db._inserted[0])
    assert payload["transport"] == "udp"
    assert payload["new_ports"] == [161]


def test_detect_changes_does_not_emit_when_neither_transport_changed():
    from app.ingest.delta import detect_changes

    asset_id = uuid.uuid4()
    org_id = uuid.uuid4()
    snapshot = [{
        "id": asset_id, "hostname": "h", "ip": "10.0.0.1",
        "open_ports": [80, 443], "open_udp_ports": [161],
        "tech_stack": {}, "tls_cert": {},
    }]
    current = _row(open_ports=[80, 443], open_udp_ports=[161])

    db = _fake_db(current)
    n = _run(detect_changes(db, org_id, snapshot))

    assert n == 0
    assert db._inserted == []
