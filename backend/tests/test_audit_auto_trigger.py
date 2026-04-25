"""Tests for services.audit_auto_trigger — the out-of-the-box wiring that
turns a scanner port_change event into an unauthenticated SMB / SNMP audit
run when the org has opted in."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from models.models import Asset, RelayAgent, Scan

# Side-effect import populates AUDITS so dispatch_audit_run can resolve
# protocol="smb" / "snmp". Mirrors test_audit_runner.py.
import agents.agent_tools  # noqa: F401


@pytest.fixture
def connected_relay(db_session, test_org):
    relay = RelayAgent(
        org_id=test_org.id,
        name="test-relay",
        token_hash="x",
        status="connected",
        last_seen_at=datetime.utcnow(),
    )
    db_session.add(relay)
    db_session.flush()
    return relay


@pytest.fixture
def linked_asset(db_session, test_org):
    """Asset with the scanner-side UUID stamped in easm_data so the bridge
    can map a scanner event back to it."""
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="winhost-1", ip="10.0.0.5",
        os="Windows Server 2022",
        easm_data={"easm_asset_id": "scanner-uuid-1"},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def _port_change_event(scanner_asset_id: str, new_ports: list[int], hostname: str = "winhost-1"):
    return {
        "id": "evt-1",
        "asset_id": scanner_asset_id,
        "event_type": "port_change",
        "created_at": "2026-04-25T00:00:00+00:00",
        "payload": {
            "hostname": hostname,
            "new_ports": new_ports,
            "removed_ports": [],
        },
    }


def test_disabled_when_org_setting_off(db_session, test_org, linked_asset, connected_relay):
    """Default behavior: settings.auto_audit_anon is unset → no dispatch."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    assert (test_org.settings or {}).get("auto_audit_anon") is None

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_smb_dispatched_on_445(db_session, test_org, linked_asset, connected_relay):
    """445 added → SMB null_session audit dispatched anonymously."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445, 80]),
        )

    assert n == 1

    scan = db_session.query(Scan).filter_by(scan_type="smb_audit").first()
    assert scan is not None
    md = scan.raw_metadata or {}
    assert md["protocol"] == "smb"
    assert md["mission"] == "null_session"
    assert md["credential_id"] is None
    assert md["relay_agent_id"] == connected_relay.id
    assert md["asset_ids"] == [linked_asset.id]


def test_snmp_dispatched_on_161(db_session, test_org, linked_asset, connected_relay):
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [161]),
        )

    assert n == 1
    scan = db_session.query(Scan).filter_by(scan_type="snmp_audit").first()
    assert scan is not None
    assert scan.raw_metadata["protocol"] == "snmp"
    assert scan.raw_metadata["mission"] == "device_posture"
    assert scan.raw_metadata["credential_id"] is None


def test_no_match_for_unrelated_ports(db_session, test_org, linked_asset, connected_relay):
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [80, 443, 22]),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_no_relay_skips_dispatch(db_session, test_org, linked_asset):
    """Without a connected relay there's no path to the target — skip
    cleanly instead of erroring."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_unknown_scanner_asset_id_no_op(db_session, test_org, linked_asset, connected_relay):
    """Scanner emits an event for an asset the backend hasn't ingested yet —
    silently skip rather than raise."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("unknown-uuid", [445]),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_cooldown_suppresses_repeat_within_24h(db_session, test_org, linked_asset, connected_relay):
    """A second port_change for the same protocol within the cooldown
    window must not produce a second audit run."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        first = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )
        second = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )

    assert first == 1
    assert second == 0
    smb_scans = db_session.query(Scan).filter_by(scan_type="smb_audit").count()
    assert smb_scans == 1


def test_cooldown_expired_allows_redispatch(db_session, test_org, linked_asset, connected_relay):
    """Past the 24h window the same (asset, protocol) is re-eligible."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    # Pre-stamp an old cooldown so the next call falls outside the window.
    stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    linked_asset.easm_data = {
        **(linked_asset.easm_data or {}),
        "_auto_audit_last": {"smb": stale},
    }
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )

    assert n == 1


def test_445_and_139_collapse_to_single_smb_run(db_session, test_org, linked_asset, connected_relay):
    """Both 445 and 139 map to the smb null_session mission — one event
    that adds both ports must produce exactly one SMB audit, not two."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445, 139]),
        )

    assert n == 1
    smb_scans = db_session.query(Scan).filter_by(scan_type="smb_audit").count()
    assert smb_scans == 1


def test_non_port_change_event_ignored(db_session, test_org, linked_asset, connected_relay):
    """Defense-in-depth: even if the bridge mistakenly forwards a
    non-port_change event, the trigger function must no-op."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    event = {
        "id": "evt-2",
        "asset_id": "scanner-uuid-1",
        "event_type": "tech_change",
        "payload": {"hostname": "winhost-1", "new_tech": {"nginx": "1.20"}},
    }

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(db_session, test_org, event)

    assert n == 0
    mock_dispatch.assert_not_called()
