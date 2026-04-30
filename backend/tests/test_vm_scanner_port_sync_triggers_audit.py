"""VM-scanner-discovered ports must drive the same anon-audit auto-trigger
that EASM port_change events do. Until this wiring landed, Nuclei findings
on non-standard ports (e.g. Redis on 16379, an HTTP service on 8443) only
created Finding rows — the auto-audit listener never ran because no
port_change event was emitted.

These tests cover the bridge in services.vm_scanner._sync_vm_ports_and_trigger_audits.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from models.models import Asset, RelayAgent, Scan

# Populate AUDITS so dispatch_audit_run can resolve protocol mappings.
import agents.agent_tools  # noqa: F401


@pytest.fixture
def connected_relay(db_session, test_org):
    from datetime import datetime
    relay = RelayAgent(
        org_id=test_org.id,
        name="vm-test-relay",
        token_hash="x",
        status="connected",
        last_seen_at=datetime.utcnow(),
    )
    db_session.add(relay)
    db_session.flush()
    return relay


@pytest.fixture
def vm_scan(db_session, test_org):
    scan = Scan(
        filename="vm-scan", scan_type="vm_scan", source_type="vm_scanner",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    return scan


@pytest.fixture
def asset_with_known_ports(db_session, vm_scan):
    """Asset already known to expose 80/443 — emulates what EASM would have
    populated. Anything new the VM scanner finds should be diffed against
    this set."""
    asset = Asset(
        scan_id=vm_scan.id,
        hostname="redis-host.example.com",
        ip="10.0.0.20",
        easm_data={"open_ports": [80, 443]},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_new_port_from_finding_triggers_audit(
    db_session, test_org, vm_scan, asset_with_known_ports, connected_relay,
):
    """A Nuclei finding with port=6379 (Redis) on an asset whose EASM data
    only knew 80/443 must:
      1. Add 6379 to easm_data["open_ports"]
      2. Fire maybe_auto_trigger_anon_audits with a synthetic TCP event
      3. Result in a dispatched exposed_datastore audit.
    """
    from services.vm_scanner import _sync_vm_ports_and_trigger_audits

    findings = [{"template_id": "redis-detect", "port": 6379}]

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        dispatched = _sync_vm_ports_and_trigger_audits(
            db_session, vm_scan, asset_with_known_ports,
            target="10.0.0.20", findings_data=findings,
        )

    assert dispatched >= 1
    db_session.refresh(asset_with_known_ports)
    assert 6379 in (asset_with_known_ports.easm_data or {}).get("open_ports", [])


def test_new_port_from_url_triggers_audit(
    db_session, test_org, vm_scan, asset_with_known_ports, connected_relay,
):
    """When the finding has no explicit port but ``matched_at`` carries a
    non-default URL port, the URL parser should surface it. 27017 → MongoDB
    rule fires."""
    from services.vm_scanner import _sync_vm_ports_and_trigger_audits

    findings = [{
        "template_id": "mongodb-detect",
        "matched_at": "http://10.0.0.20:27017/",
    }]

    with patch("services.audit_runner._dispatch_background_run", return_value="task-2"):
        dispatched = _sync_vm_ports_and_trigger_audits(
            db_session, vm_scan, asset_with_known_ports,
            target="http://10.0.0.20:27017/", findings_data=findings,
        )

    assert dispatched >= 1
    db_session.refresh(asset_with_known_ports)
    assert 27017 in (asset_with_known_ports.easm_data or {}).get("open_ports", [])


def test_known_port_does_not_retrigger(
    db_session, test_org, vm_scan, asset_with_known_ports, connected_relay,
):
    """Re-confirming a port EASM already knew about must not call dispatch.
    Without this guard every VM scan would burn a fresh audit run on each
    overlap with EASM port discovery."""
    from services.vm_scanner import _sync_vm_ports_and_trigger_audits

    findings = [{"template_id": "ssl-detect", "port": 443}]

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        dispatched = _sync_vm_ports_and_trigger_audits(
            db_session, vm_scan, asset_with_known_ports,
            target="https://10.0.0.20/", findings_data=findings,
        )

    assert dispatched == 0
    mock_dispatch.assert_not_called()


def test_org_opt_out_suppresses_dispatch(
    db_session, test_org, vm_scan, asset_with_known_ports, connected_relay,
):
    """Org-level kill switch (auto_audit_datastore=False) must suppress
    dispatch even when a brand-new datastore port is discovered. The port
    still gets persisted so the data record is correct, but no audit fires.
    """
    from services.vm_scanner import _sync_vm_ports_and_trigger_audits

    test_org.settings = {"auto_audit_datastore": False}
    db_session.flush()

    findings = [{"template_id": "redis-detect", "port": 6379}]

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        dispatched = _sync_vm_ports_and_trigger_audits(
            db_session, vm_scan, asset_with_known_ports,
            target="10.0.0.20", findings_data=findings,
        )

    assert dispatched == 0
    mock_dispatch.assert_not_called()
    db_session.refresh(asset_with_known_ports)
    # easm_data is still updated with the observed port even when audit is
    # suppressed — keeps downstream rules accurate.
    assert 6379 in (asset_with_known_ports.easm_data or {}).get("open_ports", [])


def test_no_findings_no_op(
    db_session, test_org, vm_scan, asset_with_known_ports, connected_relay,
):
    from services.vm_scanner import _sync_vm_ports_and_trigger_audits

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        dispatched = _sync_vm_ports_and_trigger_audits(
            db_session, vm_scan, asset_with_known_ports,
            target="", findings_data=[],
        )

    assert dispatched == 0
    mock_dispatch.assert_not_called()
