"""Integration tests for services.wmi_scanner.start_wmi_scan.

The relay broker's `send_task` is stubbed — we're testing the dispatch/
ingest wiring, not the real WebSocket path (which is covered by
hakuna-relay-agent's own tests). `finalize_scan` is stubbed too because
its full pipeline (threat intel, risk scoring, workflow triggers) has
its own large test surface that isn't in scope for this PR.
"""

from __future__ import annotations

import asyncio
import secrets
from unittest.mock import AsyncMock, patch

import pytest

from models.models import (
    Asset,
    IntegrationCredential,
    InventoryService,
    InventorySoftware,
    Scan,
)
from services import credential_vault


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture(autouse=True)
def integration_secret(monkeypatch):
    # credential_vault uses this to derive the AES-256-GCM key.
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))


@pytest.fixture
def scan_fixtures(db_session, test_org):
    """Two Windows assets + a basic-auth credential, ready to be scanned."""
    # Need a Scan row for the Asset FK — pre-create an empty placeholder so
    # the test fixtures have somewhere to hang.
    placeholder = Scan(filename="placeholder", scan_type="manual", source_type="manual")
    db_session.add(placeholder)
    db_session.flush()

    asset1 = Asset(scan_id=placeholder.id, hostname="winhost-1", ip="10.0.0.5")
    asset2 = Asset(scan_id=placeholder.id, hostname="winhost-2", ip="10.0.0.6")
    db_session.add_all([asset1, asset2])
    db_session.flush()

    cred = IntegrationCredential(
        org_id=test_org.id,
        name="win-admin",
        connector_id="windows-host",
        auth_type="basic",
        encrypted_values=credential_vault.encrypt({
            "username": "svc-scan",
            "password": "Passw0rd!",
            "domain": "CORP",
        }),
    )
    db_session.add(cred)
    db_session.flush()

    return {"org": test_org, "assets": [asset1, asset2], "cred": cred}


def _fake_wmi_result(host: str) -> dict:
    return {
        "os_info": [{"Caption": f"Windows Server 2022 — {host}"}],
        "software_uninstall": [
            {"name": "Google Chrome", "version": "124.0.6367.8", "vendor": "Google", "installed_on": "20240401"},
        ],
        "services": [
            {"Name": "DNS", "DisplayName": "DNS Server", "State": "Running",
             "StartMode": "Auto", "StartName": "LocalSystem"},
        ],
        "patches": [{"HotFixID": "KB5034441", "Description": "Security Update"}],
        "shares": [],
        "local_users": [],
        "local_groups": [],
        "group_membership": [],
    }


# ── Happy path ────────────────────────────────────────────────────────


def test_start_wmi_scan_happy_path(db_session, scan_fixtures):
    fx = scan_fixtures
    asset_ids = [a.id for a in fx["assets"]]

    with patch("services.wmi_scanner.get_relay_broker") as mock_broker_factory, \
         patch("services.wmi_scanner.finalize_scan") as mock_finalize:
        broker = mock_broker_factory.return_value
        broker.is_connected.return_value = True
        broker.send_task = AsyncMock(side_effect=lambda agent_id, method, config, **kw: _fake_wmi_result(config["target"]))

        from services.wmi_scanner import start_wmi_scan
        result = _run(start_wmi_scan(
            db_session, fx["org"],
            asset_ids=asset_ids,
            credential_id=fx["cred"].id,
            relay_agent_id="relay-1",
        ))

    # 1. Broker was called once per asset with method=wmi_query and the decrypted creds.
    assert broker.send_task.call_count == 2
    for call in broker.send_task.call_args_list:
        kwargs = call.kwargs
        assert kwargs["method"] == "wmi_query"
        assert kwargs["config"]["target"] in {"winhost-1", "winhost-2"}
        creds = kwargs["credentials"]
        assert creds["username"] == "svc-scan"
        assert creds["password"] == "Passw0rd!"
        assert creds["domain"] == "CORP"
        # _auth_type marker from credential_manager must be stripped before dispatch.
        assert "_auth_type" not in creds

    # 2. Scan row recorded with the right source + completed status.
    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.source_type == "wmi_inventory"
    assert scan.status == "completed"
    assert scan.raw_metadata["relay_agent_id"] == "relay-1"

    # 3. Inventory rows got written for both hosts.
    software = db_session.query(InventorySoftware).filter_by(scan_id=scan.id).all()
    assert len(software) == 2  # one Chrome per host
    assert all(s.name == "Google Chrome" for s in software)
    services = db_session.query(InventoryService).filter_by(scan_id=scan.id).all()
    assert len(services) == 2

    # 4. os_info landed on Asset.os (we only fill when empty).
    refreshed = db_session.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    assert all(a.os and a.os.startswith("Windows Server 2022") for a in refreshed)

    # 5. finalize_scan was called once with scan.id + org.id.
    mock_finalize.assert_called_once()
    _, call_kwargs = mock_finalize.call_args
    assert call_kwargs["scan_id"] == scan.id
    assert call_kwargs["org_id"] == fx["org"].id

    # 6. Summary payload is correct.
    assert result["assets_scanned"] == 2
    assert result["assets_failed"] == 0
    assert result["rows_written"] > 0


# ── Partial failures ──────────────────────────────────────────────────


def test_one_host_failure_marks_scan_partial(db_session, scan_fixtures):
    fx = scan_fixtures
    asset_ids = [a.id for a in fx["assets"]]

    async def fake_send(agent_id, method, config, **kw):
        if config["target"] == "winhost-2":
            raise RuntimeError("NTLM auth failed on target winhost-2")
        return _fake_wmi_result(config["target"])

    with patch("services.wmi_scanner.get_relay_broker") as mock_broker_factory, \
         patch("services.wmi_scanner.finalize_scan"):
        broker = mock_broker_factory.return_value
        broker.is_connected.return_value = True
        broker.send_task = AsyncMock(side_effect=fake_send)

        from services.wmi_scanner import start_wmi_scan
        result = _run(start_wmi_scan(
            db_session, fx["org"],
            asset_ids=asset_ids,
            credential_id=fx["cred"].id,
            relay_agent_id="relay-1",
        ))

    scan = db_session.query(Scan).filter_by(id=result["scan_id"]).first()
    assert scan.status == "partial"
    assert result["assets_scanned"] == 1
    assert result["assets_failed"] == 1
    # Error for the failed host is captured in raw_metadata for ops triage.
    errors = scan.raw_metadata.get("errors", [])
    assert any("NTLM auth failed" in (e.get("error") or "") for e in errors)


# ── Preconditions & validation ────────────────────────────────────────


def test_relay_not_connected_raises_connection_error(db_session, scan_fixtures):
    fx = scan_fixtures
    with patch("services.wmi_scanner.get_relay_broker") as mock_broker_factory:
        broker = mock_broker_factory.return_value
        broker.is_connected.return_value = False
        from services.wmi_scanner import start_wmi_scan
        with pytest.raises(ConnectionError):
            _run(start_wmi_scan(
                db_session, fx["org"],
                asset_ids=[a.id for a in fx["assets"]],
                credential_id=fx["cred"].id,
                relay_agent_id="missing-relay",
            ))


def test_missing_credential_raises_value_error(db_session, scan_fixtures):
    fx = scan_fixtures
    with patch("services.wmi_scanner.get_relay_broker") as mock_broker_factory:
        broker = mock_broker_factory.return_value
        broker.is_connected.return_value = True
        from services.wmi_scanner import start_wmi_scan
        with pytest.raises(ValueError, match="Credential"):
            _run(start_wmi_scan(
                db_session, fx["org"],
                asset_ids=[a.id for a in fx["assets"]],
                credential_id="does-not-exist",
                relay_agent_id="relay-1",
            ))


def test_missing_asset_ids_count_as_failed(db_session, scan_fixtures):
    """Asset IDs that don't resolve should be counted as failed, not
    crash the scan."""
    fx = scan_fixtures
    asset_ids = [fx["assets"][0].id, 99999]  # 99999 does not exist

    with patch("services.wmi_scanner.get_relay_broker") as mock_broker_factory, \
         patch("services.wmi_scanner.finalize_scan"):
        broker = mock_broker_factory.return_value
        broker.is_connected.return_value = True
        broker.send_task = AsyncMock(side_effect=lambda agent_id, method, config, **kw: _fake_wmi_result(config["target"]))

        from services.wmi_scanner import start_wmi_scan
        result = _run(start_wmi_scan(
            db_session, fx["org"],
            asset_ids=asset_ids,
            credential_id=fx["cred"].id,
            relay_agent_id="relay-1",
        ))

    assert result["assets_scanned"] == 1
    assert result["assets_failed"] == 1
