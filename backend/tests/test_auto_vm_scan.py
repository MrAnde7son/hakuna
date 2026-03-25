"""Tests for auto VM scan triggered after EASM discovery."""

import asyncio
import secrets
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = "sqlite:///:memory:"


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))


@pytest.fixture
def db_session():
    from core.database import Base
    from models.models import Organization, Scan, Asset

    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org = Organization(name="Test Org", slug="test-org", easm_org_id="easm-123", easm_domain="example.com")
    session.add(org)
    session.flush()

    yield session, org
    session.close()


def _make_easm_scan(session, org, domain="example.com"):
    from models.models import Scan

    scan = Scan(
        org_id=org.id,
        filename=f"easm-{domain}",
        scan_name=f"EASM — {domain}",
        scan_date="2026-03-25T00:00:00",
        scan_type="easm",
        source_type="easm",
        status="completed",
        raw_metadata={"domain": domain, "status": "completed"},
    )
    session.add(scan)
    session.flush()
    return scan


def _make_easm_asset(session, scan_id, hostname, ports=None, tech=None, http_status=200,
                     cdn_provider=None, waf=None):
    from models.models import Asset

    easm_data = {
        "open_ports": ports if ports is not None else [443],
        "tech_stack": tech if tech is not None else ["nginx"],
        "http_status": http_status,
        "cdn_provider": cdn_provider,
        "waf": waf,
    }
    asset = Asset(
        scan_id=scan_id,
        hostname=hostname.split(".")[0],
        fqdn=hostname,
        is_internet_facing=True,
        environment_tag="external",
        criticality=5,
        easm_data=easm_data,
        source_systems=["easm"],
    )
    session.add(asset)
    session.flush()
    return asset


class TestTriggerVmScanForEasmAssets:
    """Tests for vm_scanner.trigger_vm_scan_for_easm_assets."""

    def test_selects_high_value_assets(self, db_session):
        """Assets with high-value ports and tech stack are selected over CDN/WAF ones."""
        session, org = db_session
        scan = _make_easm_scan(session, org)

        # High-value: has web ports, tech, alive
        good = _make_easm_asset(session, scan.id, "app.example.com", ports=[443, 8080], tech=["nginx", "React"])
        # Low-value: behind CDN and WAF
        bad = _make_easm_asset(session, scan.id, "cdn.example.com", ports=[443], cdn_provider="Cloudflare", waf="Cloudflare")

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = {"scan_id": 999, "job_ids": ["j1", "j2"], "status": "running"}

            from services.vm_scanner import trigger_vm_scan_for_easm_assets
            result = _run(trigger_vm_scan_for_easm_assets(session, org, scan.id, "example.com"))

        assert result is not None
        assert result["scan_id"] == 999

        # Verify start_vm_scan was called with both targets (both have ports)
        call_args = mock_start.call_args
        targets = call_args[0][2]  # positional: db, org, targets
        asset_ids = call_args[1]["asset_ids"]

        # app.example.com should come first (higher score)
        assert targets[0] == "app.example.com"
        assert asset_ids[0] == good.id

    def test_skips_assets_with_no_ports_and_no_http(self, db_session):
        """Assets with no ports and no HTTP response are filtered out entirely."""
        session, org = db_session
        scan = _make_easm_scan(session, org)

        _make_easm_asset(session, scan.id, "dead.example.com", ports=[], http_status=None)

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            from services.vm_scanner import trigger_vm_scan_for_easm_assets
            result = _run(trigger_vm_scan_for_easm_assets(session, org, scan.id, "example.com"))

        assert result is None
        mock_start.assert_not_called()

    def test_caps_at_max_targets(self, db_session):
        """No more than MAX_AUTO_VM_TARGETS assets are selected."""
        session, org = db_session
        scan = _make_easm_scan(session, org)

        for i in range(30):
            _make_easm_asset(session, scan.id, f"host{i}.example.com", ports=[443])

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = {"scan_id": 999, "job_ids": ["j1"], "status": "running"}

            from services.vm_scanner import trigger_vm_scan_for_easm_assets, MAX_AUTO_VM_TARGETS
            result = _run(trigger_vm_scan_for_easm_assets(session, org, scan.id, "example.com"))

        targets = mock_start.call_args[0][2]
        assert len(targets) == MAX_AUTO_VM_TARGETS

    def test_idempotent_no_duplicate_scan(self, db_session):
        """Second call for the same EASM scan does not create another VM scan."""
        from models.models import Scan
        session, org = db_session
        easm_scan = _make_easm_scan(session, org)
        _make_easm_asset(session, easm_scan.id, "app.example.com", ports=[443])

        # Simulate an existing VM scan already triggered for this EASM scan
        existing_vm = Scan(
            org_id=org.id,
            filename="vm-scan-existing",
            scan_name="VM Scan — example.com (auto, from EASM)",
            scan_date="2026-03-25T00:00:00",
            scan_type="vm_scan",
            source_type="vm_scanner",
            raw_metadata={"easm_scan_id": easm_scan.id, "auto_triggered": True},
        )
        session.add(existing_vm)
        session.flush()

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            from services.vm_scanner import trigger_vm_scan_for_easm_assets
            result = _run(trigger_vm_scan_for_easm_assets(session, org, easm_scan.id, "example.com"))

        assert result is None
        mock_start.assert_not_called()

    def test_scan_record_tagged_as_auto(self, db_session):
        """The created VM scan has correct name and metadata linking back to EASM."""
        from models.models import Scan
        session, org = db_session
        easm_scan = _make_easm_scan(session, org)
        _make_easm_asset(session, easm_scan.id, "app.example.com", ports=[443])

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = {"scan_id": 999, "job_ids": ["j1"], "status": "running"}

            # Create the record that start_vm_scan would create, so tagging logic can find it
            vm_scan = Scan(
                id=999,
                org_id=org.id,
                filename="vm-scan-auto",
                scan_name="placeholder",
                scan_date="2026-03-25T00:00:00",
                scan_type="vm_scan",
                source_type="vm_scanner",
                raw_metadata={"status": "running"},
            )
            session.add(vm_scan)
            session.flush()

            from services.vm_scanner import trigger_vm_scan_for_easm_assets
            result = _run(trigger_vm_scan_for_easm_assets(session, org, easm_scan.id, "example.com"))

        # Verify scan was tagged
        vm_scan = session.query(Scan).filter(Scan.id == 999).first()
        assert "auto, from EASM" in vm_scan.scan_name
        assert vm_scan.raw_metadata["auto_triggered"] is True
        assert vm_scan.raw_metadata["triggered_by"] == "easm"
        assert vm_scan.raw_metadata["easm_scan_id"] == easm_scan.id

    def test_no_assets_returns_none(self, db_session):
        """EASM scan with no assets triggers nothing."""
        session, org = db_session
        scan = _make_easm_scan(session, org)

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            from services.vm_scanner import trigger_vm_scan_for_easm_assets
            result = _run(trigger_vm_scan_for_easm_assets(session, org, scan.id, "example.com"))

        assert result is None
        mock_start.assert_not_called()


class TestPostIngestAutoVmStep:
    """Tests that the post-ingest pipeline triggers VM scan only for EASM scans."""

    def test_skips_for_non_easm_scan(self, db_session):
        """VM auto-scan step does nothing for a regular VM scan upload."""
        from models.models import Scan
        session, org = db_session

        scan = Scan(
            org_id=org.id,
            filename="nessus-upload.nessus",
            scan_name="Nessus Upload",
            scan_date="2026-03-25T00:00:00",
            scan_type="nessus",
            source_type="nessus",
            raw_metadata={},
        )
        session.add(scan)
        session.flush()

        with patch("services.vm_scanner.trigger_vm_scan_for_easm_assets", new_callable=AsyncMock) as mock_trigger:
            from services.post_ingest import _auto_vm_scan_for_easm
            result = _auto_vm_scan_for_easm(session, org.id, scan.id)

        assert result is None
        mock_trigger.assert_not_called()

    def test_triggers_for_easm_scan(self, db_session):
        """VM auto-scan step fires for EASM source type."""
        session, org = db_session
        scan = _make_easm_scan(session, org)
        _make_easm_asset(session, scan.id, "app.example.com", ports=[443])

        with patch("services.vm_scanner.trigger_vm_scan_for_easm_assets", new_callable=AsyncMock) as mock_trigger:
            mock_trigger.return_value = {"scan_id": 999, "job_ids": ["j1"], "status": "running"}

            from services.post_ingest import _auto_vm_scan_for_easm
            result = _auto_vm_scan_for_easm(session, org.id, scan.id)

        assert result is not None
        assert result["triggered"] is True
        assert result["domain"] == "example.com"

    def test_step_in_finalize_pipeline(self, db_session):
        """The auto_vm_scan step appears in finalize_scan results for EASM scans."""
        session, org = db_session
        scan = _make_easm_scan(session, org)

        with patch("services.vm_scanner.trigger_vm_scan_for_easm_assets", new_callable=AsyncMock) as mock_trigger:
            mock_trigger.return_value = None

            from services.post_ingest import finalize_scan
            results = finalize_scan(session, scan_id=scan.id, org_id=org.id)

        assert "auto_vm_scan" in results
