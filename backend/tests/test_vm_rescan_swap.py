"""Tests for VM rescan swap-on-success.

When a user rescans a VM scan, the prior run's Finding/Asset rows are
retained until the new run completes so a failed/cancelled rescan preserves
the last-known-good results. The swap happens at finalize.
"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = "sqlite:///:memory:"


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def db_session():
    from core.database import Base
    from models.models import Organization

    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org = Organization(name="Test Org", slug="test-org")
    session.add(org)
    session.flush()

    yield session, org
    session.close()


def _seed_completed_vm_scan(session, org, run_id="run-previous"):
    """Create a VM scan as if a previous run had completed — an Asset and two
    Findings tagged with ``run_id``."""
    from models.models import Scan, Asset, Finding

    scan = Scan(
        org_id=org.id,
        filename="vm-scan-prev",
        scan_name="VM Scan — prev",
        scan_date=datetime.utcnow().isoformat(),
        scan_type="vm_scan",
        source_type="vm_scanner",
        raw_metadata={
            "targets": ["https://target.example.com"],
            "status": "completed",
            "findings_emitted": 2,
            "current_run_id": run_id,
        },
    )
    session.add(scan)
    session.flush()

    asset = Asset(
        scan_id=scan.id,
        scan_run_id=run_id,
        ip="10.0.0.1",
        hostname="target.example.com",
        source_systems=["vm_scanner"],
    )
    session.add(asset)
    session.flush()

    f1 = Finding(
        scan_id=scan.id,
        scan_run_id=run_id,
        asset_id=asset.id,
        source_type="vm_scanner",
        plugin_id="cve-2021-44228",
        plugin_name="Log4Shell",
        severity=4,
    )
    f2 = Finding(
        scan_id=scan.id,
        scan_run_id=run_id,
        asset_id=asset.id,
        source_type="vm_scanner",
        plugin_id="cve-2022-22965",
        plugin_name="Spring4Shell",
        severity=4,
    )
    session.add_all([f1, f2])
    session.flush()
    return scan, asset, [f1, f2]


class TestRescanDoesNotDeleteOldData:
    def test_rescan_keeps_prior_run_rows_until_finalize(self, db_session):
        """rescan_vm_scan mints a new run_id and leaves the previous run's
        Finding/Asset rows in place. The new run's rows are inserted alongside."""
        session, org = db_session
        from models.models import Finding, Asset
        from services import vm_scanner

        scan, asset, findings = _seed_completed_vm_scan(session, org, run_id="run-A")
        session.commit()

        with patch("services.vm_scanner._vm_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {
                "job_ids": ["job-rescan-1"],
                "targets_queued": 1,
            }
            _run(vm_scanner.rescan_vm_scan(session, scan))
            session.commit()

        # Prior run's rows still exist
        assert session.query(Finding).filter(Finding.scan_run_id == "run-A").count() == 2
        assert session.query(Asset).filter(Asset.scan_run_id == "run-A").count() == 1

        meta = scan.raw_metadata or {}
        assert meta.get("previous_run_id") == "run-A"
        assert meta.get("current_run_id") and meta["current_run_id"] != "run-A"
        assert meta.get("status") == "running"


class TestFinalizeSwapsOldRunOut:
    def test_drop_superseded_run_removes_prior_run_rows(self, db_session):
        """At finalize, _drop_superseded_run deletes rows stamped with a
        scan_run_id that doesn't match the scan's current run_id."""
        session, org = db_session
        from models.models import Finding, Asset
        from services.post_ingest import _drop_superseded_run

        scan, asset, findings = _seed_completed_vm_scan(session, org, run_id="run-A")

        # Simulate a new run having been minted and some new rows written
        scan.raw_metadata = {**(scan.raw_metadata or {}), "current_run_id": "run-B"}
        new_asset = Asset(
            scan_id=scan.id,
            scan_run_id="run-B",
            ip="10.0.0.2",
            hostname="target.example.com",
            source_systems=["vm_scanner"],
        )
        session.add(new_asset)
        session.flush()
        new_finding = Finding(
            scan_id=scan.id,
            scan_run_id="run-B",
            asset_id=new_asset.id,
            source_type="vm_scanner",
            plugin_id="cve-2023-0001",
            severity=3,
        )
        session.add(new_finding)
        session.commit()

        result = _drop_superseded_run(session, scan.id)
        session.commit()

        assert result["findings_deleted"] == 2
        assert result["assets_deleted"] == 1
        # Only the new run's rows remain
        remaining_findings = session.query(Finding).filter(Finding.scan_id == scan.id).all()
        assert [f.scan_run_id for f in remaining_findings] == ["run-B"]
        remaining_assets = session.query(Asset).filter(Asset.scan_id == scan.id).all()
        assert [a.scan_run_id for a in remaining_assets] == ["run-B"]

    def test_drop_superseded_run_auto_resolves_tickets(self, db_session):
        """FindingTickets on superseded findings are deleted (remediation is
        done — the vuln no longer shows up in the latest scan)."""
        session, org = db_session
        from models.models import FindingTicket
        from services.post_ingest import _drop_superseded_run

        scan, asset, findings = _seed_completed_vm_scan(session, org, run_id="run-A")
        ticket = FindingTicket(
            finding_id=findings[0].id,
            ticket_system="jira",
            ticket_id="10001",
            ticket_key="SEC-100",
        )
        session.add(ticket)
        session.flush()

        scan.raw_metadata = {**(scan.raw_metadata or {}), "current_run_id": "run-B"}
        session.commit()

        result = _drop_superseded_run(session, scan.id)
        session.commit()

        assert result["tickets_auto_resolved"] == 1
        assert session.query(FindingTicket).count() == 0


class TestFailureRollbackPreservesOldRun:
    def test_rollback_deletes_new_run_and_restores_previous_run_id(self, db_session):
        """A failed rescan wipes the new-run rows and restores the previous
        run_id as current, so the UI keeps showing the last successful scan."""
        session, org = db_session
        from models.models import Finding, Asset
        from services import vm_scanner

        scan, asset, findings = _seed_completed_vm_scan(session, org, run_id="run-A")

        # Simulate rescan in-flight: new run_id + one partially-written finding
        scan.raw_metadata = {
            **(scan.raw_metadata or {}),
            "previous_run_id": "run-A",
            "current_run_id": "run-B",
            "status": "running",
        }
        partial_asset = Asset(
            scan_id=scan.id,
            scan_run_id="run-B",
            ip="10.0.0.2",
            source_systems=["vm_scanner"],
        )
        session.add(partial_asset)
        session.flush()
        partial_finding = Finding(
            scan_id=scan.id,
            scan_run_id="run-B",
            asset_id=partial_asset.id,
            source_type="vm_scanner",
            plugin_id="partial-1",
            severity=3,
        )
        session.add(partial_finding)
        session.commit()

        vm_scanner._rollback_failed_run(session, scan)
        session.commit()

        # Old run survives intact
        assert session.query(Finding).filter(Finding.scan_run_id == "run-A").count() == 2
        assert session.query(Asset).filter(Asset.scan_run_id == "run-A").count() == 1
        # New run's rows are gone
        assert session.query(Finding).filter(Finding.scan_run_id == "run-B").count() == 0
        assert session.query(Asset).filter(Asset.scan_run_id == "run-B").count() == 0
        # Metadata points back at the prior run
        meta = scan.raw_metadata or {}
        assert meta.get("current_run_id") == "run-A"
        assert "previous_run_id" not in meta


class TestMidRescanQueryScoping:
    def test_get_scan_counts_only_current_run(self, db_session):
        """While a rescan is in-flight (old + new rows coexist), the scan
        detail endpoint's counts reflect only the current run."""
        session, org = db_session
        from models.models import Finding, Asset
        from sqlalchemy import func, or_

        scan, asset, findings = _seed_completed_vm_scan(session, org, run_id="run-A")

        scan.raw_metadata = {**(scan.raw_metadata or {}), "current_run_id": "run-B"}
        new_asset = Asset(
            scan_id=scan.id,
            scan_run_id="run-B",
            ip="10.0.0.2",
            source_systems=["vm_scanner"],
        )
        session.add(new_asset)
        session.flush()
        new_finding = Finding(
            scan_id=scan.id,
            scan_run_id="run-B",
            asset_id=new_asset.id,
            source_type="vm_scanner",
            plugin_id="cve-new",
            severity=3,
        )
        session.add(new_finding)
        session.commit()

        current = "run-B"
        finding_count = (
            session.query(func.count(Finding.id))
            .filter(Finding.scan_id == scan.id)
            .filter(or_(Finding.scan_run_id.is_(None), Finding.scan_run_id == current))
            .scalar()
        )
        asset_count = (
            session.query(func.count(Asset.id))
            .filter(Asset.scan_id == scan.id)
            .filter(or_(Asset.scan_run_id.is_(None), Asset.scan_run_id == current))
            .scalar()
        )
        assert finding_count == 1
        assert asset_count == 1
