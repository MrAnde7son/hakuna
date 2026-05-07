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
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("loop closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


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

    def test_shodan_vulns_asset_bypasses_top_n(self, db_session):
        """An asset with shodan_vulns is queued even when 30 higher-scoring
        web apps would otherwise consume the MAX_AUTO_VM_TARGETS slots.

        This is the exposed-VPN-with-RCE flow — the whole reason the bypass
        exists. Without it a Fortinet/Pulse box surfaced by Shodan loses to
        N web apps with richer tech stacks in the score sort.
        """
        from models.models import Asset

        session, org = db_session
        scan = _make_easm_scan(session, org)

        # 25 web apps, each with multiple high-value ports + tech stacks —
        # all would beat a port-22-only VPN box on the score sort.
        for i in range(25):
            _make_easm_asset(
                session, scan.id, f"app{i}.example.com",
                ports=[443, 8080, 8443], tech=["nginx", "React", "Express"],
            )

        # The exposed VPN box. Lone port, no tech stack, but Shodan reported
        # a known CVE banner. It must be queued.
        vpn_asset = Asset(
            scan_id=scan.id,
            hostname="vpn",
            fqdn="vpn.example.com",
            is_internet_facing=True,
            environment_tag="external",
            criticality=5,
            easm_data={
                "open_ports": [443],
                "shodan_vulns": ["CVE-2024-21762"],
                "tech_stack": [],
                "http_status": 200,
            },
            source_systems=["easm"],
        )
        session.add(vpn_asset)
        session.flush()

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = {"scan_id": 999, "job_ids": ["j1"], "status": "running"}
            from services.vm_scanner import trigger_vm_scan_for_easm_assets
            _run(trigger_vm_scan_for_easm_assets(session, org, scan.id, "example.com"))

        targets = mock_start.call_args[0][2]
        asset_ids = mock_start.call_args[1]["asset_ids"]

        # vpn.example.com must be in the queued set despite losing the score
        # sort to 25 richer web apps.
        assert "vpn.example.com" in targets
        assert vpn_asset.id in asset_ids
        # vpn comes first (bypass list is prepended).
        assert targets[0] == "vpn.example.com"

    def test_shodan_bypass_capped(self, db_session):
        """Bypass list is capped at MAX_AUTO_VM_BYPASS_TARGETS to keep one bad
        EASM run from blowing up the VM scan budget."""
        from models.models import Asset

        session, org = db_session
        scan = _make_easm_scan(session, org)

        # 60 shodan_vulns assets — bypass cap is 50.
        for i in range(60):
            asset = Asset(
                scan_id=scan.id,
                hostname=f"vpn{i}",
                fqdn=f"vpn{i}.example.com",
                is_internet_facing=True,
                environment_tag="external",
                criticality=5,
                easm_data={
                    "open_ports": [443],
                    "shodan_vulns": ["CVE-2024-21762"],
                    "http_status": 200,
                },
                source_systems=["easm"],
            )
            session.add(asset)
        session.flush()

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = {"scan_id": 999, "job_ids": ["j1"], "status": "running"}
            from services.vm_scanner import (
                trigger_vm_scan_for_easm_assets,
                MAX_AUTO_VM_BYPASS_TARGETS,
            )
            _run(trigger_vm_scan_for_easm_assets(session, org, scan.id, "example.com"))

        targets = mock_start.call_args[0][2]
        # No more than the bypass cap (the score-sort list is empty since
        # every asset is in the bypass set).
        assert len(targets) == MAX_AUTO_VM_BYPASS_TARGETS


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

    def test_flags_easm_scan_for_sweeper(self, db_session):
        """VM auto-scan step persists `needs_auto_vm_scan` instead of dispatching inline.

        Dispatch happens out-of-band in `process_pending_easm_vm_triggers` so it
        survives Cloud Run container restarts mid-finalize.
        """
        from models.models import Scan
        session, org = db_session
        scan = _make_easm_scan(session, org)
        _make_easm_asset(session, scan.id, "app.example.com", ports=[443])

        with patch("services.vm_scanner.trigger_vm_scan_for_easm_assets", new_callable=AsyncMock) as mock_trigger:
            from services.post_ingest import _auto_vm_scan_for_easm
            result = _auto_vm_scan_for_easm(session, org.id, scan.id)

        assert result is not None
        assert result["queued"] is True
        assert result["domain"] == "example.com"
        # Inline dispatch must NOT happen — that was the bug.
        mock_trigger.assert_not_called()
        # Flag must be persisted so a restart-resilient sweeper can pick it up.
        session.refresh(scan)
        assert scan.raw_metadata.get("needs_auto_vm_scan") is True

    def test_suppress_auto_followup_skips_queueing(self, db_session):
        """When the EASM scan was created with ``suppress_auto_followup=True``
        (operator unchecked the "Run automated follow-up scans" box), the VM
        auto-trigger refuses to queue — and the flag is NOT written. Same flag
        also blocks the audit auto-trigger; see test_audit_auto_trigger.py."""
        session, org = db_session
        scan = _make_easm_scan(session, org)
        scan.raw_metadata = {**(scan.raw_metadata or {}), "suppress_auto_followup": True}
        session.commit()

        from services.post_ingest import _auto_vm_scan_for_easm
        result = _auto_vm_scan_for_easm(session, org.id, scan.id)

        assert result["queued"] is False
        assert result["suppressed"] is True
        session.refresh(scan)
        assert "needs_auto_vm_scan" not in (scan.raw_metadata or {})

    def test_idempotent_when_already_pending(self, db_session):
        """Re-running the step on an already-flagged scan is a no-op."""
        session, org = db_session
        scan = _make_easm_scan(session, org)
        scan.raw_metadata = {**scan.raw_metadata, "needs_auto_vm_scan": True}
        session.commit()

        from services.post_ingest import _auto_vm_scan_for_easm
        result = _auto_vm_scan_for_easm(session, org.id, scan.id)

        assert result["queued"] is True
        assert result["already_pending"] is True

    def test_step_in_finalize_pipeline(self, db_session):
        """The auto_vm_scan step appears in finalize_scan results for EASM scans."""
        session, org = db_session
        scan = _make_easm_scan(session, org)

        with patch("services.vm_scanner.trigger_vm_scan_for_easm_assets", new_callable=AsyncMock) as mock_trigger:
            mock_trigger.return_value = None

            from services.post_ingest import finalize_scan
            results = finalize_scan(session, scan_id=scan.id, org_id=org.id)

        assert "auto_vm_scan" in results


# ─────────────────────────────────────────────────────────────────────
# EASM → VM trigger sweeper (durable handoff)
# ─────────────────────────────────────────────────────────────────────


class TestProcessPendingEasmVmTriggers:
    """Tests for vm_scanner.process_pending_easm_vm_triggers — the periodic
    sweeper that dispatches VM scans for EASM scans flagged by post_ingest."""

    def _flag(self, session, scan):
        scan.raw_metadata = {**(scan.raw_metadata or {}), "needs_auto_vm_scan": True}
        session.commit()

    def test_dispatches_flagged_scan_and_clears_flag(self, db_session):
        session, org = db_session
        scan = _make_easm_scan(session, org)
        _make_easm_asset(session, scan.id, "app.example.com", ports=[443])
        self._flag(session, scan)

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = {"scan_id": 999, "job_ids": ["j1"], "status": "running"}

            from services.vm_scanner import process_pending_easm_vm_triggers
            stats = process_pending_easm_vm_triggers(session)

        assert stats["swept"] == 1
        assert stats["dispatched"] == 1
        mock_start.assert_called_once()

        session.refresh(scan)
        # Flag must be cleared so the next sweep doesn't re-dispatch.
        assert "needs_auto_vm_scan" not in (scan.raw_metadata or {})

    def test_skips_unflagged_scan(self, db_session):
        session, org = db_session
        scan = _make_easm_scan(session, org)
        _make_easm_asset(session, scan.id, "app.example.com", ports=[443])
        # No flag set.

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            from services.vm_scanner import process_pending_easm_vm_triggers
            stats = process_pending_easm_vm_triggers(session)

        assert stats["swept"] == 0
        assert stats["dispatched"] == 0
        mock_start.assert_not_called()

    def test_clears_flag_when_no_scannable_assets(self, db_session):
        """When trigger returns None (no eligible assets) the flag is still cleared
        — re-sweeping won't change the outcome until the EASM scan re-runs."""
        session, org = db_session
        scan = _make_easm_scan(session, org)
        _make_easm_asset(session, scan.id, "dead.example.com", ports=[], http_status=None)
        self._flag(session, scan)

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            from services.vm_scanner import process_pending_easm_vm_triggers
            stats = process_pending_easm_vm_triggers(session)

        assert stats["swept"] == 1
        assert stats["dispatched"] == 0
        assert stats["skipped"] == 1
        mock_start.assert_not_called()

        session.refresh(scan)
        assert "needs_auto_vm_scan" not in (scan.raw_metadata or {})

    def test_keeps_flag_on_dispatch_error(self, db_session):
        """Transient dispatch failure leaves the flag set so the next tick retries."""
        session, org = db_session
        scan = _make_easm_scan(session, org)
        _make_easm_asset(session, scan.id, "app.example.com", ports=[443])
        self._flag(session, scan)

        with patch(
            "services.vm_scanner.trigger_vm_scan_for_easm_assets",
            new_callable=AsyncMock,
        ) as mock_trigger:
            mock_trigger.side_effect = RuntimeError("vm-api 503")

            from services.vm_scanner import process_pending_easm_vm_triggers
            stats = process_pending_easm_vm_triggers(session)

        assert stats["errors"] == 1
        assert stats["dispatched"] == 0

        session.refresh(scan)
        # Flag must still be set so the next sweep retries.
        assert scan.raw_metadata.get("needs_auto_vm_scan") is True
        # Failure counter is bumped so a permanently broken scan eventually
        # gives up instead of looping every 60s forever.
        assert scan.raw_metadata.get("auto_vm_scan_failures") == 1

    def test_drops_flag_after_max_consecutive_failures(self, db_session):
        """A permanently broken dispatch eventually clears the flag instead of
        looping forever. Observed in prod 2026-04-30 → 2026-05-07: scan 548
        retried every 60s for 6 days because no retry cap existed."""
        from services.vm_scanner import (
            MAX_AUTO_VM_SCAN_FAILURES,
            process_pending_easm_vm_triggers,
        )

        session, org = db_session
        scan = _make_easm_scan(session, org)
        _make_easm_asset(session, scan.id, "app.example.com", ports=[443])
        # Pre-seed N-1 failures so this sweep is the one that trips the cap.
        scan.raw_metadata = {
            **(scan.raw_metadata or {}),
            "needs_auto_vm_scan": True,
            "auto_vm_scan_failures": MAX_AUTO_VM_SCAN_FAILURES - 1,
        }
        session.commit()

        with patch(
            "services.vm_scanner.trigger_vm_scan_for_easm_assets",
            new_callable=AsyncMock,
        ) as mock_trigger:
            mock_trigger.side_effect = RuntimeError("vm-api 503")
            stats = process_pending_easm_vm_triggers(session)

        assert stats["errors"] == 1
        session.refresh(scan)
        assert "needs_auto_vm_scan" not in (scan.raw_metadata or {})
        assert scan.raw_metadata.get("auto_vm_scan_failures") == MAX_AUTO_VM_SCAN_FAILURES

    def test_resets_failure_counter_on_success(self, db_session):
        """A successful dispatch clears both the flag and the failure counter."""
        session, org = db_session
        scan = _make_easm_scan(session, org)
        _make_easm_asset(session, scan.id, "app.example.com", ports=[443])
        scan.raw_metadata = {
            **(scan.raw_metadata or {}),
            "needs_auto_vm_scan": True,
            "auto_vm_scan_failures": 3,
        }
        session.commit()

        with patch("services.vm_scanner.start_vm_scan", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = {"scan_id": 999, "job_ids": ["j1"], "status": "running"}
            from services.vm_scanner import process_pending_easm_vm_triggers
            stats = process_pending_easm_vm_triggers(session)

        assert stats["dispatched"] == 1
        session.refresh(scan)
        assert "needs_auto_vm_scan" not in (scan.raw_metadata or {})
        assert "auto_vm_scan_failures" not in (scan.raw_metadata or {})


# ─────────────────────────────────────────────────────────────────────
# Orphan / stale scan reaper
# ─────────────────────────────────────────────────────────────────────

def _make_vm_scan(session, org, scan_date_iso, job_statuses):
    """Build a running VM scan with a custom scan_date and job_statuses map."""
    from models.models import Scan

    scan = Scan(
        org_id=org.id,
        filename="vm-scan-test",
        scan_name="VM Scan — test",
        scan_date=scan_date_iso,
        scan_type="vm_scan",
        source_type="vm_scanner",
        raw_metadata={
            "targets": list(job_statuses.keys()),
            "status": "running",
            "job_ids": list(job_statuses.keys()),
            "total_jobs": len(job_statuses),
            "completed_jobs": 0,
            "findings_emitted": 0,
            "imported_job_ids": [],
            "job_statuses": job_statuses,
        },
    )
    session.add(scan)
    session.flush()
    return scan


class TestReapStaleVmScans:
    """Tests for reap_stale_vm_scans — both hard timeout and PENDING-orphan paths."""

    def test_reaps_scan_older_than_hard_cap(self, db_session):
        """Scans running >3h are always reaped regardless of job_statuses."""
        from datetime import datetime, timedelta
        session, org = db_session

        # 4h old, every job has already been seen STARTED — still reap on hard cap
        old = datetime.utcnow() - timedelta(hours=4)
        scan = _make_vm_scan(
            session, org, old.isoformat(),
            {"job-a": {"status": "STARTED"}},
        )
        session.commit()

        from services.vm_scanner import reap_stale_vm_scans
        with patch("services.vm_scanner._revoke_vm_jobs_sync") as mock_revoke:
            result = reap_stale_vm_scans(session)

        assert result["reaped"] == 1
        session.refresh(scan)
        assert scan.raw_metadata["status"] == "failed"
        # Reaper must also revoke the Celery tasks — without this they keep
        # draining the queue and block newer scans.
        mock_revoke.assert_called_once_with(["job-a"])

    def test_reaps_pending_orphan_after_short_threshold(self, db_session):
        """All-PENDING scans older than 20min are reaped as broker orphans."""
        from datetime import datetime, timedelta
        session, org = db_session

        old = datetime.utcnow() - timedelta(minutes=30)
        scan = _make_vm_scan(
            session, org, old.isoformat(),
            {"job-a": {"status": "PENDING"}, "job-b": {"status": "PENDING"}},
        )
        session.commit()

        from services.vm_scanner import reap_stale_vm_scans
        with patch("services.vm_scanner._revoke_vm_jobs_sync") as mock_revoke:
            result = reap_stale_vm_scans(session)

        assert result["reaped"] == 1
        session.refresh(scan)
        assert scan.raw_metadata["status"] == "failed"
        assert "broker" in scan.raw_metadata["error"].lower()
        mock_revoke.assert_called_once_with(["job-a", "job-b"])

    def test_preserves_scan_with_observed_progress(self, db_session):
        """A 30min-old scan with at least one STARTED job is still considered live."""
        from datetime import datetime, timedelta
        session, org = db_session

        old = datetime.utcnow() - timedelta(minutes=30)
        scan = _make_vm_scan(
            session, org, old.isoformat(),
            {"job-a": {"status": "PENDING"}, "job-b": {"status": "STARTED"}},
        )
        session.commit()

        from services.vm_scanner import reap_stale_vm_scans
        result = reap_stale_vm_scans(session)

        assert result["reaped"] == 0
        session.refresh(scan)
        assert scan.raw_metadata["status"] == "running"

    def test_preserves_fresh_pending_scan(self, db_session):
        """A 5min-old all-PENDING scan is still within the orphan window."""
        from datetime import datetime, timedelta
        session, org = db_session

        fresh = datetime.utcnow() - timedelta(minutes=5)
        scan = _make_vm_scan(
            session, org, fresh.isoformat(),
            {"job-a": {"status": "PENDING"}},
        )
        session.commit()

        from services.vm_scanner import reap_stale_vm_scans
        result = reap_stale_vm_scans(session)

        assert result["reaped"] == 0
        session.refresh(scan)
        assert scan.raw_metadata["status"] == "running"

    def test_skips_scan_without_populated_job_statuses(self, db_session):
        """Scan nobody has ever polled (empty job_statuses) falls through to 3h cap."""
        from datetime import datetime, timedelta
        session, org = db_session

        # 30min old but no job_statuses populated — orphan path can't decide,
        # so reaper leaves it alone until the 3h hard cap.
        old = datetime.utcnow() - timedelta(minutes=30)
        scan = _make_vm_scan(session, org, old.isoformat(), {})
        # Clear job_statuses explicitly to simulate "never polled"
        scan.raw_metadata = {**scan.raw_metadata, "job_statuses": {}}
        session.commit()

        from services.vm_scanner import reap_stale_vm_scans
        result = reap_stale_vm_scans(session)

        assert result["reaped"] == 0
        session.refresh(scan)
        assert scan.raw_metadata["status"] == "running"
