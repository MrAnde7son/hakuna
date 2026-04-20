"""Tests for post_ingest._recompute_asset_severity_counts.

The function keeps Asset.critical_count/high_count/medium_count/low_count/
info_count in sync with the actual Finding rows for the asset, across scan
boundaries. This matters when streaming ingestors (VM scanner, EASM,
integrations) link new findings to assets first discovered in an earlier
scan — the assets inventory reads the stored counter columns directly, so
a stale counter hides the finding count from the UI.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import text

from models.models import Asset, Finding, Scan
from services.post_ingest import _recompute_asset_severity_counts


def _set_org(db, table, record_id, org_id):
    db.execute(
        text(f"UPDATE {table} SET org_id = :org_id WHERE id = :id"),
        {"org_id": org_id, "id": record_id},
    )


@pytest.fixture
def two_scans(db_session, test_org):
    """Two scans in the same org — an initial 'discovery' scan and a later
    'vm' scan that attaches findings to the discovery-scan asset."""
    discovery = Scan(filename="easm.json", scan_name="EASM", status="completed")
    vm = Scan(filename="vm.json", scan_name="VM", status="completed", source_type="vm_scanner")
    db_session.add_all([discovery, vm])
    db_session.flush()
    _set_org(db_session, "scans", discovery.id, test_org.id)
    _set_org(db_session, "scans", vm.id, test_org.id)
    return discovery, vm


@pytest.fixture
def web_app_asset(db_session, test_org, two_scans):
    discovery, _vm = two_scans
    asset = Asset(
        scan_id=discovery.id,
        asset_type="web_app",
        asset_identity={"url": "http://20.83.163.0:8080"},
        ip="20.83.163.0",
        critical_count=0, high_count=0, medium_count=0, low_count=0, info_count=0,
    )
    db_session.add(asset)
    db_session.flush()
    _set_org(db_session, "assets", asset.id, test_org.id)
    return asset


def _mk_finding(db, org_id, scan_id, asset_id, severity, plugin_id):
    f = Finding(
        scan_id=scan_id, asset_id=asset_id,
        plugin_id=plugin_id, plugin_name=f"plugin {plugin_id}", severity=severity,
    )
    db.add(f)
    db.flush()
    _set_org(db, "findings", f.id, org_id)
    return f


class TestSeverityCountsCrossScan:
    def test_counts_reflect_findings_from_different_scan(
        self, db_session, test_org, two_scans, web_app_asset
    ):
        """VM scanner attaches findings to an asset created in an earlier
        scan — counts must reflect those findings even though they live in
        a different scan_id than the asset."""
        _discovery, vm = two_scans
        _mk_finding(db_session, test_org.id, vm.id, web_app_asset.id, 4, "agent-injection")
        _mk_finding(db_session, test_org.id, vm.id, web_app_asset.id, 0, "tech-detect")
        _mk_finding(db_session, test_org.id, vm.id, web_app_asset.id, 0, "form-detection")
        _mk_finding(db_session, test_org.id, vm.id, web_app_asset.id, 0, "options-method")

        new_ids = [f.id for f in db_session.query(Finding).filter(Finding.scan_id == vm.id).all()]

        result = _recompute_asset_severity_counts(db_session, vm.id, new_finding_ids=new_ids)

        assert result["updated"] == 1
        db_session.refresh(web_app_asset)
        assert web_app_asset.critical_count == 1
        assert web_app_asset.high_count == 0
        assert web_app_asset.info_count == 3

    def test_scan_wide_mode_covers_cross_scan_assets(
        self, db_session, test_org, two_scans, web_app_asset
    ):
        """Without new_finding_ids the recount should still pick up assets
        touched by findings in this scan, even when Asset.scan_id points
        to a different scan."""
        _discovery, vm = two_scans
        _mk_finding(db_session, test_org.id, vm.id, web_app_asset.id, 3, "high-thing")
        _mk_finding(db_session, test_org.id, vm.id, web_app_asset.id, 2, "medium-thing")

        result = _recompute_asset_severity_counts(db_session, vm.id)

        assert result["updated"] == 1
        db_session.refresh(web_app_asset)
        assert web_app_asset.high_count == 1
        assert web_app_asset.medium_count == 1

    def test_idempotent(self, db_session, test_org, two_scans, web_app_asset):
        _discovery, vm = two_scans
        _mk_finding(db_session, test_org.id, vm.id, web_app_asset.id, 4, "x")
        _recompute_asset_severity_counts(db_session, vm.id)
        result = _recompute_asset_severity_counts(db_session, vm.id)
        assert result["updated"] == 0
        db_session.refresh(web_app_asset)
        assert web_app_asset.critical_count == 1

    def test_no_findings_returns_zero(self, db_session, two_scans):
        _discovery, vm = two_scans
        result = _recompute_asset_severity_counts(db_session, vm.id)
        assert result == {"updated": 0, "total": 0}
