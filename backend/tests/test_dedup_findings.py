"""Tests for run_cross_scan_finding_dedup — the org-scoped finding dedup
step that runs inside services/post_ingest.finalize_scan.

These assert the contract: scanners emit raw findings, the dedup engine
alone decides what survives according to the org's resolved rule.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import services.dedup as dedup_engine
from models.models import Finding, Organization


# ═══════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def org_a(db_session):
    org = Organization(name="Org A", slug="org-a", settings={})
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def org_b(db_session):
    org = Organization(name="Org B", slug="org-b", settings={})
    db_session.add(org)
    db_session.flush()
    return org


def _make_scan(db_session, org, name="scan"):
    from models.models import Scan
    from sqlalchemy import text
    scan = Scan(filename=f"{name}.nessus", scan_name=name, status="completed")
    db_session.add(scan)
    db_session.flush()
    db_session.execute(
        text("UPDATE scans SET org_id = :oid WHERE id = :sid"),
        {"oid": org.id, "sid": scan.id},
    )
    return scan


def _make_asset(db_session, scan, org, ip):
    from models.models import Asset
    from sqlalchemy import text
    asset = Asset(scan_id=scan.id, ip=ip, hostname=f"host-{ip}", os="Linux")
    db_session.add(asset)
    db_session.flush()
    db_session.execute(
        text("UPDATE assets SET org_id = :oid WHERE id = :aid"),
        {"oid": org.id, "aid": asset.id},
    )
    return asset


def _make_finding(db_session, scan, asset, org, plugin_id, port=None, severity=2, last_seen=None):
    from sqlalchemy import text
    f = Finding(
        scan_id=scan.id,
        asset_id=asset.id,
        plugin_id=plugin_id,
        plugin_name=f"Plugin {plugin_id}",
        severity=severity,
        description="",
        solution="",
        port=str(port) if port is not None else None,
        last_seen=last_seen or datetime.utcnow(),
    )
    db_session.add(f)
    db_session.flush()
    db_session.execute(
        text("UPDATE findings SET org_id = :oid WHERE id = :fid"),
        {"oid": org.id, "fid": f.id},
    )
    return f


def _enable(cfg: dict, **overrides) -> dict:
    """Turn on the findings section of a config copy with explicit overrides."""
    import copy
    cfg = copy.deepcopy(cfg)
    cfg.setdefault("findings", {})
    cfg["findings"].update({"enabled": True, **overrides})
    return cfg


# ═══════════════════════════════════════════════════════════
# run_cross_scan_finding_dedup
# ═══════════════════════════════════════════════════════════

class TestFindingDedupDisabled:
    def test_findings_disabled_skips(self, db_session, org_a):
        scan = _make_scan(db_session, org_a)
        asset = _make_asset(db_session, scan, org_a, "10.0.0.1")
        _make_finding(db_session, scan, asset, org_a, "1001")
        _make_finding(db_session, scan, asset, org_a, "1001")

        cfg = dedup_engine.load_config()
        cfg["findings"]["enabled"] = False
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)
        assert result.get("skipped") is True

        # Nothing deleted.
        assert db_session.query(Finding).count() == 2

    def test_no_key_fields_skips(self, db_session, org_a):
        scan = _make_scan(db_session, org_a)
        asset = _make_asset(db_session, scan, org_a, "10.0.0.1")
        _make_finding(db_session, scan, asset, org_a, "1001")
        _make_finding(db_session, scan, asset, org_a, "1001")

        cfg = _enable(dedup_engine.load_config(), key_fields=[])
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)
        assert result.get("skipped") is True
        assert db_session.query(Finding).count() == 2


class TestFindingDedupStrategies:
    def test_keep_last_removes_older_duplicates(self, db_session, org_a):
        scan1 = _make_scan(db_session, org_a, "old-scan")
        scan2 = _make_scan(db_session, org_a, "new-scan")
        asset = _make_asset(db_session, scan1, org_a, "10.0.0.1")
        older = datetime.utcnow() - timedelta(days=7)
        newer = datetime.utcnow()
        f_old = _make_finding(db_session, scan1, asset, org_a, "1001", port=443, last_seen=older)
        f_new = _make_finding(db_session, scan2, asset, org_a, "1001", port=443, last_seen=newer)

        cfg = _enable(
            dedup_engine.load_config(),
            key_fields=["plugin_id", "asset_id", "port"],
            strategy="keep_last",
        )
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)

        assert result["removed"] == 1
        assert db_session.query(Finding).filter(Finding.id == f_new.id).first() is not None
        assert db_session.query(Finding).filter(Finding.id == f_old.id).first() is None

    def test_keep_first_removes_newer_duplicates(self, db_session, org_a):
        scan1 = _make_scan(db_session, org_a, "old-scan")
        scan2 = _make_scan(db_session, org_a, "new-scan")
        asset = _make_asset(db_session, scan1, org_a, "10.0.0.1")
        older = datetime.utcnow() - timedelta(days=7)
        newer = datetime.utcnow()
        f_old = _make_finding(db_session, scan1, asset, org_a, "1001", port=443, last_seen=older)
        f_new = _make_finding(db_session, scan2, asset, org_a, "1001", port=443, last_seen=newer)

        cfg = _enable(
            dedup_engine.load_config(),
            key_fields=["plugin_id", "asset_id", "port"],
            strategy="keep_first",
        )
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)

        assert result["removed"] == 1
        assert db_session.query(Finding).filter(Finding.id == f_old.id).first() is not None
        assert db_session.query(Finding).filter(Finding.id == f_new.id).first() is None

    def test_merge_unions_cves(self, db_session, org_a):
        scan1 = _make_scan(db_session, org_a, "s1")
        scan2 = _make_scan(db_session, org_a, "s2")
        asset = _make_asset(db_session, scan1, org_a, "10.0.0.1")
        f_old = _make_finding(db_session, scan1, asset, org_a, "1001", port=443)
        f_old.cves = ["CVE-2024-0001"]
        f_new = _make_finding(db_session, scan2, asset, org_a, "1001", port=443)
        f_new.cves = ["CVE-2024-0002"]
        db_session.flush()

        cfg = _enable(
            dedup_engine.load_config(),
            key_fields=["plugin_id", "asset_id", "port"],
            strategy="merge",
        )
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)

        assert result["merged"] == 1
        assert result["removed"] == 1
        survivor = db_session.query(Finding).filter(Finding.id == f_new.id).first()
        assert survivor is not None
        assert set(survivor.cves) == {"CVE-2024-0001", "CVE-2024-0002"}


class TestFindingDedupSafety:
    def test_asset_id_always_in_key_fields(self, db_session, org_a):
        """Even if the user's rule omits asset_id, dedup must not merge
        findings across different assets."""
        scan = _make_scan(db_session, org_a)
        a1 = _make_asset(db_session, scan, org_a, "10.0.0.1")
        a2 = _make_asset(db_session, scan, org_a, "10.0.0.2")
        _make_finding(db_session, scan, a1, org_a, "1001", port=443)
        _make_finding(db_session, scan, a2, org_a, "1001", port=443)

        cfg = _enable(
            dedup_engine.load_config(),
            key_fields=["plugin_id", "port"],   # deliberately omits asset_id
            strategy="keep_last",
        )
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)

        assert result["removed"] == 0
        assert "asset_id" in result["key_fields"]
        assert db_session.query(Finding).count() == 2

    def test_tenant_isolation(self, db_session, org_a, org_b):
        """Org A's dedup run doesn't touch Org B's findings, even with
        identical key values."""
        scan_a = _make_scan(db_session, org_a, "scan-a")
        scan_b = _make_scan(db_session, org_b, "scan-b")
        asset_a = _make_asset(db_session, scan_a, org_a, "10.0.0.1")
        asset_b = _make_asset(db_session, scan_b, org_b, "10.0.0.1")

        # Two dupes in org_a
        _make_finding(db_session, scan_a, asset_a, org_a, "1001", port=443)
        _make_finding(db_session, scan_a, asset_a, org_a, "1001", port=443)
        # Two dupes in org_b
        _make_finding(db_session, scan_b, asset_b, org_b, "1001", port=443)
        _make_finding(db_session, scan_b, asset_b, org_b, "1001", port=443)

        cfg = _enable(
            dedup_engine.load_config(),
            key_fields=["plugin_id", "asset_id", "port"],
            strategy="keep_last",
        )
        # Run only for org A.
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)
        assert result["removed"] == 1

        # Org B is untouched — still has both duplicates.
        from models.models import Scan
        org_b_findings = (
            db_session.query(Finding).join(Scan, Finding.scan_id == Scan.id)
            .filter(Scan.org_id == org_b.id).count()
        )
        assert org_b_findings == 2


class TestFindingDedupReturnShape:
    def test_no_duplicates_returns_zero(self, db_session, org_a):
        scan = _make_scan(db_session, org_a)
        asset = _make_asset(db_session, scan, org_a, "10.0.0.1")
        _make_finding(db_session, scan, asset, org_a, "1001")
        _make_finding(db_session, scan, asset, org_a, "1002")

        cfg = _enable(
            dedup_engine.load_config(),
            key_fields=["plugin_id", "asset_id"],
            strategy="keep_last",
        )
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)
        # asset_id preserved in input order since it's already present.
        assert result == {
            "removed": 0,
            "merged": 0,
            "strategy": "keep_last",
            "key_fields": ["plugin_id", "asset_id"],
        }


class TestFindingDedupReassignsReferrers:
    """Regression: rows in tables with NOT NULL FKs to findings.id (e.g.
    finding_ownership) must be repointed to the survivor before the loser
    is deleted. Otherwise SQLAlchemy's default cascade NULLs the FK and
    PostgreSQL rejects the UPDATE.
    """

    def test_finding_ownership_repointed_to_survivor(self, db_session, org_a):
        from models.models import FindingOwnership
        scan1 = _make_scan(db_session, org_a, "old")
        scan2 = _make_scan(db_session, org_a, "new")
        asset = _make_asset(db_session, scan1, org_a, "10.0.0.1")
        older = datetime.utcnow() - timedelta(days=7)
        newer = datetime.utcnow()
        f_old = _make_finding(db_session, scan1, asset, org_a, "1001", port=443, last_seen=older)
        f_new = _make_finding(db_session, scan2, asset, org_a, "1001", port=443, last_seen=newer)

        # Manual ownership lives on the loser.
        db_session.add(FindingOwnership(
            finding_id=f_old.id, owner_name="Alice", team="SecOps",
        ))
        db_session.flush()

        cfg = _enable(
            dedup_engine.load_config(),
            key_fields=["plugin_id", "asset_id", "port"],
            strategy="keep_last",
        )
        result = dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)
        assert result["removed"] == 1

        # Ownership survived and now points at the survivor.
        owners = db_session.query(FindingOwnership).all()
        assert len(owners) == 1
        assert owners[0].finding_id == f_new.id
        assert owners[0].team == "SecOps"

    def test_survivor_ownership_wins_over_loser(self, db_session, org_a):
        """If both survivor and loser have ownership, keep survivor's
        (UNIQUE constraint on finding_id) and drop the loser's row.
        """
        from models.models import FindingOwnership
        scan1 = _make_scan(db_session, org_a, "old")
        scan2 = _make_scan(db_session, org_a, "new")
        asset = _make_asset(db_session, scan1, org_a, "10.0.0.1")
        older = datetime.utcnow() - timedelta(days=7)
        newer = datetime.utcnow()
        f_old = _make_finding(db_session, scan1, asset, org_a, "1001", port=443, last_seen=older)
        f_new = _make_finding(db_session, scan2, asset, org_a, "1001", port=443, last_seen=newer)

        db_session.add(FindingOwnership(finding_id=f_old.id, team="Loser"))
        db_session.add(FindingOwnership(finding_id=f_new.id, team="Survivor"))
        db_session.flush()

        cfg = _enable(
            dedup_engine.load_config(),
            key_fields=["plugin_id", "asset_id", "port"],
            strategy="keep_last",
        )
        dedup_engine.run_cross_scan_finding_dedup(db_session, org_a.id, cfg)

        owners = db_session.query(FindingOwnership).all()
        assert len(owners) == 1
        assert owners[0].finding_id == f_new.id
        assert owners[0].team == "Survivor"
