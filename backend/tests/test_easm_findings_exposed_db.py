"""Tests for the EASM-EXPOSED-DB finding generator.

Verifies that `_generate_easm_findings` emits one finding per internet-facing
database port, grades severity Critical when the service banner confirms the
expected database service and High when only the port is open, and performs an
idempotent upsert on re-ingest.
"""
from datetime import datetime

import pytest

from models.models import Asset, Finding, Scan
from services.easm import _generate_easm_findings


@pytest.fixture
def easm_scan(db_session, test_org):
    scan = Scan(
        org_id=test_org.id,
        filename="easm-test",
        scan_name="EASM Test",
        scan_type="easm_full",
        source_type="easm",
        status="completed",
        raw_metadata={"domain": "hakunahq.com"},
    )
    db_session.add(scan)
    db_session.flush()
    return scan


def _make_asset(db, scan, *, fqdn="db.hakunahq.com", ip="1.2.3.4"):
    asset = Asset(
        scan_id=scan.id,
        ip=ip,
        hostname=fqdn.split(".")[0],
        fqdn=fqdn,
        source_systems=["easm"],
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.add(asset)
    db.flush()
    return asset


def _get_findings(db, asset, plugin_prefix):
    return db.query(Finding).filter(
        Finding.asset_id == asset.id,
        Finding.plugin_id.like(f"{plugin_prefix}%"),
    ).all()


def test_mysql_port_with_confirmed_banner_is_critical(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "open_ports": [3306],
        "services": {"3306": {"name": "mysql", "product": "MySQL", "version": "5.7.33"}},
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _get_findings(db_session, asset, "EASM-EXPOSED-DB-")
    assert len(findings) == 1
    f = findings[0]
    assert f.plugin_id == "EASM-EXPOSED-DB-3306"
    assert f.severity == 4
    assert f.severity_label == "Critical"
    assert f.risk_factor == "Critical"
    assert f.priority_score == 9.0
    assert f.port == "3306"
    assert "MySQL" in f.plugin_name
    assert "Confirmed by banner: yes" in f.plugin_output


def test_redis_port_without_banner_is_high(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "open_ports": [6379],
        "services": {},  # no banner info
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _get_findings(db_session, asset, "EASM-EXPOSED-DB-6379")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == 3
    assert f.severity_label == "High"
    assert f.priority_score == 7.5
    assert "Confirmed by banner: no" in f.plugin_output
    assert "Redis" in f.plugin_name


def test_multiple_db_ports_produce_distinct_findings(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "open_ports": [3306, 6379, 5432],
        "services": {
            "3306": {"name": "mysql"},
            "5432": {"name": "postgresql"},
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _get_findings(db_session, asset, "EASM-EXPOSED-DB-")
    pids = sorted(f.plugin_id for f in findings)
    assert pids == [
        "EASM-EXPOSED-DB-3306",
        "EASM-EXPOSED-DB-5432",
        "EASM-EXPOSED-DB-6379",
    ]
    # MySQL + Postgres confirmed → Critical. Redis unconfirmed → High.
    severity_by_pid = {f.plugin_id: f.severity for f in findings}
    assert severity_by_pid["EASM-EXPOSED-DB-3306"] == 4
    assert severity_by_pid["EASM-EXPOSED-DB-5432"] == 4
    assert severity_by_pid["EASM-EXPOSED-DB-6379"] == 3


def test_non_database_port_produces_no_exposed_db_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "open_ports": [80, 443, 8080],
        "services": {"80": {"name": "http"}, "443": {"name": "https"}},
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    assert _get_findings(db_session, asset, "EASM-EXPOSED-DB-") == []


def test_rerun_upserts_without_duplicating(db_session, easm_scan):
    """Second call must not create a duplicate finding and must refresh last_seen."""
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "open_ports": [3306],
        "services": {"3306": {"name": "mysql"}},
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    first = _get_findings(db_session, asset, "EASM-EXPOSED-DB-3306")
    assert len(first) == 1
    initial_last_seen = first[0].last_seen

    # Second run — same asset, same data
    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    db_session.expire_all()

    second = _get_findings(db_session, asset, "EASM-EXPOSED-DB-3306")
    assert len(second) == 1, "rerun should not create a duplicate finding"
    assert second[0].last_seen >= initial_last_seen


def test_severity_escalates_when_banner_appears_on_rerun(db_session, easm_scan):
    """An exposed port initially without banner (High) should escalate to Critical
    once a later scan identifies the service."""
    asset = _make_asset(db_session, easm_scan)

    # First scan: port open but no banner → High
    _generate_easm_findings(
        db_session, easm_scan.id, asset,
        {"hostname": asset.fqdn, "open_ports": [27017], "services": {}},
    )
    findings = _get_findings(db_session, asset, "EASM-EXPOSED-DB-27017")
    assert len(findings) == 1
    assert findings[0].severity == 3

    # Second scan: banner confirms MongoDB → Critical
    _generate_easm_findings(
        db_session, easm_scan.id, asset,
        {
            "hostname": asset.fqdn,
            "open_ports": [27017],
            "services": {"27017": {"name": "mongodb", "product": "MongoDB"}},
        },
    )
    db_session.expire_all()

    findings = _get_findings(db_session, asset, "EASM-EXPOSED-DB-27017")
    assert len(findings) == 1
    assert findings[0].severity == 4
    assert findings[0].severity_label == "Critical"
