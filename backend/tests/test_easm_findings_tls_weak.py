"""Tests for the EASM-TLS-WEAK finding generator.

Verifies protocol + cipher grading, multi-issue bundling into plugin_output,
and upsert-on-rerun behavior that mirrors EASM-TLS-CERT.
"""
from datetime import datetime, timedelta

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


def _make_asset(db, scan, *, fqdn="tls.hakunahq.com", ip="1.2.3.4"):
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


def _weak_tls_findings(db, asset):
    return db.query(Finding).filter(
        Finding.asset_id == asset.id,
        Finding.plugin_id == "EASM-TLS-WEAK",
    ).all()


def _fresh_expiry_iso():
    """Far-future expiry so the TLS-CERT block stays in the 'Info' band and
    doesn't interfere with TLS-WEAK assertions."""
    return (datetime.utcnow() + timedelta(days=365)).isoformat() + "Z"


def test_tls10_protocol_creates_high_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "TLS 1.0",
            "cipher": "ECDHE-RSA-AES256-SHA",
            "expiry": _fresh_expiry_iso(),
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _weak_tls_findings(db_session, asset)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == 3
    assert f.severity_label == "High"
    assert f.priority_score == 7.0
    assert "TLS 1.0" in f.plugin_output


def test_tls11_protocol_creates_medium_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "TLSv1.1",
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "expiry": _fresh_expiry_iso(),
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _weak_tls_findings(db_session, asset)
    assert len(findings) == 1
    assert findings[0].severity == 2
    assert findings[0].severity_label == "Medium"


def test_sslv3_protocol_creates_critical_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "SSLv3",
            "cipher": "AES128-SHA",
            "expiry": _fresh_expiry_iso(),
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _weak_tls_findings(db_session, asset)
    assert len(findings) == 1
    assert findings[0].severity == 4
    assert findings[0].severity_label == "Critical"
    assert findings[0].priority_score == 9.0


def test_rc4_cipher_creates_high_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "TLS 1.2",
            "cipher": "ECDHE-RSA-RC4-SHA",
            "expiry": _fresh_expiry_iso(),
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _weak_tls_findings(db_session, asset)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == 3
    assert "RC4" in f.plugin_output


def test_3des_cipher_creates_high_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "TLS 1.2",
            "cipher": "DES-CBC3-SHA",
            "expiry": _fresh_expiry_iso(),
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _weak_tls_findings(db_session, asset)
    assert len(findings) == 1
    assert findings[0].severity == 3


def test_strong_tls_produces_no_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "TLS 1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "expiry": _fresh_expiry_iso(),
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    assert _weak_tls_findings(db_session, asset) == []


def test_multiple_issues_bundle_into_single_finding_with_worst_severity(db_session, easm_scan):
    """TLS 1.0 (High) + RC4 (High) should produce ONE finding with High severity
    and both issues listed in plugin_output."""
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "TLS 1.0",
            "cipher": "RC4-MD5",
            "expiry": _fresh_expiry_iso(),
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    findings = _weak_tls_findings(db_session, asset)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == 3
    assert "TLS 1.0" in f.plugin_output
    assert "RC4" in f.plugin_output


def test_rerun_upserts_and_updates_severity(db_session, easm_scan):
    """Re-ingesting with a worse TLS config should update the existing finding
    in place rather than creating a duplicate, matching the EASM-TLS-CERT
    upsert pattern."""
    asset = _make_asset(db_session, easm_scan)

    # First scan: TLS 1.1 only → Medium
    _generate_easm_findings(db_session, easm_scan.id, asset, {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "TLS 1.1",
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "expiry": _fresh_expiry_iso(),
        },
    })
    findings = _weak_tls_findings(db_session, asset)
    assert len(findings) == 1
    assert findings[0].severity == 2

    # Second scan: downgraded to TLS 1.0 + RC4 → High
    _generate_easm_findings(db_session, easm_scan.id, asset, {
        "hostname": asset.fqdn,
        "tls_cert": {
            "version": "TLS 1.0",
            "cipher": "RC4-MD5",
            "expiry": _fresh_expiry_iso(),
        },
    })
    db_session.expire_all()

    findings = _weak_tls_findings(db_session, asset)
    assert len(findings) == 1, "rerun must not create a duplicate finding"
    assert findings[0].severity == 3
    assert findings[0].severity_label == "High"
