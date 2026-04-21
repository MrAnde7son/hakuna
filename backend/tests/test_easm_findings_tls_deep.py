"""Tests for the deep-TLS finding generators.

Covers EASM-TLS-CIPHER-ACCEPTED, EASM-CERT-CHAIN-UNTRUSTED, EASM-CERT-OCSP,
and EASM-CERT-CAA-MISMATCH. Same shape as the header-audit tests: feed a
raw scanner asset dict with a ``tls_deep_audit`` blob into
``_generate_easm_findings`` and assert the resulting findings.
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


def _make_asset(db, scan, *, fqdn="deep.hakunahq.com", ip="1.2.3.4"):
    asset = Asset(
        scan_id=scan.id, ip=ip,
        hostname=fqdn.split(".")[0], fqdn=fqdn,
        source_systems=["easm"],
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
    )
    db.add(asset)
    db.flush()
    return asset


def _findings(db, asset, plugin_id):
    return db.query(Finding).filter(
        Finding.asset_id == asset.id,
        Finding.plugin_id == plugin_id,
    ).all()


def _audit(issues, *, port=443):
    return {"port": port, "issues": issues}


def test_tls_deprecated_version_emits_cipher_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_deep_audit": _audit([
            {"id": "tls-deprecated-version-accepted", "severity": 3,
             "detail": "Server accepts TLSv1.0"},
        ]),
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    f = _findings(db_session, asset, "EASM-TLS-CIPHER-ACCEPTED")
    assert len(f) == 1
    assert f[0].severity == 3
    assert "TLSv1.0" in f[0].plugin_output


def test_tls_sslv3_plus_weak_cipher_bundles(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_deep_audit": _audit([
            {"id": "tls-broken-version-accepted", "severity": 4,
             "detail": "Server accepts SSLv3"},
            {"id": "tls-weak-cipher-accepted", "severity": 3,
             "detail": "Server accepts RC4-MD5"},
        ]),
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    f = _findings(db_session, asset, "EASM-TLS-CIPHER-ACCEPTED")
    assert len(f) == 1
    # Worst severity wins.
    assert f[0].severity == 4
    assert "SSLv3" in f[0].plugin_output
    assert "RC4-MD5" in f[0].plugin_output


def test_cert_chain_untrusted(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_deep_audit": _audit([
            {"id": "cert-chain-untrusted", "severity": 3,
             "detail": "Mozilla: self signed certificate"},
        ]),
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    f = _findings(db_session, asset, "EASM-CERT-CHAIN-UNTRUSTED")
    assert len(f) == 1
    assert f[0].severity == 3


def test_cert_revoked_is_critical(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_deep_audit": _audit([
            {"id": "cert-revoked", "severity": 4, "detail": "key_compromise"},
        ]),
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    f = _findings(db_session, asset, "EASM-CERT-OCSP")
    assert len(f) == 1
    assert f[0].severity == 4
    assert f[0].effort_level == "high"


def test_caa_mismatch_emits_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_deep_audit": _audit([
            {"id": "cert-caa-mismatch", "severity": 2,
             "detail": "CAA records do not authorize DigiCert Inc"},
        ]),
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    f = _findings(db_session, asset, "EASM-CERT-CAA-MISMATCH")
    assert len(f) == 1
    assert f[0].severity == 2
    assert "DigiCert" in f[0].plugin_output


def test_multiple_concerns_emit_multiple_findings(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "tls_deep_audit": _audit([
            {"id": "tls-weak-cipher-accepted", "severity": 3, "detail": "RC4"},
            {"id": "cert-chain-untrusted", "severity": 3, "detail": "expired"},
            {"id": "cert-revoked", "severity": 4, "detail": "ca_compromise"},
            {"id": "cert-caa-mismatch", "severity": 2, "detail": "Sectigo"},
        ]),
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    assert len(_findings(db_session, asset, "EASM-TLS-CIPHER-ACCEPTED")) == 1
    assert len(_findings(db_session, asset, "EASM-CERT-CHAIN-UNTRUSTED")) == 1
    assert len(_findings(db_session, asset, "EASM-CERT-OCSP")) == 1
    assert len(_findings(db_session, asset, "EASM-CERT-CAA-MISMATCH")) == 1


def test_empty_audit_emits_nothing(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {"hostname": asset.fqdn, "tls_deep_audit": _audit([])}
    _generate_easm_findings(db_session, easm_scan.id, asset, ea)
    for pid in (
        "EASM-TLS-CIPHER-ACCEPTED",
        "EASM-CERT-CHAIN-UNTRUSTED",
        "EASM-CERT-OCSP",
        "EASM-CERT-CAA-MISMATCH",
    ):
        assert _findings(db_session, asset, pid) == []


def test_rerun_updates_in_place(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea_first = {
        "hostname": asset.fqdn,
        "tls_deep_audit": _audit([
            {"id": "tls-deprecated-version-accepted", "severity": 3, "detail": "TLSv1.1"},
        ]),
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea_first)
    db_session.commit()
    first = _findings(db_session, asset, "EASM-TLS-CIPHER-ACCEPTED")
    assert len(first) == 1
    assert first[0].severity == 3

    ea_second = {
        "hostname": asset.fqdn,
        "tls_deep_audit": _audit([
            {"id": "tls-broken-version-accepted", "severity": 4, "detail": "SSLv3"},
        ]),
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea_second)
    db_session.commit()
    again = _findings(db_session, asset, "EASM-TLS-CIPHER-ACCEPTED")
    assert len(again) == 1  # no duplicate row
    assert again[0].severity == 4
    assert "SSLv3" in again[0].plugin_output
