"""Tests for EASM-HTTP-HEADER-WEAK and EASM-COOKIE-WEAK finding generators.

Mirrors the TLS-WEAK test pattern: feeds a raw scanner asset dict (`ea`) into
``_generate_easm_findings`` and verifies the bundled findings that come out.
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


def _make_asset(db, scan, *, fqdn="web.hakunahq.com", ip="1.2.3.4"):
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


def _findings(db, asset, plugin_id):
    return db.query(Finding).filter(
        Finding.asset_id == asset.id,
        Finding.plugin_id == plugin_id,
    ).all()


def test_missing_security_headers_emits_header_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "security_audit": {
            "url": "https://web.hakunahq.com/",
            "issues": [
                {"id": "hsts-missing", "severity": 2, "detail": "HSTS missing"},
                {"id": "csp-missing", "severity": 2, "detail": "CSP missing"},
                {"id": "referrer-policy-missing", "severity": 1, "detail": "Referrer-Policy missing"},
            ],
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    header_findings = _findings(db_session, asset, "EASM-HTTP-HEADER-WEAK")
    assert len(header_findings) == 1
    f = header_findings[0]
    # Worst of the three issues is severity=2 (Medium).
    assert f.severity == 2
    assert f.severity_label == "Medium"
    assert "HSTS missing" in f.plugin_output
    assert "CSP missing" in f.plugin_output
    assert "Referrer-Policy missing" in f.plugin_output

    # Cookie finding should NOT be created when no cookie issues exist.
    assert _findings(db_session, asset, "EASM-COOKIE-WEAK") == []


def test_cookie_issues_emit_cookie_finding(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "security_audit": {
            "url": "https://web.hakunahq.com/",
            "issues": [
                {"id": "cookie-insecure", "severity": 2, "detail": "Cookie 'session' lacks Secure"},
                {"id": "cookie-not-httponly", "severity": 1, "detail": "Cookie 'session' lacks HttpOnly"},
            ],
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    cookie_findings = _findings(db_session, asset, "EASM-COOKIE-WEAK")
    assert len(cookie_findings) == 1
    f = cookie_findings[0]
    assert f.severity == 2
    assert "Secure" in f.plugin_output
    assert "HttpOnly" in f.plugin_output

    assert _findings(db_session, asset, "EASM-HTTP-HEADER-WEAK") == []


def test_mixed_issues_emit_both_findings(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {
        "hostname": asset.fqdn,
        "security_audit": {
            "url": "https://web.hakunahq.com/",
            "issues": [
                {"id": "hsts-weak", "severity": 1, "detail": "HSTS max-age low"},
                {"id": "cookie-samesite-none-insecure", "severity": 2, "detail": "SameSite=None without Secure"},
            ],
        },
    }

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    assert len(_findings(db_session, asset, "EASM-HTTP-HEADER-WEAK")) == 1
    assert len(_findings(db_session, asset, "EASM-COOKIE-WEAK")) == 1


def test_empty_audit_emits_nothing(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)
    ea = {"hostname": asset.fqdn, "security_audit": {"issues": []}}

    _generate_easm_findings(db_session, easm_scan.id, asset, ea)

    assert _findings(db_session, asset, "EASM-HTTP-HEADER-WEAK") == []
    assert _findings(db_session, asset, "EASM-COOKIE-WEAK") == []


def test_rerun_updates_severity_in_place(db_session, easm_scan):
    """Second call with a worse issue set should update the existing row, not
    create a duplicate — same upsert semantics as EASM-TLS-WEAK."""
    asset = _make_asset(db_session, easm_scan)
    ea_first = {
        "hostname": asset.fqdn,
        "security_audit": {
            "issues": [{"id": "referrer-policy-missing", "severity": 1, "detail": "low"}],
        },
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea_first)
    db_session.commit()

    first = _findings(db_session, asset, "EASM-HTTP-HEADER-WEAK")
    assert len(first) == 1
    assert first[0].severity == 1

    ea_second = {
        "hostname": asset.fqdn,
        "security_audit": {
            "issues": [
                {"id": "hsts-missing", "severity": 2, "detail": "HSTS missing"},
                {"id": "csp-missing", "severity": 2, "detail": "CSP missing"},
            ],
        },
    }
    _generate_easm_findings(db_session, easm_scan.id, asset, ea_second)
    db_session.commit()

    again = _findings(db_session, asset, "EASM-HTTP-HEADER-WEAK")
    assert len(again) == 1  # no duplicate
    assert again[0].severity == 2
    assert "HSTS missing" in again[0].plugin_output
