"""Regression tests for the EASM completion finding count.

``_import_assets_for_domain`` returns the number of findings *inserted by that
call*. Mid-scan incremental imports write findings under the same scan_id, so by
the time the finalize pass runs every plugin_id already exists and the return
value is 0 — while the asset count it returns alongside is a full upsert count.
That mismatch is what made every EASM completion notification read
"N assets, 0 findings processed".

These tests pin the two halves of the fix:
  * the per-call semantics of ``_import_assets_for_domain`` (drops to 0 on a
    second pass over the same payload), and
  * the scan-wide total the notification should report instead.
"""
from datetime import datetime, timedelta

import pytest

from models.models import Asset, Finding, Scan
from services.easm import _import_assets_for_domain


@pytest.fixture
def easm_scan(db_session, test_org):
    scan = Scan(
        org_id=test_org.id,
        filename="easm-finalize-test",
        scan_name="EASM Full — hakunahq.com",
        scan_type="easm_full",
        source_type="easm",
        status="running",
        raw_metadata={"domain": "hakunahq.com"},
    )
    db_session.add(scan)
    db_session.flush()
    return scan


def _enriched_asset_payload():
    """One fully-enriched host — the shape the scanner returns post-enrichment."""
    return {
        "hostname": "www.hakunahq.com",
        "ip": "203.0.113.10",
        "open_ports": [443, 3306],
        "services": {"3306": {"name": "mysql", "product": "MySQL", "version": "8.0"}},
        "tls_cert": {
            "subject": "CN=www.hakunahq.com",
            "issuer": "CN=Test CA",
            "version": "TLS 1.0",
            "cipher": "RC4-MD5",
            "expiry": (datetime.utcnow() + timedelta(days=5)).isoformat() + "Z",
        },
    }


def test_second_pass_reports_zero_new_findings(db_session, easm_scan):
    """The finalize pass over an already-imported payload creates nothing new.

    This is the mechanism behind "N assets, 0 findings processed": the incremental
    import already wrote the findings, so the finalize call's own counter is 0
    even though the scan holds findings.
    """
    payload = [_enriched_asset_payload()]

    created_1, findings_1, _, _ = _import_assets_for_domain(
        db_session, easm_scan, payload, "hakunahq.com",
    )
    assert created_1 == 1
    assert findings_1 > 0, "first import must generate findings for an enriched host"

    created_2, findings_2, _, _ = _import_assets_for_domain(
        db_session, easm_scan, payload, "hakunahq.com",
    )
    # The asset is counted again (upsert), the findings are not — that asymmetry
    # is exactly what the notification used to publish.
    assert created_2 == 1
    assert findings_2 == 0


def test_scan_total_survives_the_second_pass(db_session, easm_scan):
    """The scan-wide count the notification should use stays stable across passes."""
    payload = [_enriched_asset_payload()]

    _import_assets_for_domain(db_session, easm_scan, payload, "hakunahq.com")
    total_after_first = db_session.query(Finding).filter(
        Finding.scan_id == easm_scan.id
    ).count()

    _import_assets_for_domain(db_session, easm_scan, payload, "hakunahq.com")
    total_after_second = db_session.query(Finding).filter(
        Finding.scan_id == easm_scan.id
    ).count()

    assert total_after_first > 0
    assert total_after_second == total_after_first, "rerun must not duplicate findings"

    # And the assets are not duplicated either — IDs stay stable.
    assert db_session.query(Asset).filter(Asset.scan_id == easm_scan.id).count() == 1
