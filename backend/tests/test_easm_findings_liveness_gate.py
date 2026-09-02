"""Tests for the liveness suppression gate in `_generate_easm_findings`.

Regression coverage for the outage where every EASM scan reported zero
findings. The gate originally suppressed on `liveness_score` alone, but the
score is a slow-moving counter that ratchets downward whenever a probe is
flaky and needs several clean cycles to recover — so hosts the scanner had
just confirmed alive still carried single-digit scores and had all their
findings suppressed. Suppression now requires both signals to agree: the
scanner's current verdict must be `likely_dead` AND the score must be under
the threshold.
"""
from datetime import datetime

import pytest

from models.models import Asset, Finding, Scan
from services.easm import _LIVENESS_SUPPRESS_THRESHOLD, _generate_easm_findings


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


def _ea(**overrides):
    """An EASM payload that always yields at least one finding (exposed Redis)."""
    ea = {
        "hostname": "db.hakunahq.com",
        "open_ports": [6379],
        "services": {"6379": {"name": "redis", "product": "Redis", "version": "6.2"}},
    }
    ea.update(overrides)
    return ea


def _count(db, asset):
    return db.query(Finding).filter(Finding.asset_id == asset.id).count()


def test_confirmed_alive_asset_is_never_suppressed(db_session, easm_scan):
    """The exact production shape: state says alive, score is ratcheted to 0."""
    asset = _make_asset(db_session, easm_scan)

    count, ids = _generate_easm_findings(
        db_session, easm_scan.id, asset,
        _ea(liveness_state="confirmed_alive", liveness_score=0),
    )

    assert count > 0
    assert len(ids) == count
    assert _count(db_session, asset) == count


def test_unconfirmed_asset_with_low_score_is_not_suppressed(db_session, easm_scan):
    """`unconfirmed` means one of three probes passed — commonly a live host
    behind a CDN or WAF that drops SYN. Not a strong enough signal to drop
    its exposure findings."""
    asset = _make_asset(db_session, easm_scan)

    count, _ = _generate_easm_findings(
        db_session, easm_scan.id, asset,
        _ea(liveness_state="unconfirmed", liveness_score=0),
    )

    assert count > 0


def test_likely_dead_asset_below_threshold_is_suppressed(db_session, easm_scan):
    asset = _make_asset(db_session, easm_scan)

    count, ids = _generate_easm_findings(
        db_session, easm_scan.id, asset,
        _ea(liveness_state="likely_dead",
            liveness_score=_LIVENESS_SUPPRESS_THRESHOLD - 1),
    )

    assert count == 0
    assert ids == []
    assert _count(db_session, asset) == 0


def test_likely_dead_asset_above_threshold_still_reports(db_session, easm_scan):
    """Both halves of the gate must agree — a recent `likely_dead` verdict
    whose score hasn't decayed through the threshold yet keeps reporting."""
    asset = _make_asset(db_session, easm_scan)

    count, _ = _generate_easm_findings(
        db_session, easm_scan.id, asset,
        _ea(liveness_state="likely_dead",
            liveness_score=_LIVENESS_SUPPRESS_THRESHOLD),
    )

    assert count > 0


def test_missing_liveness_fields_do_not_suppress(db_session, easm_scan):
    """Payloads from older scanner builds carry no liveness fields at all."""
    asset = _make_asset(db_session, easm_scan)

    count, _ = _generate_easm_findings(db_session, easm_scan.id, asset, _ea())

    assert count > 0
