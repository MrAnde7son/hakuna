"""Regression tests for EASM rescan clobbering non-EASM asset sources.

Bug: when an EASM scan re-ran, `_clear_scan_data` hard-deleted assets owned
by the EASM scan. The ondelete=CASCADE on AssetObservation cascade-wiped
observations contributed by other sources (e.g. Cloudflare), and
`_import_assets_for_domain` then recreated the asset with source_systems=["easm"]
only. The user saw Cloudflare's contribution disappear after every EASM scan.

These tests cover:
1. _clear_scan_data preserves assets that carry non-EASM source_systems.
2. _clear_scan_data preserves assets that have a non-EASM AssetObservation row.
3. _clear_scan_data still deletes EASM-only assets (no regression in cleanup).
4. _import_assets_for_domain accumulates "easm" into source_systems without
   clobbering existing sources on update.
"""
from datetime import datetime

import pytest

from models.models import Asset, AssetObservation, Scan
from services.easm import _clear_scan_data, _import_assets_for_domain


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


def _make_asset(db, scan, *, fqdn, ip, source_systems):
    asset = Asset(
        scan_id=scan.id,
        ip=ip,
        hostname=fqdn.split(".")[0],
        fqdn=fqdn,
        source_systems=source_systems,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.add(asset)
    db.flush()
    return asset


def test_clear_scan_preserves_asset_with_cloudflare_source(db_session, easm_scan):
    """Asset that has cloudflare_api in source_systems must survive EASM clear."""
    asset = _make_asset(
        db_session, easm_scan,
        fqdn="app.hakunahq.com", ip="34.54.87.52",
        source_systems=["easm", "cloudflare_api"],
    )
    db_session.add(AssetObservation(
        asset_id=asset.id, source_system="cloudflare_api",
        raw_fields={"fqdn": "app.hakunahq.com"},
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
    ))
    db_session.add(AssetObservation(
        asset_id=asset.id, source_system="easm",
        raw_fields={"fqdn": "app.hakunahq.com"},
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
    ))
    db_session.flush()

    _clear_scan_data(db_session, easm_scan.id)
    db_session.flush()

    survivor = db_session.query(Asset).filter(Asset.id == asset.id).first()
    assert survivor is not None, "asset with cloudflare_api source was wrongly deleted"
    assert "cloudflare_api" in (survivor.source_systems or [])
    assert "easm" in (survivor.source_systems or [])

    # Cloudflare observation survives; EASM observation is cleared so rescan records a fresh one.
    cf_obs = db_session.query(AssetObservation).filter(
        AssetObservation.asset_id == asset.id,
        AssetObservation.source_system == "cloudflare_api",
    ).first()
    assert cf_obs is not None, "cloudflare observation was cascade-deleted"

    easm_obs = db_session.query(AssetObservation).filter(
        AssetObservation.asset_id == asset.id,
        AssetObservation.source_system == "easm",
    ).first()
    assert easm_obs is None, "easm observation should be dropped on clear"


def test_clear_scan_preserves_asset_with_non_easm_observation_only(db_session, easm_scan):
    """Even if source_systems only lists easm, a non-easm observation must preserve the asset."""
    asset = _make_asset(
        db_session, easm_scan,
        fqdn="www.hakunahq.com", ip="104.21.10.71",
        source_systems=["easm"],  # source_systems out of sync with observations
    )
    db_session.add(AssetObservation(
        asset_id=asset.id, source_system="wiz",
        raw_fields={"fqdn": "www.hakunahq.com"},
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
    ))
    db_session.flush()

    _clear_scan_data(db_session, easm_scan.id)
    db_session.flush()

    survivor = db_session.query(Asset).filter(Asset.id == asset.id).first()
    assert survivor is not None, "asset with wiz observation was wrongly deleted"


def test_clear_scan_deletes_easm_only_assets(db_session, easm_scan):
    """Regression guard: EASM-only assets should still be cleaned up."""
    asset = _make_asset(
        db_session, easm_scan,
        fqdn="solo.hakunahq.com", ip="1.2.3.4",
        source_systems=["easm"],
    )
    asset_id = asset.id

    _clear_scan_data(db_session, easm_scan.id)
    db_session.flush()

    gone = db_session.query(Asset).filter(Asset.id == asset_id).first()
    assert gone is None, "EASM-only asset should be deleted by _clear_scan_data"


def test_import_accumulates_easm_source_without_clobber(db_session, easm_scan):
    """When EASM finds an existing asset with other sources, it appends 'easm'."""
    asset = _make_asset(
        db_session, easm_scan,
        fqdn="mixed.hakunahq.com", ip="5.6.7.8",
        source_systems=["cloudflare_api"],
    )

    _import_assets_for_domain(
        db_session, easm_scan,
        [{"hostname": "mixed.hakunahq.com", "ip": "5.6.7.8"}],
        "hakunahq.com",
    )
    db_session.flush()

    refreshed = db_session.query(Asset).filter(Asset.id == asset.id).first()
    assert refreshed is not None
    sources = refreshed.source_systems or []
    assert "cloudflare_api" in sources, "cloudflare_api source was clobbered"
    assert "easm" in sources, "easm was not accumulated onto the existing asset"
    # No duplicate asset created
    count = db_session.query(Asset).filter(
        Asset.fqdn == "mixed.hakunahq.com",
        Asset.scan_id == easm_scan.id,
    ).count()
    assert count == 1
