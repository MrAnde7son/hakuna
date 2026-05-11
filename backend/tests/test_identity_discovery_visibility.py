"""Visibility tests — identity_discovery scans must be hidden from the
active-scan picker, but identity assets must still appear in the asset
list when the user picks any non-identity scan for the same org."""

from datetime import datetime

import pytest

from models.models import Asset, Scan


def _make_scan(db_session, org, source_type, name=None):
    scan = Scan(
        org_id=org.id,
        filename=name or f"{source_type}-scan",
        scan_name=name or source_type,
        source_type=source_type,
    )
    db_session.add(scan)
    db_session.flush()
    return scan


def _make_asset(db_session, scan, asset_type, **kwargs):
    asset = Asset(
        scan_id=scan.id,
        asset_type=asset_type,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        **kwargs,
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_scan_list_hides_identity_discovery_by_default(authed_client, db_session, test_org):
    """Active-scan picker calls GET /api/scans and must not see the rolling
    identity_discovery scan — it's an enrichment job, not a scannable event."""
    _make_scan(db_session, test_org, "easm", "EASM Full")
    _make_scan(db_session, test_org, "identity_discovery", "Identity Discovery")
    r = authed_client.get("/api/scans")
    assert r.status_code == 200
    names = {s["scan_name"] for s in r.json()}
    assert "EASM Full" in names
    assert "Identity Discovery" not in names


def test_scan_list_includes_internal_when_requested(authed_client, db_session, test_org):
    """Power-user / admin flag surfaces the hidden enrichment scans for
    debugging without touching the default UX path."""
    _make_scan(db_session, test_org, "easm", "EASM Full")
    _make_scan(db_session, test_org, "identity_discovery", "Identity Discovery")
    r = authed_client.get("/api/scans?include_internal=true")
    assert r.status_code == 200
    names = {s["scan_name"] for s in r.json()}
    assert "Identity Discovery" in names


def test_picking_easm_scan_also_returns_identity_assets(authed_client, db_session, test_org):
    """The asset list filtered to a regular scan must union in this org's
    identity assets — otherwise they're stranded behind a picker filter
    the user can't change."""
    easm = _make_scan(db_session, test_org, "easm")
    identity = _make_scan(db_session, test_org, "identity_discovery")
    _make_asset(db_session, easm, "host", hostname="abirasecurity.com")
    _make_asset(
        db_session, identity, "identity",
        asset_identity={"source": "linkedin", "slug": "jane-doe"},
        asset_attributes={"display_name": "Jane Doe"},
    )

    r = authed_client.get(f"/api/assets?scan_id={easm.id}&page_size=50")
    assert r.status_code == 200
    types = sorted({a["asset_type"] for a in r.json()["assets"]})
    assert "host" in types
    assert "identity" in types


def test_picking_easm_scan_does_not_leak_other_orgs_identities(
    authed_client, db_session, test_org,
):
    """Multi-tenant safety: identities from another org's identity scan
    must NOT appear when this org picks its EASM scan."""
    from models.models import Organization

    other = Organization(name="Other Org", slug="other-org")
    db_session.add(other)
    db_session.flush()

    easm = _make_scan(db_session, test_org, "easm")
    other_identity = _make_scan(db_session, other, "identity_discovery")
    _make_asset(
        db_session, other_identity, "identity",
        asset_identity={"source": "linkedin", "slug": "leaky"},
        asset_attributes={"display_name": "Leaky Person"},
    )

    r = authed_client.get(f"/api/assets?scan_id={easm.id}&page_size=50")
    assert r.status_code == 200
    slugs = [
        (a.get("asset_identity") or {}).get("slug")
        for a in r.json()["assets"]
        if a["asset_type"] == "identity"
    ]
    assert "leaky" not in slugs
