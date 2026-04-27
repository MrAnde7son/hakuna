"""Tests for /api/ot-posture endpoints — overview matrix and consent grant/revoke."""

from datetime import datetime, timedelta, timezone

import pytest

from models.models import Asset, Scan


@pytest.fixture
def authed_client(client, auth_headers, app):
    """OT posture tests need server exceptions raised — the default TestClient
    swallows them which obscures bugs in the route under test."""
    from fastapi.testclient import TestClient
    with TestClient(app, raise_server_exceptions=True) as raising:
        class AuthedClient:
            def __init__(self, c, h):
                self._client = c
                self._headers = h
            def get(self, url, **kwargs):
                kwargs.setdefault("headers", {}).update(self._headers)
                return self._client.get(url, **kwargs)
            def post(self, url, **kwargs):
                kwargs.setdefault("headers", {}).update(self._headers)
                return self._client.post(url, **kwargs)
            def delete(self, url, **kwargs):
                kwargs.setdefault("headers", {}).update(self._headers)
                return self._client.delete(url, **kwargs)
        yield AuthedClient(raising, auth_headers)


def _seed_asset(db, org_id, *, ip, easm_data, label="ot-host"):
    scan = Scan(
        scan_name=f"scan-{label}", filename=f"scan-{label}.json",
        org_id=org_id, status="completed", scan_type="easm",
    )
    db.add(scan)
    db.flush()
    asset = Asset(
        scan_id=scan.id,
        ip=ip,
        hostname=label,
        fqdn=f"{label}.plant.local",
        easm_data=easm_data,
        asset_type="host",
        device_type="server",
    )
    db.add(asset)
    db.flush()
    return asset


def _utcnow_iso(offset_days: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=offset_days)
    return dt.replace(microsecond=0).isoformat()


def test_overview_includes_assets_with_ot_tcp_ports(authed_client, db_session, test_org):
    asset = _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.10",
        easm_data={"open_ports": [502, 443]},
        label="plc-1",
    )
    db_session.commit()

    resp = authed_client.get("/api/ot-posture/overview")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["ot_asset_count"] == 1
    row = next(r for r in data["rows"] if r["asset_id"] == asset.id)
    assert row["ot_tcp_ports_observed"] == [502]
    # No consent yet → all protocols missing
    for proto in ("ot_protocol", "ot_passive"):
        assert row["consent"][proto]["status"] == "missing"


def test_overview_excludes_assets_without_ot_signal(authed_client, db_session, test_org):
    _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.20",
        easm_data={"open_ports": [80, 443, 22]},
        label="webserver",
    )
    db_session.commit()

    resp = authed_client.get("/api/ot-posture/overview")
    assert resp.status_code == 200
    assert resp.json()["ot_asset_count"] == 0


def test_overview_marks_fresh_consent(authed_client, db_session, test_org):
    asset = _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.30",
        easm_data={
            "open_ports": [102],
            "ot_audit_consent": {
                "ot_protocol": {"granted_at": _utcnow_iso(0), "granted_by": "ops@plant"},
            },
        },
        label="s7-cpu",
    )
    db_session.commit()

    resp = authed_client.get("/api/ot-posture/overview")
    data = resp.json()
    row = next(r for r in data["rows"] if r["asset_id"] == asset.id)
    assert row["consent"]["ot_protocol"]["status"] == "fresh"
    assert row["consent"]["ot_protocol"]["days_remaining"] == 90
    # Coverage should reflect the fresh-consent protocol
    assert data["iec_62443_coverage"]["percent"] > 0


def test_overview_marks_expired_consent(authed_client, db_session, test_org):
    _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.40",
        easm_data={
            "open_ports": [44818],
            "ot_audit_consent": {
                "ot_protocol": {"granted_at": _utcnow_iso(120), "granted_by": "ops@plant"},
            },
        },
        label="enip-host",
    )
    db_session.commit()

    resp = authed_client.get("/api/ot-posture/overview")
    data = resp.json()
    row = data["rows"][0]
    assert row["consent"]["ot_protocol"]["status"] == "expired"
    assert row["consent"]["ot_protocol"]["days_remaining"] == 0
    # Expired consent doesn't count toward coverage
    assert data["iec_62443_coverage"]["percent"] == 0


def test_overview_marks_expiring_soon(authed_client, db_session, test_org):
    _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.50",
        easm_data={
            "open_ports": [502],
            "ot_audit_consent": {
                "ot_protocol": {"granted_at": _utcnow_iso(80), "granted_by": "ops@plant"},
            },
        },
        label="modbus-host",
    )
    db_session.commit()
    data = authed_client.get("/api/ot-posture/overview").json()
    assert data["rows"][0]["consent"]["ot_protocol"]["status"] == "expiring_soon"


def test_overview_keeps_assets_with_consent_even_without_ports(authed_client, db_session, test_org):
    """Revocation should remain visible — don't disappear an asset from the
    matrix just because its OT ports are no longer observed."""
    asset = _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.60",
        easm_data={
            "open_ports": [80],
            "ot_audit_consent": {
                "ot_protocol": {"granted_at": _utcnow_iso(10), "granted_by": "ops@plant"},
            },
        },
        label="ghost-plc",
    )
    db_session.commit()
    data = authed_client.get("/api/ot-posture/overview").json()
    row = next(r for r in data["rows"] if r["asset_id"] == asset.id)
    assert row["consent"]["ot_protocol"]["status"] == "fresh"


def test_grant_consent_persists_to_easm_data(authed_client, db_session, test_org):
    asset = _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.70",
        easm_data={"open_ports": [502]},
        label="grant-target",
    )
    db_session.commit()

    resp = authed_client.post("/api/ot-posture/consent", json={
        "asset_id": asset.id,
        "protocol": "ot_protocol",
        "note": "Approved by plant manager",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["consent"]["status"] == "fresh"
    assert body["consent"]["granted_by"] == "admin@test.com"

    db_session.refresh(asset)
    consent = (asset.easm_data or {}).get("ot_audit_consent") or {}
    assert "ot_protocol" in consent
    assert consent["ot_protocol"]["note"] == "Approved by plant manager"


def test_grant_consent_rejects_unknown_protocol(authed_client, db_session, test_org):
    asset = _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.80",
        easm_data={"open_ports": [502]},
        label="bad-proto",
    )
    db_session.commit()
    resp = authed_client.post("/api/ot-posture/consent", json={
        "asset_id": asset.id,
        "protocol": "definitely_not_ot",
    })
    assert resp.status_code == 400


def test_revoke_consent_clears_record(authed_client, db_session, test_org):
    asset = _seed_asset(
        db_session, test_org.id,
        ip="10.0.0.90",
        easm_data={
            "open_ports": [502],
            "ot_audit_consent": {
                "ot_protocol": {"granted_at": _utcnow_iso(0), "granted_by": "ops@plant"},
                "ot_passive": {"granted_at": _utcnow_iso(0), "granted_by": "ops@plant"},
            },
        },
        label="revoke-target",
    )
    db_session.commit()

    resp = authed_client.delete(
        "/api/ot-posture/consent",
        params={"asset_id": asset.id, "protocol": "ot_protocol"},
    )
    assert resp.status_code == 200, resp.text

    db_session.refresh(asset)
    consent = (asset.easm_data or {}).get("ot_audit_consent") or {}
    assert "ot_protocol" not in consent
    # ot_passive untouched — revocation must be per-protocol
    assert "ot_passive" in consent


def test_overview_isolates_by_org(authed_client, db_session, test_org):
    from models.models import Organization
    other_org = Organization(name="Other", slug="other-ot-org")
    db_session.add(other_org)
    db_session.flush()
    _seed_asset(
        db_session, other_org.id,
        ip="10.99.0.1",
        easm_data={"open_ports": [502]},
        label="other-org-plc",
    )
    db_session.commit()

    data = authed_client.get("/api/ot-posture/overview").json()
    assert data["ot_asset_count"] == 0
