"""HTTP tests for the identity-discovery router.

Covers consent grant / status / revoke flow, the GDPR erasure path (with
the hard-delete of any existing identity asset), and the role gate. The
weekly dispatcher has its own test module — these tests stay focused on
the request/response surface.
"""

from datetime import datetime, timedelta

import pytest

from models.models import (
    Asset,
    DataProcessingConsent,
    IdentitySuppression,
    Scan,
)
from services.identity_discovery import IDENTITY_DISCOVERY_PURPOSE
from tests.conftest import create_user, make_auth_headers


_ACK_TEXT = (
    "I confirm we have a lawful basis under GDPR to process identity data "
    "for our organization, and we accept LinkedIn ToS obligations for the "
    "data sourced from public SERP results."
)


def _create_identity_asset(db_session, org, slug, name="Jane"):
    """Build a complete (Scan + Asset) row for an existing identity so the
    erasure path has something to delete."""
    scan = Scan(
        org_id=org.id,
        filename=f"identity-discovery-org-{org.id}",
        scan_name="Identity Discovery",
        source_type="identity_discovery",
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id,
        asset_type="identity",
        asset_identity={"source": "linkedin", "slug": slug},
        asset_attributes={"display_name": name},
        source_systems=["identity_discovery"],
    )
    db_session.add(asset)
    db_session.flush()
    return asset


# ── Consent flow ────────────────────────────────────────────────────


def test_consent_status_defaults_to_disabled(authed_client):
    r = authed_client.get("/api/identity-discovery/consent")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["permitted"] is False
    assert body["granted_at"] is None


def test_grant_then_revoke_round_trip(authed_client, db_session, test_org):
    r = authed_client.post(
        "/api/identity-discovery/consent",
        json={"acknowledgment_text": _ACK_TEXT},
    )
    assert r.status_code == 200
    granted = r.json()
    assert granted["enabled"] is True
    assert granted["permitted"] is True
    assert granted["granted_at"] is not None

    db_session.expire_all()
    org = db_session.query(type(test_org)).get(test_org.id)
    assert org.identity_discovery_enabled is True
    consent = (
        db_session.query(DataProcessingConsent)
        .filter(DataProcessingConsent.org_id == test_org.id)
        .one()
    )
    assert consent.purpose == IDENTITY_DISCOVERY_PURPOSE
    # Default validity is 1 year; allow generous slack for clock drift.
    assert consent.expires_at > datetime.utcnow() + timedelta(days=350)

    r = authed_client.delete("/api/identity-discovery/consent")
    assert r.status_code == 200
    assert r.json()["enabled"] is False

    db_session.expire_all()
    org = db_session.query(type(test_org)).get(test_org.id)
    assert org.identity_discovery_enabled is False
    consent = (
        db_session.query(DataProcessingConsent)
        .filter(DataProcessingConsent.org_id == test_org.id)
        .one()
    )
    assert consent.revoked_at is not None


def test_grant_rejects_short_ack(authed_client):
    r = authed_client.post(
        "/api/identity-discovery/consent",
        json={"acknowledgment_text": "too short"},
    )
    assert r.status_code == 422


def test_analyst_cannot_grant_consent(client, db_session, test_org):
    analyst = create_user(db_session, test_org, email="analyst@test.com", role="analyst")
    headers = make_auth_headers(analyst, test_org)
    r = client.post(
        "/api/identity-discovery/consent",
        json={"acknowledgment_text": _ACK_TEXT},
        headers=headers,
    )
    assert r.status_code == 403


# ── Erasure (GDPR Art. 17) ──────────────────────────────────────────


def test_erasure_deletes_existing_asset_and_adds_suppression(
    authed_client, db_session, test_org,
):
    asset = _create_identity_asset(db_session, test_org, slug="jane-doe")
    asset_id = asset.id

    r = authed_client.post(
        "/api/identity-discovery/suppressions",
        json={"linkedin_url": "https://www.linkedin.com/in/Jane-Doe/"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["slug"] == "jane-doe"
    assert body["assets_deleted"] == 1
    assert body["already_suppressed"] is False

    # Asset is gone (hard delete, not stale).
    assert db_session.query(Asset).filter(Asset.id == asset_id).first() is None
    # Suppression row exists with the canonical slug.
    supp = db_session.query(IdentitySuppression).filter(
        IdentitySuppression.org_id == test_org.id,
        IdentitySuppression.slug == "jane-doe",
    ).one()
    assert supp.suppressed_by_user_id is not None


def test_erasure_is_idempotent(authed_client, db_session, test_org):
    authed_client.post(
        "/api/identity-discovery/suppressions",
        json={"linkedin_url": "https://www.linkedin.com/in/jane-doe/"},
    )
    r = authed_client.post(
        "/api/identity-discovery/suppressions",
        json={"linkedin_url": "https://linkedin.com/in/JANE-DOE"},
    )
    assert r.status_code == 201
    assert r.json()["already_suppressed"] is True
    # Only one suppression row regardless of how many requests.
    assert db_session.query(IdentitySuppression).filter(
        IdentitySuppression.org_id == test_org.id,
        IdentitySuppression.slug == "jane-doe",
    ).count() == 1


def test_erasure_rejects_non_linkedin_input(authed_client):
    r = authed_client.post(
        "/api/identity-discovery/suppressions",
        json={"linkedin_url": "https://example.com/profile/jane"},
    )
    assert r.status_code == 400


def test_lift_suppression(authed_client, db_session, test_org):
    db_session.add(IdentitySuppression(
        org_id=test_org.id, source="linkedin", slug="jane-doe",
    ))
    db_session.flush()
    r = authed_client.delete("/api/identity-discovery/suppressions/jane-doe")
    assert r.status_code == 200
    assert db_session.query(IdentitySuppression).filter(
        IdentitySuppression.org_id == test_org.id,
        IdentitySuppression.slug == "jane-doe",
    ).first() is None


def test_lift_suppression_404_when_missing(authed_client):
    r = authed_client.delete("/api/identity-discovery/suppressions/nobody")
    assert r.status_code == 404


# ── Per-org isolation ───────────────────────────────────────────────


def test_erasure_does_not_affect_other_orgs(authed_client, db_session, test_org):
    """Suppression in this tenant must not delete identity assets from
    another tenant — basic multi-tenant safety."""
    from models.models import Organization

    other_org = Organization(name="Other Org", slug="other-org")
    db_session.add(other_org)
    db_session.flush()

    _create_identity_asset(db_session, test_org, slug="jane-doe")
    other_asset = _create_identity_asset(db_session, other_org, slug="jane-doe")

    r = authed_client.post(
        "/api/identity-discovery/suppressions",
        json={"linkedin_url": "https://linkedin.com/in/jane-doe/"},
    )
    assert r.status_code == 201
    assert r.json()["assets_deleted"] == 1
    # Other tenant's asset survives intact.
    assert db_session.query(Asset).filter(Asset.id == other_asset.id).first() is not None
