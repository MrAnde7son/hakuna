"""AuthProfile CRUD route tests — RBAC, validation, broker integration."""

from unittest.mock import AsyncMock, patch

import pytest

from models.models import AuthProfile, IntegrationCredential
from services import credential_vault


@pytest.fixture
def seeded_credential(db_session, test_org):
    cred = IntegrationCredential(
        id="cred-abc",
        org_id=test_org.id,
        name="prod-app-cred",
        connector_id="generic",
        auth_type="basic",
        encrypted_values=credential_vault.encrypt({"username": "alice", "password": "secret"}),
    )
    db_session.add(cred)
    db_session.flush()
    return cred


def _valid_payload(cred_id, profile_type="form_login"):
    if profile_type == "static":
        return {
            "name": "prod-app-static",
            "profile_type": "static",
            "credential_id": cred_id,
            "session_ttl_seconds": 900,
        }
    return {
        "name": "prod-app",
        "profile_type": "form_login",
        "credential_id": cred_id,
        "login_url": "https://app.example.com/login",
        "login_flow": [
            {"action": "goto", "url": "https://app.example.com/login"},
            {"action": "fill", "selector": "#email", "value_from": "username"},
            {"action": "fill", "selector": "#password", "value_from": "password"},
            {"action": "click", "selector": "button[type=submit]"},
            {"action": "wait_for_url", "pattern": "/dashboard"},
        ],
        "success_condition": {"type": "url_matches", "pattern": "/dashboard"},
        "session_ttl_seconds": 900,
    }


def test_create_list_get_update_delete(authed_client, seeded_credential):
    # Create
    resp = authed_client.post("/api/auth-profiles", json=_valid_payload(seeded_credential.id))
    assert resp.status_code == 200, resp.text
    profile = resp.json()
    assert profile["name"] == "prod-app"
    assert profile["session_cached"] is False

    # List
    resp = authed_client.get("/api/auth-profiles")
    assert resp.status_code == 200
    assert any(p["id"] == profile["id"] for p in resp.json())

    # Get
    resp = authed_client.get(f"/api/auth-profiles/{profile['id']}")
    assert resp.status_code == 200
    assert resp.json()["login_url"] == "https://app.example.com/login"

    # Update
    resp = authed_client.patch(
        f"/api/auth-profiles/{profile['id']}",
        json={"login_url": "https://app.example.com/sso/login", "session_ttl_seconds": 1200},
    )
    assert resp.status_code == 200
    assert resp.json()["login_url"] == "https://app.example.com/sso/login"
    assert resp.json()["session_ttl_seconds"] == 1200

    # Delete
    resp = authed_client.delete(f"/api/auth-profiles/{profile['id']}")
    assert resp.status_code == 200
    # Subsequent get → 404
    resp = authed_client.get(f"/api/auth-profiles/{profile['id']}")
    assert resp.status_code == 404


def test_create_requires_auth(client, seeded_credential):
    resp = client.post("/api/auth-profiles", json=_valid_payload(seeded_credential.id))
    assert resp.status_code == 401


def test_duplicate_name_rejected(authed_client, seeded_credential):
    authed_client.post("/api/auth-profiles", json=_valid_payload(seeded_credential.id))
    resp = authed_client.post("/api/auth-profiles", json=_valid_payload(seeded_credential.id))
    assert resp.status_code == 409


def test_bad_credential_id_rejected(authed_client):
    resp = authed_client.post("/api/auth-profiles", json=_valid_payload("no-such-cred"))
    assert resp.status_code == 404


def test_cross_org_profile_hidden(db_session, authed_client, seeded_credential):
    # Create a profile belonging to another org directly in the DB
    from models.models import Organization
    other_org = Organization(name="Other", slug="other")
    db_session.add(other_org)
    db_session.flush()
    other_cred = IntegrationCredential(
        id="cred-other", org_id=other_org.id, name="c", connector_id="generic",
        auth_type="basic", encrypted_values=credential_vault.encrypt({"u": "v"}),
    )
    db_session.add(other_cred)
    other_profile = AuthProfile(
        id="prof-other", org_id=other_org.id, name="other-profile",
        credential_id=other_cred.id, login_url="https://x/login",
        login_flow=[], success_condition={},
    )
    db_session.add(other_profile)
    db_session.flush()

    # Current user cannot see it
    resp = authed_client.get(f"/api/auth-profiles/{other_profile.id}")
    assert resp.status_code == 404
    resp = authed_client.get("/api/auth-profiles")
    assert all(p["id"] != other_profile.id for p in resp.json())


def test_update_invalidates_cached_session(authed_client, seeded_credential, db_session):
    resp = authed_client.post("/api/auth-profiles", json=_valid_payload(seeded_credential.id))
    profile_id = resp.json()["id"]
    # Manually seed a cached session
    from datetime import datetime, timedelta
    profile = db_session.query(AuthProfile).filter(AuthProfile.id == profile_id).first()
    profile.cached_session_blob = "blob"
    profile.session_expires_at = datetime.utcnow() + timedelta(hours=1)
    profile.session_credential_hash = "stale"
    db_session.flush()

    authed_client.patch(f"/api/auth-profiles/{profile_id}", json={"name": "renamed"})

    db_session.refresh(profile)
    assert profile.cached_session_blob is None
    assert profile.session_expires_at is None


def test_test_endpoint_uses_broker(authed_client, seeded_credential):
    resp = authed_client.post("/api/auth-profiles", json=_valid_payload(seeded_credential.id))
    profile_id = resp.json()["id"]

    fake_result = {
        "success": True,
        "captured_cookies": ["session"],
        "captured_headers": [],
        "expires_at": "2030-01-01T00:00:00",
    }
    with patch("routes.auth_profile_routes.session_broker.test_login",
               new=AsyncMock(return_value=fake_result)) as mock_test:
        resp = authed_client.post(f"/api/auth-profiles/{profile_id}/test")
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert resp.json()["captured_cookies"] == ["session"]
    mock_test.assert_awaited_once()


def test_create_static_profile(authed_client, seeded_credential):
    resp = authed_client.post(
        "/api/auth-profiles",
        json=_valid_payload(seeded_credential.id, profile_type="static"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["profile_type"] == "static"
    # Static profiles don't need login_url / flow / success_condition
    assert body["login_url"] in (None, "")


def test_form_login_missing_url_rejected(authed_client, seeded_credential):
    payload = _valid_payload(seeded_credential.id)
    payload["login_url"] = ""  # empty — should fail validation
    resp = authed_client.post("/api/auth-profiles", json=payload)
    assert resp.status_code == 400
    assert "login_url" in resp.text


def test_form_login_missing_success_condition_rejected(authed_client, seeded_credential):
    payload = _valid_payload(seeded_credential.id)
    payload["success_condition"] = {}
    resp = authed_client.post("/api/auth-profiles", json=payload)
    assert resp.status_code == 400
    assert "success_condition" in resp.text


def test_unsupported_profile_type_rejected(authed_client, seeded_credential):
    payload = _valid_payload(seeded_credential.id)
    payload["profile_type"] = "oauth_authz_code"  # not yet implemented
    resp = authed_client.post("/api/auth-profiles", json=payload)
    assert resp.status_code == 400
    assert "profile_type" in resp.text


def test_static_test_endpoint_skips_broker(authed_client, seeded_credential):
    resp = authed_client.post(
        "/api/auth-profiles",
        json=_valid_payload(seeded_credential.id, profile_type="static"),
    )
    profile_id = resp.json()["id"]

    # The static test path must not call session_broker — if we patched it
    # to raise, a successful 200 proves it wasn't invoked.
    with patch("routes.auth_profile_routes.session_broker.test_login",
               new=AsyncMock(side_effect=AssertionError("broker must not run for static"))):
        resp = authed_client.post(f"/api/auth-profiles/{profile_id}/test")
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert "captured_fields" in resp.json()


def test_detect_flow_returns_llm_output(authed_client):
    fake_llm_output = {
        "success": True,
        "login_flow": [
            {"action": "goto", "url": "https://example.com/login"},
            {"action": "fill", "selector": "#email", "value_from": "username"},
            {"action": "fill", "selector": "#password", "value_from": "password"},
            {"action": "click", "selector": "button[type=submit]"},
        ],
        "success_condition": {"type": "url_matches", "pattern": "/dashboard"},
        "notes": "Detected email+password form",
    }
    with patch("routes.auth_profile_routes.auth_flow_detector.detect_login_flow",
               new=AsyncMock(return_value=fake_llm_output)) as mock_detect:
        resp = authed_client.post(
            "/api/auth-profiles/detect-flow",
            json={"login_url": "https://example.com/login"},
        )
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert resp.json()["login_flow"][0]["action"] == "goto"
    mock_detect.assert_called_once()
