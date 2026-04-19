"""vm_scanner.py — AuthProfile resolution for both static and form_login.

Confirms that _resolve_auth_profile:
- static: maps credential → ScanCredentials payload, skipping Playwright
- form_login: drives broker, then folds cookies + scraped headers onto the
  credential-derived payload (additive `headers` dict that nuclei_worker's
  `-H` builder handles — see hakuna-vm-scanner/scanner/vm/nuclei_worker.py).
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from models.models import AuthProfile, IntegrationCredential
from services import credential_vault, vm_scanner
from services.session_broker import SessionBundle, SessionBrokerError


@pytest.fixture
def basic_credential(db_session, test_org):
    cred = IntegrationCredential(
        id="cred-basic",
        org_id=test_org.id,
        name="basic-cred",
        connector_id="generic",
        auth_type="basic",
        encrypted_values=credential_vault.encrypt({"username": "alice", "password": "secret"}),
    )
    db_session.add(cred)
    db_session.flush()
    return cred


@pytest.fixture
def profile_with_cred(db_session, test_org, basic_credential):
    profile = AuthProfile(
        id="prof-1",
        org_id=test_org.id,
        name="p",
        profile_type="form_login",
        credential_id=basic_credential.id,
        login_url="https://app.example.com/login",
        login_flow=[{"action": "goto", "url": "https://app.example.com/login"}],
        success_condition={"type": "url_matches", "pattern": "/home"},
    )
    db_session.add(profile)
    db_session.flush()
    return profile


@pytest.fixture
def static_profile(db_session, test_org, basic_credential):
    profile = AuthProfile(
        id="prof-static",
        org_id=test_org.id,
        name="p-static",
        profile_type="static",
        credential_id=basic_credential.id,
    )
    db_session.add(profile)
    db_session.flush()
    return profile


def test_form_login_folds_cookie_into_headers(db_session, test_org, profile_with_cred):
    bundle = SessionBundle(
        cookie_header="sid=abc123",
        headers={"X-CSRF-Token": "tok"},
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    with patch("services.session_broker.get_or_create_session",
               new=AsyncMock(return_value=bundle)):
        result = asyncio.run(vm_scanner._resolve_auth_profile(
            db_session, test_org.id, profile_with_cred.id,
        ))

    assert result["type"] == "basic"
    assert result["username"] == "alice"
    assert result["headers"]["Cookie"] == "sid=abc123"
    assert result["headers"]["X-CSRF-Token"] == "tok"


def test_form_login_broker_failure_raises_400(db_session, test_org, profile_with_cred):
    with patch("services.session_broker.get_or_create_session",
               new=AsyncMock(side_effect=SessionBrokerError("selector missing"))):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(vm_scanner._resolve_auth_profile(
                db_session, test_org.id, profile_with_cred.id,
            ))
    assert exc_info.value.status_code == 400
    assert "selector missing" in exc_info.value.detail


def test_form_login_no_cookie_still_merges_headers(db_session, test_org, profile_with_cred):
    bundle = SessionBundle(
        cookie_header="",
        headers={"X-CSRF-Token": "only-header"},
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    with patch("services.session_broker.get_or_create_session",
               new=AsyncMock(return_value=bundle)):
        result = asyncio.run(vm_scanner._resolve_auth_profile(
            db_session, test_org.id, profile_with_cred.id,
        ))

    assert result["type"] == "basic"
    assert "Cookie" not in result.get("headers", {})
    assert result["headers"]["X-CSRF-Token"] == "only-header"


def test_static_profile_skips_broker(db_session, test_org, static_profile):
    """Static profiles must not invoke Playwright — payload comes purely
    from the credential mapping."""
    with patch("services.session_broker.get_or_create_session",
               new=AsyncMock(side_effect=AssertionError("broker must not run for static"))):
        result = asyncio.run(vm_scanner._resolve_auth_profile(
            db_session, test_org.id, static_profile.id,
        ))
    assert result["type"] == "basic"
    assert result["username"] == "alice"
    assert result["password"] == "secret"


def test_missing_profile_raises_404(db_session, test_org):
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(vm_scanner._resolve_auth_profile(db_session, test_org.id, "does-not-exist"))
    assert exc_info.value.status_code == 404
