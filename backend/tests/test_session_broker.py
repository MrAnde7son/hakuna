"""Session broker tests — cache semantics + step execution (Playwright mocked).

The broker is the Playwright driver behind AuthProfile. We mock Playwright
entirely since CI doesn't install browsers — what we need to verify here
is the *wiring*: step execution, success conditions, cache hit/miss, and
credential-rotation invalidation. End-to-end login against a real browser
is covered in the manual verification steps.

Backend convention (see test_scan_planner_persisted.py) is ``asyncio.run``,
not ``@pytest.mark.asyncio`` — pytest-asyncio isn't in requirements.
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.models import AuthProfile, IntegrationCredential
from services import credential_vault, session_broker


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def test_credential(db_session, test_org):
    cred = IntegrationCredential(
        id="cred-test-1",
        org_id=test_org.id,
        name="test-cred",
        connector_id="generic",
        auth_type="basic",
        encrypted_values=credential_vault.encrypt({"username": "alice", "password": "secret"}),
    )
    db_session.add(cred)
    db_session.flush()
    return cred


@pytest.fixture
def test_profile(db_session, test_org, test_credential):
    profile = AuthProfile(
        id="prof-test-1",
        org_id=test_org.id,
        name="test-profile",
        profile_type="form_login",
        credential_id=test_credential.id,
        login_url="https://app.example.com/login",
        login_flow=[
            {"action": "goto", "url": "https://app.example.com/login"},
            {"action": "fill", "selector": "#email", "value_from": "username"},
            {"action": "fill", "selector": "#password", "value_from": "password"},
            {"action": "click", "selector": "button[type=submit]"},
            {"action": "wait_for_url", "pattern": "/dashboard"},
        ],
        success_condition={"type": "url_matches", "pattern": "/dashboard"},
        session_ttl_seconds=900,
    )
    db_session.add(profile)
    db_session.flush()
    return profile


# ─────────────────────────────────────────────
# Cache semantics
# ─────────────────────────────────────────────

def test_get_or_create_session_runs_flow_on_miss(db_session, test_org, test_profile):
    captured_bundle = session_broker.SessionBundle(
        cookie_header="sid=abc123",
        headers={"X-CSRF-Token": "tok"},
        expires_at=datetime.utcnow() + timedelta(seconds=900),
    )
    with patch.object(session_broker, "_run_login_flow", new=AsyncMock(return_value=captured_bundle)) as mock_flow:
        bundle = asyncio.run(
            session_broker.get_or_create_session(db_session, test_org.id, test_profile.id)
        )

    assert bundle.cookie_header == "sid=abc123"
    assert bundle.headers == {"X-CSRF-Token": "tok"}
    mock_flow.assert_awaited_once()
    db_session.refresh(test_profile)
    assert test_profile.cached_session_blob is not None
    assert test_profile.session_credential_hash
    assert test_profile.session_expires_at > datetime.utcnow()


def test_cache_hit_skips_playwright(db_session, test_org, test_profile):
    bundle_v1 = session_broker.SessionBundle(
        cookie_header="sid=v1",
        headers={},
        expires_at=datetime.utcnow() + timedelta(seconds=900),
    )
    with patch.object(session_broker, "_run_login_flow", new=AsyncMock(return_value=bundle_v1)) as mock_flow:
        asyncio.run(session_broker.get_or_create_session(db_session, test_org.id, test_profile.id))
        asyncio.run(session_broker.get_or_create_session(db_session, test_org.id, test_profile.id))
        asyncio.run(session_broker.get_or_create_session(db_session, test_org.id, test_profile.id))

    assert mock_flow.await_count == 1


def test_credential_rotation_invalidates_cache(db_session, test_org, test_profile, test_credential):
    bundle_v1 = session_broker.SessionBundle(
        cookie_header="sid=v1", headers={},
        expires_at=datetime.utcnow() + timedelta(seconds=900),
    )
    bundle_v2 = session_broker.SessionBundle(
        cookie_header="sid=v2", headers={},
        expires_at=datetime.utcnow() + timedelta(seconds=900),
    )
    with patch.object(session_broker, "_run_login_flow", new=AsyncMock(side_effect=[bundle_v1, bundle_v2])) as mock_flow:
        first = asyncio.run(
            session_broker.get_or_create_session(db_session, test_org.id, test_profile.id)
        )
        test_credential.encrypted_values = credential_vault.encrypt(
            {"username": "alice", "password": "NEW_PASSWORD"}
        )
        db_session.flush()
        second = asyncio.run(
            session_broker.get_or_create_session(db_session, test_org.id, test_profile.id)
        )

    assert first.cookie_header == "sid=v1"
    assert second.cookie_header == "sid=v2"
    assert mock_flow.await_count == 2


def test_expired_session_triggers_relogin(db_session, test_org, test_profile):
    expired_bundle = session_broker.SessionBundle(
        cookie_header="old", headers={},
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )
    test_profile.cached_session_blob = credential_vault.encrypt(expired_bundle.to_dict())
    test_profile.session_expires_at = expired_bundle.expires_at
    test_profile.session_credential_hash = "stale"
    db_session.flush()

    fresh_bundle = session_broker.SessionBundle(
        cookie_header="fresh", headers={},
        expires_at=datetime.utcnow() + timedelta(seconds=900),
    )
    with patch.object(session_broker, "_run_login_flow", new=AsyncMock(return_value=fresh_bundle)) as mock_flow:
        bundle = asyncio.run(
            session_broker.get_or_create_session(db_session, test_org.id, test_profile.id)
        )

    assert bundle.cookie_header == "fresh"
    mock_flow.assert_awaited_once()


def test_invalidate_clears_cache(db_session, test_profile):
    test_profile.cached_session_blob = "xxx"
    test_profile.session_expires_at = datetime.utcnow() + timedelta(hours=1)
    test_profile.session_credential_hash = "hash"
    db_session.flush()

    session_broker.invalidate(db_session, test_profile.id)
    db_session.refresh(test_profile)
    assert test_profile.cached_session_blob is None
    assert test_profile.session_expires_at is None
    assert test_profile.session_credential_hash is None


def test_missing_profile_raises(db_session, test_org):
    with pytest.raises(session_broker.SessionBrokerError):
        asyncio.run(session_broker.get_or_create_session(db_session, test_org.id, "does-not-exist"))


def test_test_login_redacts_values(db_session, test_org, test_profile):
    bundle = session_broker.SessionBundle(
        cookie_header="session=abc123; csrf=xyz",
        headers={"X-CSRF-Token": "tok"},
        expires_at=datetime.utcnow() + timedelta(seconds=900),
    )
    with patch.object(session_broker, "_run_login_flow", new=AsyncMock(return_value=bundle)):
        result = asyncio.run(session_broker.test_login(db_session, test_org.id, test_profile.id))

    assert result["success"] is True
    assert result["captured_cookies"] == ["session", "csrf"]
    assert result["captured_headers"] == ["X-CSRF-Token"]
    dumped = str(result)
    assert "abc123" not in dumped
    assert "xyz" not in dumped
    assert "tok" not in dumped


def test_test_login_reports_failure(db_session, test_org, test_profile):
    with patch.object(session_broker, "_run_login_flow",
                      new=AsyncMock(side_effect=session_broker.SessionBrokerError("login selector not found"))):
        result = asyncio.run(session_broker.test_login(db_session, test_org.id, test_profile.id))

    assert result["success"] is False
    assert "login selector not found" in result["error"]


# ─────────────────────────────────────────────
# Step executor
# ─────────────────────────────────────────────

def test_execute_step_fill_resolves_value_from():
    page = MagicMock()
    page.fill = AsyncMock()
    asyncio.run(session_broker._execute_step(
        page, {"action": "fill", "selector": "#pw", "value_from": "password"},
        {"username": "alice", "password": "s3cret"},
    ))
    page.fill.assert_awaited_once_with("#pw", "s3cret", timeout=session_broker._DEFAULT_STEP_TIMEOUT_MS)


def test_execute_step_unknown_action_raises():
    page = MagicMock()
    with pytest.raises(session_broker.SessionBrokerError):
        asyncio.run(session_broker._execute_step(page, {"action": "teleport"}, {}))


def test_assert_success_url_matches_passes_at_target_url():
    page = MagicMock()
    page.url = "https://app.example.com/dashboard"
    page.wait_for_url = AsyncMock()
    asyncio.run(session_broker._assert_success(page, {"type": "url_matches", "pattern": "/dashboard"}))
    page.wait_for_url.assert_not_awaited()


def test_assert_success_cookie_present_fails_when_missing():
    page = MagicMock()
    page.context.cookies = AsyncMock(return_value=[{"name": "other", "value": "1"}])
    with pytest.raises(session_broker.SessionBrokerError):
        asyncio.run(session_broker._assert_success(page, {"type": "cookie_present", "name": "session"}))


def test_assert_success_empty_condition_passes():
    page = MagicMock()
    asyncio.run(session_broker._assert_success(page, {}))


def test_hash_credential_excludes_internal_fields():
    """`_auth_type` / `instance_url` shouldn't affect the hash — they're
    decorator fields added by credential_manager, not part of the login flow
    input. Otherwise, merely calling load_credentials would falsely invalidate."""
    a = session_broker._hash_credential({"username": "x", "password": "y", "_auth_type": "basic"})
    b = session_broker._hash_credential({"username": "x", "password": "y", "_auth_type": "bearer", "instance_url": "whatever"})
    assert a == b

    c = session_broker._hash_credential({"username": "x", "password": "DIFFERENT"})
    assert a != c
