"""Tests for API tokens — CRUD and bearer auth."""
from datetime import datetime, timedelta


def test_create_list_revoke_lifecycle(authed_client, db_session, test_user):
    create = authed_client.post("/api/auth/tokens", json={"name": "claude-desktop", "scopes": ["mcp:read"]})
    assert create.status_code == 200
    body = create.json()
    assert body["token"].startswith("hak_")
    assert body["token_prefix"].startswith("hak_")
    assert body["scopes"] == ["mcp:read"]
    assert body["revoked_at"] is None
    token_id = body["id"]

    listing = authed_client.get("/api/auth/tokens")
    assert listing.status_code == 200
    rows = listing.json()["tokens"]
    assert len(rows) == 1
    assert "token" not in rows[0]  # plaintext never returned again
    assert rows[0]["id"] == token_id

    revoke = authed_client.delete(f"/api/auth/tokens/{token_id}")
    assert revoke.status_code == 200
    assert revoke.json() == {"revoked": True, "id": token_id}

    listing2 = authed_client.get("/api/auth/tokens").json()["tokens"]
    assert listing2[0]["revoked_at"] is not None


def test_create_rejects_unknown_scope(authed_client):
    r = authed_client.post("/api/auth/tokens", json={"name": "x", "scopes": ["mcp:read", "wat"]})
    assert r.status_code == 400


def test_create_requires_at_least_one_scope(authed_client):
    r = authed_client.post("/api/auth/tokens", json={"name": "x", "scopes": []})
    assert r.status_code == 400


def test_create_with_expiry(authed_client):
    r = authed_client.post(
        "/api/auth/tokens",
        json={"name": "ci", "scopes": ["mcp:read"], "expires_in_days": 30},
    )
    assert r.status_code == 200
    expires = datetime.fromisoformat(r.json()["expires_at"])
    delta = expires - datetime.utcnow()
    assert timedelta(days=29) < delta <= timedelta(days=30, minutes=1)


def test_revoke_other_users_token_returns_404(authed_client, db_session, test_org):
    # Mint a token belonging to a different user.
    from tests.conftest import create_user, make_auth_headers
    other = create_user(db_session, test_org, email="other@test.com", role="analyst")
    other_headers = make_auth_headers(other, test_org)
    create = authed_client._client.post(
        "/api/auth/tokens",
        json={"name": "other", "scopes": ["mcp:read"]},
        headers=other_headers,
    )
    assert create.status_code == 200
    other_token_id = create.json()["id"]

    # The default authed_client (test_user) tries to delete it — must 404, not 200/403.
    r = authed_client.delete(f"/api/auth/tokens/{other_token_id}")
    assert r.status_code == 404


def test_api_token_can_authenticate_mcp_endpoint(authed_client, client, test_org):
    create = authed_client.post("/api/auth/tokens", json={"name": "mcp", "scopes": ["mcp:read"]})
    plaintext = create.json()["token"]

    r = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {plaintext}", "X-Org-Context": str(test_org.id)},
    )
    assert r.status_code == 200
    assert {t["name"] for t in r.json()["result"]["tools"]} >= {"list_findings", "get_finding"}


def test_revoked_token_cannot_authenticate(authed_client, client, test_org):
    create = authed_client.post("/api/auth/tokens", json={"name": "rev", "scopes": ["mcp:read"]})
    plaintext = create.json()["token"]
    token_id = create.json()["id"]
    authed_client.delete(f"/api/auth/tokens/{token_id}")

    r = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {plaintext}", "X-Org-Context": str(test_org.id)},
    )
    assert r.status_code == 401


def test_garbage_api_token_is_rejected(client, test_org):
    r = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": "Bearer hak_definitelynotreal", "X-Org-Context": str(test_org.id)},
    )
    assert r.status_code == 401


def test_expired_token_cannot_authenticate(authed_client, client, db_session, test_org):
    create = authed_client.post(
        "/api/auth/tokens",
        json={"name": "soon", "scopes": ["mcp:read"], "expires_in_days": 1},
    )
    plaintext = create.json()["token"]
    token_id = create.json()["id"]

    # Force the row's expires_at into the past.
    from models.models import ApiToken
    row = db_session.query(ApiToken).filter(ApiToken.id == token_id).first()
    row.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db_session.commit()

    r = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {plaintext}", "X-Org-Context": str(test_org.id)},
    )
    assert r.status_code == 401
