"""API tests for authentication & user management endpoints."""
import pytest
from tests.conftest import create_user, make_auth_headers


class TestRegister:
    def test_register_success(self, client):
        resp = client.post("/api/auth/register", json={
            "org_name": "New Corp",
            "email": "newuser@corp.com",
            "password": "securePass123!",
            "display_name": "New User",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["email"] == "newuser@corp.com"

    def test_register_duplicate_email(self, client, test_user):
        resp = client.post("/api/auth/register", json={
            "org_name": "Another Corp",
            "email": test_user.email,
            "password": "securePass123!",
        })
        assert resp.status_code in (400, 409)

    def test_register_missing_fields(self, client):
        resp = client.post("/api/auth/register", json={"email": "x@y.com"})
        assert resp.status_code == 422


class TestLogin:
    def test_login_success(self, client, test_user):
        resp = client.post("/api/auth/login", json={
            "email": "admin@test.com",
            "password": "testpass123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["id"] == test_user.id

    def test_login_wrong_password(self, client, test_user):
        resp = client.post("/api/auth/login", json={
            "email": "admin@test.com",
            "password": "wrongpass",
        })
        assert resp.status_code == 401

    def test_login_nonexistent_email(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "nobody@test.com",
            "password": "whatever",
        })
        assert resp.status_code == 401


class TestMe:
    def test_get_me_authenticated(self, authed_client, test_user):
        resp = authed_client.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("user", data).get("email") == test_user.email

    def test_get_me_unauthenticated(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401


class TestInviteUser:
    def test_invite_user_as_admin(self, authed_client, test_org, db_session):
        resp = authed_client.post("/api/auth/invite", json={
            "email": "invited@test.com",
            "role": "analyst",
            "password": "invitedPass123!",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "invited@test.com"
        assert data["role"] == "analyst"

    def test_invite_user_as_viewer_forbidden(self, client, db_session, test_org):
        viewer = create_user(db_session, test_org, email="viewer@test.com", role="viewer")
        headers = make_auth_headers(viewer, test_org)
        resp = client.post("/api/auth/invite", json={
            "email": "someone@test.com",
            "role": "analyst",
            "password": "pass123!",
        }, headers=headers)
        assert resp.status_code == 403

    def test_invite_duplicate_email(self, authed_client, test_user):
        resp = authed_client.post("/api/auth/invite", json={
            "email": test_user.email,
            "role": "analyst",
            "password": "pass123!",
        })
        assert resp.status_code in (400, 409)


class TestChangePassword:
    def test_change_password_success(self, authed_client):
        resp = authed_client.post("/api/auth/change-password", json={
            "current_password": "testpass123",
            "new_password": "newSecurePass456!",
        })
        assert resp.status_code == 200

    def test_change_password_wrong_current(self, authed_client):
        resp = authed_client.post("/api/auth/change-password", json={
            "current_password": "wrongcurrent",
            "new_password": "newSecurePass456!",
        })
        assert resp.status_code in (400, 401, 403)


class TestListUsers:
    def test_list_users_as_admin(self, authed_client, test_user):
        resp = authed_client.get("/api/auth/users")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_list_users_as_viewer_forbidden(self, client, db_session, test_org):
        viewer = create_user(db_session, test_org, email="viewer2@test.com", role="viewer")
        headers = make_auth_headers(viewer, test_org)
        resp = client.get("/api/auth/users", headers=headers)
        assert resp.status_code == 403
