"""API tests for RBAC permission enforcement across roles."""
import pytest
from tests.conftest import create_user, make_auth_headers


class TestRoleBasedAccess:
    """Verify that different roles have correct access levels."""

    def test_viewer_can_read_findings(self, client, db_session, test_org, test_findings):
        viewer = create_user(db_session, test_org, email="rbac-viewer@test.com", role="viewer")
        headers = make_auth_headers(viewer, test_org)
        resp = client.get("/api/findings", headers=headers)
        assert resp.status_code == 200

    def test_viewer_can_read_assets(self, client, db_session, test_org, test_assets):
        viewer = create_user(db_session, test_org, email="rbac-viewer2@test.com", role="viewer")
        headers = make_auth_headers(viewer, test_org)
        resp = client.get("/api/assets", headers=headers)
        assert resp.status_code == 200

    def test_viewer_cannot_upload(self, client, db_session, test_org):
        viewer = create_user(db_session, test_org, email="rbac-viewer3@test.com", role="viewer")
        headers = make_auth_headers(viewer, test_org)
        resp = client.post("/api/upload", headers=headers)
        assert resp.status_code in (403, 400, 422)

    def test_viewer_cannot_manage_users(self, client, db_session, test_org):
        viewer = create_user(db_session, test_org, email="rbac-viewer4@test.com", role="viewer")
        headers = make_auth_headers(viewer, test_org)
        resp = client.post("/api/auth/invite", json={
            "email": "hack@test.com",
            "role": "org_admin",
            "password": "pass123!",
        }, headers=headers)
        assert resp.status_code == 403

    def test_analyst_can_read_and_write_findings(self, client, db_session, test_org, test_findings):
        analyst = create_user(db_session, test_org, email="rbac-analyst@test.com", role="analyst")
        headers = make_auth_headers(analyst, test_org)
        # Read
        resp = client.get("/api/findings", headers=headers)
        assert resp.status_code == 200
        # Create campaign (write action)
        resp = client.post("/api/campaigns", json={
            "name": "Analyst Campaign",
            "description": "Created by analyst",
        }, headers=headers)
        assert resp.status_code in (200, 201)

    def test_analyst_cannot_manage_users(self, client, db_session, test_org):
        analyst = create_user(db_session, test_org, email="rbac-analyst2@test.com", role="analyst")
        headers = make_auth_headers(analyst, test_org)
        resp = client.post("/api/auth/invite", json={
            "email": "hack2@test.com",
            "role": "analyst",
            "password": "pass123!",
        }, headers=headers)
        assert resp.status_code == 403

    def test_org_admin_can_manage_users(self, authed_client):
        resp = authed_client.get("/api/auth/users")
        assert resp.status_code == 200

    def test_unauthenticated_gets_401(self, client):
        endpoints = [
            "/api/findings",
            "/api/assets",
            "/api/campaigns",
            "/api/scans",
            "/api/auth/users",
        ]
        for endpoint in endpoints:
            resp = client.get(endpoint)
            assert resp.status_code == 401, f"Expected 401 for {endpoint}, got {resp.status_code}"
