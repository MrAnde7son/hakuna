"""API tests for asset endpoints."""
import pytest


class TestListAssets:
    def test_list_assets(self, authed_client, test_assets):
        resp = authed_client.get("/api/assets")
        assert resp.status_code == 200
        data = resp.json()
        assert "assets" in data or "items" in data or isinstance(data, list)

    def test_list_assets_unauthenticated(self, client):
        resp = client.get("/api/assets")
        assert resp.status_code == 401

    def test_list_assets_pagination(self, authed_client, test_assets):
        resp = authed_client.get("/api/assets?page=1&page_size=2")
        assert resp.status_code == 200

    def test_list_assets_search(self, authed_client, test_assets):
        resp = authed_client.get("/api/assets?search=host-1")
        assert resp.status_code == 200

    def test_list_assets_sort(self, authed_client, test_assets):
        resp = authed_client.get("/api/assets?sort_by=ip&order=asc")
        assert resp.status_code == 200

    def test_list_assets_ids_only(self, authed_client, test_assets):
        """ids_only=true returns IDs only — used by Select All Matching."""
        resp = authed_client.get("/api/assets?ids_only=true")
        assert resp.status_code == 200
        data = resp.json()
        assert "ids" in data
        assert "assets" not in data
        assert data["total"] == len(data["ids"])
        assert data["capped"] is False

    def test_list_assets_ids_filter(self, authed_client, test_assets):
        """ids=1,2,3 filter narrows the result set to that explicit list."""
        wanted = [a.id for a in test_assets[:2]]
        resp = authed_client.get(f"/api/assets?ids={','.join(str(i) for i in wanted)}")
        assert resp.status_code == 200
        returned = {a["id"] for a in resp.json()["assets"]}
        assert returned == set(wanted)


class TestAssetDetail:
    def test_get_asset(self, authed_client, test_assets):
        asset = test_assets[0]
        resp = authed_client.get(f"/api/assets/{asset.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ip"] == asset.ip

    def test_get_asset_not_found(self, authed_client):
        resp = authed_client.get("/api/assets/99999")
        assert resp.status_code == 404


class TestUpdateAsset:
    def test_update_asset(self, authed_client, test_assets):
        asset = test_assets[0]
        resp = authed_client.patch(f"/api/assets/{asset.id}", json={
            "hostname": "updated-hostname",
        })
        assert resp.status_code == 200

    def test_update_asset_not_found(self, authed_client):
        resp = authed_client.patch("/api/assets/99999", json={"hostname": "x"})
        assert resp.status_code == 404


class TestAssetTenantIsolation:
    def test_cannot_see_other_org_assets(self, client, db_session, test_assets):
        """Assets from org A should not be visible to org B."""
        from models.models import Organization, User
        from tests.conftest import make_auth_headers, create_user

        org_b = Organization(name="Other Org", slug="other-org")
        db_session.add(org_b)
        db_session.flush()
        user_b = create_user(db_session, org_b, email="other@org.com", role="org_admin")
        headers = make_auth_headers(user_b, org_b)

        resp = client.get("/api/assets", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        items = data.get("assets", data.get("items", data)) if isinstance(data, dict) else data
        # org_b should see zero assets (they belong to org_a)
        assert len(items) == 0
