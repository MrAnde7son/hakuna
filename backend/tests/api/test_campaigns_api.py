"""API tests for campaign endpoints."""
import pytest


class TestListCampaigns:
    def test_list_campaigns(self, authed_client, test_campaign):
        resp = authed_client.get("/api/campaigns")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_list_campaigns_unauthenticated(self, client):
        resp = client.get("/api/campaigns")
        assert resp.status_code == 401


class TestCreateCampaign:
    def test_create_campaign(self, authed_client, test_findings):
        resp = authed_client.post("/api/campaigns", json={
            "name": "New Campaign",
            "description": "A new remediation campaign",
        })
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert data["name"] == "New Campaign"

    def test_create_campaign_missing_name(self, authed_client):
        resp = authed_client.post("/api/campaigns", json={
            "description": "No name",
        })
        assert resp.status_code == 422


class TestCampaignDetail:
    def test_get_campaign(self, authed_client, test_campaign):
        resp = authed_client.get(f"/api/campaigns/{test_campaign.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Test Campaign"

    def test_get_campaign_not_found(self, authed_client):
        resp = authed_client.get("/api/campaigns/99999")
        assert resp.status_code == 404


class TestUpdateCampaign:
    def test_update_campaign(self, authed_client, test_campaign):
        resp = authed_client.patch(f"/api/campaigns/{test_campaign.id}", json={
            "name": "Updated Campaign",
            "status": "completed",
        })
        assert resp.status_code == 200

    def test_update_campaign_not_found(self, authed_client):
        resp = authed_client.patch("/api/campaigns/99999", json={
            "name": "Nope",
        })
        assert resp.status_code == 404


class TestDeleteCampaign:
    def test_delete_campaign(self, authed_client, test_campaign):
        resp = authed_client.delete(f"/api/campaigns/{test_campaign.id}")
        assert resp.status_code == 200

    def test_delete_campaign_not_found(self, authed_client):
        resp = authed_client.delete("/api/campaigns/99999")
        assert resp.status_code == 404


class TestCampaignTenantIsolation:
    def test_campaign_tenant_isolation(self, client, db_session, test_campaign):
        """Campaign from org A should not be visible to org B."""
        from models.models import Organization
        from tests.conftest import make_auth_headers, create_user

        org_b = Organization(name="Org B Camp", slug="org-b-camp")
        db_session.add(org_b)
        db_session.flush()
        user_b = create_user(db_session, org_b, email="campb@org.com", role="org_admin")
        headers = make_auth_headers(user_b, org_b)

        resp = client.get(f"/api/campaigns/{test_campaign.id}", headers=headers)
        assert resp.status_code in (403, 404)

    def test_campaign_preview_does_not_leak_other_org_assets(self, client, db_session, test_assets):
        """Campaign preview in org B must not return assets from org A."""
        from models.models import Organization, Scan, Asset, Finding
        from tests.conftest import make_auth_headers, create_user, _set_org_id

        org_b = Organization(name="Org B Preview", slug="org-b-preview")
        db_session.add(org_b)
        db_session.flush()
        scan_b = Scan(org_id=org_b.id, filename="b.nessus", status="completed")
        db_session.add(scan_b)
        db_session.flush()
        asset_b = Asset(scan_id=scan_b.id, ip="10.99.0.1", hostname="org-b-host", os="Linux")
        db_session.add(asset_b)
        db_session.flush()
        _set_org_id(db_session, "assets", asset_b.id, org_b.id)
        db_session.flush()

        user_b = create_user(db_session, org_b, email="prevb@org.com", role="org_admin")
        headers = make_auth_headers(user_b, org_b)

        resp = client.post(
            "/api/campaigns/preview",
            headers=headers,
            json={"name": "probe", "query": [{"field": "os", "op": "contains", "value": "Linux"}], "query_logic": "AND"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        returned_ips = {a["ip"] for a in data.get("assets", [])}
        # Only org B's asset must appear — none of org A's test_assets (10.0.0.x).
        assert returned_ips == {"10.99.0.1"}
        for a in test_assets:
            assert a.ip not in returned_ips
