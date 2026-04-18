"""API tests for /api/inventory/api-endpoints — the proxy that surfaces
scanner-side `asset_endpoints` rows (katana/kiterunner/openapi/graphql/llm_js)
as an inventory tab.

Covers three branches of the route's scope resolution:
  1. asset_id filter on a non-EASM asset → short-circuits to empty result
  2. scan_id filter where no assets carry easm_data → empty
  3. proxy call reaches the scanner (mocked) and shape is re-keyed
"""
from unittest.mock import patch

import pytest


class TestApiEndpointsInventory:
    def test_unauthenticated_rejected(self, client):
        resp = client.get("/api/inventory/api-endpoints")
        assert resp.status_code == 401

    def test_asset_without_easm_returns_empty(
        self, authed_client, test_assets,
    ):
        """A backend asset that has no easm_data has no API endpoints to show."""
        asset = test_assets[0]
        resp = authed_client.get(f"/api/inventory/api-endpoints?asset_id={asset.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["api_endpoints"] == []

    def test_asset_not_found(self, authed_client):
        resp = authed_client.get("/api/inventory/api-endpoints?asset_id=99999")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["api_endpoints"] == []

    def test_scan_without_easm_assets_returns_empty(
        self, authed_client, test_scan,
    ):
        """A scan whose assets have no easm_data shouldn't hit the scanner."""
        with patch("services.easm.get_easm_endpoints") as mock_ep:
            resp = authed_client.get(f"/api/inventory/api-endpoints?scan_id={test_scan.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        # Scanner should never be called when no EASM assets exist in the scan
        mock_ep.assert_not_called()

    def test_proxy_rekeys_to_backend_asset(
        self, authed_client, db_session, test_org, test_scan, test_assets,
    ):
        """When an asset carries easm_data.easm_asset_id and the org has
        easm_org_id, the route proxies to the scanner and re-keys the
        response with backend asset IDs + hostnames."""
        from models.models import Organization

        # Wire the scanner-side IDs onto the test fixtures.
        asset = test_assets[0]
        asset.easm_data = {"easm_asset_id": "00000000-0000-0000-0000-000000000001"}

        org = db_session.query(Organization).filter(Organization.id == test_org.id).first()
        org.easm_org_id = "00000000-0000-0000-0000-000000000002"
        db_session.commit()

        scanner_response = {
            "total": 1,
            "limit": 100,
            "offset": 0,
            "endpoints": [{
                "id": "00000000-0000-0000-0000-000000000abc",
                "asset_id": "00000000-0000-0000-0000-000000000001",
                "asset_hostname": "scanner-host.example.com",
                "url": "https://api.example.com/v1/users",
                "path": "/v1/users",
                "method": "GET",
                "source": "kiterunner",
                "status_code": 200,
                "auth_required": True,
                "content_type": "application/json",
                "is_auth_page": False,
                "parameters": None,
                "discovered_at": "2026-04-10T12:00:00Z",
            }],
        }

        with patch("services.easm.get_easm_endpoints", return_value=scanner_response):
            resp = authed_client.get(f"/api/inventory/api-endpoints?asset_id={asset.id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["api_endpoints"]) == 1
        ep = data["api_endpoints"][0]
        # Critical rekey: scanner UUID → backend integer id
        assert ep["asset_id"] == asset.id
        # asset_label uses backend fqdn/hostname, not the scanner hostname
        assert ep["asset_label"] == (asset.fqdn or asset.hostname or asset.ip)
        # Passthrough fields
        assert ep["path"] == "/v1/users"
        assert ep["method"] == "GET"
        assert ep["source"] == "kiterunner"
        assert ep["status_code"] == 200
        assert ep["auth_required"] is True
