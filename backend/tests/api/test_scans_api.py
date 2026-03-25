"""API tests for scan endpoints."""
import pytest


class TestListScans:
    def test_list_scans(self, authed_client, test_scan):
        resp = authed_client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, (list, dict))

    def test_list_scans_unauthenticated(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 401


class TestScanDetail:
    def test_get_scan(self, authed_client, test_scan):
        resp = authed_client.get(f"/api/scans/{test_scan.id}")
        assert resp.status_code == 200

    def test_get_scan_not_found(self, authed_client):
        resp = authed_client.get("/api/scans/99999")
        assert resp.status_code == 404


class TestDeleteScan:
    def test_delete_scan(self, authed_client, test_scan):
        resp = authed_client.delete(f"/api/scans/{test_scan.id}")
        assert resp.status_code == 200

    def test_delete_scan_not_found(self, authed_client):
        resp = authed_client.delete("/api/scans/99999")
        assert resp.status_code == 404


class TestUploadScan:
    def test_upload_no_file(self, authed_client):
        resp = authed_client.post("/api/upload")
        assert resp.status_code in (400, 422)
