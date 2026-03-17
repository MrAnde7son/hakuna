"""Tests for the VM Scanner API endpoints."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from scanner.vm.api import create_app


@pytest.fixture
def client():
    """Create a test client for the VM scanner API."""
    app = create_app()
    return TestClient(app)


class TestHealthEndpoint:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "vm-scanner"


class TestCreateScan:
    def test_requires_asset_ids_or_scan_all(self, client):
        resp = client.post("/vm/scans/", json={})
        assert resp.status_code == 400

    @patch("scanner.vm.api.run_nuclei_scan")
    def test_scan_specific_assets(self, mock_task, client):
        mock_result = MagicMock()
        mock_result.id = "job-123"
        mock_task.apply_async.return_value = mock_result

        resp = client.post("/vm/scans/", json={
            "asset_ids": ["asset-1", "asset-2"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["assets_queued"] == 2
        assert len(data["job_ids"]) == 2
        assert mock_task.apply_async.call_count == 2

    @patch("scanner.vm.api.run_nuclei_scan")
    def test_scan_all(self, mock_task, client):
        import uuid

        assets = [
            {"id": uuid.uuid4()},
            {"id": uuid.uuid4()},
            {"id": uuid.uuid4()},
        ]
        mock_result = MagicMock()
        mock_result.id = "job-456"
        mock_task.apply_async.return_value = mock_result

        # Mock the async fetch_alive_assets which is called via _run_async
        with patch("scanner.vm.nuclei_worker._run_async", return_value=assets):
            resp = client.post("/vm/scans/", json={"scan_all": True})

        assert resp.status_code == 200
        data = resp.json()
        assert data["assets_queued"] == 3
        assert len(data["job_ids"]) == 3


class TestGetScanStatus:
    @patch("scanner.vm.api.run_nuclei_scan")
    def test_get_pending_job(self, mock_task, client):
        mock_result = MagicMock()
        mock_result.status = "PENDING"
        mock_result.ready.return_value = False
        mock_task.AsyncResult.return_value = mock_result

        resp = client.get("/vm/scans/job-123")
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == "job-123"
        assert data["status"] == "PENDING"
        assert data["result"] is None

    @patch("scanner.vm.api.run_nuclei_scan")
    def test_get_completed_job(self, mock_task, client):
        mock_result = MagicMock()
        mock_result.status = "SUCCESS"
        mock_result.ready.return_value = True
        mock_result.result = {
            "asset_id": "abc",
            "findings_emitted": 5,
            "templates_run": 10,
            "duration_seconds": 42.3,
            "status": "complete",
        }
        mock_task.AsyncResult.return_value = mock_result

        resp = client.get("/vm/scans/job-123")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["result"]["findings_emitted"] == 5


class TestListCustomTemplates:
    def test_list_templates(self, client, tmp_path):
        import yaml

        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        template = {
            "id": "test-list",
            "info": {
                "name": "Test List Template",
                "severity": "low",
                "tags": "http,test",
                "metadata": {"source": "custom"},
            },
        }
        (custom_dir / "test.yaml").write_text(yaml.dump(template))

        with patch("scanner.vm.api.TEMPLATES_DIR", str(tmp_path)):
            resp = client.get("/vm/templates/custom")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "Test List Template"
        assert data[0]["source"] == "custom"

    def test_list_templates_empty_dir(self, client, tmp_path):
        with patch("scanner.vm.api.TEMPLATES_DIR", str(tmp_path)):
            resp = client.get("/vm/templates/custom")
        assert resp.status_code == 200
        assert resp.json() == []


class TestValidateTemplate:
    def test_non_yaml_rejected(self, client):
        from io import BytesIO
        resp = client.post("/vm/templates/validate", files={
            "file": ("test.txt", BytesIO(b"hello"), "text/plain"),
        })
        assert resp.status_code == 400
