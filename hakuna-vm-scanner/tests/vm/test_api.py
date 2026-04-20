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

    @patch("scanner.vm.api.fetch_alive_assets")
    @patch("scanner.vm.api.run_nuclei_scan")
    def test_scan_all(self, mock_task, mock_fetch, client):
        import uuid

        assets = [
            {"id": uuid.uuid4()},
            {"id": uuid.uuid4()},
            {"id": uuid.uuid4()},
        ]
        mock_fetch.return_value = assets
        mock_result = MagicMock()
        mock_result.id = "job-456"
        mock_task.apply_async.return_value = mock_result

        resp = client.post("/vm/scans/", json={"scan_all": True})

        assert resp.status_code == 200
        data = resp.json()
        assert data["assets_queued"] == 3
        assert len(data["job_ids"]) == 3


class TestAdhocTargetFanOut:
    """The ad-hoc ``targets`` path must mirror the asset path's fan-out.

    Before this, the backend only ever dispatched via ``targets`` (asset_ids
    don't cross the scanner boundary — different ID types) which meant ffuf
    content discovery and the LLM specialists never ran on anything the
    backend sent over. Each test here locks in that the corresponding
    adhoc worker is now queued alongside nuclei.
    """

    @patch("scanner.vm.api.run_agent_scan_adhoc")
    @patch("scanner.vm.api.run_content_discovery_adhoc")
    @patch("scanner.vm.api.run_nuclei_adhoc")
    def test_web_url_dispatches_content_discovery(self, mock_nuclei, mock_cd, mock_agents, client):
        mock_nuclei.apply_async.return_value = MagicMock(id="nuclei-1")
        mock_cd.apply_async.return_value = MagicMock(id="cd-1")

        with patch("scanner.vm.api.CONTENT_DISCOVERY_ENABLED", True):
            resp = client.post("/vm/scans/", json={
                "targets": ["http://10.0.0.1:8080"],
                "enable_content_discovery": True,
            })

        assert resp.status_code == 200
        data = resp.json()
        assert data["targets_queued"] == 1
        assert set(data["job_ids"]) == {"nuclei-1", "cd-1"}
        mock_nuclei.apply_async.assert_called_once()
        mock_cd.apply_async.assert_called_once()
        mock_agents.apply_async.assert_not_called()

    @patch("scanner.vm.api.run_agent_scan_adhoc")
    @patch("scanner.vm.api.run_content_discovery_adhoc")
    @patch("scanner.vm.api.run_nuclei_adhoc")
    def test_bare_host_skips_content_discovery(self, mock_nuclei, mock_cd, mock_agents, client):
        """ffuf needs a scheme — dispatching for a bare hostname would
        fail at the worker. Only nuclei gets queued."""
        mock_nuclei.apply_async.return_value = MagicMock(id="nuclei-1")

        with patch("scanner.vm.api.CONTENT_DISCOVERY_ENABLED", True):
            resp = client.post("/vm/scans/", json={
                "targets": ["example.com"],
                "enable_content_discovery": True,
            })

        assert resp.status_code == 200
        assert resp.json()["job_ids"] == ["nuclei-1"]
        mock_cd.apply_async.assert_not_called()
        mock_agents.apply_async.assert_not_called()

    @patch("scanner.vm.api.run_agent_scan_adhoc")
    @patch("scanner.vm.api.run_content_discovery_adhoc")
    @patch("scanner.vm.api.run_nuclei_adhoc")
    def test_content_discovery_gated_by_env_flag(self, mock_nuclei, mock_cd, mock_agents, client):
        """The worker-side kill switch (CONTENT_DISCOVERY_ENABLED=false)
        must keep the task from dispatching even when the caller asks
        for it — otherwise the global switch only suppresses execution,
        not dispatch, and the queue still fills up."""
        mock_nuclei.apply_async.return_value = MagicMock(id="nuclei-1")

        with patch("scanner.vm.api.CONTENT_DISCOVERY_ENABLED", False):
            resp = client.post("/vm/scans/", json={
                "targets": ["http://10.0.0.1:8080"],
                "enable_content_discovery": True,
            })

        assert resp.status_code == 200
        assert resp.json()["job_ids"] == ["nuclei-1"]
        mock_cd.apply_async.assert_not_called()

    @patch("scanner.vm.api.run_agent_scan_adhoc")
    @patch("scanner.vm.api.run_content_discovery_adhoc")
    @patch("scanner.vm.api.run_nuclei_adhoc")
    def test_enable_agents_dispatches_adhoc_agents(self, mock_nuclei, mock_cd, mock_agents, client):
        mock_nuclei.apply_async.return_value = MagicMock(id="nuclei-1")
        mock_cd.apply_async.return_value = MagicMock(id="cd-1")
        mock_agents.apply_async.return_value = MagicMock(id="agent-1")

        with patch("scanner.vm.api.CONTENT_DISCOVERY_ENABLED", True):
            resp = client.post("/vm/scans/", json={
                "targets": ["http://10.0.0.1:8080"],
                "enable_agents": True,
                "enable_content_discovery": True,
            })

        assert resp.status_code == 200
        assert set(resp.json()["job_ids"]) == {"nuclei-1", "cd-1", "agent-1"}
        mock_agents.apply_async.assert_called_once()
        call_kwargs = mock_agents.apply_async.call_args.kwargs
        assert call_kwargs["kwargs"]["categories"] is None

    @patch("scanner.vm.api.run_agent_scan_adhoc")
    @patch("scanner.vm.api.run_content_discovery_adhoc")
    @patch("scanner.vm.api.run_nuclei_adhoc")
    def test_agents_not_dispatched_when_flag_off(self, mock_nuclei, mock_cd, mock_agents, client):
        """Agents are opt-in per scan — default False. Regression guard for
        an 'enabled by default' change that would quietly spend LLM tokens
        on every adhoc scan."""
        mock_nuclei.apply_async.return_value = MagicMock(id="nuclei-1")
        mock_cd.apply_async.return_value = MagicMock(id="cd-1")

        with patch("scanner.vm.api.CONTENT_DISCOVERY_ENABLED", True):
            resp = client.post("/vm/scans/", json={
                "targets": ["http://10.0.0.1:8080"],
            })

        assert resp.status_code == 200
        mock_agents.apply_async.assert_not_called()


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


class TestRevokeScan:
    @patch("scanner.vm.celery_app.celery_app")
    def test_revokes_pending_job(self, mock_app, client):
        mock_result = MagicMock()
        mock_result.status = "PENDING"
        mock_app.AsyncResult.return_value = mock_result

        resp = client.delete("/vm/scans/job-abc")
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == "job-abc"
        assert data["revoked"] is True
        assert data["prior_status"] == "PENDING"
        mock_app.control.revoke.assert_called_once_with(
            "job-abc", terminate=True, signal="SIGTERM"
        )

    @patch("scanner.vm.celery_app.celery_app")
    def test_noop_for_terminal_job(self, mock_app, client):
        mock_result = MagicMock()
        mock_result.status = "SUCCESS"
        mock_app.AsyncResult.return_value = mock_result

        resp = client.delete("/vm/scans/job-done")
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked"] is False
        assert data["prior_status"] == "SUCCESS"
        mock_app.control.revoke.assert_not_called()

    @patch("scanner.vm.celery_app.celery_app")
    def test_noop_for_failed_job(self, mock_app, client):
        mock_result = MagicMock()
        mock_result.status = "FAILURE"
        mock_app.AsyncResult.return_value = mock_result

        resp = client.delete("/vm/scans/job-fail")
        assert resp.status_code == 200
        assert resp.json()["revoked"] is False
        mock_app.control.revoke.assert_not_called()


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
