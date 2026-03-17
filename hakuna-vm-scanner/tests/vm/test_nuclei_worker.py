"""Tests for the Nuclei worker — finding parsing, target resolution, CPE extraction."""

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scanner.vm.nuclei_worker import _emit_finding, _extract_cpe_list, _resolve_target


class TestResolveTarget:
    """Tests for _resolve_target helper."""

    def test_prefers_http_url(self):
        asset = {"http_url": "https://example.com", "hostname": "example.com", "ip": "1.2.3.4"}
        assert _resolve_target(asset) == "https://example.com"

    def test_falls_back_to_hostname(self):
        asset = {"http_url": None, "hostname": "example.com", "ip": "1.2.3.4"}
        assert _resolve_target(asset) == "example.com"

    def test_falls_back_to_ip(self):
        asset = {"http_url": None, "hostname": None, "ip": "1.2.3.4"}
        assert _resolve_target(asset) == "1.2.3.4"

    def test_empty_returns_empty_string(self):
        asset = {"http_url": None, "hostname": None, "ip": None}
        assert _resolve_target(asset) == ""


class TestExtractCpeList:
    """Tests for _extract_cpe_list helper."""

    def test_list_of_strings(self):
        result = _extract_cpe_list(["cpe:2.3:a:apache:http_server:2.4:*", "cpe:2.3:a:php:php:8.0:*"])
        assert result == ["cpe:2.3:a:apache:http_server:2.4:*", "cpe:2.3:a:php:php:8.0:*"]

    def test_none_returns_none(self):
        assert _extract_cpe_list(None) is None

    def test_empty_list_returns_none(self):
        assert _extract_cpe_list([]) is None

    def test_dict_returns_values(self):
        result = _extract_cpe_list({"0": "cpe:2.3:a:apache:http_server:2.4:*"})
        assert result == ["cpe:2.3:a:apache:http_server:2.4:*"]

    def test_empty_dict_returns_none(self):
        assert _extract_cpe_list({}) is None


class TestEmitFinding:
    """Tests for _emit_finding — finding parsing and DB insert."""

    @pytest.fixture
    def nuclei_result(self):
        """A sample Nuclei JSONL output line."""
        return {
            "template-id": "apache-detect",
            "info": {
                "name": "Apache HTTP Server Detection",
                "severity": "info",
                "description": "Detects Apache HTTP Server.",
                "tags": ["apache", "http", "detect"],
                "reference": ["https://httpd.apache.org/"],
                "classification": {
                    "cve-id": None,
                    "cwe-id": None,
                },
                "metadata": {
                    "verified": True,
                },
            },
            "matched-at": "https://example.com/",
            "matcher-name": "version",
            "host": "example.com",
            "port": "80",
            "type": "http",
            "extracted-results": ["Apache/2.4.51"],
        }

    @pytest.mark.asyncio
    async def test_emit_finding_parses_correctly(self, nuclei_result):
        """Verify finding metadata is correctly extracted from Nuclei output."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)  # No existing finding
        conn.execute = AsyncMock()

        org_id = uuid.uuid4()
        asset_id = uuid.uuid4()

        result = await _emit_finding(conn, org_id, asset_id, nuclei_result)
        assert result is True

        # Verify dedup check was called
        conn.fetchrow.assert_called_once()

        # Verify INSERT was called (not UPDATE, since no existing finding)
        conn.execute.assert_called_once()
        call_args = conn.execute.call_args
        args = call_args[0]

        # args: (query, id, org_id, asset_id, finding_type, severity, title, description, metadata_json)
        assert args[3] == asset_id        # asset_id
        assert args[4] == "nuclei"        # finding_type
        assert args[5] == "info"          # severity
        assert args[6] == "Apache HTTP Server Detection"  # title

        metadata = json.loads(args[8])
        assert metadata["scan_source"] == "nuclei"
        assert metadata["template_id"] == "apache-detect"
        assert metadata["matched_at"] == "https://example.com/"

    @pytest.mark.asyncio
    async def test_emit_finding_normalizes_severity(self):
        """Invalid severity values are normalized to 'info'."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        conn.execute = AsyncMock()

        result_data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "UNKNOWN"},
        }

        await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), result_data)
        call_args = conn.execute.call_args[0]
        assert call_args[5] == "info"  # severity normalized

    @pytest.mark.asyncio
    async def test_emit_finding_handles_db_error(self):
        """DB errors are caught and False is returned."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(side_effect=Exception("DB error"))

        result = await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), {
            "template-id": "test",
            "info": {"name": "Test", "severity": "high"},
        })
        assert result is False

    @pytest.mark.asyncio
    async def test_emit_finding_high_severity(self, nuclei_result):
        """High severity findings are correctly classified."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        conn.execute = AsyncMock()

        nuclei_result["info"]["severity"] = "high"
        await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), nuclei_result)

        call_args = conn.execute.call_args[0]
        assert call_args[5] == "high"
