"""Tests for ApiTransport and FileTransport."""

import json
import os
import pytest
import asyncio

# ═══════════════════════════════════════════════════════════
# ApiTransport — template substitution and pagination
# ═══════════════════════════════════════════════════════════

class TestApiTransportSubstitution:
    def test_substitute_simple(self):
        from services.transports.api_transport import _substitute
        result = _substitute("{{params.offset}}", {"params": {"offset": "100"}})
        assert result == "100"

    def test_substitute_nested(self):
        from services.transports.api_transport import _substitute
        result = _substitute(
            {"header": "Bearer {{credentials.token}}", "path": "/api/{{params.version}}"},
            {"credentials": {"token": "abc"}, "params": {"version": "v2"}}
        )
        assert result["header"] == "Bearer abc"
        assert result["path"] == "/api/v2"

    def test_substitute_missing_key(self):
        from services.transports.api_transport import _substitute
        result = _substitute("{{params.missing}}", {"params": {}})
        assert result == ""

    def test_substitute_list(self):
        from services.transports.api_transport import _substitute
        result = _substitute(["{{params.a}}", "static"], {"params": {"a": "1"}})
        assert result == ["1", "static"]


class TestApiTransportDotPath:
    def test_resolve_simple(self):
        from services.transports.api_transport import _resolve_dot_path
        obj = {"response": {"results": [1, 2, 3]}}
        assert _resolve_dot_path(obj, "response.results") == [1, 2, 3]

    def test_resolve_none_on_missing(self):
        from services.transports.api_transport import _resolve_dot_path
        assert _resolve_dot_path({"a": 1}, "b.c") is None

    def test_resolve_empty_path(self):
        from services.transports.api_transport import _resolve_dot_path
        obj = {"a": 1}
        assert _resolve_dot_path(obj, "") == obj


class TestDetectRecordsPath:
    def test_detect_nested_array(self):
        from services.transports.api_transport import _detect_records_path
        obj = {"meta": {"count": 3}, "response": {"results": [{"id": 1}, {"id": 2}]}}
        assert _detect_records_path(obj) == "response.results"

    def test_detect_top_level_array(self):
        from services.transports.api_transport import _detect_records_path
        obj = {"items": [{"id": 1}], "count": 1}
        assert _detect_records_path(obj) == "items"

    def test_prefers_largest_array(self):
        from services.transports.api_transport import _detect_records_path
        obj = {"small": [{"a": 1}], "large": [{"b": 1}, {"b": 2}, {"b": 3}]}
        assert _detect_records_path(obj) == "large"


class TestAuthInjection:
    def test_bearer_auth(self):
        from services.transports.api_transport import _inject_auth
        headers = {}
        _inject_auth(headers, {"_auth_type": "bearer", "access_token": "tok123"})
        assert headers["Authorization"] == "Bearer tok123"

    def test_basic_auth(self):
        from services.transports.api_transport import _inject_auth
        import base64
        headers = {}
        _inject_auth(headers, {"_auth_type": "basic", "username": "user", "password": "pass"})
        expected = "Basic " + base64.b64encode(b"user:pass").decode()
        assert headers["Authorization"] == expected

    def test_api_key_header(self):
        from services.transports.api_transport import _inject_auth
        headers = {}
        _inject_auth(headers, {"_auth_type": "api_key", "header_name": "X-Api-Key", "api_key": "key123"})
        assert headers["X-Api-Key"] == "key123"


# ═══════════════════════════════════════════════════════════
# FileTransport
# ═══════════════════════════════════════════════════════════

class TestFileTransport:
    def test_parse_csv(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("ip,hostname,severity\n10.0.0.1,srv1,high\n10.0.0.2,srv2,low\n")

        from services.transports.file_transport import FileTransport
        transport = FileTransport()
        result = asyncio.get_event_loop().run_until_complete(
            transport.connect({"path": str(csv_file), "format": "csv"}, {})
        )
        assert result.success
        assert len(result.sample_records) == 2
        assert result.sample_records[0]["ip"] == "10.0.0.1"

    def test_parse_json_array(self, tmp_path):
        json_file = tmp_path / "data.json"
        json_file.write_text(json.dumps([{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]))

        from services.transports.file_transport import FileTransport
        transport = FileTransport()
        result = asyncio.get_event_loop().run_until_complete(
            transport.connect({"path": str(json_file), "format": "json"}, {})
        )
        assert result.success
        assert len(result.sample_records) == 2

    def test_parse_json_object(self, tmp_path):
        json_file = tmp_path / "data.json"
        json_file.write_text(json.dumps({"results": [{"id": 1}], "total": 1}))

        from services.transports.file_transport import FileTransport
        transport = FileTransport()
        result = asyncio.get_event_loop().run_until_complete(
            transport.connect({"path": str(json_file), "format": "json"}, {})
        )
        assert result.success
        assert len(result.sample_records) == 1

    def test_auto_detect_csv(self, tmp_path):
        csv_file = tmp_path / "report.csv"
        csv_file.write_text("a,b\n1,2\n")

        from services.transports.file_transport import FileTransport
        transport = FileTransport()
        result = asyncio.get_event_loop().run_until_complete(
            transport.connect({"path": str(csv_file), "format": "auto"}, {})
        )
        assert result.success

    def test_missing_file(self):
        from services.transports.file_transport import FileTransport
        transport = FileTransport()
        result = asyncio.get_event_loop().run_until_complete(
            transport.connect({"path": "/nonexistent.json", "format": "json"}, {})
        )
        assert not result.success
        assert "error" in result.error.lower() or "no such file" in result.error.lower()

    def test_fetch_all_yields_records(self, tmp_path):
        json_file = tmp_path / "data.json"
        json_file.write_text(json.dumps([{"id": i} for i in range(5)]))

        from services.transports.file_transport import FileTransport
        transport = FileTransport()

        async def collect():
            records = []
            async for r in transport.fetch_all({"path": str(json_file), "format": "json"}, {}):
                records.append(r)
            return records

        records = asyncio.get_event_loop().run_until_complete(collect())
        assert len(records) == 5
