"""Tests for the Nuclei worker — finding parsing, target resolution, CPE extraction."""

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scanner.vm.nuclei_worker import (
    _build_dedup_lookup_sql,
    _coerce_port,
    _emit_finding,
    _extract_cpe_list,
    _merge_metadata,
    _resolve_target,
)


# INSERT columns are, in order:
#   $1=id $2=org_id $3=asset_id $4=finding_type $5=severity $6=title
#   $7=description $8=plugin_id $9=port $10=protocol $11=metadata
# conn.execute positional args are (sql, $1, $2, ...) — so args[i] for i>=1 matches $i.
_INSERT_ID = 1
_INSERT_ORG = 2
_INSERT_ASSET = 3
_INSERT_FINDING_TYPE = 4
_INSERT_SEVERITY = 5
_INSERT_TITLE = 6
_INSERT_DESCRIPTION = 7
_INSERT_PLUGIN_ID = 8
_INSERT_PORT = 9
_INSERT_PROTOCOL = 10
_INSERT_METADATA = 11


@pytest.fixture(autouse=True)
def _clear_dedup_cache():
    """Ensure no test leaks a cached rule into the next."""
    from scanner.vm.dedup_config import clear_cache
    clear_cache()
    yield
    clear_cache()


def _rule(enabled=True, key_fields=("plugin_id", "asset_id", "port"), strategy="keep_last"):
    return {
        "enabled": enabled,
        "key_fields": list(key_fields),
        "strategy": strategy,
        "scope": "cross_scan",
    }


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


class TestCoercePort:
    def test_string_int(self):
        assert _coerce_port("80") == 80

    def test_int_passthrough(self):
        assert _coerce_port(443) == 443

    def test_empty_string(self):
        assert _coerce_port("") is None

    def test_none(self):
        assert _coerce_port(None) is None

    def test_garbage(self):
        assert _coerce_port("tcp/80") is None


class TestBuildDedupLookupSql:
    def test_safety_floor_always_applied(self):
        sql, cols = _build_dedup_lookup_sql([])
        assert cols == ["org_id", "asset_id"]
        assert "finding_type = 'nuclei'" in sql
        assert "status = 'open'" in sql

    def test_custom_key_fields(self):
        sql, cols = _build_dedup_lookup_sql(["plugin_id", "asset_id", "port"])
        assert cols == ["org_id", "asset_id", "plugin_id", "port"]

    def test_unsupported_fields_ignored(self):
        sql, cols = _build_dedup_lookup_sql(["plugin_id", "cve", "totally_made_up"])
        assert cols == ["org_id", "asset_id", "plugin_id"]

    def test_no_duplicates_when_key_field_already_in_safety(self):
        sql, cols = _build_dedup_lookup_sql(["org_id", "asset_id", "plugin_id"])
        assert cols == ["org_id", "asset_id", "plugin_id"]


class TestMergeMetadata:
    def test_lists_union(self):
        merged = _merge_metadata({"tags": ["a", "b"]}, {"tags": ["b", "c"]})
        assert merged["tags"] == ["a", "b", "c"]

    def test_nested_dict_merge(self):
        merged = _merge_metadata(
            {"classification": {"cve-id": "CVE-1", "cwe-id": None}},
            {"classification": {"cwe-id": "CWE-79"}},
        )
        assert merged["classification"] == {"cve-id": "CVE-1", "cwe-id": "CWE-79"}

    def test_scalar_keep_last(self):
        merged = _merge_metadata({"severity": "low"}, {"severity": "high"})
        assert merged["severity"] == "high"

    def test_existing_as_json_string(self):
        merged = _merge_metadata('{"tags": ["a"]}', {"tags": ["b"]})
        assert merged["tags"] == ["a", "b"]

    def test_invalid_existing_is_tolerated(self):
        merged = _merge_metadata("not-json", {"tags": ["a"]})
        assert merged == {"tags": ["a"]}


class TestEmitFinding:
    """Tests for _emit_finding — finding parsing, configurable dedup."""

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
                "classification": {"cve-id": None, "cwe-id": None},
            },
            "matched-at": "https://example.com/",
            "matcher-name": "version",
            "host": "example.com",
            "port": "80",
            "type": "http",
            "extracted-results": ["Apache/2.4.51"],
        }

    @pytest.mark.asyncio
    async def test_inserts_with_plugin_port_protocol(self, nuclei_result):
        """Verify new finding insert populates plugin_id, port, protocol columns."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        conn.execute = AsyncMock()

        org_id = uuid.uuid4()
        asset_id = uuid.uuid4()

        with patch("scanner.vm.nuclei_worker.get_findings_rule", AsyncMock(return_value=_rule())):
            result = await _emit_finding(conn, org_id, asset_id, nuclei_result)

        assert result is True
        conn.execute.assert_called_once()
        args = conn.execute.call_args[0]
        assert args[_INSERT_ASSET] == asset_id
        assert args[_INSERT_FINDING_TYPE] == "nuclei"
        assert args[_INSERT_SEVERITY] == "info"
        assert args[_INSERT_TITLE] == "Apache HTTP Server Detection"
        assert args[_INSERT_PLUGIN_ID] == "apache-detect"
        assert args[_INSERT_PORT] == 80
        assert args[_INSERT_PROTOCOL] == "http"

        metadata = json.loads(args[_INSERT_METADATA])
        assert metadata["scan_source"] == "nuclei"
        assert metadata["template_id"] == "apache-detect"

    @pytest.mark.asyncio
    async def test_dedup_disabled_always_inserts(self, nuclei_result):
        """When rule.enabled is False, the scanner never runs a dedup SELECT."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": uuid.uuid4(), "metadata": {}})
        conn.execute = AsyncMock()

        with patch("scanner.vm.nuclei_worker.get_findings_rule", AsyncMock(return_value=_rule(enabled=False))):
            await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), nuclei_result)

        conn.fetchrow.assert_not_called()
        conn.execute.assert_called_once()  # INSERT

    @pytest.mark.asyncio
    async def test_keep_first_drops_duplicate(self, nuclei_result):
        """keep_first strategy + existing match → no write at all."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": uuid.uuid4(), "metadata": {}})
        conn.execute = AsyncMock()

        with patch(
            "scanner.vm.nuclei_worker.get_findings_rule",
            AsyncMock(return_value=_rule(strategy="keep_first")),
        ):
            result = await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), nuclei_result)

        assert result is False
        conn.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_keep_last_updates_existing(self, nuclei_result):
        """keep_last strategy + existing match → UPDATE the row."""
        existing_id = uuid.uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": existing_id, "metadata": {}})
        conn.execute = AsyncMock()

        with patch(
            "scanner.vm.nuclei_worker.get_findings_rule",
            AsyncMock(return_value=_rule(strategy="keep_last")),
        ):
            await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), nuclei_result)

        conn.execute.assert_called_once()
        sql_arg = conn.execute.call_args[0][0]
        assert "UPDATE findings" in sql_arg
        assert conn.execute.call_args[0][1] == existing_id

    @pytest.mark.asyncio
    async def test_merge_strategy_unions_tags(self, nuclei_result):
        """merge strategy unions list fields in metadata."""
        existing_id = uuid.uuid4()
        existing_metadata = {"tags": ["seen-before"], "template_id": "apache-detect"}
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": existing_id, "metadata": existing_metadata})
        conn.execute = AsyncMock()

        with patch(
            "scanner.vm.nuclei_worker.get_findings_rule",
            AsyncMock(return_value=_rule(strategy="merge")),
        ):
            await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), nuclei_result)

        merged = json.loads(conn.execute.call_args[0][2])
        # Union of old ["seen-before"] and new ["apache","http","detect"]
        assert set(merged["tags"]) == {"seen-before", "apache", "http", "detect"}

    @pytest.mark.asyncio
    async def test_normalizes_invalid_severity(self, nuclei_result):
        """Invalid severity values are normalized to 'info'."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        conn.execute = AsyncMock()

        nuclei_result["info"]["severity"] = "UNKNOWN"
        with patch("scanner.vm.nuclei_worker.get_findings_rule", AsyncMock(return_value=_rule())):
            await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), nuclei_result)

        assert conn.execute.call_args[0][_INSERT_SEVERITY] == "info"

    @pytest.mark.asyncio
    async def test_db_error_returns_false(self, nuclei_result):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(side_effect=Exception("DB error"))

        with patch("scanner.vm.nuclei_worker.get_findings_rule", AsyncMock(return_value=_rule())):
            result = await _emit_finding(conn, uuid.uuid4(), uuid.uuid4(), nuclei_result)

        assert result is False
