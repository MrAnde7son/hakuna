"""Comprehensive tests for FieldMapper: detect_paths, map, auto_suggest, render_template."""

import pytest
from services.field_mapper import detect_paths, map_record, auto_suggest, render_template


# ═══════════════════════════════════════════════════════════
# detect_paths
# ═══════════════════════════════════════════════════════════

class TestDetectPaths:
    def test_flat_record(self):
        record = {"ip": "10.0.0.1", "hostname": "srv1", "count": 42}
        paths = detect_paths(record)
        names = [p["path"] for p in paths]
        assert "ip" in names
        assert "hostname" in names
        assert "count" in names

    def test_types_inferred(self):
        record = {"name": "test", "count": 5, "score": 3.14, "active": True, "tags": ["a"]}
        paths = {p["path"]: p["inferred_type"] for p in detect_paths(record)}
        assert paths["name"] == "string"
        assert paths["count"] == "number"
        assert paths["score"] == "number"
        assert paths["active"] == "boolean"
        assert paths["tags"] == "array"

    def test_nested_objects(self):
        record = {"asset": {"ip": "10.0.0.1", "meta": {"os": "Linux"}}}
        paths = {p["path"]: p for p in detect_paths(record)}
        assert "asset" in paths
        assert "asset.ip" in paths
        assert "asset.meta" in paths
        assert "asset.meta.os" in paths
        assert paths["asset.ip"]["sample_value"] == "10.0.0.1"

    def test_array_first_element(self):
        record = {"cves": ["CVE-2024-1234", "CVE-2024-5678"]}
        paths = {p["path"]: p for p in detect_paths(record)}
        assert "cves" in paths
        assert "cves[0]" in paths
        assert paths["cves[0]"]["sample_value"] == "CVE-2024-1234"

    def test_array_of_objects(self):
        record = {"tags": [{"name": "critical", "id": 1}]}
        paths = {p["path"]: p for p in detect_paths(record)}
        assert "tags" in paths
        assert "tags[0]" in paths
        assert "tags[0].name" in paths
        assert "tags[0].id" in paths

    def test_null_values_included(self):
        record = {"ip": "10.0.0.1", "hostname": None}
        paths = {p["path"]: p for p in detect_paths(record)}
        assert "hostname" in paths
        assert paths["hostname"]["inferred_type"] == "null"

    def test_datetime_detection_iso(self):
        record = {"created": "2024-01-15T10:30:00Z"}
        paths = {p["path"]: p for p in detect_paths(record)}
        assert paths["created"]["inferred_type"] == "datetime"

    def test_datetime_detection_epoch(self):
        record = {"ts": 1705312200}
        paths = {p["path"]: p for p in detect_paths(record)}
        assert paths["ts"]["inferred_type"] == "datetime"

    def test_max_depth(self):
        # Build deeply nested record
        record = {"a": {"b": {"c": {"d": {"e": {"f": {"g": "too_deep"}}}}}}}
        paths = {p["path"] for p in detect_paths(record)}
        assert "a.b.c.d.e.f" not in paths or "a.b.c.d.e.f.g" not in paths

    def test_max_paths_truncation(self):
        # Generate record with >200 fields
        record = {f"field_{i}": i for i in range(250)}
        paths = detect_paths(record)
        assert len(paths) <= 200

    def test_empty_record(self):
        assert detect_paths({}) == []

    def test_empty_array(self):
        record = {"items": []}
        paths = {p["path"]: p for p in detect_paths(record)}
        assert "items" in paths
        assert paths["items"]["inferred_type"] == "array"


# ═══════════════════════════════════════════════════════════
# map_record
# ═══════════════════════════════════════════════════════════

class TestMapRecord:
    def test_simple_mapping(self):
        raw = {"ip": "10.0.0.1", "name": "srv1"}
        field_map = [
            {"source": "ip", "target": "ip_address"},
            {"source": "name", "target": "hostname"},
        ]
        result = map_record(raw, field_map)
        assert result["mapped"]["ip_address"] == "10.0.0.1"
        assert result["mapped"]["hostname"] == "srv1"
        assert result["errors"] == []

    def test_nested_source(self):
        raw = {"asset": {"ip": "10.0.0.1"}}
        field_map = [{"source": "asset.ip", "target": "ip_address"}]
        result = map_record(raw, field_map)
        assert result["mapped"]["ip_address"] == "10.0.0.1"

    def test_nested_target(self):
        raw = {"ip": "10.0.0.1"}
        field_map = [{"source": "ip", "target": "asset.ip_address"}]
        result = map_record(raw, field_map)
        assert result["mapped"]["asset"]["ip_address"] == "10.0.0.1"

    def test_array_index(self):
        raw = {"cves": ["CVE-2024-1234", "CVE-2024-5678"]}
        field_map = [{"source": "cves[0]", "target": "cve_id"}]
        result = map_record(raw, field_map)
        assert result["mapped"]["cve_id"] == "CVE-2024-1234"

    def test_wildcard_array(self):
        raw = {"tags": [{"name": "critical"}, {"name": "web"}]}
        field_map = [{"source": "tags[*].name", "target": "tags"}]
        result = map_record(raw, field_map)
        assert result["mapped"]["tags"] == ["critical", "web"]

    def test_missing_source_warning(self):
        raw = {"ip": "10.0.0.1"}
        field_map = [{"source": "hostname", "target": "hostname"}]
        result = map_record(raw, field_map)
        assert result["mapped"]["hostname"] is None
        assert len(result["errors"]) == 1
        assert result["errors"][0]["level"] == "warning"

    def test_required_missing_error(self):
        raw = {"ip": "10.0.0.1"}
        field_map = [{"source": "title", "target": "title", "required": True}]
        result = map_record(raw, field_map)
        assert result["mapped"]["title"] is None
        assert len(result["errors"]) == 1
        assert result["errors"][0]["level"] == "error"

    def test_transform_map(self):
        raw = {"severity": "4"}
        field_map = [{"source": "severity", "target": "severity", "transform": {
            "type": "map", "mapping": {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}
        }}]
        result = map_record(raw, field_map)
        assert result["mapped"]["severity"] == "critical"

    def test_transform_map_missing_value(self):
        raw = {"severity": "99"}
        field_map = [{"source": "severity", "target": "severity", "transform": {
            "type": "map", "mapping": {"4": "critical"}
        }}]
        result = map_record(raw, field_map)
        # Falls through with warning
        assert result["mapped"]["severity"] == "99"
        assert len(result["errors"]) == 1

    def test_transform_boolean(self):
        raw = {"exploit": "Yes"}
        field_map = [{"source": "exploit", "target": "exploit_available", "transform": {
            "type": "boolean", "truthy": ["Yes", "yes", "true", "1"]
        }}]
        result = map_record(raw, field_map)
        assert result["mapped"]["exploit_available"] is True

    def test_transform_boolean_false(self):
        raw = {"exploit": "No"}
        field_map = [{"source": "exploit", "target": "exploit_available", "transform": {
            "type": "boolean", "truthy": ["Yes"]
        }}]
        result = map_record(raw, field_map)
        assert result["mapped"]["exploit_available"] is False

    def test_transform_float(self):
        raw = {"score": "7.5"}
        field_map = [{"source": "score", "target": "cvss_score", "transform": {"type": "float"}}]
        result = map_record(raw, field_map)
        assert result["mapped"]["cvss_score"] == 7.5

    def test_transform_float_failure(self):
        raw = {"score": "N/A"}
        field_map = [{"source": "score", "target": "cvss_score", "transform": {"type": "float"}}]
        result = map_record(raw, field_map)
        assert result["mapped"]["cvss_score"] is None
        assert len(result["errors"]) == 1

    def test_transform_integer(self):
        raw = {"count": "42.7"}
        field_map = [{"source": "count", "target": "count", "transform": {"type": "integer"}}]
        result = map_record(raw, field_map)
        assert result["mapped"]["count"] == 42

    def test_transform_datetime_iso(self):
        raw = {"date": "2024-01-15T10:30:00Z"}
        field_map = [{"source": "date", "target": "first_seen", "transform": {"type": "datetime"}}]
        result = map_record(raw, field_map)
        assert "2024-01-15" in result["mapped"]["first_seen"]

    def test_transform_datetime_epoch(self):
        raw = {"ts": 1705312200}
        field_map = [{"source": "ts", "target": "first_seen", "transform": {"type": "datetime"}}]
        result = map_record(raw, field_map)
        assert "2024-01-15" in result["mapped"]["first_seen"]

    def test_transform_datetime_epoch_ms(self):
        raw = {"ts": 1705312200000}
        field_map = [{"source": "ts", "target": "first_seen", "transform": {"type": "datetime"}}]
        result = map_record(raw, field_map)
        assert "2024-01-15" in result["mapped"]["first_seen"]

    def test_transform_expression(self):
        raw = {"score": 8.5}
        field_map = [{"source": "score", "target": "severity", "transform": {
            "type": "expression", "expr": "'critical' if value > 9 else 'high' if value > 7 else 'medium'"
        }}]
        result = map_record(raw, field_map)
        assert result["mapped"]["severity"] == "high"

    def test_transform_expression_with_record(self):
        raw = {"score": 8.5, "exploit": True}
        field_map = [{"source": "score", "target": "priority", "transform": {
            "type": "expression", "expr": "'critical' if value > 7 and record.get('exploit') else 'high'"
        }}]
        result = map_record(raw, field_map)
        assert result["mapped"]["priority"] == "critical"

    def test_multiple_fields_one_fails(self):
        """One field failure should not abort the whole record."""
        raw = {"ip": "10.0.0.1", "score": "bad"}
        field_map = [
            {"source": "ip", "target": "ip_address"},
            {"source": "score", "target": "cvss_score", "transform": {"type": "float"}},
        ]
        result = map_record(raw, field_map)
        assert result["mapped"]["ip_address"] == "10.0.0.1"
        assert result["mapped"]["cvss_score"] is None
        assert len(result["errors"]) == 1

    def test_empty_field_map(self):
        result = map_record({"ip": "10.0.0.1"}, [])
        assert result["mapped"] == {}
        assert result["errors"] == []

    def test_deeply_nested(self):
        raw = {"a": {"b": {"c": {"d": "deep_value"}}}}
        field_map = [{"source": "a.b.c.d", "target": "result"}]
        result = map_record(raw, field_map)
        assert result["mapped"]["result"] == "deep_value"


# ═══════════════════════════════════════════════════════════
# auto_suggest
# ═══════════════════════════════════════════════════════════

class TestAutoSuggest:
    def _make_paths(self, names):
        return [{"path": n, "sample_value": "x", "inferred_type": "string"} for n in names]

    def _make_schema(self, names):
        return [{"name": n, "type": "string", "group": "finding"} for n in names]

    def test_exact_alias_match(self):
        source = self._make_paths(["pluginID", "pluginName", "ip", "baseScore"])
        target = self._make_schema(["plugin_id", "title", "ip_address", "cvss_score"])
        suggestions = auto_suggest(source, target)
        mapped = {s["target"]: s["source"] for s in suggestions}
        assert mapped["plugin_id"] == "pluginID"
        assert mapped["title"] == "pluginName"
        assert mapped["ip_address"] == "ip"
        assert mapped["cvss_score"] == "baseScore"

    def test_confidence_above_threshold(self):
        source = self._make_paths(["pluginID"])
        target = self._make_schema(["plugin_id"])
        suggestions = auto_suggest(source, target)
        assert len(suggestions) == 1
        assert suggestions[0]["confidence"] > 0.7

    def test_no_match_below_threshold(self):
        source = self._make_paths(["xyzzy_field"])
        target = self._make_schema(["hostname"])
        suggestions = auto_suggest(source, target)
        # Should not suggest a match with very low similarity
        for s in suggestions:
            assert s["confidence"] > 0.7

    def test_nested_source_paths(self):
        source = self._make_paths(["asset.ip", "vuln.pluginName"])
        target = self._make_schema(["ip_address", "title"])
        suggestions = auto_suggest(source, target)
        mapped = {s["target"]: s["source"] for s in suggestions}
        assert mapped.get("ip_address") == "asset.ip"
        assert mapped.get("title") == "vuln.pluginName"

    def test_tenable_sc_fields(self):
        """Simulate Tenable SC response fields."""
        source = self._make_paths([
            "pluginID", "pluginName", "ip", "netbiosName", "severity",
            "baseScore", "cve", "exploitAvailable", "solution", "firstSeen", "lastSeen"
        ])
        target = self._make_schema([
            "plugin_id", "title", "ip_address", "hostname", "severity",
            "cvss_score", "cve_id", "exploit_available", "solution", "first_seen", "last_seen"
        ])
        suggestions = auto_suggest(source, target)
        mapped = {s["target"]: s["source"] for s in suggestions}
        assert len(mapped) >= 8  # Most should map

    def test_empty_sources(self):
        target = self._make_schema(["hostname"])
        assert auto_suggest([], target) == []

    def test_empty_schema(self):
        source = self._make_paths(["hostname"])
        assert auto_suggest(source, []) == []


# ═══════════════════════════════════════════════════════════
# render_template
# ═══════════════════════════════════════════════════════════

class TestRenderTemplate:
    def test_simple_substitution(self):
        template = {"summary": "{{finding.title}} on {{asset.hostname}}"}
        finding = {"title": "SQL Injection", "severity": "critical"}
        asset = {"hostname": "web01", "ip_address": "10.0.0.1"}
        result = render_template(template, finding, asset)
        assert result["summary"] == "SQL Injection on web01"

    def test_nested_template(self):
        template = {"fields": {"project": {"key": "SEC"}, "summary": "{{finding.title}}"}}
        finding = {"title": "XSS"}
        asset = {}
        result = render_template(template, finding, asset)
        assert result["fields"]["summary"] == "XSS"
        assert result["fields"]["project"]["key"] == "SEC"

    def test_filter_upper(self):
        template = {"severity": "{{finding.severity|upper}}"}
        result = render_template(template, {"severity": "critical"}, {})
        assert result["severity"] == "CRITICAL"

    def test_filter_capitalize(self):
        template = {"priority": "{{finding.severity|capitalize}}"}
        result = render_template(template, {"severity": "high"}, {})
        assert result["priority"] == "High"

    def test_missing_variable_empty_string(self):
        template = {"cve": "{{finding.cve_id}}"}
        result = render_template(template, {}, {})
        assert result["cve"] == ""

    def test_multiple_variables_in_string(self):
        template = {"desc": "CVE: {{finding.cve_id}} CVSS: {{finding.cvss_score}}"}
        finding = {"cve_id": "CVE-2024-1234", "cvss_score": 9.8}
        result = render_template(template, finding, {})
        assert result["desc"] == "CVE: CVE-2024-1234 CVSS: 9.8"

    def test_array_in_template(self):
        template = {"labels": ["{{finding.severity}}", "security"]}
        result = render_template(template, {"severity": "high"}, {})
        assert result["labels"] == ["high", "security"]

    def test_non_string_values_unchanged(self):
        template = {"count": 42, "active": True, "data": None}
        result = render_template(template, {}, {})
        assert result["count"] == 42
        assert result["active"] is True
        assert result["data"] is None

    def test_does_not_mutate_input(self):
        template = {"title": "{{finding.title}}"}
        original = {"title": "{{finding.title}}"}
        render_template(template, {"title": "XSS"}, {})
        assert template == original

    def test_jira_ticket_template(self):
        """Full Jira-like template from the spec."""
        template = {
            "fields": {
                "project": {"key": "SEC"},
                "summary": "[{{finding.severity|upper}}] {{finding.title}} on {{asset.hostname}}",
                "description": "CVE: {{finding.cve_id}}\nCVSS: {{finding.cvss_score}}\n\nSolution:\n{{finding.solution}}",
                "issuetype": {"name": "Bug"},
                "priority": {"name": "{{finding.severity|capitalize}}"},
            }
        }
        finding = {"severity": "critical", "title": "RCE", "cve_id": "CVE-2024-9999",
                    "cvss_score": 10.0, "solution": "Upgrade to v2"}
        asset = {"hostname": "prod-db-01"}
        result = render_template(template, finding, asset)
        assert result["fields"]["summary"] == "[CRITICAL] RCE on prod-db-01"
        assert "CVE-2024-9999" in result["fields"]["description"]
        assert result["fields"]["priority"]["name"] == "Critical"
