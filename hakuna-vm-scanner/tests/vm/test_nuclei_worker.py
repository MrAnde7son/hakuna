"""Tests for the Nuclei worker.

The worker is pure compute — it looks up asset context read-only, runs
Nuclei, and returns findings in the Celery result payload. The backend
imports results and runs them through the ingest pipeline (dedup, tagging,
SLA, risk). None of that is the scanner's concern, so there's nothing to
unit-test here about deduplication.
"""

from scanner.vm.nuclei_worker import (
    _extract_cpe_list,
    _parse_nuclei_stats,
    _resolve_target,
    _result_to_finding,
)


class TestResolveTarget:
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
    def test_list_of_strings(self):
        cpes = ["cpe:2.3:a:apache:http_server:2.4:*", "cpe:2.3:a:php:php:8.0:*"]
        assert _extract_cpe_list(cpes) == cpes

    def test_none_returns_none(self):
        assert _extract_cpe_list(None) is None

    def test_empty_list_returns_none(self):
        assert _extract_cpe_list([]) is None

    def test_dict_returns_values(self):
        assert _extract_cpe_list({"0": "cpe:2.3:a:apache:http_server:2.4:*"}) == [
            "cpe:2.3:a:apache:http_server:2.4:*"
        ]

    def test_empty_dict_returns_none(self):
        assert _extract_cpe_list({}) is None


class TestParseNucleiStats:
    def test_extracts_known_lines(self):
        stderr = [
            "[INF] Templates: 12352 |",
            "[INF] Total requests: 45210 |",
            "[INF] Results found: 3 |",
        ]
        stats = _parse_nuclei_stats(stderr)
        assert stats == {
            "templates_loaded": 12352,
            "requests_sent": 45210,
            "results_found": 3,
        }

    def test_missing_stats_return_empty(self):
        assert _parse_nuclei_stats(["[INF] random noise"]) == {}


class TestResultToFinding:
    """The payload shape run_nuclei_scan and run_nuclei_adhoc return must be
    identical — the backend's importer handles both with one code path."""

    def test_happy_path(self):
        raw = {
            "template-id": "apache-detect",
            "info": {
                "name": "Apache HTTP Server Detection",
                "severity": "info",
                "description": "Detects Apache.",
                "tags": ["apache", "http"],
                "reference": ["https://httpd.apache.org/"],
                "classification": {"cve-id": None},
            },
            "matched-at": "https://example.com/",
            "matcher-name": "version",
            "host": "example.com",
            "port": "80",
            "type": "http",
            "extracted-results": ["Apache/2.4.51"],
            "curl-command": "curl https://example.com/",
        }
        f = _result_to_finding(raw)
        assert f["template_id"] == "apache-detect"
        assert f["severity"] == "info"
        assert f["name"] == "Apache HTTP Server Detection"
        assert f["port"] == "80"
        assert f["type"] == "http"
        assert f["tags"] == ["apache", "http"]
        assert f["matcher_name"] == "version"
        assert f["extracted_results"] == ["Apache/2.4.51"]

    def test_severity_normalized(self):
        raw = {"template-id": "x", "info": {"name": "x", "severity": "UNKNOWN"}}
        assert _result_to_finding(raw)["severity"] == "info"

    def test_missing_info_defaults(self):
        raw = {"template-id": "x"}
        f = _result_to_finding(raw)
        assert f["template_id"] == "x"
        assert f["name"] == "x"   # falls back to template_id when info.name missing
        assert f["severity"] == "info"
        assert f["tags"] == []
        assert f["classification"] == {}

    def test_accepts_camelcase_templateID(self):
        raw = {"templateID": "x", "info": {"name": "X", "severity": "high"}}
        f = _result_to_finding(raw)
        assert f["template_id"] == "x"
        assert f["severity"] == "high"
