"""Tests for the Nuclei worker.

The worker is pure compute — it looks up asset context read-only, runs
Nuclei, and returns findings in the Celery result payload. The backend
imports results and runs them through the ingest pipeline (dedup, tagging,
SLA, risk). None of that is the scanner's concern, so there's nothing to
unit-test here about deduplication.
"""

import inspect

from scanner.vm.nuclei_worker import (
    _extract_cpe_list,
    _has_dast_template,
    _parse_nuclei_stats,
    _resolve_target,
    _result_to_finding,
    run_nuclei_adhoc,
    run_nuclei_scan,
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


class TestHasDastTemplate:
    """Controls whether nuclei is invoked with -dast.

    Must be True whenever the router included a custom/dast/ path so that
    fuzzing-mode templates actually execute; must be False on scans with
    no DAST templates so we don't change the semantics of unrelated scans.
    """

    def test_true_when_dast_path_present(self):
        args = ["-tags", "apache,http", "-t", "/app/templates/custom/dast/xss.yaml"]
        assert _has_dast_template(args) is True

    def test_false_when_only_non_dast_customs(self):
        args = ["-tags", "ollama", "-t", "/app/templates/custom/ai/exposed-ollama.yaml"]
        assert _has_dast_template(args) is False

    def test_false_on_tag_only_args(self):
        """Fallback path (only -tags, no -t) must not enable -dast."""
        assert _has_dast_template(["-tags", "generic,exposure"]) is False

    def test_false_on_empty_args(self):
        assert _has_dast_template([]) is False

    def test_does_not_false_positive_on_similar_path(self):
        """'dastardly' in a path shouldn't trip the check — we require the
        exact custom/dast/ segment."""
        args = ["-t", "/app/templates/custom/ot/dastardly-probe.yaml"]
        assert _has_dast_template(args) is False


class TestScanPlanPlumbing:
    """PR 1 only plumbs the scan_plan arg through; PR 2 will consume it.

    These tests pin the wire contract — both Celery tasks accept an optional
    ``scan_plan`` kwarg with the expected default. Without these, a backend
    upgrade that starts sending plans against an old worker would 500 on
    Celery's argument validation rather than fall through gracefully.
    """

    def test_run_nuclei_scan_accepts_scan_plan_kwarg(self):
        sig = inspect.signature(run_nuclei_scan.__wrapped__)
        assert "scan_plan" in sig.parameters
        assert sig.parameters["scan_plan"].default is None

    def test_run_nuclei_adhoc_accepts_scan_plan_kwarg(self):
        sig = inspect.signature(run_nuclei_adhoc.__wrapped__)
        assert "scan_plan" in sig.parameters
        assert sig.parameters["scan_plan"].default is None
