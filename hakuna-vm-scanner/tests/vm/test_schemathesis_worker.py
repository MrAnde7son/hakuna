"""Tests for the Schemathesis worker.

Covers the deterministic parts we actually own: credential flattening,
endpoint grouping by spec, finding payload shape (including the seeded
llm_validation verdict that the backend's ingest relies on).

The Schemathesis driver itself is intentionally not exercised here — it
depends on an installed Schemathesis, network access to a spec, and
Hypothesis generation. Those belong in an integration test against a
real example API; the worker's job of (1) query endpoints, (2) group,
(3) emit findings is fully testable without that.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from scanner.vm.schemathesis_worker import (
    _check_to_finding,
    _credentials_to_headers,
    _extracted_evidence,
    _group_endpoints_by_spec,
    _loads,
    _redacted_headers_for_log,
    _TRUE_POSITIVE_CHECKS,
)


class TestCredentialsToHeaders:
    def test_basic_emits_auth_header(self):
        h = _credentials_to_headers({
            "type": "basic", "username": "alice", "password": "s3cret",
        })
        assert h["Authorization"].startswith("Basic ")
        # Base64("alice:s3cret")
        assert h["Authorization"] == "Basic YWxpY2U6czNjcmV0"

    def test_bearer_emits_authorization(self):
        h = _credentials_to_headers({"type": "bearer", "token": "abc.def"})
        assert h == {"Authorization": "Bearer abc.def"}

    def test_cookie_emits_cookie_header(self):
        h = _credentials_to_headers({"type": "cookie", "cookie": "sid=xyz"})
        assert h == {"Cookie": "sid=xyz"}

    def test_extra_headers_merge_across_types(self):
        """The session broker folds cookies + CSRF tokens into `headers` —
        this must layer on top of any primary auth scheme so nuclei
        and schemathesis behave identically."""
        h = _credentials_to_headers({
            "type": "bearer",
            "token": "t",
            "headers": {"X-CSRF-Token": "v", "X-Requested-With": "XMLHttpRequest"},
        })
        assert h["Authorization"] == "Bearer t"
        assert h["X-CSRF-Token"] == "v"
        assert h["X-Requested-With"] == "XMLHttpRequest"

    def test_none_credentials_returns_empty_dict(self):
        assert _credentials_to_headers(None) == {}

    def test_unknown_type_still_honors_extra_headers(self):
        """Unknown auth_type shouldn't drop the headers dict — the backend
        sometimes produces type='header' with only `headers` populated."""
        h = _credentials_to_headers({
            "type": "header",
            "headers": {"X-API-Key": "k"},
        })
        assert h == {"X-API-Key": "k"}


class TestRedactedHeaders:
    def test_all_values_masked(self):
        out = _redacted_headers_for_log({"Authorization": "Bearer abc", "X-CSRF": "t"})
        assert out == {"Authorization": "***", "X-CSRF": "***"}

    def test_empty_input(self):
        assert _redacted_headers_for_log({}) == {}


class TestLoadsJson:
    def test_dict_passthrough(self):
        assert _loads({"a": 1}) == {"a": 1}

    def test_string_parsed(self):
        assert _loads('{"a": 1}') == {"a": 1}

    def test_none_returns_none(self):
        assert _loads(None) is None

    def test_garbage_returns_none(self):
        assert _loads("not json") is None


class TestGroupEndpointsBySpec:
    def test_groups_openapi_by_spec_url(self):
        rows = [
            {
                "source": "openapi", "url": "https://api.example.com/v1/users",
                "method": "GET", "path": "/v1/users",
                "evidence": json.dumps({"spec_url": "https://api.example.com/openapi.json"}),
            },
            {
                "source": "openapi", "url": "https://api.example.com/v1/users/{id}",
                "method": "DELETE", "path": "/v1/users/{id}",
                "evidence": json.dumps({"spec_url": "https://api.example.com/openapi.json"}),
            },
            {
                "source": "openapi", "url": "https://other.example.com/api",
                "method": "GET", "path": "/api",
                "evidence": json.dumps({"spec_url": "https://other.example.com/swagger.json"}),
            },
        ]
        groups = _group_endpoints_by_spec(rows)
        assert len(groups) == 2
        kinds = [g["kind"] for g in groups]
        assert kinds == ["openapi", "openapi"]
        # Each spec group keeps its rows together — ordering isn't
        # guaranteed but counts must match.
        sizes = sorted(len(g["rows"]) for g in groups)
        assert sizes == [1, 2]

    def test_groups_graphql_by_endpoint_url(self):
        rows = [
            {
                "source": "graphql", "url": "https://api.example.com/graphql",
                "method": "POST", "path": "Query.users",
                "evidence": json.dumps({"operation_kind": "Query", "operation_name": "users"}),
            },
        ]
        groups = _group_endpoints_by_spec(rows)
        assert len(groups) == 1
        assert groups[0]["kind"] == "graphql"
        assert groups[0]["graphql_url"] == "https://api.example.com/graphql"

    def test_skips_rows_without_spec_url(self):
        """An openapi row with an empty evidence blob can't be fuzzed —
        we need the spec URL to load into Schemathesis."""
        rows = [
            {
                "source": "openapi", "url": "https://api.example.com/v1",
                "method": "GET", "path": "/v1",
                "evidence": json.dumps({}),
            },
        ]
        assert _group_endpoints_by_spec(rows) == []

    def test_mixed_sources_handled_independently(self):
        rows = [
            {
                "source": "openapi", "url": "https://api.example.com/x",
                "method": "GET", "path": "/x",
                "evidence": json.dumps({"spec_url": "https://api.example.com/openapi.json"}),
            },
            {
                "source": "graphql", "url": "https://api.example.com/graphql",
                "method": "POST", "path": "Query.me",
                "evidence": None,
            },
        ]
        groups = _group_endpoints_by_spec(rows)
        kinds = sorted(g["kind"] for g in groups)
        assert kinds == ["graphql", "openapi"]

    def test_ignores_non_api_sources(self):
        """katana / kiterunner / llm_js endpoints aren't schema-backed and
        must not reach the schemathesis fuzzer."""
        rows = [
            {"source": "katana", "url": "https://x/y", "method": "GET",
             "path": "/y", "evidence": None},
            {"source": "llm_js", "url": "https://x/z", "method": "GET",
             "path": "/z", "evidence": None},
        ]
        assert _group_endpoints_by_spec(rows) == []


class TestCheckToFinding:
    def _case(self, method="GET", path="/v1/users"):
        return SimpleNamespace(method=method, path=path, as_curl=lambda: f"curl {method} {path}")

    def _response(self, status_code=500, text="boom"):
        return SimpleNamespace(status_code=status_code, text=text)

    def test_server_error_emits_true_positive_verdict(self):
        """5xx on a valid-per-schema input is a concrete backend bug — the
        seeded llm_validation.verdict must be 'true_positive' so the
        prioritizer ranks it above signature matches."""
        f = _check_to_finding(
            check_name="not_a_server_error",
            case=self._case(),
            response=self._response(status_code=500),
            message="Server error: 500",
            target="https://api.example.com",
            endpoint_row={"method": "GET", "path": "/v1/users"},
        )
        assert f["llm_validation"]["verdict"] == "true_positive"
        assert f["llm_validation"]["source"] == "schemathesis"
        assert f["severity"] == "high"
        assert "api-fuzz" in f["tags"]

    def test_status_code_conformance_needs_review(self):
        """Undocumented status codes are often docs drift, not bugs — must
        not be auto-promoted to true_positive."""
        f = _check_to_finding(
            check_name="status_code_conformance",
            case=self._case(),
            response=self._response(status_code=418, text="teapot"),
            message="418 not in documented responses",
            target="https://api.example.com",
            endpoint_row={"method": "GET", "path": "/v1/users"},
        )
        assert f["llm_validation"]["verdict"] == "needs_review"
        assert f["severity"] == "low"

    def test_response_schema_conformance_true_positive(self):
        """Schema violations on inputs the API itself considers valid are
        authoritatively real — the contract says 'response shape is X'
        and the server broke it. Bucket into true_positive."""
        f = _check_to_finding(
            check_name="response_schema_conformance",
            case=self._case(),
            response=self._response(status_code=200, text="{}"),
            message="required key 'id' missing",
            target="https://api.example.com",
            endpoint_row={"method": "GET", "path": "/v1/users"},
        )
        assert f["llm_validation"]["verdict"] == "true_positive"

    def test_finding_shape_matches_nuclei_payload(self):
        """The backend's _import_nuclei_job_findings reads a fixed set of
        keys — template_id, severity, name, description, matched_at,
        host, port, type, tags, reference, classification, curl_command,
        matcher_name, extracted_results. Regression guard against drift."""
        f = _check_to_finding(
            check_name="not_a_server_error",
            case=self._case(),
            response=self._response(),
            message="x",
            target="https://api.example.com",
            endpoint_row={"method": "GET", "path": "/v1/users"},
        )
        required_keys = {
            "template_id", "severity", "name", "description", "matched_at",
            "host", "port", "type", "tags", "reference", "classification",
            "curl_command", "matcher_name", "extracted_results",
        }
        assert required_keys.issubset(set(f))

    def test_true_positive_set_matches_severity_mapping(self):
        """Invariant: every check we bucket as true_positive must have a
        severity >= medium so the prioritizer actually sees the signal."""
        from scanner.vm.schemathesis_worker import _CHECK_TO_SEVERITY
        for check in _TRUE_POSITIVE_CHECKS:
            assert _CHECK_TO_SEVERITY[check] in ("medium", "high", "critical")


class TestExtractedEvidence:
    def test_includes_status_and_body_snippet(self):
        resp = SimpleNamespace(status_code=500, text="stack trace...")
        out = _extracted_evidence(500, resp, "server error")
        joined = " ".join(out)
        assert "status_code=500" in joined
        assert "stack trace" in joined

    def test_truncates_long_body(self):
        resp = SimpleNamespace(status_code=500, text="x" * 1000)
        out = _extracted_evidence(500, resp, "")
        # body[:200] prefix + no overflow
        body_lines = [p for p in out if p.startswith("body[:200]=")]
        assert len(body_lines) == 1
        assert len(body_lines[0]) <= len("body[:200]=") + 200
