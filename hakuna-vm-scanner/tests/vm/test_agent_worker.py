"""Tests for the specialist agent worker.

Covers the deterministic surface:
  - applicability predicates per specialist
  - specialist selection with category filtering
  - credential flattening (parallel to schemathesis_worker)
  - agent-payload → nuclei-shape finding translation (including
    stable template_id and llm_validation verdict mapping)
  - probe tool handlers (http_request, check_pattern, emit_finding)
  - safe-URL gating

The LLM agent loop itself requires an ANTHROPIC_API_KEY + real network
access; integration coverage belongs in a separate suite. What we own
here is the payload shape the backend ingests, the budget / gating
logic, and the tool interface.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from scanner.vm.agent_specialists import (
    AGENT_CATEGORIES,
    SPECIALISTS,
    AgentContext,
    TOOLS,
    _analyze_jwt_handler,
    _check_pattern_handler,
    _check_security_headers_handler,
    _classify_login_success,
    _diff_responses_handler,
    _emit_finding_handler,
    _extract_forms,
    _extract_forms_handler,
    _extract_hidden_fields,
    _has_any_http_endpoint,
    _has_auth_surface,
    _has_authn_surface,
    _has_authz_surface,
    _has_parameterised_endpoint,
    _has_state_change_surface,
    _memory_set_handler,
    _oob_check_handler,
    _oob_get_probe_handler,
    _render_page_handler,
    _request_handler,
    _safe_url,
    _summary_handler,
    _try_login_handler,
    seed_base_endpoint,
    select_applicable_specialists,
    tool_schemas_for_anthropic,
)
from scanner.vm.agent_worker import (
    _agent_payload_to_finding,
    _apply_discovered_identity,
    _classify_cwe,
    _composition_hints,
    _credentials_to_headers,
    _seed_scan_config_capability,
    _trim_evidence,
)
from scanner.vm.capabilities import Capability, CapabilityType, asset_scope


def _ctx(**overrides) -> AgentContext:
    defaults = dict(
        asset_id="a-1", org_id="o-1",
        target="https://example.com",
        endpoints=[],
        headers={},
        http_client=None,
        rate_limiter=None,
        deadline=10**10,  # effectively unbounded for unit tests
    )
    defaults.update(overrides)
    return AgentContext(**defaults)


class TestApplicabilityPredicates:
    def test_any_http_endpoint_matches_http_target(self):
        assert _has_any_http_endpoint(_ctx(target="https://x.example.com"))

    def test_any_http_endpoint_matches_endpoint_list(self):
        assert _has_any_http_endpoint(_ctx(
            target="10.0.0.1", endpoints=[{"url": "https://x/api"}],
        ))

    def test_no_http_surface_is_false(self):
        assert not _has_any_http_endpoint(_ctx(target="10.0.0.1"))

    def test_parameterised_detects_openapi_parameters(self):
        eps = [{"url": "https://x/api", "parameters": [{"name": "id"}]}]
        assert _has_parameterised_endpoint(_ctx(endpoints=eps))

    def test_parameterised_detects_query_string(self):
        eps = [{"url": "https://x/api?id=1", "parameters": None}]
        assert _has_parameterised_endpoint(_ctx(endpoints=eps))

    def test_parameterised_accepts_static_paths_with_http_surface(self):
        """Static-only endpoints used to gate out injection/SSRF, which
        skipped apps whose entire attack surface was a root-page form
        (ffuf doesn't parse HTML, so the parameters only appear once
        the agent fetches the page). We now trust the specialist to do
        that discovery — any HTTP surface qualifies, and the prompt
        tells the agent to harvest forms before picking candidates."""
        eps = [{"url": "https://x/api/static", "parameters": None}]
        assert _has_parameterised_endpoint(_ctx(endpoints=eps))

    def test_parameterised_true_for_bare_http_target(self):
        """Adhoc flow seeds a synthetic base endpoint; even without that,
        the predicate must consider a bare http(s) target as probeable."""
        assert _has_parameterised_endpoint(_ctx(target="http://20.0.0.1:8080"))

    def test_parameterised_false_when_no_http_surface(self):
        """A bare-IP target with no endpoints and no scheme stays out —
        nothing for the agent to GET against."""
        assert not _has_parameterised_endpoint(_ctx(target="10.0.0.1"))

    def test_authz_surface_detects_provided_headers(self):
        """Session broker injected a cookie → we can run authz probes."""
        assert _has_authz_surface(_ctx(headers={"Cookie": "sid=x"}))

    def test_authz_surface_detects_auth_required_endpoint(self):
        eps = [{"url": "https://x/api", "auth_required": True}]
        assert _has_authz_surface(_ctx(endpoints=eps))

    def test_authz_surface_false_when_nothing_to_probe(self):
        """authz needs a working identity to diff against — a bare
        http target with no session is not enough."""
        assert not _has_authz_surface(_ctx())
        assert not _has_authz_surface(_ctx(target="https://x.example.com"))

    def test_back_compat_alias_matches_authz(self):
        """``_has_auth_surface`` remains importable for older callers and
        retains the pre-split (strict) semantics."""
        assert _has_auth_surface is _has_authz_surface

    def test_authn_surface_detects_headers(self):
        assert _has_authn_surface(_ctx(headers={"Cookie": "sid=x"}))

    def test_authn_surface_detects_auth_required_endpoint(self):
        eps = [{"url": "https://x/api", "auth_required": True}]
        assert _has_authn_surface(_ctx(endpoints=eps))

    def test_authn_surface_true_for_bare_http_target(self):
        """Broadened for adhoc scans — the authn specialist fetches the
        base URL and harvests login forms itself, so any http(s) target
        qualifies (without this, weak-creds detection never runs on
        ad-hoc targets like a freshly-spun DVWA)."""
        assert _has_authn_surface(_ctx(target="http://dvwa"))

    def test_authn_surface_false_when_no_http_surface(self):
        assert not _has_authn_surface(_ctx(target="10.0.0.1"))

    def test_state_change_surface_true_for_post_endpoint(self):
        eps = [{"url": "https://x/api/save", "method": "POST"}]
        assert _has_state_change_surface(_ctx(endpoints=eps))

    def test_state_change_surface_true_for_delete_endpoint(self):
        eps = [{"url": "https://x/api/item/1", "method": "DELETE"}]
        assert _has_state_change_surface(_ctx(endpoints=eps))

    def test_state_change_surface_true_for_bare_http_target(self):
        """The CSRF specialist discovers state-changing forms itself;
        any http(s) target qualifies so adhoc scans can run it."""
        assert _has_state_change_surface(_ctx(target="http://dvwa"))

    def test_state_change_surface_false_for_bare_non_http(self):
        assert not _has_state_change_surface(_ctx(target="10.0.0.1"))


class TestSelectApplicableSpecialists:
    def test_empty_ctx_produces_no_specialists(self):
        """An asset with no HTTP, no endpoints, no auth surface must
        return zero specialists. Running LLM agents on an unscannable
        asset is the most wasteful thing this worker can do."""
        assert select_applicable_specialists(_ctx(target="10.0.0.1")) == []

    def test_parameterised_endpoint_enables_injection_and_xss_and_ssrf(self):
        eps = [{"url": "https://x/api?id=1", "parameters": [{"name": "id"}]}]
        selected = select_applicable_specialists(_ctx(
            target="https://x", endpoints=eps,
        ))
        cats = {s.category for s in selected}
        assert "injection" in cats
        assert "xss" in cats
        assert "ssrf" in cats

    def test_bare_http_target_enables_injection_and_xss_and_ssrf(self):
        """An http(s) target with no pre-discovered endpoints still
        selects injection/xss/ssrf — the specialists fetch the page
        and harvest forms themselves. This is the fix for the common
        case of a simple app whose only input is a root-page form."""
        selected = select_applicable_specialists(_ctx(
            target="http://20.0.0.1:8080", endpoints=[],
        ))
        cats = {s.category for s in selected}
        assert "injection" in cats
        assert "xss" in cats
        assert "ssrf" in cats

    def test_auth_headers_enable_authn_and_authz(self):
        """With auth headers present, authn/authz have something to
        diff against. Injection still applies because headers alone
        don't imply parameterised endpoints — confirm separately."""
        selected = select_applicable_specialists(_ctx(
            target="https://x", headers={"Cookie": "sid=x"},
        ))
        cats = {s.category for s in selected}
        assert "authn" in cats
        assert "authz" in cats

    def test_adhoc_http_target_enables_authn_and_csrf_but_not_authz(self):
        """An adhoc web scan with no session still needs to exercise
        weak-credentials detection (authn) and missing-CSRF-token
        detection — both specialists discover their own surface. authz
        stays gated because IDOR diffing requires authenticated access."""
        selected = select_applicable_specialists(_ctx(
            target="http://dvwa", endpoints=[], headers={},
        ))
        cats = {s.category for s in selected}
        assert "authn" in cats
        assert "csrf" in cats
        assert "authz" not in cats

    def test_explicit_csrf_filter_applies_predicate(self):
        """Requesting csrf on a non-http target still drops it."""
        selected = select_applicable_specialists(
            _ctx(target="10.0.0.1"), categories=["csrf"],
        )
        assert selected == []

    def test_explicit_category_filter_narrows_selection(self):
        """Callers can pin specialists. But applicable_when still runs
        — requesting authz on an asset with no auth surface must drop it."""
        eps = [{"url": "https://x/api?id=1", "parameters": [{"name": "id"}]}]
        selected = select_applicable_specialists(
            _ctx(target="https://x", endpoints=eps),
            categories=["authz"],
        )
        assert selected == []

    def test_unknown_category_silently_dropped(self):
        selected = select_applicable_specialists(
            _ctx(target="https://x"),
            categories=["not_a_thing"],
        )
        assert selected == []


class TestSeedBaseEndpoint:
    def test_seeds_when_empty_and_http_target(self):
        seeded = seed_base_endpoint([], "http://20.0.0.1:8080")
        assert len(seeded) == 1
        assert seeded[0]["url"] == "http://20.0.0.1:8080"
        assert seeded[0]["method"] == "GET"
        assert seeded[0]["source"] == "synthetic_base"

    def test_seeds_when_empty_and_https_target(self):
        seeded = seed_base_endpoint([], "https://example.com")
        assert len(seeded) == 1
        assert seeded[0]["url"] == "https://example.com"

    def test_noop_when_endpoints_present(self):
        existing = [{"url": "https://x/api"}]
        assert seed_base_endpoint(existing, "https://x") is existing

    def test_noop_when_target_is_bare_ip(self):
        """Without a scheme we can't synthesize a URL the agent can GET."""
        assert seed_base_endpoint([], "10.0.0.1") == []

    def test_noop_when_target_empty(self):
        assert seed_base_endpoint([], "") == []


class TestCredentialsToHeaders:
    def test_bearer_extra_headers_merge(self):
        h = _credentials_to_headers({
            "type": "bearer", "token": "t",
            "headers": {"X-CSRF": "v"},
        })
        assert h == {"Authorization": "Bearer t", "X-CSRF": "v"}

    def test_none_is_empty(self):
        assert _credentials_to_headers(None) == {}

    def test_cookie_type_sets_cookie_header(self):
        h = _credentials_to_headers({"type": "cookie", "cookie": "sid=x"})
        assert h == {"Cookie": "sid=x"}


class TestAgentPayloadToFinding:
    def _spec(self, cat="injection"):
        return SPECIALISTS[cat]

    def test_true_positive_verdict_preserved(self):
        f = _agent_payload_to_finding(
            specialist=self._spec("injection"),
            payload={
                "severity": "high",
                "title": "SQLi in /api/users?id",
                "description": "single quote produced MySQL error",
                "evidence_url": "https://x/api/users?id=1'",
                "evidence_request": "curl https://x/api/users?id=1%27",
                "evidence_response": "ERROR 1064 (42000): You have an error...",
                "verdict": "true_positive",
                "confidence": 0.95,
            },
            target="https://x",
        )
        assert f["llm_validation"]["verdict"] == "true_positive"
        assert f["llm_validation"]["source"] == "agent-injection"
        assert f["llm_validation"]["confidence"] == 0.95
        assert f["severity"] == "high"

    def test_finding_shape_matches_backend_ingest(self):
        """Regression guard — same required keys as Nuclei payload."""
        f = _agent_payload_to_finding(
            specialist=self._spec("xss"),
            payload={
                "severity": "medium", "title": "reflected", "description": "",
                "verdict": "true_positive",
            },
            target="https://x",
        )
        required = {
            "template_id", "severity", "name", "description", "matched_at",
            "host", "port", "type", "tags", "reference", "classification",
            "curl_command", "matcher_name", "extracted_results",
        }
        assert required.issubset(set(f))

    def test_tags_include_agent_and_category(self):
        f = _agent_payload_to_finding(
            specialist=self._spec("ssrf"),
            payload={"severity": "high", "title": "t", "description": "d",
                     "verdict": "true_positive"},
            target="https://x",
        )
        assert "agent" in f["tags"]
        assert "ssrf" in f["tags"]

    def test_template_id_stable_across_calls(self):
        """Dedup relies on a stable template_id per vuln. Same
        category + evidence_url + parameter → same template_id, so
        re-running the scan doesn't create dupes."""
        payload = {
            "severity": "medium", "title": "t", "description": "d",
            "evidence_url": "https://x/a", "parameter": "id",
            "verdict": "true_positive",
        }
        f1 = _agent_payload_to_finding(
            specialist=self._spec("injection"), payload=payload, target="https://x",
        )
        f2 = _agent_payload_to_finding(
            specialist=self._spec("injection"), payload=payload, target="https://x",
        )
        assert f1["template_id"] == f2["template_id"]

    def test_template_id_stable_when_llm_rewords_title(self):
        """The LLM rewords titles between runs on the same vuln (e.g.
        'parameter in /path' vs 'Parameter at /path'). Those must still
        collapse to one template_id — otherwise the backend's
        plugin_id-keyed dedup treats them as distinct findings."""
        base = {
            "severity": "critical", "description": "d",
            "evidence_url": "http://dvwa/vulnerabilities/exec/",
            "parameter": "ip",
            "verdict": "true_positive",
        }
        f1 = _agent_payload_to_finding(
            specialist=self._spec("injection"),
            payload={**base, "title": "OS Command Injection via `ip` parameter in /vulnerabilities/exec/"},
            target="http://dvwa",
        )
        f2 = _agent_payload_to_finding(
            specialist=self._spec("injection"),
            payload={**base, "title": "OS Command Injection via `ip` Parameter at /vulnerabilities/exec/"},
            target="http://dvwa",
        )
        assert f1["template_id"] == f2["template_id"]

    def test_template_id_differs_across_parameters_on_same_endpoint(self):
        """Two genuinely distinct vulns on the same endpoint but
        different input parameters (e.g. SQLi on ?id= AND SQLi on
        ?name=) must remain distinct findings."""
        base = {
            "severity": "high", "title": "SQLi", "description": "d",
            "evidence_url": "http://dvwa/vulnerabilities/sqli/",
            "verdict": "true_positive",
        }
        f_id = _agent_payload_to_finding(
            specialist=self._spec("injection"),
            payload={**base, "parameter": "id"}, target="http://dvwa",
        )
        f_name = _agent_payload_to_finding(
            specialist=self._spec("injection"),
            payload={**base, "parameter": "name"}, target="http://dvwa",
        )
        assert f_id["template_id"] != f_name["template_id"]

    def test_template_id_parameter_case_insensitive(self):
        """LLM capitalization of param names ('ID' vs 'id') must not
        fragment dedup — the translator lowercases before hashing."""
        base = {
            "severity": "high", "title": "SQLi", "description": "d",
            "evidence_url": "http://dvwa/vulnerabilities/sqli/",
            "verdict": "true_positive",
        }
        f_lower = _agent_payload_to_finding(
            specialist=self._spec("injection"),
            payload={**base, "parameter": "id"}, target="http://dvwa",
        )
        f_upper = _agent_payload_to_finding(
            specialist=self._spec("injection"),
            payload={**base, "parameter": "ID"}, target="http://dvwa",
        )
        assert f_lower["template_id"] == f_upper["template_id"]

    def test_template_id_missing_parameter_collapses(self):
        """Endpoint-level vulns without a specific input (default
        login, exposed admin panel) should still dedup across runs
        even when the LLM omits the parameter field entirely."""
        base = {
            "severity": "critical", "title": "default creds",
            "description": "d", "evidence_url": "http://dvwa/login.php",
            "verdict": "true_positive",
        }
        f1 = _agent_payload_to_finding(
            specialist=self._spec("authn"), payload=base, target="http://dvwa",
        )
        f2 = _agent_payload_to_finding(
            specialist=self._spec("authn"),
            payload={**base, "parameter": ""}, target="http://dvwa",
        )
        assert f1["template_id"] == f2["template_id"]

    def test_template_id_differs_across_categories(self):
        """Same bug title under two categories is still two findings — an
        LLM calling it XSS and another calling it SSRF must not collide."""
        payload = {"severity": "high", "title": "same", "description": "",
                   "evidence_url": "https://x/a", "verdict": "true_positive"}
        f_inj = _agent_payload_to_finding(
            specialist=self._spec("injection"), payload=payload, target="https://x",
        )
        f_xss = _agent_payload_to_finding(
            specialist=self._spec("xss"), payload=payload, target="https://x",
        )
        assert f_inj["template_id"] != f_xss["template_id"]

    def test_unknown_severity_coerced_to_info(self):
        f = _agent_payload_to_finding(
            specialist=self._spec("injection"),
            payload={"severity": "SUPERCRITICAL", "title": "t",
                     "description": "", "verdict": "true_positive"},
            target="https://x",
        )
        assert f["severity"] == "info"

    def test_needs_review_verdict_default_confidence(self):
        f = _agent_payload_to_finding(
            specialist=self._spec("xss"),
            payload={"severity": "low", "title": "maybe", "description": "",
                     "verdict": "needs_review"},
            target="https://x",
        )
        assert f["llm_validation"]["verdict"] == "needs_review"
        assert 0.0 <= f["llm_validation"]["confidence"] <= 1.0

    def test_invalid_verdict_falls_back_to_needs_review(self):
        """LLM output isn't trusted — if it invents a verdict, we must
        map it to needs_review rather than surface it to prioritization."""
        f = _agent_payload_to_finding(
            specialist=self._spec("authz"),
            payload={"severity": "high", "title": "t", "description": "",
                     "verdict": "definitely-real"},
            target="https://x",
        )
        assert f["llm_validation"]["verdict"] == "needs_review"

    def test_confidence_clamped_to_unit_interval(self):
        f = _agent_payload_to_finding(
            specialist=self._spec("authn"),
            payload={"severity": "high", "title": "t", "description": "",
                     "verdict": "true_positive", "confidence": 42.0},
            target="https://x",
        )
        assert f["llm_validation"]["confidence"] == 1.0


class TestClassifyCwe:
    """Agent findings used to ship with empty classification, leaving them
    CWE-less in the UI. The category-keyed map populates classification
    so the backend's CWE extractor (vm_scanner._extract_nuclei_cwes) can
    pick them up the same way it does for Nuclei findings."""

    def test_category_default_when_no_keyword_matches(self):
        # csrf has no keyword overrides — always falls to the default.
        assert _classify_cwe("csrf", "Anything goes here") == ["CWE-352"]
        # ssrf likewise has no overrides.
        assert _classify_cwe("ssrf", "Blind SSRF to internal metadata") == ["CWE-918"]

    def test_unknown_category_returns_empty(self):
        # If a new category ships in the worker before the map is updated,
        # we'd rather emit no CWE than the wrong one.
        assert _classify_cwe("brand-new-category", "anything") == []

    def test_injection_keywords_pick_specific_cwe(self):
        spec = _classify_cwe
        assert spec("injection", "SQL Injection via id parameter") == ["CWE-89"]
        assert spec("injection", "OS Command Injection via ip") == ["CWE-78"]
        assert spec("injection", "Server-side template injection in name") == ["CWE-1336"]
        assert spec("injection", "LDAP injection in search") == ["CWE-90"]
        assert spec("injection", "XPath injection in lookup") == ["CWE-643"]
        assert spec("injection", "NoSQL injection in mongo query") == ["CWE-943"]
        assert spec("injection", "CRLF header injection") == ["CWE-93"]
        # Generic injection without a recognisable subtype falls to CWE-74.
        assert spec("injection", "Some weird injection") == ["CWE-74"]

    def test_authn_keywords_pick_specific_cwe(self):
        assert _classify_cwe("authn", "DVWA default login admin/password") == ["CWE-798"]
        assert _classify_cwe("authn", "No rate limit on login form") == ["CWE-307"]
        assert _classify_cwe("authn", "Missing authentication on /admin") == ["CWE-306"]
        assert _classify_cwe("authn", "Generic auth bypass") == ["CWE-287"]

    def test_files_distinguishes_lfi_from_rfi(self):
        assert _classify_cwe("files", "LFI in page parameter") == ["CWE-22"]
        assert _classify_cwe("files", "Remote file inclusion via URL") == ["CWE-98"]

    def test_authz_keywords_pick_specific_cwe(self):
        assert _classify_cwe("authz", "IDOR exposing user 42 invoice") == ["CWE-639"]
        assert _classify_cwe("authz", "Missing authorization on /admin") == ["CWE-862"]
        assert _classify_cwe("authz", "Generic broken access control") == ["CWE-863"]

    def test_classification_is_populated_in_finding(self):
        f = _agent_payload_to_finding(
            specialist=SPECIALISTS["injection"],
            payload={"severity": "high", "title": "SQL Injection in id",
                     "description": "", "verdict": "true_positive"},
            target="http://x",
        )
        assert f["classification"] == {"cwe-id": ["CWE-89"]}


class TestTrimEvidence:
    def test_truncates_long_request_and_response(self):
        out = _trim_evidence("r" * 1000, "s" * 1000)
        assert len(out) == 2
        # Each payload is capped at 500 chars + prefix ("request: " or "response: ")
        assert all(len(line) <= len("response: ") + 500 for line in out)

    def test_omits_empty_pieces(self):
        assert _trim_evidence("", "") == []
        assert _trim_evidence("req", "") == ["request: req"]


class TestSafeUrl:
    def test_rejects_file_scheme(self):
        assert not _safe_url("file:///etc/passwd")

    def test_rejects_data_scheme(self):
        assert not _safe_url("data:text/html,<script>")

    def test_rejects_javascript_scheme(self):
        assert not _safe_url("javascript:alert(1)")

    def test_allows_http_and_https(self):
        assert _safe_url("http://x.example.com/a")
        assert _safe_url("https://x.example.com/a")


class TestRequestHandler:
    def test_rejects_unsafe_url_before_network(self):
        """file:// must never touch the http client."""
        ctx = _ctx()
        ctx.http_client = MagicMock()
        result = _request_handler({"url": "file:///etc/passwd"}, ctx)
        assert "error" in result
        ctx.http_client.request.assert_not_called()

    def test_rejects_when_client_missing(self):
        result = _request_handler({"url": "https://x/"}, _ctx())
        assert result["error"] == "http client not configured"

    def test_rejects_past_deadline(self):
        ctx = _ctx(deadline=0)  # already past
        ctx.http_client = MagicMock()
        result = _request_handler({"url": "https://x/"}, ctx)
        assert result["error"] == "asset deadline reached"

    def test_returns_status_and_truncated_body(self):
        """Body returned to the LLM is capped to keep tool_result small."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "A" * 10_000
        mock_resp.content = b"A" * 10_000
        mock_resp.headers = {"Content-Type": "text/html", "Set-Cookie": "x=y"}
        mock_client.request.return_value = mock_resp
        ctx = _ctx(http_client=mock_client)

        result = _request_handler({"url": "https://x/"}, ctx)
        assert result["status_code"] == 200
        assert len(result["body"]) == 5_000
        # Sensitive headers are redacted before handing back to the LLM.
        assert "set-cookie" not in result["headers"]

    def test_merges_ctx_headers_with_extra_headers(self):
        """Auth headers from the session broker must stick on every probe,
        and per-call extras layer on top without clobbering them."""
        mock_client = MagicMock()
        mock_resp = MagicMock(status_code=200, text="", content=b"", headers={})
        mock_client.request.return_value = mock_resp
        ctx = _ctx(http_client=mock_client, headers={"Authorization": "Bearer t"})

        _request_handler(
            {"url": "https://x/", "headers": {"X-Trace": "abc"}}, ctx,
        )
        kwargs = mock_client.request.call_args.kwargs
        assert kwargs["headers"]["Authorization"] == "Bearer t"
        assert kwargs["headers"]["X-Trace"] == "abc"

    def test_timeout_returns_error_dict(self):
        mock_client = MagicMock()
        mock_client.request.side_effect = httpx.TimeoutException("timed out")
        ctx = _ctx(http_client=mock_client)
        result = _request_handler({"url": "https://x/"}, ctx)
        assert result["error"] == "timeout"

    def test_signals_extracted_into_capability_store(self):
        """Every successful response auto-populates capabilities. This is
        the contract that lets specialists rely on the typed app-model
        instead of re-deriving it from raw bytes — if the wiring breaks,
        the whole signal-extraction pipeline goes silently dark."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.content = b""
        # PHPSESSID → FRAMEWORK=php; the URL contributes ROUTE_TEMPLATE.
        mock_resp.headers = {"Set-Cookie": "PHPSESSID=abc; Path=/"}
        mock_client.request.return_value = mock_resp
        ctx = _ctx(http_client=mock_client)

        _request_handler({"url": "https://x/api/users"}, ctx)

        types = [c.type for c in ctx.capabilities.all()]
        assert "framework" in types
        assert "route_template" in types

    def test_signal_extraction_failure_does_not_break_response(self):
        """The signal extractor is best-effort; an exception inside it
        must not prevent the LLM from getting the response. Without this
        guarantee one bad regex would brick every http_request call."""
        from unittest.mock import patch
        mock_client = MagicMock()
        mock_resp = MagicMock(status_code=200, text="", content=b"", headers={})
        mock_client.request.return_value = mock_resp
        ctx = _ctx(http_client=mock_client)

        with patch(
            "scanner.vm.agent_specialists.extract_signals",
            side_effect=RuntimeError("boom"),
        ):
            result = _request_handler({"url": "https://x/"}, ctx)
        assert result["status_code"] == 200


class TestProbeErrorOracle:
    def test_runs_battery_and_summarises(self):
        """End-to-end: call the oracle on an endpoint, confirm we fire
        the full probe set, attribute framework/web_root capabilities
        from each response, and return the per-probe summary the LLM
        will read back."""
        from scanner.vm.agent_specialists import _probe_error_oracle_handler

        # First probe (malformed JSON) returns a Pydantic-style 422;
        # the rest 404. We expect a FastAPI fingerprint via body chrome
        # and a validation rule attribution.
        responses = [
            MagicMock(
                status_code=422,
                text=(
                    '{"detail":[{"loc":["body","email"],'
                    '"msg":"value is not a valid email address",'
                    '"type":"value_error.email"}]}'
                ),
                content=b"x",
                headers={"Content-Type": "application/json", "Server": "uvicorn"},
            ),
            MagicMock(status_code=400, text="bad", content=b"x", headers={}),
            MagicMock(status_code=415, text="Unsupported Media Type",
                      content=b"x", headers={}),
            MagicMock(status_code=405, text="Method Not Allowed",
                      content=b"x", headers={"Allow": "GET"}),
            MagicMock(status_code=404, text="not found", content=b"x", headers={}),
            MagicMock(status_code=431, text="too big", content=b"x", headers={}),
        ]
        mock_client = MagicMock()
        mock_client.request.side_effect = responses
        ctx = _ctx(http_client=mock_client, target="https://api.example.com")

        out = _probe_error_oracle_handler(
            {"url": "https://api.example.com/users", "method": "POST"},
            ctx,
        )

        # Fired the full battery (one request per probe in _ERROR_PROBES).
        assert len(out["probes"]) == 6
        # Validation rule was attributed (FastAPI shape on probe 1).
        rules = out["inferred"]["validation_rules"]
        assert any(r.get("param") == "email" for r in rules)
        # uvicorn → asgi framework hint surfaced.
        names = {fw["name"] for fw in out["inferred"]["frameworks"]}
        assert "asgi" in names
        # Capabilities were committed to the store, not just returned.
        store_types = [c.type for c in ctx.capabilities.all()]
        assert "framework" in store_types
        assert "validation_rule" in store_types

    def test_rejects_missing_url(self):
        from scanner.vm.agent_specialists import _probe_error_oracle_handler
        out = _probe_error_oracle_handler({}, _ctx(http_client=MagicMock()))
        assert "error" in out

    def test_rejects_unsafe_url(self):
        from scanner.vm.agent_specialists import _probe_error_oracle_handler
        out = _probe_error_oracle_handler(
            {"url": "file:///etc/passwd"}, _ctx(http_client=MagicMock()),
        )
        assert "error" in out


class TestCheckPatternHandler:
    def test_matches_returns_group(self):
        out = _check_pattern_handler(
            {"body": "ERROR 1064 (42000)", "pattern": r"ERROR \d+"},
            _ctx(),
        )
        assert out["matched"] is True
        assert out["match_text"] == "ERROR 1064"

    def test_no_match(self):
        out = _check_pattern_handler(
            {"body": "hello", "pattern": "world"}, _ctx(),
        )
        assert out == {"matched": False, "match_text": None}

    def test_invalid_regex_returns_error(self):
        """Malformed regex from the LLM must not crash the handler."""
        out = _check_pattern_handler(
            {"body": "x", "pattern": "[unclosed"}, _ctx(),
        )
        assert "error" in out


class TestSimpleHandlers:
    def test_emit_finding_echoes_payload(self):
        payload = {"severity": "high", "title": "t"}
        out = _emit_finding_handler(payload, _ctx())
        assert out["status"] == "recorded"
        assert out["payload"] == payload

    def test_summary_acks(self):
        out = _summary_handler({"conclusion": "done"}, _ctx())
        assert out["status"] == "acknowledged"


class TestMemorySetHandler:
    def test_stores_and_returns_total_keys(self):
        ctx = _ctx()
        out = _memory_set_handler({"key": "waf_present", "value": "cloudflare"}, ctx)
        assert out["status"] == "stored"
        assert ctx.shared_memory["waf_present"] == "cloudflare"
        assert out["total_keys"] == 1

    def test_requires_key(self):
        assert "error" in _memory_set_handler({"value": "x"}, _ctx())

    def test_requires_value(self):
        assert "error" in _memory_set_handler({"key": "k"}, _ctx())

    def test_coerces_dict_value_to_json(self):
        """Non-string values are JSON-serialised before storage so the
        next specialist's initial message stays flat text."""
        ctx = _ctx()
        _memory_set_handler({"key": "cookie", "value": {"sid": "abc"}}, ctx)
        assert '"sid"' in ctx.shared_memory["cookie"]

    def test_truncates_long_values(self):
        ctx = _ctx()
        _memory_set_handler({"key": "k", "value": "x" * 10_000}, ctx)
        assert len(ctx.shared_memory["k"]) <= 2_000

    def test_rejects_when_full(self):
        """Capacity cap protects downstream initial-message size."""
        ctx = _ctx(shared_memory={f"k{i}": "v" for i in range(32)})
        out = _memory_set_handler({"key": "new", "value": "v"}, ctx)
        assert "error" in out
        assert "new" not in ctx.shared_memory

    def test_overwrite_existing_key_allowed_when_full(self):
        """Hitting the cap shouldn't stop the agent from correcting
        a prior memory entry."""
        ctx = _ctx(shared_memory={f"k{i}": "v" for i in range(32)})
        out = _memory_set_handler({"key": "k0", "value": "updated"}, ctx)
        assert out["status"] == "stored"
        assert ctx.shared_memory["k0"] == "updated"

    def test_mirrors_valid_credentials_to_typed_capability(self):
        """Composition foundation: memory_set calls that existing prompts
        already make should produce typed CRED capabilities without any
        prompt change. Regression guard — if the prompt key or the
        legacy-bridge parser drifts, this catches it before the scheduler
        rewrite starts depending on the typed view."""
        ctx = _ctx(current_specialist="authn")
        _memory_set_handler({"key": "valid_credentials", "value": "admin:admin"}, ctx)
        creds = ctx.capabilities.query(type=CapabilityType.CRED)
        assert len(creds) == 1
        assert creds[0].value["username"] == "admin"
        assert creds[0].provenance == "specialist:authn"

    def test_mirrors_unknown_key_as_note(self):
        """Unclassified but user-visible hints become NOTE capabilities
        so typed consumers at least know *something* was recorded."""
        ctx = _ctx()
        _memory_set_handler({"key": "cookie_shape", "value": "PHPSESSID=..."}, ctx)
        notes = ctx.capabilities.query(type=CapabilityType.NOTE)
        assert len(notes) == 1
        assert notes[0].value["key"] == "cookie_shape"

    def test_does_not_mirror_underscore_prefixed_keys(self):
        """Internal bookkeeping (OOB tokens) is audit trail, not a
        capability. Prompts already hide these from the MEMORY block;
        the capability store should stay equally clean."""
        ctx = _ctx()
        _memory_set_handler({"key": "_oob_tokens", "value": "abc,def"}, ctx)
        assert ctx.capabilities.all() == []


class TestDiffResponsesHandler:
    def test_detects_status_change(self):
        out = _diff_responses_handler({
            "baseline": {"status_code": 200, "body": "ok", "elapsed_ms": 10, "body_length": 2},
            "probe": {"status_code": 500, "body": "err", "elapsed_ms": 12, "body_length": 3},
        }, _ctx())
        assert out["status_changed"] is True
        assert out["status_baseline"] == 200
        assert out["status_probe"] == 500

    def test_computes_length_and_timing_deltas(self):
        """Timing delta is how a time-based SQLi specialist confirms.
        Length delta is how a boolean-based SQLi specialist confirms."""
        out = _diff_responses_handler({
            "baseline": {"status_code": 200, "body": "a", "elapsed_ms": 50, "body_length": 1},
            "probe": {"status_code": 200, "body": "a" * 100, "elapsed_ms": 5_200, "body_length": 100},
        }, _ctx())
        assert out["length_delta"] == 99
        assert out["elapsed_delta_ms"] == 5_150

    def test_reports_added_and_removed_lines(self):
        out = _diff_responses_handler({
            "baseline": {"status_code": 200, "body": "hello\nworld", "elapsed_ms": 10},
            "probe": {"status_code": 200, "body": "hello\nuid=0(root)", "elapsed_ms": 10},
        }, _ctx())
        assert "uid=0(root)" in out["added_lines"]
        assert "world" in out["removed_lines"]

    def test_rejects_non_dict_inputs(self):
        """LLMs occasionally pass strings instead of objects. Surface the
        error rather than crashing."""
        out = _diff_responses_handler({"baseline": "{}", "probe": {}}, _ctx())
        assert "error" in out


class TestOOBHandlers:
    def test_get_probe_unconfigured(self, monkeypatch):
        """With no collaborator URL set, the tool returns configured=False
        and the prompts instruct the model to skip blind-case branches."""
        monkeypatch.setattr("scanner.vm.agent_specialists._OOB_BASE_URL", "")
        out = _oob_get_probe_handler({}, _ctx())
        assert out["configured"] is False
        assert "error" in out

    def test_get_probe_configured_returns_unique_token(self, monkeypatch):
        monkeypatch.setattr(
            "scanner.vm.agent_specialists._OOB_BASE_URL", "https://collab.example",
        )
        ctx = _ctx()
        out = _oob_get_probe_handler({}, ctx)
        assert out["configured"] is True
        assert out["probe_url"].startswith("https://collab.example/probe/")
        assert out["token"] in out["probe_url"]
        # Token is recorded in shared_memory for audit trail.
        assert out["token"] in ctx.shared_memory.get("_oob_tokens", "")

    def test_get_probe_tokens_accumulate(self, monkeypatch):
        """Multiple probes in one run are recorded without clobbering."""
        monkeypatch.setattr(
            "scanner.vm.agent_specialists._OOB_BASE_URL", "https://collab.example",
        )
        ctx = _ctx()
        t1 = _oob_get_probe_handler({}, ctx)["token"]
        t2 = _oob_get_probe_handler({}, ctx)["token"]
        assert t1 != t2
        assert t1 in ctx.shared_memory["_oob_tokens"]
        assert t2 in ctx.shared_memory["_oob_tokens"]

    def test_check_unconfigured(self, monkeypatch):
        monkeypatch.setattr("scanner.vm.agent_specialists._OOB_BASE_URL", "")
        out = _oob_check_handler({"token": "abc"}, _ctx())
        assert out["configured"] is False

    def test_check_requires_token(self, monkeypatch):
        monkeypatch.setattr(
            "scanner.vm.agent_specialists._OOB_BASE_URL", "https://collab.example",
        )
        out = _oob_check_handler({}, _ctx(http_client=MagicMock()))
        assert "error" in out

    def test_check_parses_hits_field(self, monkeypatch):
        monkeypatch.setattr(
            "scanner.vm.agent_specialists._OOB_BASE_URL", "https://collab.example",
        )
        mock_client = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"hits": ["GET /probe/abc from 1.2.3.4", "another"]}
        mock_client.get.return_value = mock_resp
        out = _oob_check_handler({"token": "abc"}, _ctx(http_client=mock_client))
        assert out["hit_count"] == 2
        assert len(out["hits"]) == 2

    def test_check_parses_interactions_field(self, monkeypatch):
        """interact.sh-style collaborators use 'interactions' not 'hits' —
        we accept both to avoid locking users into one backend."""
        monkeypatch.setattr(
            "scanner.vm.agent_specialists._OOB_BASE_URL", "https://collab.example",
        )
        mock_client = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"interactions": [{"type": "dns"}]}
        mock_client.get.return_value = mock_resp
        out = _oob_check_handler({"token": "abc"}, _ctx(http_client=mock_client))
        assert out["hit_count"] == 1

    def test_check_handles_collaborator_error(self, monkeypatch):
        """A 500 from the collaborator shouldn't bubble into the LLM as an
        unclassified tool exception — it should come back as a diagnostic
        error dict so the model can move on."""
        monkeypatch.setattr(
            "scanner.vm.agent_specialists._OOB_BASE_URL", "https://collab.example",
        )
        mock_client = MagicMock()
        mock_client.get.return_value = MagicMock(status_code=503)
        out = _oob_check_handler({"token": "abc"}, _ctx(http_client=mock_client))
        assert "error" in out
        assert "503" in out["error"]


class TestToolSchemas:
    def test_anthropic_schemas_include_all_tools(self):
        schemas = tool_schemas_for_anthropic()
        names = {s["name"] for s in schemas}
        assert names == set(TOOLS.keys())

    def test_schemas_have_required_shape(self):
        """Anthropic tool-use requires name, description, input_schema."""
        for s in tool_schemas_for_anthropic():
            assert "name" in s
            assert "description" in s
            assert s["input_schema"]["type"] == "object"


class TestSpecialistsRegistry:
    def test_specialists_match_categories(self):
        assert set(SPECIALISTS.keys()) == set(AGENT_CATEGORIES)
        # 9 today: injection, xss, ssrf, authn, authz, csrf, files, upload, session.
        # Adding a new category here is a deliberate expansion — update
        # the assertion and document the new spec's rationale in the
        # SPECIALISTS dict comment.
        assert len(AGENT_CATEGORIES) == 9

    def test_every_specialist_has_bounded_iterations(self):
        """Nobody runs unbounded — every prompt must pair with a cap."""
        for spec in SPECIALISTS.values():
            assert 1 <= spec.max_iterations <= 20

    def test_every_specialist_references_emit_finding(self):
        """Prompts must tell the model how to surface findings. Without
        this the agent does all the work and emits nothing."""
        for spec in SPECIALISTS.values():
            assert "emit_finding" in spec.system_prompt.lower() or \
                   "emit finding" in spec.system_prompt.lower() or \
                   "EMIT_FINDING" in spec.system_prompt


class TestBuildInitialMessage:
    def test_omits_memory_block_when_empty(self):
        """Default state — no prior specialists have run, so no MEMORY
        section should appear and pollute the prompt."""
        from scanner.vm.agent_worker import _build_initial_message
        msg = _build_initial_message(_ctx(), SPECIALISTS["injection"])
        assert "MEMORY" not in msg

    def test_includes_memory_block_when_populated(self):
        """Hints from earlier specialists must land in the prompt so the
        model uses them instead of re-discovering."""
        from scanner.vm.agent_worker import _build_initial_message
        ctx = _ctx(shared_memory={"valid_user_id": "42", "waf_present": "false"})
        msg = _build_initial_message(ctx, SPECIALISTS["authz"])
        assert "MEMORY" in msg
        assert "valid_user_id" in msg
        assert "42" in msg

    def test_hides_underscore_prefixed_keys(self):
        """Internal bookkeeping (OOB token list) must not leak into the
        prompt — the model doesn't need our audit trail, and it bloats
        the context for every specialist."""
        from scanner.vm.agent_worker import _build_initial_message
        ctx = _ctx(shared_memory={"_oob_tokens": "abc,def", "jwt_leaked": "true"})
        msg = _build_initial_message(ctx, SPECIALISTS["authn"])
        assert "_oob_tokens" not in msg
        assert "abc" not in msg
        assert "jwt_leaked" in msg

    def test_renders_capabilities_block_when_populated(self):
        """Typed primitives stashed by earlier specialists must surface
        as a CAPABILITIES block so the next specialist sees structured
        facts, not just prose hints. Drives the composition story once
        downstream prompts are rewritten to consume this block."""
        from scanner.vm.agent_specialists import _memory_set_handler
        from scanner.vm.agent_worker import _build_initial_message
        ctx = _ctx(current_specialist="authn")
        _memory_set_handler({"key": "valid_credentials", "value": "admin:admin"}, ctx)
        # Switch specialist context so the block renders for the next run.
        ctx.current_specialist = "injection"
        msg = _build_initial_message(ctx, SPECIALISTS["injection"])
        assert "CAPABILITIES" in msg
        assert "credentials" in msg
        assert "admin" in msg

    def test_omits_capabilities_block_when_empty(self):
        """Default state — no capabilities recorded, no block in the
        prompt. The header noise-floor stays low for the common case."""
        from scanner.vm.agent_worker import _build_initial_message
        msg = _build_initial_message(_ctx(), SPECIALISTS["injection"])
        assert "CAPABILITIES" not in msg


class TestExtractForms:
    """Structured form parsing is how every content-discovery prompt
    steps — asking the model to parse HTML in-prompt is wasteful and
    misses hidden CSRF tokens on ~30% of real forms. The parser is
    deterministic, so the tests pin down the known-hard cases.
    """

    def test_parses_single_form_with_inputs(self):
        html = '''
        <form action="/login" method="post">
          <input type="text" name="username" placeholder="user" required>
          <input type="password" name="password">
          <input type="hidden" name="csrf_token" value="abc123">
          <input type="submit" name="Login" value="Login">
        </form>
        '''
        forms = _extract_forms(html)
        assert len(forms) == 1
        form = forms[0]
        assert form["action"] == "/login"
        assert form["method"] == "POST"
        assert form["has_password_input"] is True
        assert form["is_state_changing"] is True

        names = {i["name"] for i in form["inputs"]}
        assert {"username", "password", "csrf_token", "Login"} <= names

        csrf_input = next(i for i in form["inputs"] if i["name"] == "csrf_token")
        assert csrf_input["looks_like_csrf"] is True

    def test_recognises_csrf_token_name_variants(self):
        """The CSRF name regex must catch the common naming conventions —
        missing one means the LLM won't know which hidden field to
        preserve, and POSTs fail silently."""
        for name in (
            "csrf", "_csrf", "csrfmiddlewaretoken",
            "authenticity_token", "user_token",
            "__RequestVerificationToken", "anti-forgery",
        ):
            html = f'<form><input type="hidden" name="{name}" value="x"></form>'
            forms = _extract_forms(html)
            assert forms[0]["inputs"][0]["looks_like_csrf"] is True, name

    def test_multiple_forms_independent(self):
        """Pages often carry a search form + a login form. The parser
        must emit both, not merge them."""
        html = '''
        <form action="/search" method="get"><input name="q"></form>
        <form action="/login" method="post"><input type="password" name="p"></form>
        '''
        forms = _extract_forms(html)
        assert len(forms) == 2
        assert forms[0]["method"] == "GET"
        assert forms[0]["is_state_changing"] is False
        assert forms[1]["method"] == "POST"

    def test_textarea_and_select_captured(self):
        """XSS / injection specialists target textareas and selects
        just as often as text inputs — the parser must emit them."""
        html = '''
        <form><textarea name="body"></textarea>
        <select name="country"></select></form>
        '''
        forms = _extract_forms(html)
        kinds = {i["kind"] for i in forms[0]["inputs"]}
        assert "textarea" in kinds
        assert "select" in kinds

    def test_empty_html_returns_empty(self):
        handler_result = _extract_forms_handler({"html": ""}, _ctx())
        assert handler_result == {"forms": [], "total": 0}

    def test_handler_rejects_non_string(self):
        result = _extract_forms_handler({"html": 123}, _ctx())
        assert "error" in result


class TestAnalyzeJwtHandler:
    """Common JWT misconfigurations the tool must catch. Each
    corresponds to an actual security report pattern seen in the wild.
    """

    @staticmethod
    def _jwt(header: dict, payload: dict, signature: str = "sig") -> str:
        import base64
        def enc(d):
            raw = json.dumps(d, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        parts = [enc(header), enc(payload)]
        if signature is not None:
            parts.append(signature)
        return ".".join(parts)

    def test_alg_none_flagged_critical(self):
        """The canonical JWT misconfiguration — server accepts unsigned
        tokens. Must be flagged critical so the LLM emits a finding."""
        token = self._jwt({"alg": "none", "typ": "JWT"}, {"user": "admin"}, "")
        result = _analyze_jwt_handler({"token": token}, _ctx())
        assert result["valid_structure"] is True
        assert result["highest_severity"] == "critical"
        ids = {i["id"] for i in result["issues"]}
        assert "alg_none_accepted_in_header" in ids

    def test_missing_signature_segment_flagged(self):
        """Two-segment JWT with a real alg declared — almost always a
        bug in the signing pipeline. High severity."""
        token = self._jwt({"alg": "HS256"}, {"user": "x"}, signature=None)
        result = _analyze_jwt_handler({"token": token}, _ctx())
        ids = {i["id"] for i in result["issues"]}
        assert "missing_signature_segment" in ids

    def test_missing_exp_flagged(self):
        token = self._jwt({"alg": "HS256"}, {"user": "x"}, "abc")
        result = _analyze_jwt_handler({"token": token}, _ctx())
        ids = {i["id"] for i in result["issues"]}
        assert "missing_exp" in ids

    def test_admin_claim_flagged(self):
        """A claim named ``admin`` in the payload is a composition
        signal — if the LLM has alg:none primitive, it can flip this."""
        token = self._jwt({"alg": "HS256"}, {"admin": False}, "abc")
        result = _analyze_jwt_handler({"token": token}, _ctx())
        ids = {i["id"] for i in result["issues"]}
        assert "claim_admin_controls_privileges" in ids

    def test_malformed_structure_rejected(self):
        result = _analyze_jwt_handler({"token": "not.a.jwt.at.all"}, _ctx())
        assert result["valid_structure"] is False

    def test_missing_token_returns_error(self):
        assert "error" in _analyze_jwt_handler({}, _ctx())


class TestCheckSecurityHeadersHandler:
    def _resp(self, *, url="https://example.com/", headers=None, status=200):
        return {
            "url": url, "status_code": status, "headers": headers or {},
        }

    def test_flags_missing_hsts_on_https(self):
        out = _check_security_headers_handler(
            {"response": self._resp(headers={})}, _ctx(),
        )
        ids = {f["id"] for f in out["findings"]}
        assert "missing_hsts" in ids

    def test_does_not_flag_missing_hsts_on_http(self):
        """HSTS is meaningless on HTTP — the flag comes via the HTTPS
        connection. Don't surface a false positive."""
        out = _check_security_headers_handler(
            {"response": self._resp(url="http://example.com/")}, _ctx(),
        )
        ids = {f["id"] for f in out["findings"]}
        assert "missing_hsts" not in ids

    def test_flags_hsts_short_max_age(self):
        out = _check_security_headers_handler(
            {"response": self._resp(headers={
                "Strict-Transport-Security": "max-age=3600",
            })}, _ctx(),
        )
        ids = {f["id"] for f in out["findings"]}
        assert "hsts_short_max_age" in ids

    def test_flags_missing_csp(self):
        out = _check_security_headers_handler(
            {"response": self._resp(headers={})}, _ctx(),
        )
        ids = {f["id"] for f in out["findings"]}
        assert "missing_csp" in ids

    def test_flags_csp_unsafe_inline(self):
        out = _check_security_headers_handler(
            {"response": self._resp(headers={
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            })}, _ctx(),
        )
        ids = {f["id"] for f in out["findings"]}
        assert "csp_unsafe_directives" in ids

    def test_flags_missing_clickjack_protection(self):
        out = _check_security_headers_handler(
            {"response": self._resp(headers={})}, _ctx(),
        )
        ids = {f["id"] for f in out["findings"]}
        assert "missing_clickjack_protection" in ids

    def test_csp_frame_ancestors_counts_as_clickjack_protection(self):
        """Modern apps use CSP frame-ancestors instead of X-Frame-Options.
        Must not flag both if CSP covers it."""
        out = _check_security_headers_handler(
            {"response": self._resp(headers={
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            })}, _ctx(),
        )
        ids = {f["id"] for f in out["findings"]}
        assert "missing_clickjack_protection" not in ids

    def test_flags_cookie_missing_httponly(self):
        out = _check_security_headers_handler(
            {"response": self._resp(headers={
                "Set-Cookie": "sid=abc; Path=/",
            })}, _ctx(),
        )
        ids = {f["id"] for f in out["findings"]}
        assert "cookie_missing_httponly" in ids

    def test_well_configured_response_no_findings(self):
        """Sanity check — a fully-hardened response produces zero
        findings. Protects against regex drift breaking recognition."""
        out = _check_security_headers_handler({"response": self._resp(
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Set-Cookie": "sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
            },
        )}, _ctx())
        assert out["findings"] == [], out["findings"]

    def test_rejects_non_dict_response(self):
        assert "error" in _check_security_headers_handler(
            {"response": "not a dict"}, _ctx(),
        )


class TestRenderPageHandler:
    """The heavy one — we don't actually drive Chromium in unit tests
    (that belongs in integration). What we pin down is the no-playwright
    graceful-degrade path and argument validation.
    """

    def test_returns_unavailable_when_playwright_missing(self, monkeypatch):
        """Simulate an image built without chromium. Handler must not
        crash — just return available=false so the LLM falls back."""
        import sys
        # Temporarily shadow playwright module with ImportError-raising
        # proxy by removing it from sys.modules and blocking reimport.
        monkeypatch.setitem(sys.modules, "playwright", None)
        monkeypatch.setitem(sys.modules, "playwright.sync_api", None)

        result = _render_page_handler({"url": "https://example.com"}, _ctx())
        assert result["available"] is False
        assert "error" in result

    def test_rejects_unsafe_scheme(self):
        result = _render_page_handler({"url": "file:///etc/passwd"}, _ctx())
        assert "error" in result

    def test_rejects_empty_url(self):
        result = _render_page_handler({"url": ""}, _ctx())
        assert "error" in result

    def test_rejects_past_deadline(self):
        result = _render_page_handler(
            {"url": "https://example.com"}, _ctx(deadline=0),
        )
        assert "error" in result


class TestPerSpecialistModelRouting:
    """The authn-on-Sonnet story: authn declares preferred_provider +
    preferred_model, the worker resolves a specific adapter for it,
    and the rest of the specialists stay on the scan-wide default.
    """

    def test_authn_declares_preferred_provider(self):
        """Regression guard — the declaration is what makes the
        routing happen. If someone reverts it, the scan quietly
        degrades back to Flash for authn. Routed through Vertex-
        hosted Claude so billing stays on the existing GCP project."""
        authn = SPECIALISTS["authn"]
        assert authn.preferred_provider == "vertex_ai"
        assert authn.preferred_model.startswith("claude-")

    def test_injection_declares_preferred_provider(self):
        """Injection is the composition-target counterpart to authn
        (authn is the source). Same multi-step orchestration profile,
        same need for a stronger model. Empirically Flash yielded
        enriched runs that produced zero HTTP probes — Sonnet fixes
        it. Routed via Vertex for GCP billing (same as authn)."""
        injection = SPECIALISTS["injection"]
        assert injection.preferred_provider == "vertex_ai"
        assert injection.preferred_model.startswith("claude-")

    def test_authn_max_iterations_bumped(self):
        """Authn's tool sequence is the longest — doubled from the
        pre-composition budget."""
        assert SPECIALISTS["authn"].max_iterations >= 20

    def test_build_adapter_map_uses_preferred_when_model_differs(self, monkeypatch):
        """When the default is vertex_ai/gemini and a spec prefers
        vertex_ai/claude, the map must build a separate adapter for
        the spec — not short-circuit to the default just because the
        provider matches. This is the key fix for single-provider
        multi-model routing: authn + injection want Claude on Vertex,
        xss wants Gemini on Vertex, all three via the same GCP
        project."""
        from scanner.vm.agent_worker import _build_adapter_map
        from scanner.vm.llm_provider import LLMProviderInfo

        default_info = LLMProviderInfo(
            provider="vertex_ai", model="gemini-2.5-flash",
            config={"project_id": "p", "location": "us-central1"},
        )
        default_adapter = MagicMock(name="default_adapter")
        preferred_adapter = MagicMock(name="preferred_adapter")

        monkeypatch.setattr(
            "scanner.vm.agent_worker.build_adapter",
            lambda info: preferred_adapter,
        )

        integration_configs = {
            "vertex_ai": {"is_enabled": True, "project_id": "p"},
        }

        selected = [
            SPECIALISTS["authn"], SPECIALISTS["injection"], SPECIALISTS["xss"],
        ]
        amap = _build_adapter_map(
            selected, integration_configs, default_adapter, default_info,
        )
        # Both authn and injection declare a claude-* model → routed
        # to the preferred (Claude) adapter even though the provider
        # matches the default.
        assert amap["authn"] is preferred_adapter
        assert amap["injection"] is preferred_adapter
        # XSS has no preference → default (Gemini) adapter.
        assert amap["xss"] is default_adapter

    def test_build_adapter_map_short_circuits_when_model_matches(self, monkeypatch):
        """If a spec's preferred (provider, model) matches the scan
        default exactly, reuse the default adapter — no point building
        a second instance of the same thing."""
        from scanner.vm.agent_worker import _build_adapter_map
        from scanner.vm.llm_provider import LLMProviderInfo
        from dataclasses import replace

        default_info = LLMProviderInfo(
            provider="vertex_ai", model="gemini-2.5-flash",
            config={"project_id": "p", "location": "us-central1"},
        )
        default_adapter = MagicMock(name="default_adapter")

        # Force build_adapter to fail so we can prove it wasn't called.
        def _should_not_call(info):
            raise AssertionError(f"build_adapter called for {info!r}")
        monkeypatch.setattr(
            "scanner.vm.agent_worker.build_adapter", _should_not_call,
        )

        # Clone authn with preferred_model matching the default.
        spec = replace(
            SPECIALISTS["authn"],
            preferred_provider="vertex_ai",
            preferred_model="gemini-2.5-flash",
        )
        amap = _build_adapter_map(
            [spec], {}, default_adapter, default_info,
        )
        assert amap["authn"] is default_adapter

    def test_build_adapter_map_falls_back_when_preferred_unavailable(self, monkeypatch):
        """Air-gapped / Vertex-only deployment: Anthropic not
        configured, authn must still run — on the default adapter."""
        from scanner.vm.agent_worker import _build_adapter_map
        from scanner.vm.llm_provider import LLMProviderInfo

        default_info = LLMProviderInfo(
            provider="vertex_ai", model="gemini-2.5-flash", config={},
        )
        default_adapter = MagicMock()
        integration_configs: dict = {}  # no Anthropic configured

        amap = _build_adapter_map(
            [SPECIALISTS["authn"]], integration_configs,
            default_adapter, default_info,
        )
        assert amap["authn"] is default_adapter


class TestExtractHiddenFields:
    """The hidden-field parser is what makes ``try_login`` robust on
    apps with per-session CSRF tokens (DVWA, Django, Rails). If it
    drops a token, the POST fails silently and default-creds goes
    undetected.
    """

    def test_extracts_dvwa_style_user_token(self):
        html = (
            '<form action="login.php" method="post">'
            '<input type="text" name="username" />'
            '<input type="password" name="password" />'
            '<input type="hidden" name="user_token" value="abc123" />'
            '<input type="submit" name="Login" value="Login" />'
            '</form>'
        )
        fields = _extract_hidden_fields(html)
        assert fields == {"user_token": "abc123"}

    def test_extracts_multiple_hidden_fields(self):
        """Rails-style forms carry both ``authenticity_token`` AND
        ``utf8``. Both must surface so the POST validates."""
        html = (
            '<input type="hidden" name="authenticity_token" value="xyz" />'
            '<input type="hidden" name="utf8" value="&#x2713;" />'
        )
        fields = _extract_hidden_fields(html)
        assert fields["authenticity_token"] == "xyz"
        assert fields["utf8"] == "&#x2713;"

    def test_handles_unquoted_attributes(self):
        """Real HTML often uses unquoted values. Regex must survive
        that without dropping fields."""
        html = '<input type=hidden name=token value=raw123>'
        fields = _extract_hidden_fields(html)
        assert fields == {"token": "raw123"}

    def test_handles_single_quoted_values(self):
        html = "<input type='hidden' name='csrf' value='q1' />"
        fields = _extract_hidden_fields(html)
        assert fields == {"csrf": "q1"}

    def test_ignores_non_hidden_inputs(self):
        """Must not pick up visible fields — those are the credentials
        we'll fill in ourselves, and accidentally echoing a placeholder
        value (``value="enter username"``) would break the login POST."""
        html = (
            '<input type="text" name="username" value="" />'
            '<input type="password" name="password" />'
            '<input type="hidden" name="token" value="t1" />'
        )
        fields = _extract_hidden_fields(html)
        assert fields == {"token": "t1"}

    def test_handles_empty_value(self):
        """A hidden field may be intentionally blank (placeholder to
        be filled by JS). We capture it so the POST body shape matches
        what the form expected."""
        html = '<input type="hidden" name="empty" value="" />'
        fields = _extract_hidden_fields(html)
        assert fields == {"empty": ""}

    def test_no_forms_returns_empty(self):
        assert _extract_hidden_fields("<html><body>nothing</body></html>") == {}


class TestClassifyLoginSuccess:
    """The heuristic is the difference between ``authn finds DVWA creds
    and unlocks composition`` and ``authn runs 8 iterations doing
    nothing``. Each signal below has been observed in the wild.
    """

    def test_redirected_away_from_login_is_success(self):
        """DVWA's canonical success: POST /login.php → 302 → /index.php."""
        ok, reason = _classify_login_success(
            login_url="http://dvwa/login.php",
            final_url="http://dvwa/index.php",
            final_status=200,
            body="<a href=logout.php>Logout</a>",
        )
        assert ok is True

    def test_failure_marker_overrides_status(self):
        """Even on a 200 OK with seemingly-fine URL, an explicit
        ``Login failed`` marker must veto success. Covers apps that
        re-render the login page with an error div."""
        ok, reason = _classify_login_success(
            login_url="http://dvwa/login.php",
            final_url="http://dvwa/login.php",
            final_status=200,
            body="<div class='error'>Login failed.</div>",
        )
        assert ok is False
        assert "failure_marker" in reason

    def test_5xx_is_failure(self):
        ok, _ = _classify_login_success(
            login_url="http://app/login", final_url="http://app/login",
            final_status=500, body="",
        )
        assert ok is False

    def test_post_auth_marker_without_redirect(self):
        """SPAs sometimes return 200 with the same URL but a
        dashboard-shaped body. Logout link is a strong post-auth tell."""
        ok, _ = _classify_login_success(
            login_url="http://app/login", final_url="http://app/login",
            final_status=200, body="<a href=/logout>Sign out</a>",
        )
        assert ok is True

    def test_ambiguous_response_is_not_success(self):
        """No redirect, no markers → can't claim success. Beats a
        false-positive CRED commit that would confuse composition."""
        ok, _ = _classify_login_success(
            login_url="http://app/login", final_url="http://app/login",
            final_status=200, body="<html></html>",
        )
        assert ok is False

    def test_redirect_to_another_login_is_not_success(self):
        """Some apps 302 to /signin on failure. Must not classify as
        success just because the URL changed."""
        ok, _ = _classify_login_success(
            login_url="http://app/login", final_url="http://app/signin?error=1",
            final_status=200, body="",
        )
        assert ok is False


class TestTryLoginHandler:
    """End-to-end handler test against a mocked httpx client. Covers
    the hot paths: successful login auto-commits a CRED, failure does
    not, hidden fields get forwarded verbatim, and errors fail gracefully
    without leaving partial state in the capability store.
    """

    @staticmethod
    def _responses(*args):
        """Build a MagicMock.request side-effect that yields the given
        response sequence in order."""
        responses = list(args)
        def _side_effect(*_a, **_kw):
            if not responses:
                raise AssertionError("client called more times than expected")
            return responses.pop(0)
        return _side_effect

    @staticmethod
    def _resp(status=200, text="", url="http://dvwa/login.php"):
        r = MagicMock()
        r.status_code = status
        r.text = text
        r.url = url
        r.headers = {}
        r.content = text.encode() if isinstance(text, str) else b""
        return r

    def test_successful_login_commits_cred_capability(self):
        """Happy path: authn's Step 2 with DVWA-shaped success. Tool
        must auto-commit so composition fires even if the LLM skips
        the follow-up tool calls."""
        client = MagicMock()
        client.request.side_effect = self._responses(
            self._resp(  # GET /login.php
                status=200,
                text='<form><input type="hidden" name="user_token" value="tok1"></form>',
            ),
            self._resp(  # POST /login.php → followed to /index.php
                status=200,
                text="<a href=logout.php>Logout</a>",
                url="http://dvwa/index.php",
            ),
        )
        ctx = _ctx(http_client=client, current_specialist="authn")

        result = _try_login_handler({
            "login_url": "http://dvwa/login.php",
            "username": "admin",
            "password": "password",
            "extra_static_fields": {"Login": "Login"},
        }, ctx)

        assert result["likely_successful"] is True
        assert result["capability_committed"] is True
        assert result["extracted_hidden_fields"] == ["user_token"]
        assert "user_token" in result["posted_field_names"]
        assert "Login" in result["posted_field_names"]
        assert "username" in result["posted_field_names"]
        creds = ctx.capabilities.query(type=CapabilityType.CRED)
        assert len(creds) == 1
        assert creds[0].value["username"] == "admin"
        assert creds[0].provenance == "specialist:authn"
        # Shared memory mirrored too, so prompts reading MEMORY still work.
        assert ctx.shared_memory["valid_credentials"] == "admin:password"

    def test_failed_login_does_not_commit(self):
        """Wrong creds → 200 OK on login page with failure marker.
        Must NOT commit a CRED — a false commit would trigger spurious
        composition re-runs against an unauthenticated session."""
        client = MagicMock()
        client.request.side_effect = self._responses(
            self._resp(
                status=200,
                text='<input type="hidden" name="token" value="t">',
            ),
            self._resp(
                status=200,
                text="<div>Login failed.</div>",
                url="http://dvwa/login.php",
            ),
        )
        ctx = _ctx(http_client=client, current_specialist="authn")

        result = _try_login_handler({
            "login_url": "http://dvwa/login.php",
            "username": "wrong", "password": "wrong",
        }, ctx)

        assert result["likely_successful"] is False
        assert result["capability_committed"] is False
        assert ctx.capabilities.query(type=CapabilityType.CRED) == []
        assert "valid_credentials" not in ctx.shared_memory

    def test_rejects_missing_required_params(self):
        ctx = _ctx(http_client=MagicMock())
        result = _try_login_handler({"login_url": "http://x"}, ctx)
        assert "error" in result

    def test_rejects_unsafe_scheme(self):
        """file:// / javascript: etc. must never touch the network,
        same discipline as http_request."""
        ctx = _ctx(http_client=MagicMock())
        result = _try_login_handler({
            "login_url": "file:///etc/passwd",
            "username": "a", "password": "b",
        }, ctx)
        assert "error" in result

    def test_rejects_past_deadline(self):
        ctx = _ctx(http_client=MagicMock(), deadline=0)
        result = _try_login_handler({
            "login_url": "http://x/login",
            "username": "a", "password": "b",
        }, ctx)
        assert "error" in result

    def test_get_failure_propagates_error(self):
        """If the login page can't even be reached, we surface the
        error to the LLM — which then knows not to waste iterations
        retrying the same dead URL."""
        client = MagicMock()
        client.request.side_effect = Exception("connection refused")
        ctx = _ctx(http_client=client)
        result = _try_login_handler({
            "login_url": "http://dead/login",
            "username": "a", "password": "b",
        }, ctx)
        assert "error" in result
        assert "GET" in result["error"]

    def test_custom_field_names_are_used(self):
        """Real apps use ``user`` / ``pass`` / ``email`` / ``j_username``.
        Field-name overrides must land in the POST body verbatim."""
        client = MagicMock()
        client.request.side_effect = self._responses(
            self._resp(status=200, text="<html></html>"),
            self._resp(status=200, text="ok",
                       url="http://app/dashboard"),
        )
        ctx = _ctx(http_client=client)

        result = _try_login_handler({
            "login_url": "http://app/login",
            "username": "foo", "password": "bar",
            "username_field": "email",
            "password_field": "pwd",
        }, ctx)

        assert "email" in result["posted_field_names"]
        assert "pwd" in result["posted_field_names"]
        # Check the actual POST call carried the correct data.
        post_call = client.request.call_args_list[1]
        assert post_call.kwargs["data"]["email"] == "foo"
        assert post_call.kwargs["data"]["pwd"] == "bar"


class TestSeedScanConfigCapability:
    """Scan-configured credentials must materialise as capabilities so
    the composition machinery (hints, scheduler idempotency, re-runs
    against identifier-bearing caps) works uniformly whether the
    primitive came from the operator up front or from authn's
    discovery path. Before this, operators passing ``credentials={...}``
    got authenticated probes but an empty CAPABILITIES block — no
    prompt steer toward post-auth endpoints.
    """

    def test_basic_creates_cred_capability(self):
        ctx = _ctx()
        _seed_scan_config_capability(ctx, {
            "type": "basic", "username": "admin", "password": "password",
        })
        creds = ctx.capabilities.query(type=CapabilityType.CRED)
        assert len(creds) == 1
        assert creds[0].value["username"] == "admin"
        assert creds[0].provenance == "scan_config"

    def test_bearer_creates_session_capability(self):
        ctx = _ctx()
        _seed_scan_config_capability(ctx, {
            "type": "bearer", "token": "eyJhbGciOi...",
        })
        sessions = ctx.capabilities.query(type=CapabilityType.SESSION)
        assert len(sessions) == 1
        assert sessions[0].value["jwt"].startswith("eyJ")

    def test_cookie_creates_session_capability(self):
        """DVWA-shape: operator logs in manually, pastes
        PHPSESSID=...; security=low into scan config."""
        ctx = _ctx()
        _seed_scan_config_capability(ctx, {
            "type": "cookie", "cookie": "PHPSESSID=abc; security=low",
        })
        sessions = ctx.capabilities.query(type=CapabilityType.SESSION)
        assert len(sessions) == 1
        assert "PHPSESSID" in sessions[0].value["cookie"]

    def test_empty_credentials_is_noop(self):
        """No credentials → no capability. Prevents spurious CAPABILITIES
        block on anonymous scans where the whole point is to see what
        a no-auth probe finds."""
        ctx = _ctx()
        _seed_scan_config_capability(ctx, None)
        assert ctx.capabilities.all() == []

    def test_basic_with_empty_fields_is_noop(self):
        """Malformed scan config (missing username + password) must
        not produce a useless CRED row with empty strings."""
        ctx = _ctx()
        _seed_scan_config_capability(ctx, {
            "type": "basic", "username": "", "password": "",
        })
        assert ctx.capabilities.all() == []

    def test_unknown_type_is_noop(self):
        """Unrecognised auth scheme (e.g. future NTLM) falls through
        without crashing — scan still runs with whatever headers were
        derived, just without a typed capability."""
        ctx = _ctx()
        _seed_scan_config_capability(ctx, {"type": "ntlm", "token": "x"})
        assert ctx.capabilities.all() == []


class TestApplyDiscoveredIdentity:
    """The auth-refresh half of composition. Without this, a CRED
    capability committed by authn is visible to the LLM but the
    http_request tool's default headers stay anonymous — the re-run
    of injection against admin endpoints fails to authenticate.

    Non-destructive invariants are load-bearing: scan-configured
    headers reflect operator intent and must not be silently replaced.
    """

    @staticmethod
    def _cred_cap(ctx, user="admin", pw="admin", confidence=0.95) -> Capability:
        return Capability(
            type=CapabilityType.CRED,
            scope=asset_scope(ctx.asset_id),
            value={"scheme": "basic", "username": user, "password": pw},
            confidence=confidence,
            provenance="specialist:authn",
        )

    def test_injects_basic_auth_from_cred_capability(self):
        """Canonical chain: authn discovered admin/admin, the next
        specialist's probes must go out authenticated without the LLM
        constructing the header itself."""
        ctx = _ctx()
        ctx.capabilities.add(self._cred_cap(ctx))
        added = _apply_discovered_identity(ctx)
        assert added == ["Authorization"]
        assert ctx.headers["Authorization"].startswith("Basic ")

    def test_does_not_overwrite_existing_authorization(self):
        """Scan-configured auth wins over discovered — operator intent
        is authoritative. A session broker token should never be
        replaced by a guessed admin/admin."""
        ctx = _ctx(headers={"Authorization": "Bearer scan-token"})
        ctx.capabilities.add(self._cred_cap(ctx))
        added = _apply_discovered_identity(ctx)
        assert added == []
        assert ctx.headers["Authorization"] == "Bearer scan-token"

    def test_case_insensitive_header_check(self):
        """HTTP headers are case-insensitive per RFC 7230. A lowercase
        existing ``authorization`` must still block injection."""
        ctx = _ctx(headers={"authorization": "Bearer scan-token"})
        ctx.capabilities.add(self._cred_cap(ctx))
        added = _apply_discovered_identity(ctx)
        assert added == []

    def test_prefers_higher_confidence_cred(self):
        """When multiple creds exist, the stronger confidence wins so
        an OOB-validated pair beats a timing-based guess."""
        ctx = _ctx()
        ctx.capabilities.add(self._cred_cap(ctx, user="weak", pw="x", confidence=0.6))
        ctx.capabilities.add(self._cred_cap(ctx, user="strong", pw="y", confidence=0.95))
        _apply_discovered_identity(ctx)
        import base64
        auth = ctx.headers["Authorization"]
        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode()
        assert decoded == "strong:y"

    def test_falls_back_to_jwt_session_when_no_creds(self):
        """A SESSION capability with a JWT must become ``Authorization:
        Bearer ...`` when no CRED exists — this is how authz's
        ``jwt_leaked_in_body`` path unlocks authenticated probing."""
        ctx = _ctx()
        ctx.capabilities.add(Capability(
            type=CapabilityType.SESSION,
            scope=asset_scope(ctx.asset_id),
            value={"jwt": "eyJhbGciOiJub25lIn0..."},
            confidence=0.9,
        ))
        added = _apply_discovered_identity(ctx)
        assert added == ["Authorization"]
        assert ctx.headers["Authorization"] == "Bearer eyJhbGciOiJub25lIn0..."

    def test_injects_cookie_from_session_capability(self):
        ctx = _ctx()
        ctx.capabilities.add(Capability(
            type=CapabilityType.SESSION,
            scope=asset_scope(ctx.asset_id),
            value={"cookie": "sid=abc123"},
            confidence=0.9,
        ))
        added = _apply_discovered_identity(ctx)
        assert "Cookie" in added
        assert ctx.headers["Cookie"] == "sid=abc123"

    def test_cred_preferred_over_session_for_authorization(self):
        """When both CRED and a JWT-SESSION exist, CRED wins — concrete
        user:pass lets the LLM re-authenticate if the session expires
        mid-scan, whereas a bearer is one-shot."""
        ctx = _ctx()
        ctx.capabilities.add(self._cred_cap(ctx))
        ctx.capabilities.add(Capability(
            type=CapabilityType.SESSION,
            scope=asset_scope(ctx.asset_id),
            value={"jwt": "old-token"},
            confidence=0.99,  # higher confidence, still loses
        ))
        _apply_discovered_identity(ctx)
        assert ctx.headers["Authorization"].startswith("Basic ")

    def test_empty_store_is_noop(self):
        """Baseline case — no capabilities, no injection, no header
        mutation. Guards against the helper accidentally adding
        default creds when there's nothing to inject."""
        ctx = _ctx()
        added = _apply_discovered_identity(ctx)
        assert added == []
        assert ctx.headers == {}

    def test_does_not_inject_cred_with_missing_fields(self):
        """Malformed CRED capability (e.g. both username and password
        empty) must not produce ``Basic :`` auth — silently wrong
        header is worse than no header."""
        ctx = _ctx()
        ctx.capabilities.add(Capability(
            type=CapabilityType.CRED,
            scope=asset_scope(ctx.asset_id),
            value={"scheme": "basic", "username": "", "password": ""},
        ))
        added = _apply_discovered_identity(ctx)
        assert "Authorization" not in ctx.headers


class TestCompositionHints:
    """The prompt-side counterpart to identity injection. The LLM sees
    these bullets alongside the CAPABILITIES block so it knows HOW to
    exploit what was discovered, not just WHAT was discovered.
    """

    def test_empty_store_produces_no_hints(self):
        """Baseline runs must not see any composition bullets — keeps
        the initial message lean when there's nothing to compose yet."""
        assert _composition_hints(_ctx()) == []

    def test_cred_triggers_auth_hint(self):
        """The hint must tell the model two things: probes are already
        authenticated, and it should focus on post-auth endpoints —
        that's the whole composition payoff."""
        ctx = _ctx()
        ctx.capabilities.add(Capability(
            type=CapabilityType.CRED,
            scope=asset_scope(ctx.asset_id),
            value={"scheme": "basic", "username": "a", "password": "b"},
        ))
        hints = _composition_hints(ctx)
        assert len(hints) == 1
        assert "authenticated" in hints[0].lower()
        assert "admin" in hints[0].lower() or "/api" in hints[0].lower()

    def test_identifier_triggers_idor_hint(self):
        ctx = _ctx()
        ctx.capabilities.add(Capability(
            type=CapabilityType.IDENTIFIER,
            scope=asset_scope(ctx.asset_id),
            value={"kind": "user_id", "value": "42"},
        ))
        hints = _composition_hints(ctx)
        assert any("idor" in h.lower() or "authz" in h.lower() for h in hints)

    def test_internal_host_triggers_ssrf_hint(self):
        ctx = _ctx()
        ctx.capabilities.add(Capability(
            type=CapabilityType.INTERNAL_HOST,
            scope=asset_scope(ctx.asset_id),
            value={"host": "10.0.0.5", "port": 6379},
        ))
        hints = _composition_hints(ctx)
        assert any("ssrf" in h.lower() for h in hints)

    def test_multiple_primitives_produce_multiple_hints(self):
        """When several composition triggers fire on the same asset,
        each gets its own bullet — operators can trace exactly which
        primitives shaped the re-run prompt."""
        ctx = _ctx()
        ctx.capabilities.add(Capability(
            type=CapabilityType.CRED,
            scope=asset_scope(ctx.asset_id),
            value={"scheme": "basic", "username": "a", "password": "b"},
        ))
        ctx.capabilities.add(Capability(
            type=CapabilityType.IDENTIFIER,
            scope=asset_scope(ctx.asset_id),
            value={"kind": "user_id", "value": "42"},
        ))
        ctx.capabilities.add(Capability(
            type=CapabilityType.WEB_ROOT,
            scope=asset_scope(ctx.asset_id),
            value={"path": "/var/www/html"},
        ))
        assert len(_composition_hints(ctx)) == 3

    def test_hints_ignore_notes(self):
        """NOTE capabilities don't carry structured exploit semantics —
        they're hints for the model's judgement, not composition
        triggers. Must not produce COMPOSITION bullets."""
        ctx = _ctx()
        ctx.capabilities.add(Capability(
            type=CapabilityType.NOTE,
            scope=asset_scope(ctx.asset_id),
            value={"key": "waf", "text": "cloudflare"},
        ))
        assert _composition_hints(ctx) == []


class TestBuildInitialMessageComposition:
    """Integration-ish tests: ensure the identity injection AND the
    hints both land in the initial message when composition fires."""

    def test_composition_block_appears_when_hints_fire(self):
        from scanner.vm.agent_specialists import _memory_set_handler
        from scanner.vm.agent_worker import _build_initial_message
        ctx = _ctx(current_specialist="authn")
        _memory_set_handler({"key": "valid_credentials", "value": "admin:admin"}, ctx)
        ctx.current_specialist = "authz"
        msg = _build_initial_message(ctx, SPECIALISTS["authz"])
        assert "COMPOSITION GUIDANCE" in msg
        # CAPABILITIES block + COMPOSITION GUIDANCE block must coexist —
        # typed facts above, exploit instructions below.
        assert "CAPABILITIES" in msg
        assert msg.index("CAPABILITIES") < msg.index("COMPOSITION GUIDANCE")


class TestRunAgentScanAdhoc:
    """The adhoc task skips the asset_context / endpoint_slice DB queries
    and builds the AgentContext from the raw target. We exercise the
    pre-LLM branches — the specialist loop itself is covered by the
    asset-path tests.
    """

    @staticmethod
    def _run(target: str, org_id: str | None = None, credentials: dict | None = None, categories: list[str] | None = None) -> dict:
        import asyncio
        from scanner.vm.agent_worker import _run_agent_scan_adhoc_async
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                _run_agent_scan_adhoc_async(MagicMock(), target, org_id, credentials, categories)
            )
        finally:
            loop.close()

    @staticmethod
    def _fake_conn():
        """asyncpg.Connection stub whose .close() is awaitable."""
        from unittest.mock import AsyncMock
        conn = MagicMock()
        conn.close = AsyncMock(return_value=None)
        return conn

    def test_skips_when_no_provider_configured(self, monkeypatch):
        """No LLM key at all — the task must no-op cleanly, not crash.
        Mirrors the asset path's behaviour for air-gapped deployments."""
        from unittest.mock import AsyncMock

        monkeypatch.setattr(
            "scanner.vm.agent_worker.fetch_integration_configs",
            AsyncMock(return_value=[]),
        )
        monkeypatch.setattr(
            "scanner.vm.agent_worker.resolve_provider", lambda cfg: None,
        )
        monkeypatch.setattr(
            "scanner.vm.agent_worker.asyncpg.connect",
            AsyncMock(return_value=self._fake_conn()),
        )

        result = self._run("http://example.com")
        assert result["status"] == "skipped"
        assert "LLM provider" in result["error"]
        assert result["target"] == "http://example.com"

    def test_skips_when_no_applicable_specialists(self, monkeypatch):
        """A bare-IP target (no http scheme, no endpoints, no auth
        headers) has no specialists that apply. The task must skip
        without spending tokens."""
        from unittest.mock import AsyncMock

        provider_info = SimpleNamespace(provider="anthropic", model="claude-test")

        monkeypatch.setattr(
            "scanner.vm.agent_worker.fetch_integration_configs",
            AsyncMock(return_value=[]),
        )
        monkeypatch.setattr(
            "scanner.vm.agent_worker.resolve_provider", lambda cfg: provider_info,
        )
        monkeypatch.setattr(
            "scanner.vm.agent_worker.build_adapter", lambda p: MagicMock(),
        )
        monkeypatch.setattr(
            "scanner.vm.agent_worker.asyncpg.connect",
            AsyncMock(return_value=self._fake_conn()),
        )

        result = self._run("10.0.0.1")
        assert result["status"] == "skipped"
        assert "no applicable specialists" in result["error"]
