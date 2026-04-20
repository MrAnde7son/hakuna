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
    _check_pattern_handler,
    _emit_finding_handler,
    _has_any_http_endpoint,
    _has_auth_surface,
    _has_parameterised_endpoint,
    _request_handler,
    _safe_url,
    _summary_handler,
    seed_base_endpoint,
    select_applicable_specialists,
    tool_schemas_for_anthropic,
)
from scanner.vm.agent_worker import (
    _agent_payload_to_finding,
    _credentials_to_headers,
    _trim_evidence,
)


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

    def test_auth_surface_detects_provided_headers(self):
        """Session broker injected a cookie → we can run authn probes."""
        assert _has_auth_surface(_ctx(headers={"Cookie": "sid=x"}))

    def test_auth_surface_detects_auth_required_endpoint(self):
        eps = [{"url": "https://x/api", "auth_required": True}]
        assert _has_auth_surface(_ctx(endpoints=eps))

    def test_auth_surface_false_when_nothing_to_probe(self):
        assert not _has_auth_surface(_ctx())


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
        category + title + evidence_url → same template_id, so
        re-running the scan doesn't create dupes."""
        payload = {
            "severity": "medium", "title": "t", "description": "d",
            "evidence_url": "https://x/a", "verdict": "true_positive",
        }
        f1 = _agent_payload_to_finding(
            specialist=self._spec("injection"), payload=payload, target="https://x",
        )
        f2 = _agent_payload_to_finding(
            specialist=self._spec("injection"), payload=payload, target="https://x",
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
    def test_five_specialists_exactly(self):
        assert set(SPECIALISTS.keys()) == set(AGENT_CATEGORIES)
        assert len(AGENT_CATEGORIES) == 5

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
