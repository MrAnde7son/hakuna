"""Tests for the content discovery worker.

Deterministic pieces only: credential flattening, base URL resolution,
exposure rule matching, finding payload shape, ffuf result parsing,
param-target selection. The actual ffuf subprocess is stubbed — we
don't re-test ffuf's CLI, and spinning up an HTTP target per test
would couple the unit suite to network behavior.
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from scanner.vm.content_discovery_worker import (
    MAX_ENDPOINTS_PER_ASSET,
    _credentials_to_headers,
    _exposure_to_finding,
    _extract_hits,
    _load_exposure_rules,
    _path_from_hit,
    _redact_headers,
    _resolve_base_url,
    _rule_matches,
    _select_param_targets,
)


# ── Credential flattening ────────────────────────────────────────


class TestCredentialsToHeaders:
    def test_basic_emits_auth_header(self):
        h = _credentials_to_headers(
            {"type": "basic", "username": "alice", "password": "s3cret"}
        )
        assert h["Authorization"] == "Basic YWxpY2U6czNjcmV0"

    def test_bearer_token(self):
        h = _credentials_to_headers({"type": "bearer", "token": "t"})
        assert h == {"Authorization": "Bearer t"}

    def test_cookie(self):
        h = _credentials_to_headers({"type": "cookie", "cookie": "sid=xyz"})
        assert h == {"Cookie": "sid=xyz"}

    def test_none_returns_empty(self):
        assert _credentials_to_headers(None) == {}

    def test_extra_headers_layer(self):
        """Session broker folds csrf/cookie into `headers` — must merge on
        top of any primary scheme, same semantics as the other workers."""
        h = _credentials_to_headers(
            {"type": "bearer", "token": "t", "headers": {"X-CSRF": "v"}}
        )
        assert h["Authorization"] == "Bearer t"
        assert h["X-CSRF"] == "v"

    def test_header_only_credential(self):
        h = _credentials_to_headers(
            {"type": "header", "headers": {"X-API-Key": "k"}}
        )
        assert h == {"X-API-Key": "k"}


class TestRedactHeaders:
    def test_values_masked(self):
        assert _redact_headers({"Authorization": "Bearer t"}) == {"Authorization": "***"}

    def test_empty(self):
        assert _redact_headers({}) == {}


# ── Base URL resolution ──────────────────────────────────────────


class TestResolveBaseURL:
    def test_http_url_wins(self):
        asset = {"http_url": "https://api.example.com/some/path", "open_ports": [443]}
        # Path is stripped — we append FUZZ ourselves.
        assert _resolve_base_url(asset) == "https://api.example.com"

    def test_http_url_preserves_port(self):
        asset = {"http_url": "http://api.example.com:8080", "open_ports": [8080]}
        assert _resolve_base_url(asset) == "http://api.example.com:8080"

    def test_hostname_with_443_uses_https(self):
        asset = {"hostname": "api.example.com", "open_ports": [443]}
        assert _resolve_base_url(asset) == "https://api.example.com"

    def test_hostname_with_80_uses_http(self):
        asset = {"hostname": "api.example.com", "open_ports": [80]}
        assert _resolve_base_url(asset) == "http://api.example.com"

    def test_hostname_with_8080_uses_http_with_port(self):
        asset = {"hostname": "api.example.com", "open_ports": [8080]}
        assert _resolve_base_url(asset) == "http://api.example.com:8080"

    def test_ip_fallback(self):
        asset = {"hostname": None, "ip": "10.0.0.1", "open_ports": [80]}
        assert _resolve_base_url(asset) == "http://10.0.0.1"

    def test_no_web_port_returns_none(self):
        """OT/IoT assets often have no web port — must be skipped, not
        silently scanned on a guessed port (which is how you brick PLCs)."""
        asset = {"hostname": "plc1.internal", "open_ports": [502]}
        assert _resolve_base_url(asset) is None

    def test_no_host_returns_none(self):
        asset = {"open_ports": [443]}
        assert _resolve_base_url(asset) is None


# ── Exposure rule matching ───────────────────────────────────────


class TestRuleMatching:
    def _rule(self, **overrides):
        rule = {
            "id": "test-rule",
            "path_suffixes": [".env"],
            "status_codes": [200],
            "body_contains_any": ["SECRET="],
        }
        rule.update(overrides)
        return rule

    def test_full_match(self):
        rule = self._rule()
        assert _rule_matches(rule, "/.env", 200, "DB_HOST=x\nSECRET=abc") is True

    def test_path_suffix_only_nonmatching(self):
        rule = self._rule()
        assert _rule_matches(rule, "/index.html", 200, "SECRET=abc") is False

    def test_status_code_mismatch(self):
        rule = self._rule()
        assert _rule_matches(rule, "/.env", 404, "SECRET=abc") is False

    def test_body_keyword_mismatch(self):
        rule = self._rule()
        assert _rule_matches(rule, "/.env", 200, "hello world") is False

    def test_missing_body_check_is_permissive(self):
        """Rules without body_contains_any / body_regex match purely on
        path+status — needed for e.g. .DS_Store where the body has no
        reliable signature."""
        rule = self._rule(body_contains_any=None)
        assert _rule_matches(rule, "/.env", 200, "") is True

    def test_regex_path_matches_nested_suffix(self):
        """A path like /foo/.git/HEAD should match a rule with
        suffix .git/HEAD — critical for proxy-prefixed apps where .git
        is exposed under a subpath."""
        rule = self._rule(path_suffixes=[".git/HEAD"], status_codes=[200],
                          body_contains_any=["ref:"])
        assert _rule_matches(rule, "/foo/.git/HEAD", 200, "ref: refs/heads/main") is True


class TestLoadExposureRules:
    def test_loads_bundled_rules(self):
        """The bundled exposures.json must parse — this is the smoke test
        that the wordlists directory ships with the worker. Every rule
        we commit is validated here implicitly."""
        rules = _load_exposure_rules()
        assert len(rules) > 0
        ids = {r["id"] for r in rules}
        # Spot-check the critical ones so a rename is caught in review.
        assert "git-directory-exposed" in ids
        assert "dotenv-exposed" in ids

    def test_malformed_rule_skipped(self, tmp_path):
        """One bad rule must not disable the whole sink."""
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({
            "rules": [
                {"id": "good", "path_suffixes": ["x"], "status_codes": [200]},
                {"path_suffixes": ["no_id"]},
                {"id": "bad_regex", "path_suffixes": ["y"], "body_regex": "[invalid"},
            ]
        }))
        with patch("scanner.vm.content_discovery_worker.CONTENT_DISCOVERY_EXPOSURES_RULES", str(bad)):
            rules = _load_exposure_rules()
        ids = [r["id"] for r in rules]
        assert "good" in ids
        assert "bad_regex" in ids  # kept, but with _body_regex_compiled=None
        assert "no_id" not in [r.get("id") for r in rules]

    def test_missing_file_returns_empty(self, tmp_path):
        with patch(
            "scanner.vm.content_discovery_worker.CONTENT_DISCOVERY_EXPOSURES_RULES",
            str(tmp_path / "does-not-exist.json"),
        ):
            assert _load_exposure_rules() == []


# ── Finding payload shape ────────────────────────────────────────


class TestExposureToFinding:
    def test_shape_matches_nuclei_contract(self):
        """Same-shape as nuclei_worker / schemathesis_worker so the
        backend's _import_nuclei_job_findings ingests with no special
        casing. Any drift here breaks ingest silently."""
        rule = {
            "id": "dotenv-exposed",
            "name": "Exposed .env",
            "severity": "critical",
            "description": "env file served plaintext",
            "references": ["https://example.com/advisory"],
        }
        f = _exposure_to_finding(
            rule=rule,
            url="https://target.test/.env",
            path="/.env",
            status_code=200,
            content_length=512,
            target="https://target.test",
        )
        # Contract fields that ingest reads directly
        assert f["template_id"] == "content-discovery-dotenv-exposed"
        assert f["severity"] == "critical"
        assert f["type"] == "content-discovery"
        assert "content-discovery" in f["tags"]
        assert "exposure" in f["tags"]
        assert "dotenv-exposed" in f["tags"]
        assert f["matched_at"] == "https://target.test/.env"
        assert f["llm_validation"]["verdict"] == "true_positive"
        assert f["llm_validation"]["source"] == "content_discovery"

    def test_severity_defaults_to_info(self):
        rule = {"id": "x", "name": "X"}
        f = _exposure_to_finding(
            rule=rule, url="u", path="/p", status_code=200,
            content_length=0, target="t",
        )
        assert f["severity"] == "info"


# ── ffuf output parsing ──────────────────────────────────────────


class TestExtractHits:
    def test_nested_input_parsed(self):
        raw = {
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "url": "https://target.test/admin",
                    "status": 200,
                    "length": 1234,
                    "content": "<!doctype html>",
                }
            ]
        }
        hits = _extract_hits(raw)
        assert len(hits) == 1
        assert hits[0]["input"] == "admin"
        assert hits[0]["path"] == "/admin"
        assert hits[0]["status"] == 200

    def test_empty_results(self):
        assert _extract_hits({}) == []
        assert _extract_hits({"results": []}) == []


class TestPathFromHit:
    def test_from_url(self):
        assert _path_from_hit({"url": "https://x/foo/bar"}, None) == "/foo/bar"

    def test_from_input_dict(self):
        assert _path_from_hit({"input": {"FUZZ": "admin"}}, None) == "/admin"

    def test_from_input_string(self):
        assert _path_from_hit({"input": "api/v1"}, None) == "/api/v1"

    def test_leading_slash_preserved(self):
        assert _path_from_hit({"input": "/foo"}, None) == "/foo"


# ── Param target selection ───────────────────────────────────────


class TestSelectParamTargets:
    def test_static_assets_skipped(self):
        """Fuzzing params on /favicon.ico is meaningless and burns budget."""
        hits = [
            {"url": "https://t/app.js", "path": "/app.js", "status": 200, "length": 5000},
            {"url": "https://t/api/users", "path": "/api/users", "status": 200, "length": 500},
            {"url": "https://t/logo.png", "path": "/logo.png", "status": 200, "length": 9000},
        ]
        targets = _select_param_targets(hits, "https://t")
        assert targets == ["https://t/api/users"]

    def test_only_200_and_500_considered(self):
        """401/403 are interesting *endpoints* but param fuzzing them
        without creds doesn't reach the real handler. 500 is worth
        probing — a broken handler may still differentiate on params."""
        hits = [
            {"url": "https://t/a", "path": "/a", "status": 200, "length": 100},
            {"url": "https://t/b", "path": "/b", "status": 401, "length": 100},
            {"url": "https://t/c", "path": "/c", "status": 500, "length": 100},
            {"url": "https://t/d", "path": "/d", "status": 302, "length": 100},
        ]
        targets = _select_param_targets(hits, "https://t")
        assert "https://t/a" in targets
        assert "https://t/c" in targets
        assert "https://t/b" not in targets
        assert "https://t/d" not in targets

    def test_empty_bodies_skipped(self):
        """Zero-length 200s are usually soft hits ffuf's calibration missed."""
        hits = [
            {"url": "https://t/a", "path": "/a", "status": 200, "length": 5},
            {"url": "https://t/b", "path": "/b", "status": 200, "length": 500},
        ]
        assert _select_param_targets(hits, "https://t") == ["https://t/b"]

    def test_dedup(self):
        hits = [
            {"url": "https://t/api", "path": "/api", "status": 200, "length": 500},
            {"url": "https://t/api", "path": "/api", "status": 200, "length": 500},
        ]
        assert _select_param_targets(hits, "https://t") == ["https://t/api"]


# ── Contract with bundled rules ──────────────────────────────────


class TestBundledRulesContract:
    """Guardrail tests against the committed exposures.json — guards
    against silent schema drift when someone edits the JSON directly
    without updating the worker.
    """

    def test_every_rule_has_required_fields(self):
        rules = _load_exposure_rules()
        for r in rules:
            assert r.get("id"), "rule missing id"
            assert r.get("severity") in {"critical", "high", "medium", "low", "info"}
            assert isinstance(r.get("path_suffixes"), list) and r["path_suffixes"]

    def test_dotenv_rule_fires_on_realistic_body(self):
        rules = _load_exposure_rules()
        rule = next(r for r in rules if r["id"] == "dotenv-exposed")
        body = "DB_HOST=prod.example.com\nDB_PASSWORD=s3cret\nAPI_KEY=x\n"
        assert _rule_matches(rule, "/.env", 200, body) is True

    def test_git_rule_fires_on_realistic_body(self):
        rules = _load_exposure_rules()
        rule = next(r for r in rules if r["id"] == "git-directory-exposed")
        assert _rule_matches(rule, "/.git/HEAD", 200, "ref: refs/heads/main\n") is True


# ── Max endpoint cap ─────────────────────────────────────────────


def test_max_endpoints_cap_is_sane():
    """Catch accidental bumps — 200 already risks flooding asset_endpoints
    when content discovery runs on a directory-listing-enabled server."""
    assert 50 <= MAX_ENDPOINTS_PER_ASSET <= 500
