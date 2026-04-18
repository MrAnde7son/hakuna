"""Unit tests for takeover fingerprinting + AI exposure probes.

These tests intentionally avoid any network I/O. They exercise only the
pure-Python matching/loading logic — the HTTP probe orchestration is
covered implicitly by the aiohttp session boundary, which is trivial to
mock but offers little value vs. the matchers.
"""

import pytest


# ---------------------------------------------------------------------------
# Takeover fingerprint DB — pure matcher tests
# ---------------------------------------------------------------------------


class TestTakeoverFingerprints:
    def test_db_loads_and_has_required_services(self):
        from app.ingest.liveness import _TAKEOVER_DB, reload_takeover_db

        reload_takeover_db()

        names = {s["name"] for s in _TAKEOVER_DB}
        required = {
            "aws-s3", "github-pages", "heroku", "azure-webapps",
            "netlify", "fastly", "shopify", "tumblr", "unbounce",
            "cargo-collective", "ghost", "surge",
        }
        missing = required - names
        assert not missing, f"takeover DB is missing services: {missing}"

    def test_cname_pattern_matches_s3(self):
        from app.ingest.liveness import _match_cname_service, reload_takeover_db

        reload_takeover_db()
        svc = _match_cname_service(["my-bucket.s3.amazonaws.com"])
        assert svc is not None
        assert svc["name"] == "aws-s3"

    def test_cname_pattern_matches_github_pages(self):
        from app.ingest.liveness import _match_cname_service, reload_takeover_db

        reload_takeover_db()
        svc = _match_cname_service(["someuser.github.io"])
        assert svc is not None
        assert svc["name"] == "github-pages"

    def test_cname_pattern_no_match_returns_none(self):
        from app.ingest.liveness import _match_cname_service, reload_takeover_db

        reload_takeover_db()
        assert _match_cname_service(["cdn.example.com"]) is None
        assert _match_cname_service([]) is None

    def test_body_fingerprint_matches_s3(self):
        from app.ingest.liveness import _match_body_service, reload_takeover_db

        reload_takeover_db()
        body = (
            "<Error><Code>NoSuchBucket</Code>"
            "<Message>The specified bucket does not exist</Message></Error>"
        )
        svc = _match_body_service(404, body)
        assert svc is not None
        assert svc["name"] == "aws-s3"

    def test_body_fingerprint_requires_correct_status(self):
        from app.ingest.liveness import _match_body_service, reload_takeover_db

        reload_takeover_db()
        # s3 fingerprint requires 404; a 200 with the same body should miss.
        assert _match_body_service(200, "NoSuchBucket") is None

    def test_body_fingerprint_matches_heroku(self):
        from app.ingest.liveness import _match_body_service, reload_takeover_db

        reload_takeover_db()
        body = "No such app\nhttps://herokucdn.com/error-pages/no-such-app.html"
        svc = _match_body_service(404, body)
        assert svc is not None
        assert svc["name"] == "heroku"


# ---------------------------------------------------------------------------
# AI exposure probe DB — schema + matcher tests
# ---------------------------------------------------------------------------


class TestAIExposureProbes:
    def test_db_loads_all_required_services(self):
        from app.ingest.ai_exposure_probe import _DB, reload_db

        reload_db()
        services = {p["service"] for p in _DB}
        required = {
            "ollama", "qdrant", "vllm", "mcp", "litellm",
            "milvus", "chroma", "langserve",
        }
        missing = required - services
        assert not missing, f"AI exposure DB is missing services: {missing}"

    def test_probes_have_required_fields(self):
        from app.ingest.ai_exposure_probe import _DB, reload_db

        reload_db()
        for probe in _DB:
            assert probe.get("name"), f"probe missing name: {probe}"
            assert probe.get("service"), f"probe missing service: {probe}"
            assert probe.get("path"), f"{probe['name']} missing path"
            assert probe.get("title"), f"{probe['name']} missing title"
            assert probe.get("severity") in {"critical", "high", "medium", "low"}, (
                f"{probe['name']} has invalid severity"
            )
            sw = probe.get("success_when") or {}
            assert sw.get("status_in"), f"{probe['name']} missing success_when.status_in"

    def test_matches_success_happy_path(self):
        from app.ingest.ai_exposure_probe import _matches_success

        probe = {
            "success_when": {
                "status_in": [200, 400],
                "body_contains_any": ["\"model\"", "missing"],
            }
        }
        assert _matches_success(probe, 200, '{"model": "llama"}') is True
        assert _matches_success(probe, 400, "missing required field") is True

    def test_matches_success_wrong_status(self):
        from app.ingest.ai_exposure_probe import _matches_success

        probe = {
            "success_when": {
                "status_in": [200],
                "body_contains_any": ["foo"],
            }
        }
        assert _matches_success(probe, 404, "foo") is False

    def test_matches_success_missing_body_fingerprint(self):
        from app.ingest.ai_exposure_probe import _matches_success

        probe = {
            "success_when": {
                "status_in": [200],
                "body_contains_any": ["\"tools\"", "\"jsonrpc\""],
            }
        }
        assert _matches_success(probe, 200, "just a plain html page") is False

    def test_matches_success_fail_when_overrides(self):
        from app.ingest.ai_exposure_probe import _matches_success

        probe = {
            "success_when": {
                "status_in": [200, 401],
                "body_contains_any": ["anything"],
            },
            "fail_when": {"status_in": [401, 403]},
        }
        # 401 would otherwise match success — fail_when kills it.
        assert _matches_success(probe, 401, "anything") is False
        assert _matches_success(probe, 200, "anything") is True

    def test_applies_to_asset_type(self):
        from app.ingest.ai_exposure_probe import _applies_to_asset_type

        probe_typed = {"asset_types": ["ai_inference", "vector_db"]}
        probe_untyped = {}

        assert _applies_to_asset_type(probe_typed, "ai_inference") is True
        assert _applies_to_asset_type(probe_typed, "ai_agent") is False
        assert _applies_to_asset_type(probe_untyped, "anything") is True
        assert _applies_to_asset_type(probe_untyped, None) is True

    def test_pick_base_urls_prefers_https_and_includes_ollama_port(self):
        from app.ingest.ai_exposure_probe import _pick_base_urls

        urls = _pick_base_urls({
            "hostname": "ai.example.com",
            "open_ports": [443, 11434],
        })
        assert "https://ai.example.com" in urls
        assert "http://ai.example.com:11434" in urls

    def test_pick_base_urls_falls_back_to_https_when_no_http_ports(self):
        from app.ingest.ai_exposure_probe import _pick_base_urls

        urls = _pick_base_urls({
            "hostname": "nothing.example.com",
            "open_ports": [],
        })
        assert urls == ["https://nothing.example.com"]

    def test_ai_asset_types_set(self):
        from app.ingest.ai_exposure_probe import AI_ASSET_TYPES

        assert "ai_inference" in AI_ASSET_TYPES
        assert "ai_agent" in AI_ASSET_TYPES
        assert "ai_gateway" in AI_ASSET_TYPES
        assert "vector_db" in AI_ASSET_TYPES
        # Non-AI types must not be included.
        assert "camera" not in AI_ASSET_TYPES
        assert "web_server" not in AI_ASSET_TYPES
