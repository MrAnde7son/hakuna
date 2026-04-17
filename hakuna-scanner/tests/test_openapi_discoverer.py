"""Tests for openapi_discoverer.

Focus on parse_openapi_spec — the pure logic that turns a raw spec dict
into endpoint records. Network probing is exercised lightly via httpx's
MockTransport so we don't depend on a separate aioresponses dep.
"""
import pytest

from app.ingest.openapi_discoverer import (
    WELL_KNOWN_PATHS,
    parse_openapi_spec,
)


# ── parse_openapi_spec ──────────────────────────────────────────


class TestParseOpenApiSpec:
    def test_openapi_3_basic(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {"operationId": "listUsers"},
                    "post": {"operationId": "createUser"},
                },
                "/users/{id}": {
                    "get": {"operationId": "getUser"},
                },
            },
        }
        out = parse_openapi_spec(spec, "https://api.example.com")
        urls_methods = sorted([(e["url"], e["method"]) for e in out])
        assert urls_methods == [
            ("https://api.example.com/users", "GET"),
            ("https://api.example.com/users", "POST"),
            ("https://api.example.com/users/{id}", "GET"),
        ]

    def test_swagger_2_basic(self):
        """Swagger 2 specs use the same paths × methods structure."""
        spec = {
            "swagger": "2.0",
            "paths": {
                "/orders": {"get": {}, "delete": {}},
            },
        }
        out = parse_openapi_spec(spec, "https://api.example.com")
        methods = sorted([e["method"] for e in out])
        assert methods == ["DELETE", "GET"]

    def test_global_security_marks_operations_auth_required(self):
        spec = {
            "openapi": "3.0.0",
            "security": [{"bearerAuth": []}],
            "paths": {
                "/private": {"get": {}},
            },
        }
        out = parse_openapi_spec(spec, "https://api.example.com")
        assert out[0]["auth_required"] is True

    def test_operation_security_overrides_global(self):
        """Empty operation-level security ([]) explicitly disables auth for
        that operation even when global security is set — OpenAPI rule."""
        spec = {
            "openapi": "3.0.0",
            "security": [{"bearerAuth": []}],
            "paths": {
                "/public": {"get": {"security": []}},
                "/private": {"get": {}},
            },
        }
        out = {(e["path"], e["auth_required"]) for e in parse_openapi_spec(spec, "")}
        assert ("/public", False) in out
        assert ("/private", True) in out

    def test_no_security_block_means_no_auth(self):
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {}}}}
        assert parse_openapi_spec(spec, "")[0]["auth_required"] is False

    def test_operation_parameters_included(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query", "required": False},
                            {"name": "offset", "in": "query"},
                        ],
                    },
                },
            },
        }
        params = parse_openapi_spec(spec, "")[0]["parameters"]
        assert params == [
            {"name": "limit", "in": "query", "required": False},
            {"name": "offset", "in": "query", "required": False},
        ]

    def test_path_level_parameters_inherited_by_operations(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "get": {},
                    "delete": {"parameters": [{"name": "force", "in": "query"}]},
                },
            },
        }
        out = {e["method"]: e["parameters"] for e in parse_openapi_spec(spec, "")}
        assert out["GET"] == [{"name": "id", "in": "path", "required": True}]
        assert out["DELETE"] == [
            {"name": "id", "in": "path", "required": True},
            {"name": "force", "in": "query", "required": False},
        ]

    def test_ref_only_parameters_dropped(self):
        """We don't follow $refs — they're skipped during normalization
        rather than producing half-populated rows."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/x": {
                    "get": {
                        "parameters": [
                            {"$ref": "#/components/parameters/X"},
                            {"name": "real", "in": "query"},
                        ],
                    },
                },
            },
        }
        params = parse_openapi_spec(spec, "")[0]["parameters"]
        assert params == [{"name": "real", "in": "query", "required": False}]

    def test_request_body_content_type(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {"schema": {"type": "object"}},
                            },
                        },
                    },
                },
            },
        }
        assert parse_openapi_spec(spec, "")[0]["content_type"] == "application/json"

    def test_no_paths_returns_empty(self):
        assert parse_openapi_spec({"openapi": "3.0.0"}, "") == []

    def test_non_dict_paths_returns_empty(self):
        assert parse_openapi_spec({"openapi": "3.0.0", "paths": "not a dict"}, "") == []

    def test_unknown_methods_skipped(self):
        """Custom verbs in a spec (e.g. 'trace', 'connect') aren't in our
        whitelist — that's intentional, we only enumerate the standard set
        the planner can do something with."""
        spec = {
            "openapi": "3.0.0",
            "paths": {"/x": {"trace": {}, "get": {}}},
        }
        methods = [e["method"] for e in parse_openapi_spec(spec, "")]
        assert methods == ["GET"]


class TestWellKnownPaths:
    def test_includes_canonical_openapi_3_paths(self):
        for must_have in ("/openapi.json", "/swagger.json", "/v3/api-docs"):
            assert must_have in WELL_KNOWN_PATHS

    def test_path_order_starts_with_openapi_json(self):
        """Most-likely-first ordering. A change here is significant — the
        first hit wins per asset and reordering changes which spec we'd
        record on a server that exposes both."""
        assert WELL_KNOWN_PATHS[0] == "/openapi.json"
