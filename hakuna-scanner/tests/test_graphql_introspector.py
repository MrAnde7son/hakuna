"""Tests for graphql_introspector — schema-to-endpoints projection.

Live HTTP probing tests would require a fake server fixture; we cover the
pure projection logic here. The HTTP path is exercised in integration
tests at the harness level.
"""
from app.ingest.graphql_introspector import (
    CANDIDATE_PATHS,
    _schema_to_endpoints,
)


class TestSchemaToEndpoints:
    def test_query_fields_become_endpoints(self):
        schema_data = {
            "schema": {
                "queryType": {
                    "name": "Query",
                    "fields": [{"name": "users"}, {"name": "user"}],
                },
            },
            "url": "https://api.example.com/graphql",
        }
        out = _schema_to_endpoints(schema_data, "https://api.example.com/graphql")
        paths = sorted(e["path"] for e in out)
        assert paths == ["Query.user", "Query.users"]
        # Every endpoint is POST against the GraphQL URL itself
        assert all(e["method"] == "POST" for e in out)
        assert all(e["url"] == "https://api.example.com/graphql" for e in out)

    def test_mutation_and_subscription_included(self):
        schema_data = {
            "schema": {
                "queryType": {"fields": [{"name": "ping"}]},
                "mutationType": {"fields": [{"name": "createUser"}]},
                "subscriptionType": {"fields": [{"name": "userAdded"}]},
            },
        }
        out = _schema_to_endpoints(schema_data, "https://api.example.com/graphql")
        kinds = sorted({e["operation_kind"] for e in out})
        assert kinds == ["Mutation", "Query", "Subscription"]

    def test_missing_type_blocks_skipped(self):
        schema_data = {"schema": {"queryType": None, "mutationType": None}}
        assert _schema_to_endpoints(schema_data, "https://x") == []

    def test_unnamed_fields_skipped(self):
        """A defensive parse — fields without a name are non-actionable."""
        schema_data = {
            "schema": {
                "queryType": {"fields": [{"name": ""}, {"name": "good"}]},
            },
        }
        out = _schema_to_endpoints(schema_data, "https://x")
        assert len(out) == 1
        assert out[0]["operation_name"] == "good"

    def test_empty_schema_returns_empty(self):
        assert _schema_to_endpoints({"schema": {}}, "https://x") == []


class TestCandidatePaths:
    def test_contains_canonical_graphql_paths(self):
        for must_have in ("/graphql", "/api/graphql", "/v1/graphql"):
            assert must_have in CANDIDATE_PATHS

    def test_graphql_path_first(self):
        """Most APIs expose /graphql; first-hit-wins, so order matters."""
        assert CANDIDATE_PATHS[0] == "/graphql"
