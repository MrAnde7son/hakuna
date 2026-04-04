"""Tests for low-code asset type classification rules."""
import pytest
from unittest.mock import MagicMock

from services.asset_type_rules import (
    resolve_identity,
    _resolve_identity_value,
    normalize_asset_data,
    evaluate_asset_type_rules,
    get_condition_catalog,
)


# ─────────────────────────────────────────────
# Identity mapping resolution
# ─────────────────────────────────────────────

class TestResolveIdentityValue:
    def test_direct_field_copy(self):
        assert _resolve_identity_value("hostname", {"hostname": "web01"}) == "web01"

    def test_missing_field_returns_none(self):
        assert _resolve_identity_value("hostname", {}) is None

    def test_static_value(self):
        assert _resolve_identity_value("@static(nessus)", {}) == "nessus"

    def test_extract_domain_from_url(self):
        data = {"hostname": "http://app.example.com:8080/path"}
        assert _resolve_identity_value("@extract_domain(hostname)", data) == "app.example.com"

    def test_extract_domain_bare_hostname(self):
        data = {"hostname": "myserver.local"}
        assert _resolve_identity_value("@extract_domain(hostname)", data) == "myserver.local"

    def test_extract_path(self):
        data = {"hostname": "http://app.example.com:8080/api/v1"}
        assert _resolve_identity_value("@extract_path(hostname)", data) == "/api/v1"

    def test_extract_port(self):
        data = {"hostname": "http://app.example.com:8080/path"}
        assert _resolve_identity_value("@extract_port(hostname)", data) == "8080"

    def test_lower(self):
        data = {"hostname": "MyServer.LOCAL"}
        assert _resolve_identity_value("@lower(hostname)", data) == "myserver.local"

    def test_upper(self):
        data = {"fqdn": "myserver.local"}
        assert _resolve_identity_value("@upper(fqdn)", data) == "MYSERVER.LOCAL"

    def test_coalesce_first_present(self):
        data = {"http_url": "https://example.com", "hostname": "web01"}
        assert _resolve_identity_value("@coalesce(http_url,hostname)", data) == "https://example.com"

    def test_coalesce_fallback(self):
        data = {"hostname": "web01"}
        assert _resolve_identity_value("@coalesce(http_url,hostname)", data) == "web01"

    def test_coalesce_all_empty(self):
        assert _resolve_identity_value("@coalesce(http_url,hostname)", {}) is None

    def test_unknown_function_fallback(self):
        data = {"hostname": "web01"}
        assert _resolve_identity_value("@unknown_func(hostname)", data) == "web01"


class TestResolveIdentity:
    def test_full_mapping(self):
        mapping = {
            "url": "hostname",
            "domain": "@extract_domain(hostname)",
            "display_name": "hostname",
        }
        data = {"hostname": "http://10.0.0.1:8080/app"}
        result = resolve_identity(mapping, data)
        assert result == {
            "url": "http://10.0.0.1:8080/app",
            "domain": "10.0.0.1",
            "display_name": "http://10.0.0.1:8080/app",
        }

    def test_static_mixed(self):
        mapping = {
            "provider": "@static(aws)",
            "instance_id": "hostname",
        }
        data = {"hostname": "i-0abc123"}
        result = resolve_identity(mapping, data)
        assert result == {"provider": "aws", "instance_id": "i-0abc123"}

    def test_missing_fields_excluded(self):
        mapping = {"ip": "ip", "fqdn": "fqdn"}
        data = {"ip": "10.0.0.1"}
        result = resolve_identity(mapping, data)
        assert result == {"ip": "10.0.0.1"}
        assert "fqdn" not in result


# ─────────────────────────────────────────────
# Data normalization
# ─────────────────────────────────────────────

class TestNormalizeAssetData:
    def test_passthrough_basic_fields(self):
        raw = {"hostname": "web01", "ip": "10.0.0.1"}
        norm = normalize_asset_data(raw)
        assert norm["hostname"] == "web01"
        assert norm["ip"] == "10.0.0.1"

    def test_flattens_easm_data(self):
        raw = {
            "hostname": "app.example.com",
            "easm_data": {
                "tech_stack": ["Apache 2.4", "PHP 7.4"],
                "open_ports": [80, 443],
                "http_url": "https://app.example.com",
                "http_title": "My App",
                "cdn_provider": "Cloudflare",
                "services": {"80": {"name": "http", "product": "Apache"}},
            },
        }
        norm = normalize_asset_data(raw)
        assert norm["tech_stack"] == ["Apache 2.4", "PHP 7.4"]
        assert norm["open_ports"] == [80, 443]
        assert norm["http_url"] == "https://app.example.com"
        assert norm["cdn_provider"] == "Cloudflare"

    def test_does_not_overwrite_existing_fields(self):
        raw = {
            "http_url": "https://override.com",
            "easm_data": {"http_url": "https://easm.com"},
        }
        norm = normalize_asset_data(raw)
        assert norm["http_url"] == "https://override.com"

    def test_has_http_port_true(self):
        raw = {"open_ports": [22, 443, 3306]}
        norm = normalize_asset_data(raw)
        assert norm["has_http_port"] is True

    def test_has_http_port_false(self):
        raw = {"open_ports": [22, 3306, 5432]}
        norm = normalize_asset_data(raw)
        assert norm["has_http_port"] is False

    def test_has_http_port_empty(self):
        norm = normalize_asset_data({})
        assert norm["has_http_port"] is False

    def test_has_web_service_by_name(self):
        raw = {"services": {"443": {"name": "https", "product": "nginx"}}}
        norm = normalize_asset_data(raw)
        assert norm["has_web_service"] is True

    def test_has_web_service_by_port(self):
        raw = {"services": {"8080": {"name": "unknown"}}}
        norm = normalize_asset_data(raw)
        assert norm["has_web_service"] is True

    def test_has_web_service_false(self):
        raw = {"services": {"22": {"name": "ssh"}}}
        norm = normalize_asset_data(raw)
        assert norm["has_web_service"] is False

    def test_has_web_tech_true(self):
        raw = {"tech_stack": ["Apache 2.4", "PHP 7.4", "React 18"]}
        norm = normalize_asset_data(raw)
        assert norm["has_web_tech"] is True

    def test_has_web_tech_false(self):
        raw = {"tech_stack": ["OpenSSH 8.2", "PostgreSQL 14"]}
        norm = normalize_asset_data(raw)
        assert norm["has_web_tech"] is False

    def test_has_web_cpe_true(self):
        raw = {"cpe": ["cpe:/o:linux:linux_kernel:5.10", "cpe:/a:apache:http_server:2.4.52"]}
        norm = normalize_asset_data(raw)
        assert norm["has_web_cpe"] is True

    def test_has_web_cpe_false(self):
        raw = {"cpe": ["cpe:/o:linux:linux_kernel:5.10", "cpe:/a:openssh:openssh:8.2"]}
        norm = normalize_asset_data(raw)
        assert norm["has_web_cpe"] is False

    def test_best_url_from_http_url(self):
        raw = {"http_url": "https://app.example.com", "hostname": "web01"}
        norm = normalize_asset_data(raw)
        assert norm["best_url"] == "https://app.example.com"

    def test_best_url_from_url_hostname(self):
        raw = {"hostname": "http://10.0.0.1:8080/"}
        norm = normalize_asset_data(raw)
        assert norm["best_url"] == "http://10.0.0.1:8080/"

    def test_best_url_none_for_bare_hostname(self):
        raw = {"hostname": "server01"}
        norm = normalize_asset_data(raw)
        assert norm["best_url"] is None

    def test_best_domain_from_url(self):
        raw = {"http_url": "https://app.example.com/path"}
        norm = normalize_asset_data(raw)
        assert norm["best_domain"] == "app.example.com"

    def test_best_domain_from_fqdn(self):
        raw = {"fqdn": "server01.corp.local"}
        norm = normalize_asset_data(raw)
        assert norm["best_domain"] == "server01.corp.local"


# ─────────────────────────────────────────────
# Rule evaluation (with mocked DB)
# ─────────────────────────────────────────────

def _make_rule(name, conditions, target, identity_mapping=None,
               priority=100, source_filter=None, condition_logic="AND",
               default_attributes=None):
    rule = MagicMock()
    rule.id = 1
    rule.name = name
    rule.conditions = conditions
    rule.condition_logic = condition_logic
    rule.target_asset_type = target
    rule.identity_mapping = identity_mapping or {}
    rule.default_attributes = default_attributes or {}
    rule.priority = priority
    rule.source_filter = source_filter
    rule.is_enabled = True
    return rule


class TestEvaluateAssetTypeRules:
    def _mock_db_with_rules(self, rules):
        db = MagicMock()
        query = MagicMock()
        db.query.return_value = query
        query.filter.return_value = query
        query.order_by.return_value = query
        query.all.return_value = rules
        return db

    def test_matching_rule_returns_result(self):
        rule = _make_rule(
            "WAS Detection",
            [{"field": "system_type", "op": "eq", "value": "web_application"}],
            "web_app",
            {"url": "hostname", "domain": "@extract_domain(hostname)"},
        )
        db = self._mock_db_with_rules([rule])
        asset_data = {
            "hostname": "http://10.0.0.1:8080/",
            "system_type": "web_application",
            "ip": "10.0.0.1",
        }
        result = evaluate_asset_type_rules(asset_data, db)
        assert result is not None
        assert result["asset_type"] == "web_app"
        assert result["asset_identity"]["url"] == "http://10.0.0.1:8080/"
        assert result["asset_identity"]["domain"] == "10.0.0.1"

    def test_no_match_returns_none(self):
        rule = _make_rule(
            "WAS Detection",
            [{"field": "system_type", "op": "eq", "value": "web_application"}],
            "web_app",
        )
        db = self._mock_db_with_rules([rule])
        asset_data = {"hostname": "server01", "system_type": "general-purpose"}
        result = evaluate_asset_type_rules(asset_data, db)
        assert result is None

    def test_source_filter_skips_non_matching(self):
        rule = _make_rule(
            "Nessus WAS only",
            [{"field": "system_type", "op": "eq", "value": "web_application"}],
            "web_app",
            source_filter="nessus",
        )
        db = self._mock_db_with_rules([rule])
        asset_data = {"hostname": "http://app/", "system_type": "web_application"}
        result = evaluate_asset_type_rules(asset_data, db, source_type="qualys")
        assert result is None

    def test_source_filter_matches(self):
        rule = _make_rule(
            "Nessus WAS only",
            [{"field": "system_type", "op": "eq", "value": "web_application"}],
            "web_app",
            {"url": "hostname"},
            source_filter="nessus",
        )
        db = self._mock_db_with_rules([rule])
        asset_data = {"hostname": "http://app/", "system_type": "web_application"}
        result = evaluate_asset_type_rules(asset_data, db, source_type="nessus")
        assert result is not None
        assert result["asset_type"] == "web_app"

    def test_priority_first_match_wins(self):
        rule_a = _make_rule(
            "High prio", [{"field": "hostname", "op": "contains", "value": "app"}],
            "web_app", priority=10,
        )
        rule_b = _make_rule(
            "Low prio", [{"field": "hostname", "op": "contains", "value": "app"}],
            "api_endpoint", priority=50,
        )
        db = self._mock_db_with_rules([rule_a, rule_b])
        asset_data = {"hostname": "app-server-01"}
        result = evaluate_asset_type_rules(asset_data, db)
        assert result["asset_type"] == "web_app"

    def test_or_logic(self):
        rule = _make_rule(
            "URL or WAS",
            [
                {"field": "hostname", "op": "startswith", "value": "http"},
                {"field": "system_type", "op": "eq", "value": "web_application"},
            ],
            "web_app",
            condition_logic="OR",
        )
        db = self._mock_db_with_rules([rule])
        asset_data = {"hostname": "http://10.0.0.1/", "system_type": None}
        result = evaluate_asset_type_rules(asset_data, db)
        assert result is not None
        assert result["asset_type"] == "web_app"

    # ── Fingerprint-based tests ──────────────────────────────

    def test_has_http_port_derived(self):
        """has_http_port is auto-computed from open_ports by normalization."""
        rule = _make_rule(
            "HTTP port",
            [{"field": "has_http_port", "op": "is_true"}],
            "web_app",
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {"hostname": "server01", "open_ports": [22, 443]}, db,
        )
        assert result is not None
        assert result["asset_type"] == "web_app"

    def test_has_http_port_false_no_match(self):
        rule = _make_rule(
            "HTTP port",
            [{"field": "has_http_port", "op": "is_true"}],
            "web_app",
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {"hostname": "dbserver", "open_ports": [22, 5432]}, db,
        )
        assert result is None

    def test_has_web_service_from_services_dict(self):
        rule = _make_rule(
            "Web service",
            [{"field": "has_web_service", "op": "is_true"}],
            "web_app",
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {"hostname": "internal", "services": {"443": {"name": "https"}}}, db,
        )
        assert result is not None

    def test_has_web_tech_from_tech_stack(self):
        rule = _make_rule(
            "Web tech",
            [{"field": "has_web_tech", "op": "is_true"}],
            "web_app",
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {"hostname": "app01", "tech_stack": ["nginx 1.22", "React 18"]}, db,
        )
        assert result is not None

    def test_has_web_cpe(self):
        rule = _make_rule(
            "Web CPE",
            [{"field": "has_web_cpe", "op": "is_true"}],
            "web_app",
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {"hostname": "web01", "cpe": ["cpe:/a:apache:http_server:2.4"]}, db,
        )
        assert result is not None

    def test_easm_data_flattened_for_rules(self):
        """Rules can match on easm_data fields via normalization."""
        rule = _make_rule(
            "EASM httpx",
            [{"field": "http_url", "op": "startswith", "value": "https://"}],
            "web_app",
            {"url": "http_url", "domain": "@extract_domain(http_url)"},
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {
                "hostname": "app.example.com",
                "easm_data": {"http_url": "https://app.example.com", "open_ports": [443]},
            },
            db,
        )
        assert result is not None
        assert result["asset_identity"]["url"] == "https://app.example.com"
        assert result["asset_identity"]["domain"] == "app.example.com"

    def test_list_has_any_operator(self):
        """has_any operator matches comma-separated values against list fields."""
        rule = _make_rule(
            "Common web ports",
            [{"field": "open_ports", "op": "has_any", "value": "80,443,8080"}],
            "web_app",
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {"hostname": "srv01", "open_ports": [22, 8080, 3306]}, db,
        )
        assert result is not None

    def test_list_contains_operator(self):
        """list_contains does substring match on list items."""
        rule = _make_rule(
            "Has Apache",
            [{"field": "tech_stack", "op": "list_contains", "value": "apache"}],
            "web_app",
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {"hostname": "web01", "tech_stack": ["Apache 2.4.52", "OpenSSL 1.1"]}, db,
        )
        assert result is not None

    def test_coalesce_in_identity_mapping(self):
        """@coalesce picks first non-empty field."""
        rule = _make_rule(
            "Coalesce test",
            [{"field": "has_http_port", "op": "is_true"}],
            "web_app",
            {"url": "@coalesce(http_url,hostname)", "domain": "best_domain"},
        )
        db = self._mock_db_with_rules([rule])
        result = evaluate_asset_type_rules(
            {"hostname": "app.example.com", "open_ports": [443]}, db,
        )
        assert result is not None
        # No http_url, so coalesce falls back to hostname
        assert result["asset_identity"]["url"] == "app.example.com"

    def test_no_rules_returns_none(self):
        db = self._mock_db_with_rules([])
        result = evaluate_asset_type_rules({"hostname": "srv"}, db)
        assert result is None


class TestConditionCatalog:
    def test_catalog_returns_groups(self):
        catalog = get_condition_catalog()
        assert isinstance(catalog, list)
        group_names = [g["group"] for g in catalog]
        assert "Asset Properties" in group_names
        assert "Service Fingerprint" in group_names
        assert "Source Context" in group_names
        assert "Derived (auto-computed)" in group_names

    def test_catalog_has_fingerprint_fields(self):
        catalog = get_condition_catalog()
        all_fields = [
            c["field"]
            for g in catalog
            for c in g["conditions"]
        ]
        assert "system_type" in all_fields
        assert "open_ports" in all_fields
        assert "tech_stack" in all_fields
        assert "cpe" in all_fields
        assert "has_http_port" in all_fields
        assert "has_web_service" in all_fields
        assert "has_web_tech" in all_fields
        assert "has_web_cpe" in all_fields
        assert "http_url" in all_fields
        assert "http_status" in all_fields
        assert "cdn_provider" in all_fields
        assert "best_url" in all_fields
        assert "best_domain" in all_fields
