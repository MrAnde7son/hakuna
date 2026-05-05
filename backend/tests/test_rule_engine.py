"""
Tests for services/rule_engine.py — pure-function helpers only (no DB required).

Covered functions:
    _str_op, _num_op, _eval_asset,
    migrate_autotag_condition, migrate_campaign_condition, migrate_conditions
"""
import sys
import os

import pytest

# Allow importing from the backend root without a full package install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.rule_engine import (
    _str_op,
    _num_op,
    _eval_asset,
    _eval_finding_row,
    migrate_autotag_condition,
    migrate_campaign_condition,
    migrate_conditions,
)


class _FakeFinding:
    """Minimal finding stub for _eval_finding_row tests."""
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
        self.custom_fields = kw.get("custom_fields", None)


# ─────────────────────────────────────────────────────────
# _str_op
# ─────────────────────────────────────────────────────────

class TestStrOp:
    # --- eq / neq ---

    def test_eq_match_case_insensitive(self):
        assert _str_op("Windows Server 2019", "eq", "windows server 2019") is True

    def test_eq_no_match(self):
        assert _str_op("linux", "eq", "windows") is False

    def test_neq_match(self):
        assert _str_op("linux", "neq", "windows") is True

    def test_neq_same_value_case_insensitive(self):
        assert _str_op("Linux", "neq", "linux") is False

    # --- contains / not_contains ---

    def test_contains_substring(self):
        assert _str_op("prod-server-01", "contains", "prod") is True

    def test_contains_no_match(self):
        assert _str_op("dev-server-01", "contains", "prod") is False

    def test_not_contains_absent(self):
        assert _str_op("dev-server-01", "not_contains", "prod") is True

    def test_not_contains_present(self):
        assert _str_op("prod-server-01", "not_contains", "prod") is False

    def test_contains_case_insensitive(self):
        assert _str_op("PROD-SERVER", "contains", "prod") is True

    # --- startswith / endswith ---

    def test_startswith_match(self):
        assert _str_op("prod-server-01", "startswith", "prod") is True

    def test_startswith_no_match(self):
        assert _str_op("dev-server-01", "startswith", "prod") is False

    def test_endswith_match(self):
        assert _str_op("server.example.com", "endswith", ".com") is True

    def test_endswith_no_match(self):
        assert _str_op("server.example.com", "endswith", ".org") is False

    def test_startswith_case_insensitive(self):
        assert _str_op("PROD-SERVER", "startswith", "prod") is True

    # --- glob ---

    def test_glob_wildcard_match(self):
        # Pattern *.prod.* requires a literal "." on both sides of "prod".
        assert _str_op("web.prod.internal", "glob", "*.prod.*") is True

    def test_glob_no_match(self):
        assert _str_op("web.dev.internal", "glob", "*.prod.*") is False

    def test_glob_question_mark(self):
        # "server?" matches exactly one trailing character
        assert _str_op("servers", "glob", "server?") is True
        assert _str_op("server", "glob", "server?") is False

    def test_glob_case_insensitive(self):
        # Both sides are lowercased before matching.
        assert _str_op("WEB.PROD.INTERNAL", "glob", "*.prod.*") is True

    # --- regex ---

    def test_regex_match(self):
        assert _str_op("CVE-2021-44228", "regex", r"CVE-\d{4}-\d+") is True

    def test_regex_no_match(self):
        assert _str_op("no-cve-here", "regex", r"CVE-\d{4}-\d+") is False

    def test_regex_invalid_pattern_returns_false(self):
        assert _str_op("anything", "regex", r"[invalid") is False

    def test_regex_case_insensitive(self):
        assert _str_op("WINDOWS SERVER", "regex", "windows") is True

    # --- cidr ---

    def test_cidr_ip_in_range(self):
        assert _str_op("10.0.0.5", "cidr", "10.0.0.0/24") is True

    def test_cidr_ip_outside_range(self):
        assert _str_op("192.168.1.1", "cidr", "10.0.0.0/24") is False

    def test_cidr_exact_network_address(self):
        assert _str_op("172.16.0.0", "cidr", "172.16.0.0/16") is True

    def test_cidr_broadcast_address(self):
        assert _str_op("10.0.0.255", "cidr", "10.0.0.0/24") is True

    def test_cidr_invalid_ip_returns_false(self):
        assert _str_op("not-an-ip", "cidr", "10.0.0.0/24") is False

    def test_cidr_invalid_network_returns_false(self):
        assert _str_op("10.0.0.1", "cidr", "not-a-cidr") is False

    # --- unknown op ---

    def test_unknown_op_returns_false(self):
        assert _str_op("anything", "totally_unknown_op", "value") is False


# ─────────────────────────────────────────────────────────
# _num_op
# ─────────────────────────────────────────────────────────

class TestNumOp:
    def test_eq_match(self):
        assert _num_op(7.0, "eq", 7) is True

    def test_eq_no_match(self):
        assert _num_op(7.0, "eq", 8) is False

    def test_neq_match(self):
        assert _num_op(7.0, "neq", 8) is True

    def test_neq_same_value(self):
        assert _num_op(7.0, "neq", 7.0) is False

    def test_gt_above(self):
        assert _num_op(8.0, "gt", 7) is True

    def test_gt_equal(self):
        assert _num_op(7.0, "gt", 7) is False

    def test_lt_below(self):
        assert _num_op(6.0, "lt", 7) is True

    def test_lt_equal(self):
        assert _num_op(7.0, "lt", 7) is False

    def test_gte_equal(self):
        assert _num_op(7.0, "gte", 7) is True

    def test_gte_above(self):
        assert _num_op(8.0, "gte", 7) is True

    def test_gte_below(self):
        assert _num_op(6.0, "gte", 7) is False

    def test_lte_equal(self):
        assert _num_op(7.0, "lte", 7) is True

    def test_lte_below(self):
        assert _num_op(6.0, "lte", 7) is True

    def test_lte_above(self):
        assert _num_op(8.0, "lte", 7) is False

    def test_non_numeric_value_returns_false(self):
        assert _num_op(7.0, "eq", "not-a-number") is False

    def test_none_value_returns_false(self):
        assert _num_op(7.0, "gte", None) is False

    def test_string_numeric_value_is_coerced(self):
        assert _num_op(7.0, "eq", "7.0") is True

    def test_unknown_op_returns_false(self):
        assert _num_op(5.0, "between", 3) is False


# ─────────────────────────────────────────────────────────
# _eval_asset
# ─────────────────────────────────────────────────────────

class TestEvalAsset:
    # --- string fields ---

    def test_ip_eq_match(self):
        asset = {"ip": "192.168.1.10"}
        assert _eval_asset({"field": "ip", "op": "eq", "value": "192.168.1.10"}, asset) is True

    def test_hostname_contains_match(self):
        asset = {"hostname": "prod-web-01"}
        assert _eval_asset({"field": "hostname", "op": "contains", "value": "prod"}, asset) is True

    def test_fqdn_endswith_match(self):
        asset = {"fqdn": "host.example.com"}
        assert _eval_asset({"field": "fqdn", "op": "endswith", "value": ".com"}, asset) is True

    def test_os_contains_match(self):
        asset = {"os": "Windows Server 2019"}
        assert _eval_asset({"field": "os", "op": "contains", "value": "Windows"}, asset) is True

    def test_os_missing_field_treated_as_empty_string(self):
        # When asset dict has no "os" key it should not raise, just not match.
        asset = {}
        assert _eval_asset({"field": "os", "op": "eq", "value": "anything"}, asset) is False

    # --- numeric fields ---

    def test_criticality_gte_match(self):
        asset = {"criticality": 8}
        assert _eval_asset({"field": "criticality", "op": "gte", "value": 7}, asset) is True

    def test_criticality_gte_no_match(self):
        asset = {"criticality": 5}
        assert _eval_asset({"field": "criticality", "op": "gte", "value": 7}, asset) is False

    def test_risk_score_lte_match(self):
        asset = {"risk_score": 6.5}
        assert _eval_asset({"field": "risk_score", "op": "lte", "value": 7.0}, asset) is True

    def test_critical_count_gt_zero(self):
        asset = {"critical_count": 3}
        assert _eval_asset({"field": "critical_count", "op": "gt", "value": 0}, asset) is True

    def test_numeric_field_missing_defaults_to_zero(self):
        # Missing field → defaults to 0
        asset = {}
        assert _eval_asset({"field": "critical_count", "op": "gt", "value": 0}, asset) is False

    # --- source field (membership check) ---

    def test_source_contains_match(self):
        asset = {"source_systems": ["nessus", "easm"]}
        assert _eval_asset({"field": "source", "op": "contains", "value": "nessus"}, asset) is True

    def test_source_contains_no_match(self):
        asset = {"source_systems": ["qualys"]}
        assert _eval_asset({"field": "source", "op": "contains", "value": "nessus"}, asset) is False

    def test_source_not_contains_absent(self):
        asset = {"source_systems": ["nessus"]}
        assert _eval_asset({"field": "source", "op": "not_contains", "value": "qualys"}, asset) is True

    def test_source_not_contains_present(self):
        asset = {"source_systems": ["nessus", "qualys"]}
        assert _eval_asset({"field": "source", "op": "not_contains", "value": "qualys"}, asset) is False

    def test_source_case_insensitive(self):
        asset = {"source_systems": ["Nessus"]}
        assert _eval_asset({"field": "source", "op": "contains", "value": "nessus"}, asset) is True

    def test_source_empty_list_not_contains_is_true(self):
        asset = {"source_systems": []}
        assert _eval_asset({"field": "source", "op": "not_contains", "value": "nessus"}, asset) is True

    def test_source_missing_key_not_contains_is_true(self):
        asset = {}
        assert _eval_asset({"field": "source", "op": "not_contains", "value": "nessus"}, asset) is True

    # --- ip with cidr op ---

    def test_ip_cidr_in_range(self):
        asset = {"ip": "10.0.0.50"}
        assert _eval_asset({"field": "ip", "op": "cidr", "value": "10.0.0.0/24"}, asset) is True

    def test_ip_cidr_out_of_range(self):
        asset = {"ip": "192.168.0.1"}
        assert _eval_asset({"field": "ip", "op": "cidr", "value": "10.0.0.0/24"}, asset) is False


# ─────────────────────────────────────────────────────────
# migrate_autotag_condition
# ─────────────────────────────────────────────────────────

class TestMigrateAutotagCondition:
    def test_already_new_format_passes_through(self):
        cond = {"field": "ip", "op": "cidr", "value": "10.0.0.0/24"}
        assert migrate_autotag_condition(cond) == cond

    def test_ip_range_maps_to_cidr(self):
        cond = {"field": "ip_range", "value": "10.0.0.0/24"}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "ip", "op": "cidr", "value": "10.0.0.0/24"}

    def test_hostname_pattern_maps_to_glob(self):
        cond = {"field": "hostname_pattern", "value": "*.prod.*"}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "hostname", "op": "glob", "value": "*.prod.*"}

    def test_fqdn_contains_maps_correctly(self):
        cond = {"field": "fqdn_contains", "value": ".example.com"}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "fqdn", "op": "contains", "value": ".example.com"}

    def test_os_contains_maps_correctly(self):
        cond = {"field": "os_contains", "value": "Windows"}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "os", "op": "contains", "value": "Windows"}

    def test_criticality_gte_maps_correctly(self):
        cond = {"field": "criticality_gte", "value": 7}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "criticality", "op": "gte", "value": 7}

    def test_boolean_field_has_exploit_sets_none_value(self):
        cond = {"field": "has_exploit", "value": True}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "finding.exploit", "op": "is_true", "value": None}

    def test_boolean_field_has_cve_sets_none_value(self):
        cond = {"field": "has_cve", "value": True}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "finding.has_cve", "op": "is_true", "value": None}

    def test_severity_gte_maps_correctly(self):
        cond = {"field": "severity_gte", "value": 3}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "finding.severity", "op": "gte", "value": 3}

    def test_plugin_family_contains_maps_correctly(self):
        cond = {"field": "plugin_family_contains", "value": "Windows"}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "finding.plugin_family", "op": "contains", "value": "Windows"}

    def test_unknown_field_passes_through(self):
        cond = {"field": "totally_unknown_field", "value": "something"}
        assert migrate_autotag_condition(cond) == cond

    def test_environment_equals_maps_correctly(self):
        cond = {"field": "environment_equals", "value": "dmz"}
        result = migrate_autotag_condition(cond)
        assert result == {"field": "environment_tag", "op": "eq", "value": "dmz"}


# ─────────────────────────────────────────────────────────
# migrate_campaign_condition
# ─────────────────────────────────────────────────────────

class TestMigrateCampaignCondition:
    def test_already_new_format_passes_through(self):
        cond = {"field": "finding.severity", "op": "gte", "value": 3}
        assert migrate_campaign_condition(cond) == cond

    def test_has_exploit_maps_to_is_true_with_none_value(self):
        cond = {"type": "has_exploit"}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "finding.exploit", "op": "is_true", "value": None}

    def test_has_critical_vuln_forces_value_4(self):
        cond = {"type": "has_critical_vuln"}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "finding.severity", "op": "gte", "value": 4}

    def test_has_high_vuln_forces_value_3(self):
        cond = {"type": "has_high_vuln"}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "finding.severity", "op": "gte", "value": 3}

    def test_severity_gte_keeps_original_value(self):
        cond = {"type": "severity_gte", "value": 2}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "finding.severity", "op": "gte", "value": 2}

    def test_is_internet_facing_maps_to_is_true(self):
        cond = {"type": "is_internet_facing"}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "inventory.is_internet_facing", "op": "is_true", "value": None}

    def test_criticality_gte_keeps_original_value(self):
        cond = {"type": "criticality_gte", "value": 8}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "criticality", "op": "gte", "value": 8}

    def test_no_edr_maps_to_is_true(self):
        cond = {"type": "no_edr"}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "inventory.no_edr", "op": "is_true", "value": None}

    def test_plugin_family_contains_keeps_value(self):
        cond = {"type": "plugin_family_contains", "value": "Windows"}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "finding.plugin_family", "op": "contains", "value": "Windows"}

    def test_has_zero_day_maps_to_is_true(self):
        cond = {"type": "has_zero_day"}
        result = migrate_campaign_condition(cond)
        assert result == {"field": "finding.zero_day", "op": "is_true", "value": None}

    def test_unknown_type_passes_through(self):
        cond = {"type": "totally_unknown_type", "value": "foo"}
        assert migrate_campaign_condition(cond) == cond

    def test_forced_value_overrides_original_value(self):
        # has_critical_vuln ignores any incoming value; forced_val=4 wins.
        cond = {"type": "has_critical_vuln", "value": 99}
        result = migrate_campaign_condition(cond)
        assert result["value"] == 4


# ─────────────────────────────────────────────────────────
# migrate_conditions (list dispatcher)
# ─────────────────────────────────────────────────────────

class TestMigrateConditions:
    def test_autotag_mode_migrates_list(self):
        conditions = [
            {"field": "ip_range", "value": "10.0.0.0/8"},
            {"field": "has_exploit", "value": True},
        ]
        result = migrate_conditions(conditions, mode="autotag")
        assert result[0] == {"field": "ip", "op": "cidr", "value": "10.0.0.0/8"}
        assert result[1] == {"field": "finding.exploit", "op": "is_true", "value": None}

    def test_campaign_mode_migrates_list(self):
        conditions = [
            {"type": "has_critical_vuln"},
            {"type": "no_edr"},
        ]
        result = migrate_conditions(conditions, mode="campaign")
        assert result[0]["field"] == "finding.severity"
        assert result[1]["field"] == "inventory.no_edr"

    def test_default_mode_is_autotag(self):
        # No mode arg → should behave as autotag
        conditions = [{"field": "ip_range", "value": "192.168.0.0/16"}]
        result = migrate_conditions(conditions)
        assert result[0]["op"] == "cidr"

    def test_empty_list_returns_empty_list(self):
        assert migrate_conditions([], mode="autotag") == []

    def test_none_returns_empty_list(self):
        assert migrate_conditions(None, mode="campaign") == []

    def test_mixed_old_and_new_format(self):
        # One already-migrated condition alongside an old one.
        conditions = [
            {"field": "ip", "op": "eq", "value": "10.0.0.1"},  # new format
            {"field": "os_contains", "value": "Linux"},         # old format
        ]
        result = migrate_conditions(conditions, mode="autotag")
        assert result[0] == {"field": "ip", "op": "eq", "value": "10.0.0.1"}
        assert result[1] == {"field": "os", "op": "contains", "value": "Linux"}


# ─────────────────────────────────────────────────────────
# _eval_finding_row — finding.id (bulk match)
# ─────────────────────────────────────────────────────────

class TestFindingIdBulkMatch:
    """finding.id supports comma-separated bulk values, used by the
    Create-Campaign-from-Aggregated-Solution CTA."""

    def _f(self, fid):
        return _FakeFinding(id=fid)

    def test_eq_single_id_match(self):
        assert _eval_finding_row({"field": "finding.id", "op": "eq", "value": "42"}, self._f(42)) is True

    def test_eq_single_id_no_match(self):
        assert _eval_finding_row({"field": "finding.id", "op": "eq", "value": "42"}, self._f(99)) is False

    def test_eq_bulk_csv_match(self):
        cond = {"field": "finding.id", "op": "eq", "value": "1,2,3,42,100"}
        assert _eval_finding_row(cond, self._f(42)) is True

    def test_eq_bulk_csv_no_match(self):
        cond = {"field": "finding.id", "op": "eq", "value": "1,2,3"}
        assert _eval_finding_row(cond, self._f(99)) is False

    def test_eq_csv_with_whitespace(self):
        cond = {"field": "finding.id", "op": "eq", "value": "1, 2 , 3"}
        assert _eval_finding_row(cond, self._f(2)) is True

    def test_neq_match(self):
        cond = {"field": "finding.id", "op": "neq", "value": "1,2,3"}
        assert _eval_finding_row(cond, self._f(99)) is True

    def test_neq_no_match(self):
        cond = {"field": "finding.id", "op": "neq", "value": "1,2,3"}
        assert _eval_finding_row(cond, self._f(2)) is False

    def test_empty_value_returns_false(self):
        assert _eval_finding_row({"field": "finding.id", "op": "eq", "value": ""}, self._f(1)) is False

    def test_invalid_value_returns_false(self):
        # Non-numeric input must not raise
        assert _eval_finding_row({"field": "finding.id", "op": "eq", "value": "abc"}, self._f(1)) is False

