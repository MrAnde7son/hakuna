"""
Comprehensive tests for the dedup service (no DB required).

Covers:
- _deep_merge: recursive dict merging
- _make_keys: hashable key construction in AND/OR modes
- _merge_dicts: field-level merge strategy
- dedup_records: full dedup engine (keep_first / keep_last / merge)
- dedup_inventory: per-entity-type config application
- load_config / save_config: config I/O with tmp files
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.dedup import (
    DEFAULT_CONFIG,
    _deep_merge,
    _make_keys,
    _merge_dicts,
    dedup_inventory,
    dedup_records,
    load_config,
    save_config,
)


# ═══════════════════════════════════════════════════════════
# _deep_merge
# ═══════════════════════════════════════════════════════════

class TestDeepMerge:
    def test_simple_override(self):
        base = {"a": 1, "b": 2}
        override = {"b": 99}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 99}

    def test_new_keys_added(self):
        base = {"a": 1}
        override = {"b": 2, "c": 3}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 2, "c": 3}

    def test_nested_merge(self):
        base = {"top": {"x": 1, "y": 2}, "other": "unchanged"}
        override = {"top": {"y": 99, "z": 3}}
        result = _deep_merge(base, override)
        assert result["top"] == {"x": 1, "y": 99, "z": 3}
        assert result["other"] == "unchanged"

    def test_non_dict_values_replaced(self):
        base = {"a": [1, 2, 3]}
        override = {"a": [4, 5]}
        result = _deep_merge(base, override)
        assert result["a"] == [4, 5]

    def test_empty_override_returns_base_copy(self):
        base = {"a": 1, "b": {"c": 2}}
        result = _deep_merge(base, {})
        assert result == base
        # Must be a copy, not the same object
        assert result is not base

    def test_deep_override_does_not_mutate_base(self):
        base = {"nested": {"key": "original"}}
        override = {"nested": {"key": "changed"}}
        _deep_merge(base, override)
        assert base["nested"]["key"] == "original"


# ═══════════════════════════════════════════════════════════
# _make_keys
# ═══════════════════════════════════════════════════════════

class TestMakeKeys:
    # AND mode (composite key) ─────────────────────────────

    def test_and_mode_all_fields_present(self):
        record = {"plugin_id": "12345", "asset_id": 7, "port": 443}
        keys = _make_keys(record, ["plugin_id", "asset_id", "port"], key_mode="and")
        assert len(keys) == 1
        # Composite key contains all three fields
        key = keys[0]
        assert ("plugin_id", "12345") in key
        assert ("asset_id", "7") in key
        assert ("port", "443") in key

    def test_and_mode_missing_all_fields_returns_empty(self):
        record = {}
        keys = _make_keys(record, ["plugin_id", "asset_id"], key_mode="and")
        assert keys == []

    def test_and_mode_partial_fields_still_produces_key(self):
        # Only some fields present — still generates a key (partial match)
        record = {"plugin_id": "99", "port": None}
        keys = _make_keys(record, ["plugin_id", "port"], key_mode="and")
        assert len(keys) == 1
        # plugin_id present, port absent → None entry
        key = dict(keys[0])
        assert key["plugin_id"] == "99"
        assert key["port"] is None

    def test_and_mode_list_expand_field_cve(self):
        record = {"cves": ["CVE-2024-001", "CVE-2024-002"]}
        keys = _make_keys(record, ["cve"], key_mode="and")
        assert len(keys) == 1
        # cves sorted and packed as a tuple
        key = dict(keys[0])
        assert key["cve"] == ("CVE-2024-001", "CVE-2024-002")

    def test_and_mode_empty_cves_list_returns_empty(self):
        record = {"cves": []}
        keys = _make_keys(record, ["cve"], key_mode="and")
        assert keys == []

    # OR mode (one key per field) ──────────────────────────

    def test_or_mode_each_field_is_separate_key(self):
        record = {"ip": "10.0.0.1", "hostname": "srv01", "fqdn": "srv01.example.com"}
        keys = _make_keys(record, ["ip", "hostname", "fqdn"], key_mode="or")
        assert ("ip", "10.0.0.1") in keys
        assert ("hostname", "srv01") in keys
        assert ("fqdn", "srv01.example.com") in keys
        assert len(keys) == 3

    def test_or_mode_missing_fields_produce_no_key(self):
        record = {"ip": "10.0.0.1", "hostname": None, "fqdn": ""}
        keys = _make_keys(record, ["ip", "hostname", "fqdn"], key_mode="or")
        # Only ip has a value
        assert keys == [("ip", "10.0.0.1")]

    def test_or_mode_all_missing_returns_empty(self):
        record = {}
        keys = _make_keys(record, ["ip", "hostname"], key_mode="or")
        assert keys == []

    def test_or_mode_list_expand_cve(self):
        record = {"cves": ["CVE-2024-100", "CVE-2024-200"]}
        keys = _make_keys(record, ["cve"], key_mode="or")
        assert ("cve", "CVE-2024-100") in keys
        assert ("cve", "CVE-2024-200") in keys
        assert len(keys) == 2


# ═══════════════════════════════════════════════════════════
# _merge_dicts
# ═══════════════════════════════════════════════════════════

class TestMergeDicts:
    def test_list_fields_are_unioned(self):
        first = {"cves": ["CVE-2024-001", "CVE-2024-002"]}
        second = {"cves": ["CVE-2024-002", "CVE-2024-003"]}
        result = _merge_dicts(first, second)
        assert set(result["cves"]) == {"CVE-2024-001", "CVE-2024-002", "CVE-2024-003"}
        # No duplicates
        assert len(result["cves"]) == 3

    def test_bool_fields_are_ored(self):
        first = {"exploit_available": False}
        second = {"exploit_available": True}
        result = _merge_dicts(first, second)
        assert result["exploit_available"] is True

    def test_bool_false_or_false_stays_false(self):
        first = {"exploit_available": False}
        second = {"exploit_available": False}
        result = _merge_dicts(first, second)
        assert result["exploit_available"] is False

    def test_scalar_first_non_null_wins(self):
        first = {"os": "Linux", "description": None}
        second = {"os": "Windows", "description": "A finding"}
        result = _merge_dicts(first, second)
        # first's os wins (non-null)
        assert result["os"] == "Linux"
        # second fills in the null description
        assert result["description"] == "A finding"

    def test_hostname_prefers_real_hostname_over_ip(self):
        # First record has IP-as-hostname, second has real hostname
        first = {"hostname": "192.168.1.1"}
        second = {"hostname": "webserver01"}
        result = _merge_dicts(first, second)
        assert result["hostname"] == "webserver01"

    def test_hostname_real_hostname_not_replaced_by_ip(self):
        # First record already has a real hostname — should not be replaced by an IP
        first = {"hostname": "dbserver01"}
        second = {"hostname": "10.0.0.5"}
        result = _merge_dicts(first, second)
        assert result["hostname"] == "dbserver01"

    def test_new_keys_from_second_added(self):
        first = {"ip": "10.0.0.1"}
        second = {"ip": "10.0.0.1", "os": "Linux"}
        result = _merge_dicts(first, second)
        assert result["os"] == "Linux"

    def test_list_union_preserves_order(self):
        first = {"tags": ["a", "b"]}
        second = {"tags": ["c", "a"]}
        result = _merge_dicts(first, second)
        # "a" appears only once; "c" appended after existing items
        assert result["tags"].index("a") < result["tags"].index("c")
        assert result["tags"].count("a") == 1


# ═══════════════════════════════════════════════════════════
# dedup_records
# ═══════════════════════════════════════════════════════════

class TestDedupRecords:
    # keep_first ───────────────────────────────────────────

    def test_keep_first_retains_first_seen(self):
        records = [
            {"ip": "10.0.0.1", "os": "Linux"},
            {"ip": "10.0.0.1", "os": "Windows"},
        ]
        result = dedup_records(records, ["ip"], "keep_first", key_mode="and")
        assert len(result) == 1
        assert result[0]["os"] == "Linux"

    def test_keep_first_distinct_records_both_kept(self):
        records = [
            {"ip": "10.0.0.1"},
            {"ip": "10.0.0.2"},
        ]
        result = dedup_records(records, ["ip"], "keep_first", key_mode="and")
        assert len(result) == 2

    # keep_last ────────────────────────────────────────────

    def test_keep_last_retains_last_seen(self):
        records = [
            {"ip": "10.0.0.1", "os": "Linux"},
            {"ip": "10.0.0.1", "os": "Windows"},
        ]
        result = dedup_records(records, ["ip"], "keep_last", key_mode="and")
        assert len(result) == 1
        assert result[0]["os"] == "Windows"

    def test_keep_last_three_duplicates_keeps_last(self):
        records = [
            {"ip": "10.0.0.1", "ver": 1},
            {"ip": "10.0.0.1", "ver": 2},
            {"ip": "10.0.0.1", "ver": 3},
        ]
        result = dedup_records(records, ["ip"], "keep_last", key_mode="and")
        assert len(result) == 1
        assert result[0]["ver"] == 3

    # merge ────────────────────────────────────────────────

    def test_merge_strategy_unions_lists(self):
        records = [
            {"ip": "10.0.0.1", "cves": ["CVE-2024-001"]},
            {"ip": "10.0.0.1", "cves": ["CVE-2024-002"]},
        ]
        result = dedup_records(records, ["ip"], "merge", key_mode="and")
        assert len(result) == 1
        assert set(result[0]["cves"]) == {"CVE-2024-001", "CVE-2024-002"}

    def test_merge_strategy_ors_booleans(self):
        records = [
            {"ip": "10.0.0.1", "exploit_available": False},
            {"ip": "10.0.0.1", "exploit_available": True},
        ]
        result = dedup_records(records, ["ip"], "merge", key_mode="and")
        assert result[0]["exploit_available"] is True

    # Empty / no-key edge cases ────────────────────────────

    def test_empty_records_returned_unchanged(self):
        assert dedup_records([], ["ip"], "keep_first") == []

    def test_empty_key_fields_returned_unchanged(self):
        records = [{"ip": "10.0.0.1"}]
        assert dedup_records(records, [], "keep_first") == records

    def test_records_with_no_matching_keys_kept_in_result(self):
        # Records where all key fields are None/missing go to no_key list
        records = [
            {"ip": None, "hostname": None},
            {"ip": None, "hostname": None},
        ]
        result = dedup_records(records, ["ip"], "keep_first", key_mode="and")
        # Both kept — they can't be deduplicated without a key
        assert len(result) == 2

    # OR mode dedup ────────────────────────────────────────

    def test_or_mode_matches_on_any_field(self):
        # These two records share the same IP but different hostnames.
        # In OR mode, matching ip is enough to consider them duplicates.
        records = [
            {"ip": "10.0.0.1", "hostname": "host-a", "os": "Linux"},
            {"ip": "10.0.0.1", "hostname": "host-b", "os": "Windows"},
        ]
        result = dedup_records(records, ["ip", "hostname"], "keep_first", key_mode="or")
        assert len(result) == 1

    def test_or_mode_no_overlap_keeps_both(self):
        # No field values overlap → separate records
        records = [
            {"ip": "10.0.0.1", "hostname": "host-a"},
            {"ip": "10.0.0.2", "hostname": "host-b"},
        ]
        result = dedup_records(records, ["ip", "hostname"], "keep_first", key_mode="or")
        assert len(result) == 2

    # AND mode dedup ───────────────────────────────────────

    def test_and_mode_requires_all_fields_to_match(self):
        # Same plugin_id but different asset_id → NOT duplicates in AND mode
        records = [
            {"plugin_id": "1001", "asset_id": 1, "port": 80},
            {"plugin_id": "1001", "asset_id": 2, "port": 80},
        ]
        result = dedup_records(records, ["plugin_id", "asset_id"], "keep_first", key_mode="and")
        assert len(result) == 2

    def test_and_mode_full_match_is_deduplicated(self):
        records = [
            {"plugin_id": "1001", "asset_id": 5, "note": "first"},
            {"plugin_id": "1001", "asset_id": 5, "note": "second"},
        ]
        result = dedup_records(records, ["plugin_id", "asset_id"], "keep_first", key_mode="and")
        assert len(result) == 1
        assert result[0]["note"] == "first"


# ═══════════════════════════════════════════════════════════
# dedup_inventory
# ═══════════════════════════════════════════════════════════

class TestDedupInventory:
    def _enabled_cfg(self, **inventory_overrides) -> dict:
        """Build a minimal config dict with dedup enabled."""
        cfg = {
            "enabled": True,
            "apply_on_upload": True,
            "inventory": {
                "users": {
                    "enabled": True,
                    "key_fields": ["username", "domain"],
                    "strategy": "merge",
                },
                "software": {
                    "enabled": True,
                    "key_fields": ["name", "version"],
                    "strategy": "keep_first",
                },
            },
        }
        cfg["inventory"].update(inventory_overrides)
        return cfg

    def test_disabled_config_returns_inventory_unchanged(self):
        inventory = {"users": [{"username": "alice"}, {"username": "alice"}]}
        cfg = {"enabled": False, "apply_on_upload": True, "inventory": {}}
        result = dedup_inventory(inventory, cfg)
        assert result is inventory

    def test_apply_on_upload_false_returns_inventory_unchanged(self):
        inventory = {"users": [{"username": "alice"}, {"username": "alice"}]}
        cfg = {"enabled": True, "apply_on_upload": False, "inventory": {}}
        result = dedup_inventory(inventory, cfg)
        assert result is inventory

    def test_processes_configured_entity_type(self):
        inventory = {
            "users": [
                {"username": "alice", "domain": "corp", "groups": ["admins"]},
                {"username": "alice", "domain": "corp", "groups": ["users"]},
            ]
        }
        cfg = self._enabled_cfg()
        result = dedup_inventory(inventory, cfg)
        assert len(result["users"]) == 1
        # merge strategy → lists unioned
        assert set(result["users"][0]["groups"]) == {"admins", "users"}

    def test_entity_type_disabled_in_config_is_skipped(self):
        inventory = {
            "software": [
                {"name": "curl", "version": "7.80"},
                {"name": "curl", "version": "7.80"},
            ]
        }
        cfg = self._enabled_cfg(
            software={"enabled": False, "key_fields": ["name", "version"], "strategy": "keep_first"}
        )
        result = dedup_inventory(inventory, cfg)
        # Disabled → no dedup → both records kept
        assert len(result["software"]) == 2

    def test_empty_entity_list_passes_through(self):
        inventory = {"users": [], "software": []}
        cfg = self._enabled_cfg()
        result = dedup_inventory(inventory, cfg)
        assert result["users"] == []
        assert result["software"] == []

    def test_missing_entity_in_inventory_defaults_to_empty_list(self):
        inventory = {}
        cfg = self._enabled_cfg()
        result = dedup_inventory(inventory, cfg)
        assert result.get("users") == []

    def test_multiple_entity_types_deduplicated_independently(self):
        inventory = {
            "users": [
                {"username": "bob", "domain": "corp"},
                {"username": "bob", "domain": "corp"},
            ],
            "software": [
                {"name": "openssl", "version": "1.1.1"},
                {"name": "openssl", "version": "1.1.1"},
                {"name": "openssl", "version": "3.0"},
            ],
        }
        cfg = self._enabled_cfg()
        result = dedup_inventory(inventory, cfg)
        assert len(result["users"]) == 1
        assert len(result["software"]) == 2  # different versions kept separate


# ═══════════════════════════════════════════════════════════
# load_config / save_config
# ═══════════════════════════════════════════════════════════

class TestConfigIO:
    def test_save_and_load_roundtrip(self, tmp_path, monkeypatch):
        """Config written to disk is read back and deep-merged with defaults."""
        import services.dedup as dedup_mod

        config_file = tmp_path / "dedup_config.json"
        monkeypatch.setattr(dedup_mod, "CONFIG_PATH", config_file)

        custom_cfg = {"enabled": False, "assets": {"key_fields": ["fqdn"]}}
        save_config(custom_cfg)

        loaded = load_config()
        # Our override is merged in
        assert loaded["enabled"] is False
        assert loaded["assets"]["key_fields"] == ["fqdn"]
        # Defaults for unspecified keys are still present
        assert "inventory" in loaded

    def test_load_config_no_file_returns_defaults(self, tmp_path, monkeypatch):
        import services.dedup as dedup_mod

        config_file = tmp_path / "nonexistent_config.json"
        monkeypatch.setattr(dedup_mod, "CONFIG_PATH", config_file)

        loaded = load_config()
        assert loaded == DEFAULT_CONFIG

    def test_load_config_invalid_json_returns_defaults(self, tmp_path, monkeypatch):
        import services.dedup as dedup_mod

        config_file = tmp_path / "bad_config.json"
        config_file.write_text("{ this is not json }")
        monkeypatch.setattr(dedup_mod, "CONFIG_PATH", config_file)

        loaded = load_config()
        assert loaded == DEFAULT_CONFIG

    def test_save_config_writes_valid_json(self, tmp_path, monkeypatch):
        import services.dedup as dedup_mod

        config_file = tmp_path / "dedup_config.json"
        monkeypatch.setattr(dedup_mod, "CONFIG_PATH", config_file)

        save_config({"enabled": True, "my_key": "my_value"})

        raw = json.loads(config_file.read_text())
        assert raw["enabled"] is True
        assert raw["my_key"] == "my_value"
