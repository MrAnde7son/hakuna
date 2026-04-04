"""Tests for multi-type asset model: asset_type, asset_identity, per-type dedup."""
import json
import pytest

from services import dedup as dedup_engine
from services.asset_classifier import classify_asset, ASSET_TYPE_DEFAULTS


# ─────────────────────────────────────────────
# Per-type dedup config helpers
# ─────────────────────────────────────────────

class TestAssetTypeConfigResolution:
    """Test get_asset_type_config with per-type and legacy configs."""

    def test_per_type_config_returns_correct_type(self):
        cfg = {
            "assets": {
                "host": {"enabled": True, "key_fields": ["ip", "fqdn"], "key_mode": "or"},
                "web_app": {"enabled": True, "key_fields": ["url"], "key_mode": "and"},
            }
        }
        host_cfg = dedup_engine.get_asset_type_config(cfg, "host")
        assert host_cfg["key_fields"] == ["ip", "fqdn"]
        assert host_cfg["key_mode"] == "or"

        web_cfg = dedup_engine.get_asset_type_config(cfg, "web_app")
        assert web_cfg["key_fields"] == ["url"]
        assert web_cfg["key_mode"] == "and"

    def test_unknown_type_returns_defaults(self):
        cfg = {"assets": {"host": {"enabled": True, "key_fields": ["ip"]}}}
        custom_cfg = dedup_engine.get_asset_type_config(cfg, "saas_app")
        assert custom_cfg["enabled"] is True
        assert custom_cfg["key_mode"] == "and"

    def test_legacy_flat_config_backward_compat(self):
        """Old flat config (pre per-type) should still work."""
        cfg = {
            "assets": {
                "enabled": True,
                "key_fields": ["ip"],
                "key_mode": "or",
                "strategy": "merge",
                "scope": "cross_scan",
            }
        }
        host_cfg = dedup_engine.get_asset_type_config(cfg, "host")
        assert host_cfg["key_fields"] == ["ip"]
        assert host_cfg["key_mode"] == "or"

        # Even non-host types fall back to the flat config
        web_cfg = dedup_engine.get_asset_type_config(cfg, "web_app")
        assert web_cfg["key_fields"] == ["ip"]


# ─────────────────────────────────────────────
# Field resolution from asset_identity
# ─────────────────────────────────────────────

class TestGetAssetField:
    """Test _get_asset_field resolves from columns and asset_identity."""

    def test_dict_column_field(self):
        record = {"ip": "10.0.0.1", "hostname": "srv01"}
        assert dedup_engine._get_asset_field(record, "ip") == "10.0.0.1"

    def test_dict_identity_field(self):
        record = {"asset_identity": {"url": "http://example.com", "domain": "example.com"}}
        assert dedup_engine._get_asset_field(record, "url") == "http://example.com"

    def test_dict_column_takes_precedence(self):
        record = {"ip": "10.0.0.1", "asset_identity": {"ip": "192.168.1.1"}}
        assert dedup_engine._get_asset_field(record, "ip") == "10.0.0.1"

    def test_dict_missing_field_returns_none(self):
        record = {"ip": "10.0.0.1"}
        assert dedup_engine._get_asset_field(record, "url") is None


# ─────────────────────────────────────────────
# In-memory asset dedup by type
# ─────────────────────────────────────────────

class TestDedupAssetRecords:
    """Test dedup_asset_records with per-type config."""

    def test_host_dedup_by_ip(self):
        cfg = {
            "assets": {
                "host": {"enabled": True, "key_fields": ["ip"], "key_mode": "or", "strategy": "merge"},
            }
        }
        records = [
            {"asset_type": "host", "ip": "10.0.0.1", "hostname": "srv01"},
            {"asset_type": "host", "ip": "10.0.0.1", "hostname": "srv01-alias"},
            {"asset_type": "host", "ip": "10.0.0.2", "hostname": "srv02"},
        ]
        result = dedup_engine.dedup_asset_records(records, cfg)
        assert len(result) == 2

    def test_web_app_dedup_by_url(self):
        cfg = {
            "assets": {
                "web_app": {"enabled": True, "key_fields": ["url"], "key_mode": "and", "strategy": "keep_last"},
            }
        }
        records = [
            {"asset_type": "web_app", "asset_identity": {"url": "http://app.com:8080/", "domain": "app.com"}},
            {"asset_type": "web_app", "asset_identity": {"url": "http://app.com:8080/", "domain": "app.com"}},
            {"asset_type": "web_app", "asset_identity": {"url": "http://other.com/", "domain": "other.com"}},
        ]
        result = dedup_engine.dedup_asset_records(records, cfg)
        assert len(result) == 2

    def test_different_types_never_dedup(self):
        """A host and a web_app with the same IP should NOT dedup."""
        cfg = {
            "assets": {
                "host": {"enabled": True, "key_fields": ["ip"], "key_mode": "or", "strategy": "merge"},
                "web_app": {"enabled": True, "key_fields": ["url"], "key_mode": "and", "strategy": "keep_last"},
            }
        }
        records = [
            {"asset_type": "host", "ip": "10.0.0.1"},
            {"asset_type": "web_app", "ip": "10.0.0.1", "asset_identity": {"url": "http://10.0.0.1:8080/"}},
        ]
        result = dedup_engine.dedup_asset_records(records, cfg)
        assert len(result) == 2

    def test_web_app_different_ports_stay_separate(self):
        """Two WAS assets on same IP but different ports should NOT dedup (different URLs)."""
        cfg = {
            "assets": {
                "web_app": {"enabled": True, "key_fields": ["url"], "key_mode": "and", "strategy": "keep_last"},
            }
        }
        records = [
            {"asset_type": "web_app", "ip": "10.0.0.1", "asset_identity": {"url": "http://10.0.0.1:8080/"}},
            {"asset_type": "web_app", "ip": "10.0.0.1", "asset_identity": {"url": "http://10.0.0.1:443/"}},
        ]
        result = dedup_engine.dedup_asset_records(records, cfg)
        assert len(result) == 2

    def test_custom_type_with_no_config_passes_through(self):
        """Unknown custom asset types with no dedup config should not be dropped."""
        cfg = {"assets": {"host": {"enabled": True, "key_fields": ["ip"], "strategy": "merge"}}}
        records = [
            {"asset_type": "saas_app", "asset_identity": {"tenant": "acme", "app": "salesforce"}},
            {"asset_type": "saas_app", "asset_identity": {"tenant": "acme", "app": "slack"}},
        ]
        result = dedup_engine.dedup_asset_records(records, cfg)
        # No config = no key_fields = pass through
        assert len(result) == 2

    def test_default_asset_type_is_host(self):
        """Records without asset_type should default to host."""
        cfg = {
            "assets": {
                "host": {"enabled": True, "key_fields": ["ip"], "key_mode": "or", "strategy": "merge"},
            }
        }
        records = [
            {"ip": "10.0.0.1"},
            {"ip": "10.0.0.1"},
        ]
        result = dedup_engine.dedup_asset_records(records, cfg)
        assert len(result) == 1


# ─────────────────────────────────────────────
# Classifier for non-host types
# ─────────────────────────────────────────────

class TestClassifyNonHostAssets:
    """Test classify_asset returns correct defaults for non-host types."""

    def test_web_app_classification(self):
        result = classify_asset({"asset_type": "web_app", "hostname": "http://example.com"})
        assert result["environment_tag"] == "external"
        assert result["business_context"] == "Web Application"
        assert result["context_criticality"] == 7

    def test_cloud_instance_classification(self):
        result = classify_asset({"asset_type": "cloud_instance"})
        assert result["environment_tag"] == "cloud"
        assert result["context_criticality"] == 5

    def test_unknown_custom_type_gets_safe_defaults(self):
        result = classify_asset({"asset_type": "ai_agent"})
        assert result["environment_tag"] == "internal"
        assert result["context_criticality"] == 5

    def test_host_type_uses_existing_logic(self):
        """Host assets should still use the heuristic classifier."""
        result = classify_asset({"asset_type": "host", "hostname": "prod-web-01"})
        assert result["environment_tag"] == "production"

    def test_no_asset_type_defaults_to_host(self):
        result = classify_asset({"hostname": "dev-db-01"})
        assert result["environment_tag"] == "development"

    def test_all_known_types_have_defaults(self):
        for atype in ASSET_TYPE_DEFAULTS:
            result = classify_asset({"asset_type": atype})
            assert "environment_tag" in result
            assert "business_context" in result


# ─────────────────────────────────────────────
# Entity registry dict_fields merge
# ─────────────────────────────────────────────

class TestDictFieldsMerge:
    """Test _merge_model_row handles dict_fields correctly."""

    def test_unpack_entity_map_3_element(self):
        entry = ("Model", ["list1"], ["bool1"])
        model, lf, bf, df = dedup_engine._unpack_entity_map(entry)
        assert model == "Model"
        assert df == []

    def test_unpack_entity_map_4_element(self):
        entry = ("Model", ["list1"], ["bool1"], ["dict1"])
        model, lf, bf, df = dedup_engine._unpack_entity_map(entry)
        assert df == ["dict1"]


# ─────────────────────────────────────────────
# Parser WAS detection
# ─────────────────────────────────────────────

class TestParserWASDetection:
    """Test that the XML parser detects WAS scans and populates asset_type/identity."""

    def test_was_asset_type_set(self):
        """When system-type is web_application, asset_type should be web_app."""
        from parsers.parser import parse_nessus_xml
        import xml.etree.ElementTree as ET

        xml = '''<?xml version="1.0"?>
        <NessusClientData_v2>
          <Policy><policyName>WAS</policyName></Policy>
          <Report name="test">
            <ReportHost name="http://10.0.0.1:8080/">
              <HostProperties>
                <tag name="system-type">web_application</tag>
                <tag name="HOST_END">2025-01-01</tag>
              </HostProperties>
            </ReportHost>
          </Report>
        </NessusClientData_v2>'''

        result = parse_nessus_xml(xml, "test.nessus")
        assets = result["assets"]
        assert len(assets) == 1
        assert assets[0]["asset_type"] == "web_app"
        assert assets[0]["asset_identity"]["url"] == "http://10.0.0.1:8080/"
        assert assets[0]["asset_identity"]["domain"] == "10.0.0.1"
        # IP should still be extracted for correlation
        assert assets[0]["ip"] == "10.0.0.1"

    def test_regular_host_no_asset_type(self):
        """Regular host scans should not set asset_type (defaults in model)."""
        from parsers.parser import parse_nessus_xml

        xml = '''<?xml version="1.0"?>
        <NessusClientData_v2>
          <Policy><policyName>Basic</policyName></Policy>
          <Report name="test">
            <ReportHost name="10.0.0.1">
              <HostProperties>
                <tag name="host-ip">10.0.0.1</tag>
                <tag name="HOST_END">2025-01-01</tag>
              </HostProperties>
            </ReportHost>
          </Report>
        </NessusClientData_v2>'''

        result = parse_nessus_xml(xml, "test.nessus")
        assets = result["assets"]
        assert len(assets) == 1
        # No asset_type set (will default to "host" in model)
        assert assets[0].get("asset_type") is None or assets[0].get("asset_type") == "host"
        # But asset_identity should be populated with IP
        assert assets[0].get("asset_identity", {}).get("ip") == "10.0.0.1"
