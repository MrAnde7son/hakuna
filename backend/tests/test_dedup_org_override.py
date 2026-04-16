"""Tests for the per-org dedup config override helpers.

Mirrors backend/core/risk_config.py's pattern:
    - Global config lives in backend/config/dedup_config.json
    - Per-org overrides live in Organization.settings["dedup_config"]
    - Overrides are deep-merged on top of the global at read time
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import services.dedup as dedup_engine
from models.models import Organization


# ═══════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def org_a(db_session):
    org = Organization(name="Org A", slug="org-a", settings={})
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def org_b(db_session):
    org = Organization(name="Org B", slug="org-b", settings={})
    db_session.add(org)
    db_session.flush()
    return org


# ═══════════════════════════════════════════════════════════
# load_config_for_org
# ═══════════════════════════════════════════════════════════

class TestLoadConfigForOrg:
    def test_org_none_returns_global(self, db_session):
        cfg = dedup_engine.load_config_for_org(db_session, None)
        global_cfg = dedup_engine.load_config()
        assert cfg == global_cfg

    def test_no_override_returns_global(self, db_session, org_a):
        cfg = dedup_engine.load_config_for_org(db_session, org_a.id)
        global_cfg = dedup_engine.load_config()
        assert cfg == global_cfg

    def test_unknown_org_returns_global(self, db_session):
        cfg = dedup_engine.load_config_for_org(db_session, 999999)
        assert cfg == dedup_engine.load_config()

    def test_sparse_override_deep_merged(self, db_session, org_a):
        """Overriding findings.strategy should NOT drop findings.key_fields."""
        org_a.settings = {
            "dedup_config": {
                "findings": {"strategy": "merge"},
            },
        }
        db_session.flush()

        cfg = dedup_engine.load_config_for_org(db_session, org_a.id)
        # The override applies:
        assert cfg["findings"]["strategy"] == "merge"
        # …but the global fields we didn't override survive:
        assert cfg["findings"]["key_fields"] == ["plugin_id", "asset_id", "port"]
        assert cfg["findings"]["scope"] == "cross_scan"

    def test_full_section_override_replaces(self, db_session, org_a):
        """A fully-specified section override replaces the whole block's matching keys."""
        org_a.settings = {
            "dedup_config": {
                "findings": {
                    "enabled": True,
                    "key_fields": ["normalized_id", "asset_id", "url_path", "http_method"],
                    "strategy": "merge",
                    "scope": "cross_scan",
                },
            },
        }
        db_session.flush()

        cfg = dedup_engine.load_config_for_org(db_session, org_a.id)
        assert cfg["findings"]["key_fields"] == [
            "normalized_id", "asset_id", "url_path", "http_method",
        ]
        assert cfg["findings"]["strategy"] == "merge"

    def test_tenant_isolation(self, db_session, org_a, org_b):
        """Org A's override is not visible to Org B."""
        org_a.settings = {"dedup_config": {"findings": {"strategy": "keep_first"}}}
        db_session.flush()

        cfg_a = dedup_engine.load_config_for_org(db_session, org_a.id)
        cfg_b = dedup_engine.load_config_for_org(db_session, org_b.id)

        assert cfg_a["findings"]["strategy"] == "keep_first"
        # Org B falls back to the global default (keep_last).
        assert cfg_b["findings"]["strategy"] == "keep_last"


# ═══════════════════════════════════════════════════════════
# save_config_for_org
# ═══════════════════════════════════════════════════════════

class TestSaveConfigForOrg:
    def test_save_persists_override(self, db_session, org_a):
        override = {"findings": {"strategy": "merge"}}
        dedup_engine.save_config_for_org(db_session, org_a.id, override)

        # Re-read and confirm the override was recorded…
        db_session.refresh(org_a)
        assert org_a.settings["dedup_config"] == override

        # …and that load_config_for_org returns the merged view.
        cfg = dedup_engine.load_config_for_org(db_session, org_a.id)
        assert cfg["findings"]["strategy"] == "merge"
        assert cfg["findings"]["key_fields"] == ["plugin_id", "asset_id", "port"]  # from global

    def test_save_preserves_other_settings_keys(self, db_session, org_a):
        """Dedup override must not trample over other Organization.settings keys."""
        org_a.settings = {"risk_config": {"severity_scores": {"critical": 9.5}}}
        db_session.flush()

        dedup_engine.save_config_for_org(db_session, org_a.id, {"findings": {"enabled": True}})
        db_session.refresh(org_a)

        assert "risk_config" in org_a.settings
        assert org_a.settings["risk_config"]["severity_scores"]["critical"] == 9.5
        assert org_a.settings["dedup_config"]["findings"]["enabled"] is True

    def test_save_unknown_org_raises(self, db_session):
        with pytest.raises(ValueError):
            dedup_engine.save_config_for_org(db_session, 999999, {"findings": {}})

    def test_save_org_none_uses_global_file(self, db_session, monkeypatch):
        """save_config_for_org(None, cfg) should delegate to save_config()."""
        called = {}

        def fake_save_config(cfg):
            called["cfg"] = cfg

        monkeypatch.setattr(dedup_engine, "save_config", fake_save_config)
        dedup_engine.save_config_for_org(db_session, None, {"findings": {"enabled": False}})
        assert called["cfg"] == {"findings": {"enabled": False}}


# ═══════════════════════════════════════════════════════════
# delete_config_for_org / has_org_override / load_org_override
# ═══════════════════════════════════════════════════════════

class TestOverrideLifecycle:
    def test_has_override_false_when_none(self, db_session, org_a):
        assert dedup_engine.has_org_override(db_session, org_a.id) is False

    def test_has_override_true_after_save(self, db_session, org_a):
        dedup_engine.save_config_for_org(db_session, org_a.id, {"findings": {"enabled": True}})
        assert dedup_engine.has_org_override(db_session, org_a.id) is True

    def test_has_override_none_org_returns_false(self, db_session):
        assert dedup_engine.has_org_override(db_session, None) is False

    def test_load_org_override_empty_when_none(self, db_session, org_a):
        assert dedup_engine.load_org_override(db_session, org_a.id) == {}

    def test_load_org_override_returns_sparse(self, db_session, org_a):
        override = {"findings": {"strategy": "keep_first"}}
        dedup_engine.save_config_for_org(db_session, org_a.id, override)
        assert dedup_engine.load_org_override(db_session, org_a.id) == override

    def test_delete_removes_override(self, db_session, org_a):
        dedup_engine.save_config_for_org(db_session, org_a.id, {"findings": {"enabled": True}})
        assert dedup_engine.has_org_override(db_session, org_a.id) is True

        removed = dedup_engine.delete_config_for_org(db_session, org_a.id)
        assert removed is True
        assert dedup_engine.has_org_override(db_session, org_a.id) is False

        # After deletion, load_config_for_org reverts to the global.
        cfg = dedup_engine.load_config_for_org(db_session, org_a.id)
        assert cfg == dedup_engine.load_config()

    def test_delete_returns_false_when_no_override(self, db_session, org_a):
        assert dedup_engine.delete_config_for_org(db_session, org_a.id) is False

    def test_delete_none_org_returns_false(self, db_session):
        assert dedup_engine.delete_config_for_org(db_session, None) is False

    def test_delete_preserves_other_settings_keys(self, db_session, org_a):
        org_a.settings = {
            "dedup_config": {"findings": {"enabled": True}},
            "risk_config": {"severity_scores": {"critical": 9.5}},
        }
        db_session.flush()

        dedup_engine.delete_config_for_org(db_session, org_a.id)
        db_session.refresh(org_a)

        assert "dedup_config" not in org_a.settings
        assert "risk_config" in org_a.settings
