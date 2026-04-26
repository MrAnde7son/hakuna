"""PR 2 — compliance YAML loader.

Pins:
  - Validation: every rule's field/op pair must be in the rule_engine catalog.
  - Idempotency: re-loading an unchanged YAML is a no-op (status=skipped).
  - Drift: changed YAML triggers updated status, bumps rule_version when the
    rule body changed, drops controls/mappings absent from the new file.
  - Audit: framework load writes an AuditLog row with entity_type
    "compliance_framework_release".
  - Bundled CIS v8 YAML: parses, validates, and round-trips through the loader.
"""

import os
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.models import (
    AuditLog,
    ComplianceFramework, ComplianceControl, ComplianceControlMapping,
    ComplianceFrameworkRelease,
)
from services import compliance_loader


# ─── helpers ───────────────────────────────────────────────────

def _write_yaml(tmp_path: Path, slug: str, content: str) -> Path:
    fw_dir = tmp_path / slug
    fw_dir.mkdir()
    yaml_path = fw_dir / "v1.yaml"
    yaml_path.write_text(textwrap.dedent(content))
    return yaml_path


_VALID_YAML = """
framework:
  slug: test_fw
  name: Test Framework
  version: "1.0"
release:
  tag: "test-r1"
  notes: "first release"
controls:
  - ref: "1.1"
    title: First Control
    domain: Test
    testability: automated
    mappings:
      - key: test_fw_1_1_kev_unresolved
        when:
          logic: AND
          conditions:
            - field: finding.is_kev
              op: is_true
            - field: finding.workflow_status
              op: not_in
              value: [resolved, false_positive]
"""


# ─── Validation ────────────────────────────────────────────────

class TestValidation:
    def test_unknown_field_blocks_load(self, db_session, tmp_path):
        bad = _VALID_YAML.replace("finding.is_kev", "finding.bogus_field")
        path = _write_yaml(tmp_path, "test_fw", bad)
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "validation_error"
        assert "finding.bogus_field" in result["error"]
        # No DB writes happened.
        assert db_session.query(ComplianceFramework).filter_by(slug="test_fw").first() is None

    def test_unknown_op_blocks_load(self, db_session, tmp_path):
        bad = _VALID_YAML.replace("op: is_true", "op: not_an_op")
        path = _write_yaml(tmp_path, "test_fw", bad)
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "validation_error"
        assert "not_an_op" in result["error"]

    def test_missing_framework_block(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw", "controls: []\n")
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "schema_error"

    def test_missing_slug(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw",
                           "framework:\n  name: NoSlug\n  version: '1'\ncontrols: []\n")
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "schema_error"

    def test_in_op_validates_against_catalog(self, db_session, tmp_path):
        # PR 2 added in / not_in to rule_engine; loader must accept them on
        # any catalog-registered field.
        path = _write_yaml(tmp_path, "test_fw", _VALID_YAML)
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "loaded", result


# ─── Idempotency ───────────────────────────────────────────────

class TestIdempotency:
    def test_first_load_status_loaded(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw", _VALID_YAML)
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "loaded"
        assert result["framework_slug"] == "test_fw"
        assert result["release_tag"] == "test-r1"
        assert result["controls_loaded"] == 1
        # DB state
        fw = db_session.query(ComplianceFramework).filter_by(slug="test_fw").one()
        assert db_session.query(ComplianceControl).filter_by(framework_id=fw.id).count() == 1
        assert db_session.query(ComplianceControlMapping).count() == 1

    def test_reload_unchanged_is_skipped(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw", _VALID_YAML)
        compliance_loader.load_framework_from_path(db_session, path)
        result2 = compliance_loader.load_framework_from_path(db_session, path)
        assert result2["status"] == "skipped"
        # No duplicate release row.
        assert db_session.query(ComplianceFrameworkRelease).count() == 1
        # No duplicate mapping row.
        assert db_session.query(ComplianceControlMapping).count() == 1

    def test_changed_rule_bumps_version(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw", _VALID_YAML)
        compliance_loader.load_framework_from_path(db_session, path)
        m1 = db_session.query(ComplianceControlMapping).one()
        assert m1.rule_version == 1
        # Change the conditions list — same key, different rule body.
        changed = _VALID_YAML.replace("op: not_in", "op: in")
        path.write_text(textwrap.dedent(changed))
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "updated"
        db_session.expire_all()
        m2 = db_session.query(ComplianceControlMapping).one()
        assert m2.rule_version == 2

    def test_removed_mapping_is_dropped(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw", _VALID_YAML)
        compliance_loader.load_framework_from_path(db_session, path)
        # Re-publish with no mappings under the control.
        no_mappings = _VALID_YAML.split("    mappings:")[0] + "    mappings: []\n"
        path.write_text(textwrap.dedent(no_mappings))
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "updated"
        assert db_session.query(ComplianceControlMapping).count() == 0
        # Control itself survives.
        assert db_session.query(ComplianceControl).count() == 1

    def test_removed_control_is_dropped(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw", _VALID_YAML)
        compliance_loader.load_framework_from_path(db_session, path)
        # Re-publish with empty controls list.
        no_controls = _VALID_YAML.split("controls:")[0] + "controls: []\n"
        path.write_text(textwrap.dedent(no_controls))
        result = compliance_loader.load_framework_from_path(db_session, path)
        assert result["status"] == "updated"
        assert db_session.query(ComplianceControl).count() == 0
        assert db_session.query(ComplianceControlMapping).count() == 0


# ─── Audit log ─────────────────────────────────────────────────

class TestAuditLog:
    def test_first_load_writes_audit_row(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw", _VALID_YAML)
        compliance_loader.load_framework_from_path(db_session, path)
        rows = db_session.query(AuditLog).filter_by(
            entity_type="compliance_framework_release"
        ).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.action == "loaded"
        assert row.entity_name == "test_fw"
        assert row.changes["release_tag"] == "test-r1"
        assert row.changes["controls_count"] == 1

    def test_skipped_load_does_not_write_audit_row(self, db_session, tmp_path):
        path = _write_yaml(tmp_path, "test_fw", _VALID_YAML)
        compliance_loader.load_framework_from_path(db_session, path)
        compliance_loader.load_framework_from_path(db_session, path)
        rows = db_session.query(AuditLog).filter_by(
            entity_type="compliance_framework_release"
        ).all()
        assert len(rows) == 1  # only the first load


# ─── load_all_frameworks discovery ─────────────────────────────

class TestLoadAllFrameworks:
    def test_loads_from_default_root(self, db_session, tmp_path):
        # Two framework dirs, one valid YAML each.
        _write_yaml(tmp_path, "test_a", _VALID_YAML.replace("test_fw", "test_a"))
        _write_yaml(tmp_path, "test_b", _VALID_YAML.replace("test_fw", "test_b"))
        results = compliance_loader.load_all_frameworks(db_session, root=tmp_path)
        assert len(results) == 2
        assert {r["framework_slug"] for r in results} == {"test_a", "test_b"}
        assert all(r["status"] == "loaded" for r in results)

    def test_one_invalid_does_not_block_others(self, db_session, tmp_path):
        _write_yaml(tmp_path, "test_good", _VALID_YAML.replace("test_fw", "test_good"))
        bad_yaml = _VALID_YAML.replace("test_fw", "test_bad").replace(
            "finding.is_kev", "finding.bogus"
        )
        _write_yaml(tmp_path, "test_bad", bad_yaml)
        results = compliance_loader.load_all_frameworks(db_session, root=tmp_path)
        statuses = {r.get("framework_slug") or r.get("path"): r["status"] for r in results}
        assert "test_good" in (r.get("framework_slug") for r in results)
        # Good one loaded.
        assert statuses.get("test_good") == "loaded"
        # Bad one reported as validation_error and didn't write.
        bad = next(r for r in results if r["status"] == "validation_error")
        assert "finding.bogus" in bad["error"]
        assert db_session.query(ComplianceFramework).filter_by(slug="test_bad").first() is None


# ─── Bundled CIS v8 YAML round-trip ────────────────────────────

class TestBundledCisV8:
    """The shipped CIS v8 YAML must parse, validate, and load cleanly."""

    def test_cis_v8_loads(self, db_session):
        results = compliance_loader.load_all_frameworks(db_session)
        cis = [r for r in results if r.get("framework_slug") == "cis_v8"]
        assert cis, f"cis_v8 not found among loaded frameworks: {results}"
        assert cis[0]["status"] in ("loaded", "skipped"), cis[0]
        # The framework + at least the eight controls in the shipped YAML.
        fw = db_session.query(ComplianceFramework).filter_by(slug="cis_v8").one()
        ctrl_count = db_session.query(ComplianceControl).filter_by(framework_id=fw.id).count()
        assert ctrl_count >= 8, f"expected ≥8 CIS controls, got {ctrl_count}"
        # Mappings populated where testability != manual_only.
        mapping_count = db_session.query(ComplianceControlMapping).join(
            ComplianceControl, ComplianceControl.id == ComplianceControlMapping.control_id
        ).filter(ComplianceControl.framework_id == fw.id).count()
        assert mapping_count >= 8

    def test_cis_v8_release_tag_matches_yaml(self, db_session):
        compliance_loader.load_all_frameworks(db_session)
        fw = db_session.query(ComplianceFramework).filter_by(slug="cis_v8").one()
        rel = db_session.query(ComplianceFrameworkRelease).filter_by(framework_id=fw.id).one()
        assert rel.release_tag == "2026.04.25-v1"
        assert rel.mapping_file_sha256 and len(rel.mapping_file_sha256) == 64

    def test_cis_v8_manual_only_control_has_no_mappings(self, db_session):
        compliance_loader.load_all_frameworks(db_session)
        # 16.1 is shipped as manual_only.
        ctrl = (
            db_session.query(ComplianceControl)
            .join(ComplianceFramework)
            .filter(ComplianceFramework.slug == "cis_v8", ComplianceControl.ref == "16.1")
            .one()
        )
        assert ctrl.testability == "manual_only"
        assert (
            db_session.query(ComplianceControlMapping)
            .filter_by(control_id=ctrl.id).count() == 0
        )


# ─── All bundled framework YAMLs round-trip ────────────────────

class TestAllBundledFrameworks:
    """Every YAML under backend/compliance/frameworks/ must validate, load,
    and be a no-op on a second call (sha256-stable)."""

    EXPECTED_SLUGS = {
        "cis_v8",
        "pci_dss_4_0",
        "soc2_2017",
        "nist_csf_2_0",
        "iso_27001_2022",
        "hipaa_security",
    }

    def test_all_frameworks_load_cleanly(self, db_session):
        results = compliance_loader.load_all_frameworks(db_session)
        slugs = {r.get("framework_slug") for r in results if r.get("framework_slug")}
        missing = self.EXPECTED_SLUGS - slugs
        assert not missing, f"missing frameworks: {missing}; got: {slugs}"
        for r in results:
            assert r["status"] in ("loaded", "updated", "skipped"), r

    def test_reload_is_skipped_for_all(self, db_session):
        compliance_loader.load_all_frameworks(db_session)
        second = compliance_loader.load_all_frameworks(db_session)
        for r in second:
            if r.get("framework_slug") in self.EXPECTED_SLUGS:
                assert r["status"] == "skipped", (
                    f"framework {r.get('framework_slug')!r} should be sha-stable on reload, "
                    f"got status={r.get('status')!r}"
                )
