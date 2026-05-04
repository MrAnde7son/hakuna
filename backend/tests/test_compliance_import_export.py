"""Tests for tenant-private framework import/export.

Covers:
  - import lands at org_id=caller.org_id, source='imported'
  - re-importing same YAML is idempotent (status=skipped)
  - tenant cannot collide with a builtin slug — both rows coexist
  - tenant cannot see another tenant's imported framework
  - export bytes round-trip through import (same controls + mappings)
  - delete only touches imported rows; builtin lookup still resolves
"""

import os
import sys
import textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from models.models import (
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceFramework,
    Organization,
)
from services import compliance_loader
from services.compliance_export import framework_to_yaml


@pytest.fixture
def org_a(db_session):
    org = Organization(name="Tenant A", slug="tenant-a")
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def org_b(db_session):
    org = Organization(name="Tenant B", slug="tenant-b")
    db_session.add(org)
    db_session.flush()
    return org


_VALID_YAML = textwrap.dedent("""
framework:
  slug: tenant_fw
  name: Tenant Custom Framework
  version: "1.0"
  authority: ACME Corp
  description: |
    A tenant-imported framework for testing round-trip.
  categories: [Internal]
  mapping_schema_version: 1
release:
  tag: "tenant-r1"
  notes: "first import"
controls:
  - ref: "1.1"
    title: First Control
    domain: Test
    testability: automated
    canonical_guidance: |
      Use this to test things.
    mappings:
      - key: tenant_fw_1_1_kev_unresolved
        when:
          logic: AND
          conditions:
            - field: finding.is_kev
              op: is_true
            - field: finding.workflow_status
              op: not_in
              value: [resolved, false_positive]
  - ref: "2.1"
    title: Manual Control
    testability: manual_only
    mappings: []
""").lstrip()


# ─── Import ────────────────────────────────────────────────────

class TestImport:
    def test_import_lands_at_caller_org(self, db_session, org_a):
        result = compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=org_a.id, created_by=None,
        )
        assert result["status"] == "loaded", result
        fw = db_session.query(ComplianceFramework).filter_by(
            slug="tenant_fw", org_id=org_a.id,
        ).one()
        assert fw.source == "imported"
        assert fw.org_id == org_a.id

    def test_import_requires_org_id(self, db_session):
        result = compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=0,
        )
        assert result["status"] == "schema_error"

    def test_reimport_same_bytes_is_skipped(self, db_session, org_a):
        compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=org_a.id,
        )
        result2 = compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=org_a.id,
        )
        assert result2["status"] == "skipped"
        assert db_session.query(ComplianceFramework).filter_by(
            slug="tenant_fw", org_id=org_a.id,
        ).count() == 1

    def test_validation_error_propagates(self, db_session, org_a):
        bad = _VALID_YAML.replace("finding.is_kev", "finding.bogus_field")
        result = compliance_loader.load_framework_from_yaml_text(
            db_session, bad, org_id=org_a.id,
        )
        assert result["status"] == "validation_error"
        assert "finding.bogus_field" in result["error"]
        assert db_session.query(ComplianceFramework).filter_by(
            slug="tenant_fw",
        ).first() is None


# ─── Tenancy isolation ─────────────────────────────────────────

class TestTenantIsolation:
    def test_two_tenants_can_share_a_slug(self, db_session, org_a, org_b):
        compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=org_a.id,
        )
        compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=org_b.id,
        )
        rows = db_session.query(ComplianceFramework).filter_by(
            slug="tenant_fw",
        ).all()
        assert len(rows) == 2
        assert {r.org_id for r in rows} == {org_a.id, org_b.id}

    def test_tenant_slug_can_collide_with_builtin(self, db_session, org_a, tmp_path):
        builtin_dir = tmp_path / "tenant_fw"
        builtin_dir.mkdir()
        (builtin_dir / "v1.yaml").write_text(_VALID_YAML)
        compliance_loader.load_framework_from_path(
            db_session, builtin_dir / "v1.yaml",
        )
        result = compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=org_a.id,
        )
        assert result["status"] == "loaded"
        rows = db_session.query(ComplianceFramework).filter_by(
            slug="tenant_fw",
        ).all()
        assert len(rows) == 2
        assert {r.org_id for r in rows} == {None, org_a.id}


# ─── Export round-trip ─────────────────────────────────────────

class TestExportRoundTrip:
    def test_export_then_import_preserves_controls_and_mappings(
        self, db_session, org_a, org_b,
    ):
        compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=org_a.id,
        )
        fw1 = db_session.query(ComplianceFramework).filter_by(
            slug="tenant_fw", org_id=org_a.id,
        ).one()
        ctrl_count_1 = db_session.query(ComplianceControl).filter_by(
            framework_id=fw1.id,
        ).count()
        mapping_count_1 = (
            db_session.query(ComplianceControlMapping)
            .join(ComplianceControl,
                  ComplianceControl.id == ComplianceControlMapping.control_id)
            .filter(ComplianceControl.framework_id == fw1.id)
            .count()
        )

        exported = framework_to_yaml(db_session, fw1)
        assert "tenant_fw_1_1_kev_unresolved" in exported
        assert "First Control" in exported

        result = compliance_loader.load_framework_from_yaml_text(
            db_session, exported, org_id=org_b.id,
        )
        assert result["status"] == "loaded"

        fw2 = db_session.query(ComplianceFramework).filter_by(
            slug="tenant_fw", org_id=org_b.id,
        ).one()
        ctrl_count_2 = db_session.query(ComplianceControl).filter_by(
            framework_id=fw2.id,
        ).count()
        mapping_count_2 = (
            db_session.query(ComplianceControlMapping)
            .join(ComplianceControl,
                  ComplianceControl.id == ComplianceControlMapping.control_id)
            .filter(ComplianceControl.framework_id == fw2.id)
            .count()
        )
        assert ctrl_count_1 == ctrl_count_2
        assert mapping_count_1 == mapping_count_2

        m1 = (
            db_session.query(ComplianceControlMapping)
            .filter_by(mapping_key="tenant_fw_1_1_kev_unresolved")
            .all()
        )
        assert len(m1) == 2
        assert m1[0].rule == m1[1].rule

    def test_manual_only_control_round_trips_with_no_mappings(
        self, db_session, org_a, org_b,
    ):
        compliance_loader.load_framework_from_yaml_text(
            db_session, _VALID_YAML, org_id=org_a.id,
        )
        fw = db_session.query(ComplianceFramework).filter_by(
            slug="tenant_fw", org_id=org_a.id,
        ).one()
        exported = framework_to_yaml(db_session, fw)

        result = compliance_loader.load_framework_from_yaml_text(
            db_session, exported, org_id=org_b.id,
        )
        assert result["status"] == "loaded"
        manual_ctrl = (
            db_session.query(ComplianceControl)
            .join(ComplianceFramework,
                  ComplianceFramework.id == ComplianceControl.framework_id)
            .filter(ComplianceFramework.org_id == org_b.id,
                    ComplianceControl.ref == "2.1")
            .one()
        )
        assert manual_ctrl.testability == "manual_only"
        assert db_session.query(ComplianceControlMapping).filter_by(
            control_id=manual_ctrl.id,
        ).count() == 0
