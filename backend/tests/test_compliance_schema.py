"""PR 1 — compliance schema model tests.

Pins constraints, defaults, and FK cascade behavior for the 9 new tables
that the compliance evaluator (PR 3) and API (PR 4) build on. Catches
schema drift before downstream PRs land.
"""

import os
import sys
from datetime import datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.models import (
    Organization, User, Scan, Asset, Finding, FindingException,
    ComplianceFramework, ComplianceControl, ComplianceControlMapping,
    ComplianceFrameworkRelease, OrgFrameworkSubscription,
    ComplianceCompensatingControl, ComplianceControlStatus,
    ComplianceFindingStatus, ComplianceReportRun,
)


# ─── helpers ───────────────────────────────────────────────────

def _seed_org(db):
    org = Organization(name="Test Org", slug="test-org")
    db.add(org)
    db.flush()
    return org


def _seed_framework(db, *, slug="pci_dss_4_0", version="4.0.1"):
    fw = ComplianceFramework(
        slug=slug, name="PCI DSS", version=version, authority="PCI SSC",
    )
    db.add(fw)
    db.flush()
    return fw


def _seed_control(db, framework, *, ref="6.3.3", title="Patches", testability="automated"):
    c = ComplianceControl(
        framework_id=framework.id, ref=ref, title=title,
        domain="Vulnerability Management", testability=testability,
    )
    db.add(c)
    db.flush()
    return c


def _seed_finding(db):
    scan = Scan(filename="t.nessus", source_type="nessus")
    db.add(scan); db.flush()
    asset = Asset(scan_id=scan.id, ip="10.0.0.1")
    db.add(asset); db.flush()
    f = Finding(scan_id=scan.id, asset_id=asset.id, plugin_id="100")
    db.add(f); db.flush()
    return f


# ─── ComplianceFramework ──────────────────────────────────────

class TestComplianceFramework:
    def test_create_with_minimal_fields(self, db_session):
        fw = ComplianceFramework(slug="cis_v8", name="CIS Controls", version="8.1")
        db_session.add(fw)
        db_session.flush()
        assert fw.id is not None
        assert fw.categories == []
        assert fw.mapping_schema_version == 1

    def test_slug_is_unique(self, db_session):
        db_session.add(ComplianceFramework(slug="dup", name="A", version="1"))
        db_session.flush()
        db_session.add(ComplianceFramework(slug="dup", name="B", version="2"))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_slug_version_uniqueness_constraint_named(self, db_session):
        # Compound unique constraint exists alongside the slug-only unique.
        # Smoke check that the constraint name matches what the loader expects.
        names = {c.name for c in ComplianceFramework.__table__.constraints}
        assert "uq_compliance_framework_slug_version" in names


# ─── ComplianceControl ────────────────────────────────────────

class TestComplianceControl:
    def test_unique_per_framework_ref(self, db_session):
        fw = _seed_framework(db_session)
        _seed_control(db_session, fw, ref="6.3.3")
        with pytest.raises(IntegrityError):
            _seed_control(db_session, fw, ref="6.3.3")

    def test_same_ref_allowed_in_different_framework(self, db_session):
        fw1 = _seed_framework(db_session, slug="pci_dss_4_0", version="4.0.1")
        fw2 = _seed_framework(db_session, slug="soc2_2017", version="2017")
        _seed_control(db_session, fw1, ref="6.3.3")
        # Should not raise — different framework, same ref string.
        _seed_control(db_session, fw2, ref="6.3.3")

    def test_default_testability_is_automated(self, db_session):
        fw = _seed_framework(db_session)
        c = ComplianceControl(framework_id=fw.id, ref="X", title="t")
        db_session.add(c); db_session.flush()
        assert c.testability == "automated"

    def test_cascade_delete_from_framework(self, db_session):
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        cid = c.id
        db_session.delete(fw)
        db_session.flush()
        assert db_session.query(ComplianceControl).filter_by(id=cid).first() is None


# ─── ComplianceControlMapping ─────────────────────────────────

class TestComplianceControlMapping:
    def test_mapping_key_globally_unique(self, db_session):
        fw = _seed_framework(db_session)
        c1 = _seed_control(db_session, fw, ref="A")
        c2 = _seed_control(db_session, fw, ref="B")
        db_session.add(ComplianceControlMapping(
            control_id=c1.id, mapping_key="dup", rule={"logic": "AND", "conditions": []},
        ))
        db_session.flush()
        # Duplicate key under a *different* control still must fail — mapping_key
        # is the cross-control identity used by compliance_finding_status.
        db_session.add(ComplianceControlMapping(
            control_id=c2.id, mapping_key="dup", rule={"logic": "AND", "conditions": []},
        ))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_default_rule_version(self, db_session):
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        m = ComplianceControlMapping(
            control_id=c.id, mapping_key="m1",
            rule={"logic": "AND", "conditions": []},
        )
        db_session.add(m); db_session.flush()
        assert m.rule_version == 1

    def test_cascade_delete_from_control(self, db_session):
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        m = ComplianceControlMapping(
            control_id=c.id, mapping_key="cascade-test",
            rule={"logic": "AND", "conditions": []},
        )
        db_session.add(m); db_session.flush()
        mid = m.id
        db_session.delete(c)
        db_session.flush()
        assert db_session.query(ComplianceControlMapping).filter_by(id=mid).first() is None


# ─── ComplianceFrameworkRelease ───────────────────────────────

class TestFrameworkRelease:
    def test_release_tag_unique_per_framework(self, db_session):
        fw = _seed_framework(db_session)
        db_session.add(ComplianceFrameworkRelease(
            framework_id=fw.id, release_tag="2026.04.24-v1",
            mapping_file_sha256="abc",
        ))
        db_session.flush()
        db_session.add(ComplianceFrameworkRelease(
            framework_id=fw.id, release_tag="2026.04.24-v1",
            mapping_file_sha256="def",
        ))
        with pytest.raises(IntegrityError):
            db_session.flush()


# ─── OrgFrameworkSubscription ─────────────────────────────────

class TestOrgFrameworkSubscription:
    def test_one_subscription_per_org_framework(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        db_session.add(OrgFrameworkSubscription(org_id=org.id, framework_id=fw.id))
        db_session.flush()
        db_session.add(OrgFrameworkSubscription(org_id=org.id, framework_id=fw.id))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_scope_rule_can_be_null(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        sub = OrgFrameworkSubscription(org_id=org.id, framework_id=fw.id, enabled=True)
        db_session.add(sub); db_session.flush()
        assert sub.scope_rule is None
        assert sub.scope_tag_expr is None

    def test_cascade_delete_with_org(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        sub = OrgFrameworkSubscription(org_id=org.id, framework_id=fw.id)
        db_session.add(sub); db_session.flush()
        sid = sub.id
        db_session.delete(org)
        db_session.flush()
        assert db_session.query(OrgFrameworkSubscription).filter_by(id=sid).first() is None


# ─── ComplianceCompensatingControl ────────────────────────────

class TestCompensatingControl:
    def test_minimal_create(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        cc = ComplianceCompensatingControl(
            org_id=org.id, control_id=c.id,
            rationale="WAF blocks the exploit path; documented in ticket SEC-123",
        )
        db_session.add(cc); db_session.flush()
        assert cc.linked_ticket_ids == []
        assert cc.linked_exception_id is None

    def test_links_to_finding_exception(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        # FindingException is the canonical risk-acceptance/compensating-control
        # store; compliance_compensating_controls bridges to it via linked_exception_id.
        fe = FindingException(
            org_id=org.id, exception_type="compensating_control",
            compensating_control_detail="WAF rule 4242", reason="docs in SEC-123",
            is_active=True,
        )
        db_session.add(fe); db_session.flush()
        cc = ComplianceCompensatingControl(
            org_id=org.id, control_id=c.id,
            rationale="Linked to FE",
            linked_exception_id=fe.id,
        )
        db_session.add(cc); db_session.flush()
        assert cc.linked_exception_id == fe.id

    def test_exception_delete_nulls_link_not_cascades(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        fe = FindingException(
            org_id=org.id, exception_type="compensating_control",
            reason="x", is_active=True,
        )
        db_session.add(fe); db_session.flush()
        cc = ComplianceCompensatingControl(
            org_id=org.id, control_id=c.id,
            rationale="r", linked_exception_id=fe.id,
        )
        db_session.add(cc); db_session.flush()
        cc_id = cc.id
        db_session.delete(fe)
        db_session.flush()
        # SET NULL is enforced by the DB; expire the in-memory copy so we
        # re-read the persisted state instead of the cached attribute.
        db_session.expire_all()
        survivor = db_session.query(ComplianceCompensatingControl).filter_by(id=cc_id).one()
        assert survivor.linked_exception_id is None


# ─── ComplianceControlStatus ──────────────────────────────────

class TestControlStatus:
    def test_one_status_row_per_org_control(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        db_session.add(ComplianceControlStatus(org_id=org.id, control_id=c.id, state="passing"))
        db_session.flush()
        db_session.add(ComplianceControlStatus(org_id=org.id, control_id=c.id, state="failing"))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_default_state_is_not_applicable(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        s = ComplianceControlStatus(org_id=org.id, control_id=c.id)
        db_session.add(s); db_session.flush()
        assert s.state == "not_applicable"
        assert s.in_scope_asset_count == 0
        assert s.failing_finding_count == 0
        assert s.evaluator_version == 1


# ─── ComplianceFindingStatus ──────────────────────────────────

class TestFindingStatus:
    def test_one_row_per_finding_control_mapping(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        f = _seed_finding(db_session)
        db_session.add(ComplianceFindingStatus(
            org_id=org.id, finding_id=f.id, control_id=c.id,
            mapping_key="m1", verdict="failing",
        ))
        db_session.flush()
        # Different mapping_key under the same finding+control is allowed.
        db_session.add(ComplianceFindingStatus(
            org_id=org.id, finding_id=f.id, control_id=c.id,
            mapping_key="m2", verdict="failing",
        ))
        db_session.flush()
        # Duplicate (finding, control, mapping_key) must fail.
        db_session.add(ComplianceFindingStatus(
            org_id=org.id, finding_id=f.id, control_id=c.id,
            mapping_key="m1", verdict="failing",
        ))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_finding_delete_cascades(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        f = _seed_finding(db_session)
        cfs = ComplianceFindingStatus(
            org_id=org.id, finding_id=f.id, control_id=c.id,
            mapping_key="m1", verdict="failing",
        )
        db_session.add(cfs); db_session.flush()
        cfs_id = cfs.id
        db_session.delete(f)
        db_session.flush()
        assert db_session.query(ComplianceFindingStatus).filter_by(id=cfs_id).first() is None

    def test_default_match_signal_empty_dict(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        c = _seed_control(db_session, fw)
        f = _seed_finding(db_session)
        cfs = ComplianceFindingStatus(
            org_id=org.id, finding_id=f.id, control_id=c.id,
            mapping_key="m1",
        )
        db_session.add(cfs); db_session.flush()
        assert cfs.verdict == "failing"
        assert cfs.match_signal == {}


# ─── ComplianceReportRun ──────────────────────────────────────

class TestReportRun:
    def test_minimal_create(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        run = ComplianceReportRun(
            org_id=org.id, framework_id=fw.id, format="pdf",
        )
        db_session.add(run); db_session.flush()
        assert run.status == "queued"
        assert run.snapshot == {}
        assert run.generated_at is None

    def test_generated_at_settable(self, db_session):
        org = _seed_org(db_session)
        fw = _seed_framework(db_session)
        when = datetime.utcnow() - timedelta(minutes=5)
        run = ComplianceReportRun(
            org_id=org.id, framework_id=fw.id, format="csv",
            status="succeeded", artifact_uri="minio://bucket/x.csv",
            generated_at=when,
        )
        db_session.add(run); db_session.flush()
        assert run.generated_at == when


# ─── Permission registration ───────────────────────────────────

class TestPagePermission:
    def test_page_compliance_in_all_permission_keys(self):
        from core.auth import ALL_PERMISSION_KEYS
        assert "page_compliance" in ALL_PERMISSION_KEYS

    def test_superadmin_and_org_admin_get_it(self):
        from core.auth import BUILTIN_ROLE_DEFAULTS
        assert BUILTIN_ROLE_DEFAULTS["superadmin"].get("page_compliance") is True
        assert BUILTIN_ROLE_DEFAULTS["org_admin"].get("page_compliance") is True

    def test_analyst_and_viewer_default_off(self):
        # PR 1 ships gated — only admins see the tab until per-org rollout flips it.
        from core.auth import BUILTIN_ROLE_DEFAULTS
        assert "page_compliance" not in BUILTIN_ROLE_DEFAULTS["analyst"]
        assert "page_compliance" not in BUILTIN_ROLE_DEFAULTS["viewer"]
