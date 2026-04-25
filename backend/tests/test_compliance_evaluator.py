"""PR 3 — compliance evaluator behavior.

Pins the runtime that materializes (finding × control) and (org × control)
state from the canonical YAML rules:

  - Rule match → compliance_finding_status row with the right verdict
  - exception_id and workflow_status drive verdict
  - Findings without CVE *and* without CWE skip the evaluator
  - Scope rule narrows the asset set
  - Control state recomputes (passing / failing / not_applicable)
  - Full-scan rebuild drops stale rows; incremental upserts
  - No subscription = evaluator is a no-op
  - Re-running is idempotent (no duplicate rows)
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime

from models.models import (
    Asset, Finding, FindingException, Organization, Scan, Tag, TagAssignment,
    ComplianceFramework, ComplianceControl, ComplianceControlMapping,
    ComplianceControlStatus, ComplianceFindingStatus,
    OrgFrameworkSubscription,
)
from services.compliance_evaluator import (
    EVALUATOR_VERSION, evaluate,
    _build_match_signal, _compute_verdict, _is_compliance_evaluable, _matched_via,
)


# ─── helpers ───────────────────────────────────────────────────

def _seed_org_and_scan(db):
    org = Organization(name="Test", slug="test")
    db.add(org); db.flush()
    scan = Scan(filename="t.nessus", source_type="nessus", org_id=org.id)
    db.add(scan); db.flush()
    return org, scan


def _seed_asset(db, scan, *, ip="10.0.0.1", hostname="h1", environment_tag="prod"):
    a = Asset(scan_id=scan.id, ip=ip, hostname=hostname, environment_tag=environment_tag)
    db.add(a); db.flush()
    return a


def _seed_finding(db, scan, asset, **kwargs):
    defaults = dict(
        plugin_id="100", severity=3, workflow_status="open",
        cves=[], cwe_ids=[],
    )
    defaults.update(kwargs)
    f = Finding(scan_id=scan.id, asset_id=asset.id, **defaults)
    db.add(f); db.flush()
    return f


def _seed_framework_with_control(db, *, mapping_rule, mapping_key="m1",
                                  control_ref="C1", framework_slug="fw"):
    fw = ComplianceFramework(slug=framework_slug, name="Test FW", version="1")
    db.add(fw); db.flush()
    c = ComplianceControl(
        framework_id=fw.id, ref=control_ref, title="Test Control",
        domain="Test", testability="automated",
    )
    db.add(c); db.flush()
    m = ComplianceControlMapping(
        control_id=c.id, mapping_key=mapping_key, rule=mapping_rule, rule_version=1,
    )
    db.add(m); db.flush()
    return fw, c, m


def _subscribe(db, org, fw, *, scope_rule=None):
    sub = OrgFrameworkSubscription(
        org_id=org.id, framework_id=fw.id, enabled=True, scope_rule=scope_rule,
    )
    db.add(sub); db.flush()
    return sub


_KEV_RULE = {
    "logic": "AND",
    "conditions": [
        {"field": "finding.is_kev", "op": "is_true"},
        {"field": "finding.workflow_status", "op": "not_in",
         "value": ["resolved", "false_positive"]},
    ],
}

_CWE_RULE = {
    "logic": "AND",
    "conditions": [
        {"field": "finding.cwe", "op": "contains_any",
         "value": ["CWE-79", "CWE-89"]},
    ],
}


# ─── pure helpers ──────────────────────────────────────────────

class TestComputeVerdict:
    def test_exception_suppressed_takes_priority(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        fe = FindingException(org_id=org.id, exception_type="accepted_risk",
                              reason="x", is_active=True)
        db_session.add(fe); db_session.flush()
        f = _seed_finding(db_session, scan, asset,
                          workflow_status="resolved", exception_id=fe.id)
        assert _compute_verdict(f) == "exception_suppressed"

    def test_resolved(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset, workflow_status="resolved")
        assert _compute_verdict(f) == "resolved"

    def test_default_failing(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset)
        assert _compute_verdict(f) == "failing"


class TestIsComplianceEvaluable:
    def test_cve_only(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset, cves=["CVE-2021-1"])
        assert _is_compliance_evaluable(f) is True

    def test_cwe_only(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset, cwe_ids=["CWE-79"])
        assert _is_compliance_evaluable(f) is True

    def test_neither(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset)
        assert _is_compliance_evaluable(f) is False


class TestMatchedVia:
    def test_cve_rule(self):
        assert _matched_via({"conditions": [{"field": "finding.cve"}]}) == "cve_cwe"

    def test_cwe_rule(self):
        assert _matched_via({"conditions": [{"field": "finding.cwe"}]}) == "cve_cwe"

    def test_plugin_id(self):
        assert _matched_via({"conditions": [{"field": "finding.plugin_id"}]}) == "plugin_id"

    def test_plugin_family(self):
        assert _matched_via({"conditions": [{"field": "finding.plugin_family"}]}) == "plugin_family"

    def test_inventory(self):
        assert _matched_via({"conditions": [{"field": "inventory.kerberoastable_user"}]}) == "inventory"

    def test_kev(self):
        assert _matched_via({"conditions": [{"field": "finding.is_kev"}]}) == "threat_intel"


class TestBuildMatchSignal:
    def test_records_cve_when_present(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset, cves=["CVE-2021-44228"])
        sig = _build_match_signal(f, {"conditions": [{"field": "finding.cve"}]})
        assert sig["cves"] == ["CVE-2021-44228"]

    def test_records_cwe_and_severity(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset, cwe_ids=["CWE-79"], severity=4)
        sig = _build_match_signal(f, {"conditions": [
            {"field": "finding.cwe"}, {"field": "finding.severity"},
        ]})
        assert sig["cwes"] == ["CWE-79"]
        assert sig["severity"] == 4


# ─── End-to-end evaluation ─────────────────────────────────────

class TestEvaluateNoSubscription:
    def test_returns_zero_when_org_has_no_subscriptions(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        _seed_finding(db_session, scan, asset, is_kev=True, cves=["CVE-1"])
        result = evaluate(db_session, scan_id=scan.id)
        assert result["evaluated"] == 0
        assert result["reason"] == "no_subscriptions"

    def test_returns_zero_when_scan_has_no_org(self, db_session):
        scan = Scan(filename="x", source_type="nessus")
        db_session.add(scan); db_session.flush()
        result = evaluate(db_session, scan_id=scan.id)
        assert result["reason"] == "no_org"


class TestEvaluateRuleMatches:
    def test_kev_rule_creates_failing_status(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset,
                          is_kev=True, cves=["CVE-2021-44228"])
        fw, control, mapping = _seed_framework_with_control(
            db_session, mapping_rule=_KEV_RULE,
        )
        _subscribe(db_session, org, fw)

        result = evaluate(db_session, scan_id=scan.id)

        assert result["evaluated"] == 1
        rows = db_session.query(ComplianceFindingStatus).all()
        assert len(rows) == 1
        assert rows[0].verdict == "failing"
        # KEV is populated by threat-intel enrichment, not the parser.
        assert rows[0].matched_via == "threat_intel"
        assert rows[0].finding_id == f.id
        assert rows[0].control_id == control.id
        assert rows[0].mapping_key == "m1"
        assert rows[0].match_signal.get("is_kev") is True

    def test_cwe_rule_matches(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset, cwe_ids=["CWE-79"])
        fw, control, _ = _seed_framework_with_control(
            db_session, mapping_rule=_CWE_RULE,
        )
        _subscribe(db_session, org, fw)

        result = evaluate(db_session, scan_id=scan.id)

        assert result["evaluated"] == 1
        row = db_session.query(ComplianceFindingStatus).one()
        assert row.match_signal.get("cwes") == ["CWE-79"]

    def test_resolved_finding_gets_resolved_verdict(self, db_session):
        # Use a rule that would match even when status=resolved (no
        # workflow_status filter) so we can exercise the verdict flag.
        rule = {
            "logic": "AND",
            "conditions": [{"field": "finding.cwe", "op": "contains_any", "value": ["CWE-79"]}],
        }
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset,
                          cwe_ids=["CWE-79"], workflow_status="resolved")
        fw, _, _ = _seed_framework_with_control(db_session, mapping_rule=rule)
        _subscribe(db_session, org, fw)

        evaluate(db_session, scan_id=scan.id)

        row = db_session.query(ComplianceFindingStatus).one()
        assert row.verdict == "resolved"

    def test_finding_with_exception_marked_suppressed(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        fe = FindingException(org_id=org.id, exception_type="accepted_risk",
                              reason="ok", is_active=True)
        db_session.add(fe); db_session.flush()
        f = _seed_finding(db_session, scan, asset,
                          cwe_ids=["CWE-79"], exception_id=fe.id)
        rule = {
            "logic": "AND",
            "conditions": [{"field": "finding.cwe", "op": "contains_any", "value": ["CWE-79"]}],
        }
        fw, _, _ = _seed_framework_with_control(db_session, mapping_rule=rule)
        _subscribe(db_session, org, fw)

        evaluate(db_session, scan_id=scan.id)

        row = db_session.query(ComplianceFindingStatus).one()
        assert row.verdict == "exception_suppressed"


class TestSoftAcceptSkipsUnmappable:
    def test_finding_without_cve_or_cwe_is_skipped(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        # Severity 4 + KEV-style match would normally count, but we have
        # no taxonomy keys → soft-accept skips it.
        _seed_finding(db_session, scan, asset, is_kev=True, severity=4)
        fw, _, _ = _seed_framework_with_control(db_session, mapping_rule=_KEV_RULE)
        _subscribe(db_session, org, fw)

        result = evaluate(db_session, scan_id=scan.id)

        assert result["evaluated"] == 0
        assert db_session.query(ComplianceFindingStatus).count() == 0


# ─── Control-level state machine ───────────────────────────────

class TestControlStateMachine:
    def test_passing_when_no_failing_findings(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        # Finding doesn't match the rule (no KEV).
        _seed_finding(db_session, scan, asset, cves=["CVE-1"], is_kev=False)
        fw, control, _ = _seed_framework_with_control(
            db_session, mapping_rule=_KEV_RULE,
        )
        _subscribe(db_session, org, fw)

        evaluate(db_session, scan_id=scan.id)

        st = db_session.query(ComplianceControlStatus).filter_by(control_id=control.id).one()
        assert st.state == "passing"
        assert st.failing_finding_count == 0
        assert st.in_scope_asset_count >= 1
        assert st.evaluator_version == EVALUATOR_VERSION

    def test_failing_when_match(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        _seed_finding(db_session, scan, asset, cves=["CVE-1"], is_kev=True)
        fw, control, _ = _seed_framework_with_control(
            db_session, mapping_rule=_KEV_RULE,
        )
        _subscribe(db_session, org, fw)

        evaluate(db_session, scan_id=scan.id)

        st = db_session.query(ComplianceControlStatus).filter_by(control_id=control.id).one()
        assert st.state == "failing"
        assert st.failing_finding_count == 1
        assert st.failing_asset_count == 1
        assert st.first_failed_at is not None

    def test_not_applicable_when_no_mappings(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        _seed_finding(db_session, scan, asset, cves=["CVE-1"])
        fw = ComplianceFramework(slug="empty_fw", name="Empty", version="1")
        db_session.add(fw); db_session.flush()
        c = ComplianceControl(
            framework_id=fw.id, ref="X", title="manual only",
            testability="manual_only",
        )
        db_session.add(c); db_session.flush()
        _subscribe(db_session, org, fw)

        evaluate(db_session, scan_id=scan.id)

        st = db_session.query(ComplianceControlStatus).filter_by(control_id=c.id).one()
        assert st.state == "not_applicable"


# ─── Idempotency / drift ───────────────────────────────────────

class TestIdempotency:
    def test_re_eval_does_not_duplicate_rows(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        _seed_finding(db_session, scan, asset, cves=["CVE-1"], is_kev=True)
        fw, _, _ = _seed_framework_with_control(db_session, mapping_rule=_KEV_RULE)
        _subscribe(db_session, org, fw)

        evaluate(db_session, scan_id=scan.id)
        evaluate(db_session, scan_id=scan.id)

        assert db_session.query(ComplianceFindingStatus).count() == 1

    def test_full_scan_rebuild_drops_stale_failing_row(self, db_session):
        # Initial state: finding matches, row written.
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        f = _seed_finding(db_session, scan, asset, cves=["CVE-1"], is_kev=True)
        fw, _, _ = _seed_framework_with_control(db_session, mapping_rule=_KEV_RULE)
        _subscribe(db_session, org, fw)
        evaluate(db_session, scan_id=scan.id)
        assert db_session.query(ComplianceFindingStatus).count() == 1

        # Finding gets resolved → KEV rule's workflow_status filter excludes it.
        f.workflow_status = "resolved"
        db_session.flush()

        evaluate(db_session, scan_id=scan.id)

        # Full-scan eval (new_finding_ids=None) wipes prior rows; the rule
        # no longer matches, so no row is reinserted.
        assert db_session.query(ComplianceFindingStatus).count() == 0


class TestIncrementalMode:
    def test_incremental_only_evaluates_supplied_finding_ids(self, db_session):
        org, scan = _seed_org_and_scan(db_session)
        asset = _seed_asset(db_session, scan)
        old_f = _seed_finding(db_session, scan, asset, cves=["CVE-1"], is_kev=True)
        new_f = _seed_finding(db_session, scan, asset,
                              plugin_id="200", cves=["CVE-2"], is_kev=True)
        fw, _, _ = _seed_framework_with_control(db_session, mapping_rule=_KEV_RULE)
        _subscribe(db_session, org, fw)

        result = evaluate(db_session, scan_id=scan.id, new_finding_ids=[new_f.id])

        assert result["evaluated"] == 1
        rows = db_session.query(ComplianceFindingStatus).all()
        assert {r.finding_id for r in rows} == {new_f.id}
