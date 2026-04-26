"""PR 4 — compliance API tests.

Covers:
  - Auth gating: page_compliance permission required, viewer is rejected
  - Tenant isolation: an org can't see another org's subscriptions /
    compensating controls / finding statuses
  - CRUD: subscribe, scope update, unsubscribe, compensating control
    create/delete
  - State effects: compensating control flips verdicts and recomputes
    control state to compensating_control / partial; deleting it flips
    back; resolved findings stay resolved when CC is removed
  - Reverse lookup: GET /api/findings/{id} now carries satisfies_controls
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.auth import create_access_token, hash_password
from models.models import (
    Asset, ComplianceControl, ComplianceControlMapping, ComplianceFramework,
    ComplianceCompensatingControl, ComplianceControlStatus, ComplianceFindingStatus,
    Finding, FindingException, Organization, OrgFrameworkSubscription,
    Scan, User,
)
from services.compliance_evaluator import evaluate as evaluate_compliance


# ─── helpers ───────────────────────────────────────────────────

def _seed_finding(db, scan, asset, **kwargs):
    defaults = dict(plugin_id="100", severity=3, workflow_status="open",
                    cves=[], cwe_ids=[])
    defaults.update(kwargs)
    f = Finding(scan_id=scan.id, asset_id=asset.id, **defaults)
    db.add(f); db.flush()
    return f


def _seed_framework_with_control(db, *, slug="cis_v8", control_ref="C1",
                                  rule=None, mapping_key="m1"):
    rule = rule or {
        "logic": "AND",
        "conditions": [
            {"field": "finding.is_kev", "op": "is_true"},
        ],
    }
    fw = ComplianceFramework(slug=slug, name=slug.upper(), version="1")
    db.add(fw); db.flush()
    c = ComplianceControl(framework_id=fw.id, ref=control_ref,
                          title="Test Control", testability="automated")
    db.add(c); db.flush()
    m = ComplianceControlMapping(control_id=c.id, mapping_key=mapping_key,
                                  rule=rule, rule_version=1)
    db.add(m); db.flush()
    return fw, c, m


# ─── Permission gating ────────────────────────────────────────

class TestAuthGating:
    def test_unauthenticated_request_rejected(self, client):
        r = client.get("/api/compliance/frameworks")
        assert r.status_code in (401, 403)

    def test_viewer_role_rejected(self, db_session, client, test_org):
        viewer = User(
            email="viewer@test.com",
            hashed_password=hash_password("x"),
            display_name="Viewer",
            role="viewer",
            org_id=test_org.id,
            is_active=True,
        )
        db_session.add(viewer); db_session.flush()
        token = create_access_token(viewer.id, test_org.id, viewer.role)
        r = client.get("/api/compliance/frameworks", headers={
            "Authorization": f"Bearer {token}",
            "X-Org-Context": str(test_org.id),
        })
        assert r.status_code == 403, r.text
        assert "page_compliance" in r.text

    def test_org_admin_allowed(self, authed_client):
        r = authed_client.get("/api/compliance/frameworks")
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ─── Frameworks endpoint ──────────────────────────────────────

class TestListFrameworks:
    def test_returns_subscribed_flag(self, db_session, authed_client, test_org):
        fw1, _, _ = _seed_framework_with_control(db_session, slug="fwa", mapping_key="fwa-m1")
        fw2, _, _ = _seed_framework_with_control(db_session, slug="fwb", mapping_key="fwb-m1")
        # Subscribe to fwa only.
        db_session.add(OrgFrameworkSubscription(
            org_id=test_org.id, framework_id=fw1.id, enabled=True,
        ))
        db_session.commit()

        r = authed_client.get("/api/compliance/frameworks")
        assert r.status_code == 200
        rows = {row["slug"]: row for row in r.json()}
        assert rows["fwa"]["subscribed"] is True
        assert rows["fwb"]["subscribed"] is False


# ─── Subscribe / unsubscribe / scope ──────────────────────────

class TestSubscriptions:
    def test_subscribe_creates_row(self, db_session, authed_client, test_org):
        fw, _, _ = _seed_framework_with_control(db_session, slug="fwa")
        db_session.commit()

        r = authed_client.post(
            "/api/compliance/frameworks/fwa/subscribe",
            json={"scope_tag_expr": "env:prod"},
        )
        assert r.status_code == 200, r.text
        sub = db_session.query(OrgFrameworkSubscription).filter_by(
            org_id=test_org.id, framework_id=fw.id,
        ).first()
        assert sub is not None
        assert sub.enabled is True
        assert sub.scope_tag_expr == "env:prod"

    def test_subscribe_is_idempotent(self, db_session, authed_client, test_org):
        fw, _, _ = _seed_framework_with_control(db_session, slug="fwa")
        db_session.commit()
        authed_client.post("/api/compliance/frameworks/fwa/subscribe", json={})
        r2 = authed_client.post("/api/compliance/frameworks/fwa/subscribe",
                                json={"scope_tag_expr": "env:dev"})
        assert r2.status_code == 200
        # Only one row.
        count = db_session.query(OrgFrameworkSubscription).filter_by(
            org_id=test_org.id, framework_id=fw.id,
        ).count()
        assert count == 1

    def test_unknown_framework_returns_404(self, authed_client):
        r = authed_client.post(
            "/api/compliance/frameworks/totally-nope/subscribe", json={},
        )
        assert r.status_code == 404

    def test_unsubscribe_disables(self, db_session, authed_client, test_org):
        fw, _, _ = _seed_framework_with_control(db_session, slug="fwa")
        db_session.commit()
        authed_client.post("/api/compliance/frameworks/fwa/subscribe", json={})
        r = authed_client.delete("/api/compliance/frameworks/fwa/subscribe")
        assert r.status_code == 200
        sub = db_session.query(OrgFrameworkSubscription).filter_by(
            org_id=test_org.id, framework_id=fw.id,
        ).one()
        assert sub.enabled is False

    def test_scope_update(self, db_session, authed_client, test_org):
        fw, _, _ = _seed_framework_with_control(db_session, slug="fwa")
        db_session.commit()
        authed_client.post("/api/compliance/frameworks/fwa/subscribe", json={})
        r = authed_client.patch(
            "/api/compliance/frameworks/fwa/scope",
            json={"scope_tag_expr": "env:prod,cde:yes",
                  "enabled": False},
        )
        assert r.status_code == 200
        sub = db_session.query(OrgFrameworkSubscription).filter_by(
            org_id=test_org.id, framework_id=fw.id,
        ).one()
        assert sub.enabled is False
        assert sub.scope_tag_expr == "env:prod,cde:yes"


# ─── Controls listing + detail + findings ─────────────────────

class TestControlsAndFindings:
    def _setup(self, db, org, *, with_finding=True, is_kev=True):
        fw, ctrl, _ = _seed_framework_with_control(db, slug="cis_v8")
        sub = OrgFrameworkSubscription(
            org_id=org.id, framework_id=fw.id, enabled=True,
        )
        db.add(sub); db.flush()
        scan = Scan(filename="t.nessus", source_type="nessus", org_id=org.id)
        db.add(scan); db.flush()
        asset = Asset(scan_id=scan.id, ip="10.0.0.1")
        db.add(asset); db.flush()
        if with_finding:
            f = _seed_finding(db, scan, asset, cves=["CVE-2021-44228"], is_kev=is_kev)
            evaluate_compliance(db, scan_id=scan.id)
            return fw, ctrl, f
        return fw, ctrl, None

    def test_list_controls_includes_status(self, db_session, authed_client, test_org):
        fw, ctrl, _ = self._setup(db_session, test_org)
        db_session.commit()

        r = authed_client.get("/api/compliance/frameworks/cis_v8/controls")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        item = body["items"][0]
        assert item["ref"] == "C1"
        assert item["state"] == "failing"
        assert item["failing_finding_count"] == 1
        assert item["mapping_count"] == 1

    def test_list_controls_state_filter(self, db_session, authed_client, test_org):
        self._setup(db_session, test_org)
        db_session.commit()
        r = authed_client.get("/api/compliance/frameworks/cis_v8/controls?state=passing")
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_get_control_detail(self, db_session, authed_client, test_org):
        fw, ctrl, _ = self._setup(db_session, test_org)
        db_session.commit()
        r = authed_client.get(f"/api/compliance/controls/{ctrl.id}")
        assert r.status_code == 200
        body = r.json()
        assert body["ref"] == "C1"
        assert body["state"] == "failing"
        assert len(body["mappings"]) == 1
        assert body["compensating_controls"] == []

    def test_list_findings_under_control(self, db_session, authed_client, test_org):
        fw, ctrl, f = self._setup(db_session, test_org)
        db_session.commit()
        r = authed_client.get(f"/api/compliance/controls/{ctrl.id}/findings")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        item = body["items"][0]
        assert item["finding_id"] == f.id
        assert item["verdict"] == "failing"
        assert item["finding"]["plugin_id"] == "100"

    def test_findings_verdict_filter(self, db_session, authed_client, test_org):
        _, ctrl, _ = self._setup(db_session, test_org)
        db_session.commit()
        r = authed_client.get(
            f"/api/compliance/controls/{ctrl.id}/findings?verdict=resolved",
        )
        assert r.status_code == 200
        assert r.json()["items"] == []


# ─── Compensating controls + state machine ───────────────────

class TestCompensatingControls:
    def _setup(self, db, org):
        fw, ctrl, _ = _seed_framework_with_control(db, slug="cis_v8")
        db.add(OrgFrameworkSubscription(
            org_id=org.id, framework_id=fw.id, enabled=True,
        )); db.flush()
        scan = Scan(filename="t.nessus", source_type="nessus", org_id=org.id)
        db.add(scan); db.flush()
        asset = Asset(scan_id=scan.id, ip="10.0.0.1")
        db.add(asset); db.flush()
        f = _seed_finding(db, scan, asset, cves=["CVE-1"], is_kev=True)
        evaluate_compliance(db, scan_id=scan.id)
        return fw, ctrl, f

    def test_create_flips_verdict_and_state(self, db_session, authed_client, test_org):
        _, ctrl, f = self._setup(db_session, test_org)
        db_session.commit()

        r = authed_client.post(
            f"/api/compliance/controls/{ctrl.id}/compensating-controls",
            json={"rationale": "WAF blocks the exploit path"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["rows_flipped"] == 1
        # Status row flipped.
        status = db_session.query(ComplianceFindingStatus).filter_by(
            finding_id=f.id, control_id=ctrl.id,
        ).one()
        assert status.verdict == "satisfied_by_compensating"
        # Control state moved to compensating_control.
        ctrl_status = db_session.query(ComplianceControlStatus).filter_by(
            org_id=test_org.id, control_id=ctrl.id,
        ).one()
        assert ctrl_status.state == "compensating_control"

    def test_partial_state_when_some_failing_remain(self, db_session, authed_client, test_org):
        fw, ctrl, _ = _seed_framework_with_control(db_session, slug="cis_v8")
        db_session.add(OrgFrameworkSubscription(
            org_id=test_org.id, framework_id=fw.id, enabled=True,
        )); db_session.flush()
        scan = Scan(filename="t.nessus", source_type="nessus", org_id=test_org.id)
        db_session.add(scan); db_session.flush()
        a1 = Asset(scan_id=scan.id, ip="10.0.0.1"); db_session.add(a1); db_session.flush()
        f1 = _seed_finding(db_session, scan, a1, cves=["CVE-1"], is_kev=True)
        evaluate_compliance(db_session, scan_id=scan.id)
        # Flip only f1 to satisfied via the CC.
        cc = ComplianceCompensatingControl(
            org_id=test_org.id, control_id=ctrl.id,
            rationale="docs", scope_rule=None,
        )
        db_session.add(cc); db_session.flush()
        # Then add a second failing row directly so we exercise the partial path.
        a2 = Asset(scan_id=scan.id, ip="10.0.0.2"); db_session.add(a2); db_session.flush()
        f2 = _seed_finding(db_session, scan, a2, cves=["CVE-2"], is_kev=True,
                            plugin_id="200")
        # Apply the compensating control via the helper (flips f1 only — f2 hasn't been evaluated yet).
        from services.compliance_evaluator import apply_compensating_control
        apply_compensating_control(db_session, cc)
        # Now evaluate f2 → it lands as failing.
        evaluate_compliance(db_session, scan_id=scan.id, new_finding_ids=[f2.id])
        db_session.commit()

        ctrl_status = db_session.query(ComplianceControlStatus).filter_by(
            org_id=test_org.id, control_id=ctrl.id,
        ).one()
        assert ctrl_status.state == "partial"

    def test_delete_flips_back_to_failing(self, db_session, authed_client, test_org):
        _, ctrl, f = self._setup(db_session, test_org)
        db_session.commit()
        cr = authed_client.post(
            f"/api/compliance/controls/{ctrl.id}/compensating-controls",
            json={"rationale": "documented WAF rule SEC-123"},
        )
        cc_id = cr.json()["id"]

        dr = authed_client.delete(f"/api/compliance/compensating-controls/{cc_id}")
        assert dr.status_code == 200
        assert dr.json()["rows_flipped_back"] == 1
        # Verdict back to failing — the finding's still open.
        status = db_session.query(ComplianceFindingStatus).filter_by(
            finding_id=f.id,
        ).one()
        assert status.verdict == "failing"

    def test_delete_keeps_resolved_when_finding_was_resolved_during_cc(
        self, db_session, authed_client, test_org,
    ):
        _, ctrl, f = self._setup(db_session, test_org)
        db_session.commit()
        cr = authed_client.post(
            f"/api/compliance/controls/{ctrl.id}/compensating-controls",
            json={"rationale": "documented WAF rule SEC-123"},
        )
        cc_id = cr.json()["id"]

        # Finding gets resolved while CC is active.
        f.workflow_status = "resolved"
        db_session.commit()

        authed_client.delete(f"/api/compliance/compensating-controls/{cc_id}")
        status = db_session.query(ComplianceFindingStatus).filter_by(
            finding_id=f.id,
        ).one()
        # Verdict should reflect current finding state, not blindly flip back.
        assert status.verdict == "resolved"

    def test_linked_exception_must_be_in_org(self, db_session, authed_client, test_org):
        # Other org's exception should be rejected.
        other = Organization(name="Other", slug="other")
        db_session.add(other); db_session.flush()
        fe = FindingException(org_id=other.id, exception_type="compensating_control",
                              reason="nope", is_active=True)
        db_session.add(fe); db_session.flush()
        _, ctrl, _ = self._setup(db_session, test_org)
        db_session.commit()

        r = authed_client.post(
            f"/api/compliance/controls/{ctrl.id}/compensating-controls",
            json={"rationale": "cross-org exception attempt", "linked_exception_id": fe.id},
        )
        assert r.status_code == 404


# ─── Tenant isolation ─────────────────────────────────────────

class TestTenantIsolation:
    def test_compensating_control_from_other_org_404(self, db_session, authed_client, test_org):
        # Create a CC under a different org; current user's org can't delete it.
        other = Organization(name="Other", slug="other"); db_session.add(other); db_session.flush()
        fw, ctrl, _ = _seed_framework_with_control(db_session, slug="cis_v8")
        cc = ComplianceCompensatingControl(
            org_id=other.id, control_id=ctrl.id, rationale="x",
        )
        db_session.add(cc); db_session.flush()
        db_session.commit()

        r = authed_client.delete(f"/api/compliance/compensating-controls/{cc.id}")
        assert r.status_code == 404


# ─── Reverse lookup on findings ──────────────────────────────

class TestSatisfiesControlsLookup:
    def test_endpoint_returns_per_control_verdict(self, db_session, authed_client, test_org):
        fw, ctrl, _ = _seed_framework_with_control(db_session, slug="cis_v8")
        db_session.add(OrgFrameworkSubscription(
            org_id=test_org.id, framework_id=fw.id, enabled=True,
        )); db_session.flush()
        scan = Scan(filename="t.nessus", source_type="nessus", org_id=test_org.id)
        db_session.add(scan); db_session.flush()
        asset = Asset(scan_id=scan.id, ip="10.0.0.1"); db_session.add(asset); db_session.flush()
        f = _seed_finding(db_session, scan, asset, cves=["CVE-1"], is_kev=True)
        evaluate_compliance(db_session, scan_id=scan.id)
        db_session.commit()

        r = authed_client.get(f"/api/compliance/findings/{f.id}/satisfies-controls")
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 1
        assert body[0]["framework_slug"] == "cis_v8"
        assert body[0]["control_ref"] == "C1"
        assert body[0]["verdict"] == "failing"

    def test_finding_response_includes_satisfies_controls(self, db_session, authed_client, test_org):
        fw, ctrl, _ = _seed_framework_with_control(db_session, slug="cis_v8")
        db_session.add(OrgFrameworkSubscription(
            org_id=test_org.id, framework_id=fw.id, enabled=True,
        )); db_session.flush()
        scan = Scan(filename="t.nessus", source_type="nessus", org_id=test_org.id)
        db_session.add(scan); db_session.flush()
        asset = Asset(scan_id=scan.id, ip="10.0.0.1"); db_session.add(asset); db_session.flush()
        f = _seed_finding(db_session, scan, asset, cves=["CVE-1"], is_kev=True)
        evaluate_compliance(db_session, scan_id=scan.id)
        db_session.commit()

        r = authed_client.get(f"/api/findings/{f.id}")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "satisfies_controls" in body
        assert len(body["satisfies_controls"]) == 1
        assert body["satisfies_controls"][0]["control_ref"] == "C1"
        assert body["satisfies_controls"][0]["framework_slug"] == "cis_v8"
