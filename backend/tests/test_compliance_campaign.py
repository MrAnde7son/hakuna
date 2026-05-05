"""Tests for the compliance → Campaign creation endpoints.

Covers:
  - POST /api/compliance/controls/{id}/campaign
      * happy path: campaign created, query is union of mapping rules,
        finding set materialised from compliance_finding_status
      * also_include_control_ids bundles multiple controls
      * cross-framework bundling rejected
      * 404 on missing control
      * audit + linkage row written
  - POST /api/compliance/frameworks/{slug}/campaign
      * bundles every failing control of the framework
      * 400 when no failing controls
  - GET /api/campaigns/{id} surfaces compliance_controls with progress
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.models import (
    Asset, Campaign, CampaignComplianceControl, CampaignFinding,
    ComplianceControl, ComplianceControlMapping, ComplianceControlStatus,
    ComplianceFindingStatus, ComplianceFramework, Finding, Scan,
)


# ── Helpers ──────────────────────────────────────────────────


def _seed_framework(db, *, slug="cis_v8"):
    fw = ComplianceFramework(slug=slug, name=slug.upper(), version="1")
    db.add(fw); db.flush()
    return fw


def _seed_control(db, fw, *, ref="C1", title="Test", mapping_rule=None,
                   mapping_key=None):
    c = ComplianceControl(framework_id=fw.id, ref=ref, title=title,
                          testability="automated")
    db.add(c); db.flush()
    rule = mapping_rule or {
        "logic": "AND",
        "conditions": [{"field": "finding.is_kev", "op": "is_true"}],
    }
    m = ComplianceControlMapping(
        control_id=c.id,
        mapping_key=mapping_key or f"{fw.slug}-{ref}-m1",
        rule=rule, rule_version=1,
    )
    db.add(m); db.flush()
    return c, m


def _seed_finding(db, scan, asset, **kwargs):
    defaults = dict(plugin_id="100", severity=3, workflow_status="open",
                    cves=[], cwe_ids=[])
    defaults.update(kwargs)
    f = Finding(scan_id=scan.id, asset_id=asset.id, **defaults)
    db.add(f); db.flush()
    return f


def _seed_failing_status(db, org_id, control, finding, mapping_key):
    db.add(ComplianceFindingStatus(
        org_id=org_id, finding_id=finding.id, control_id=control.id,
        mapping_key=mapping_key, verdict="failing", matched_via="cve_cwe",
        match_signal={},
    ))


# ── Tests ────────────────────────────────────────────────────


class TestCreateCampaignFromControl:
    def test_happy_path_creates_campaign_with_findings(
        self, db_session, authed_client, test_org, test_scan, test_assets,
    ):
        fw = _seed_framework(db_session, slug="hipaa_security")
        ctrl, mapping = _seed_control(db_session, fw, ref="164.312(a)(1)")
        f = _seed_finding(db_session, test_scan, test_assets[0],
                          plugin_id="kev-1", is_kev=True)
        _seed_failing_status(db_session, test_org.id, ctrl, f, mapping.mapping_key)
        db_session.commit()

        r = authed_client.post(f"/api/compliance/controls/{ctrl.id}/campaign", json={})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["finding_count"] == 1
        assert body["control_ids"] == [ctrl.id]
        assert "164.312(a)(1)" in body["name"]

        camp = db_session.query(Campaign).filter_by(id=body["id"]).first()
        assert camp.org_id == test_org.id
        assert camp.query_logic == "OR"
        # Mapping conditions copied verbatim
        assert {"field": "finding.is_kev", "op": "is_true"} in camp.query
        # Linkage row exists
        link = db_session.query(CampaignComplianceControl).filter_by(
            campaign_id=camp.id,
        ).one()
        assert link.control_id == ctrl.id
        assert link.org_id == test_org.id
        # Finding materialised
        cfs = db_session.query(CampaignFinding).filter_by(campaign_id=camp.id).all()
        assert len(cfs) == 1
        assert cfs[0].finding_id == f.id

    def test_bundles_sibling_controls_via_also_include(
        self, db_session, authed_client, test_org, test_scan, test_assets,
    ):
        fw = _seed_framework(db_session, slug="hipaa_security")
        c1, m1 = _seed_control(db_session, fw, ref="164.312(a)(1)",
                                mapping_key="m-a1")
        c2, m2 = _seed_control(db_session, fw, ref="164.312(a)(2)",
                                mapping_key="m-a2")
        f1 = _seed_finding(db_session, test_scan, test_assets[0], plugin_id="x1")
        f2 = _seed_finding(db_session, test_scan, test_assets[0], plugin_id="x2")
        _seed_failing_status(db_session, test_org.id, c1, f1, m1.mapping_key)
        _seed_failing_status(db_session, test_org.id, c2, f2, m2.mapping_key)
        db_session.commit()

        r = authed_client.post(
            f"/api/compliance/controls/{c1.id}/campaign",
            json={"also_include_control_ids": [c2.id]},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body["control_ids"]) == {c1.id, c2.id}
        assert body["finding_count"] == 2

    def test_cross_framework_bundling_rejected(
        self, db_session, authed_client, test_org,
    ):
        fw1 = _seed_framework(db_session, slug="hipaa_security")
        fw2 = _seed_framework(db_session, slug="pci_dss")
        c1, _ = _seed_control(db_session, fw1, ref="164.312",
                               mapping_key="hipaa-1")
        c2, _ = _seed_control(db_session, fw2, ref="6.3.3",
                               mapping_key="pci-1")
        db_session.commit()

        r = authed_client.post(
            f"/api/compliance/controls/{c1.id}/campaign",
            json={"also_include_control_ids": [c2.id]},
        )
        assert r.status_code == 400
        assert "same framework" in r.text

    def test_unknown_control_returns_404(self, authed_client):
        r = authed_client.post("/api/compliance/controls/99999/campaign", json={})
        assert r.status_code == 404

    def test_creates_campaign_even_with_no_failing_findings(
        self, db_session, authed_client, test_org,
    ):
        """Regression: query should still be materialised even if zero findings
        currently match — the campaign acts as a watch-list."""
        fw = _seed_framework(db_session, slug="cis_v8")
        ctrl, _ = _seed_control(db_session, fw, ref="1.1")
        db_session.commit()

        r = authed_client.post(f"/api/compliance/controls/{ctrl.id}/campaign", json={})
        assert r.status_code == 200
        body = r.json()
        assert body["finding_count"] == 0


class TestCreateCampaignFromFramework:
    def test_bundles_all_failing_controls(
        self, db_session, authed_client, test_org, test_scan, test_assets,
    ):
        fw = _seed_framework(db_session, slug="cis_v8")
        c1, m1 = _seed_control(db_session, fw, ref="1.1", mapping_key="cis-1.1")
        c2, m2 = _seed_control(db_session, fw, ref="1.2", mapping_key="cis-1.2")
        c3, _  = _seed_control(db_session, fw, ref="2.1", mapping_key="cis-2.1")  # passing
        f1 = _seed_finding(db_session, test_scan, test_assets[0], plugin_id="p1")
        f2 = _seed_finding(db_session, test_scan, test_assets[0], plugin_id="p2")
        _seed_failing_status(db_session, test_org.id, c1, f1, m1.mapping_key)
        _seed_failing_status(db_session, test_org.id, c2, f2, m2.mapping_key)
        for c, state in [(c1, "failing"), (c2, "failing"), (c3, "passing")]:
            db_session.add(ComplianceControlStatus(
                org_id=test_org.id, control_id=c.id, state=state,
                failing_finding_count=1 if state == "failing" else 0,
            ))
        db_session.commit()

        r = authed_client.post(f"/api/compliance/frameworks/{fw.slug}/campaign", json={})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["control_count"] == 2
        assert set(body["control_ids"]) == {c1.id, c2.id}
        assert body["finding_count"] == 2

    def test_no_failing_controls_returns_400(
        self, db_session, authed_client, test_org,
    ):
        fw = _seed_framework(db_session, slug="cis_v8")
        c, _ = _seed_control(db_session, fw, ref="1.1")
        db_session.add(ComplianceControlStatus(
            org_id=test_org.id, control_id=c.id, state="passing",
        ))
        db_session.commit()

        r = authed_client.post(f"/api/compliance/frameworks/{fw.slug}/campaign", json={})
        assert r.status_code == 400


class TestGetCampaignWithComplianceControls:
    def test_get_campaign_returns_compliance_controls_with_progress(
        self, db_session, authed_client, test_org, test_scan, test_assets,
    ):
        fw = _seed_framework(db_session, slug="hipaa_security")
        ctrl, mapping = _seed_control(db_session, fw, ref="164.312(a)(1)")
        f1 = _seed_finding(db_session, test_scan, test_assets[0], plugin_id="a")
        f2 = _seed_finding(db_session, test_scan, test_assets[0], plugin_id="b")
        _seed_failing_status(db_session, test_org.id, ctrl, f1, mapping.mapping_key)
        _seed_failing_status(db_session, test_org.id, ctrl, f2, mapping.mapping_key)
        db_session.commit()

        r = authed_client.post(f"/api/compliance/controls/{ctrl.id}/campaign", json={})
        camp_id = r.json()["id"]

        # Mark one finding resolved
        cf = db_session.query(CampaignFinding).filter_by(
            campaign_id=camp_id, finding_id=f1.id,
        ).first()
        cf.status = "resolved"
        db_session.commit()

        r = authed_client.get(f"/api/campaigns/{camp_id}")
        assert r.status_code == 200, r.text
        controls = r.json()["compliance_controls"]
        assert len(controls) == 1
        assert controls[0]["control_id"] == ctrl.id
        assert controls[0]["framework_slug"] == "hipaa_security"
        assert controls[0]["total"] == 2
        assert controls[0]["resolved"] == 1

    def test_get_campaign_without_compliance_links_returns_empty(
        self, db_session, authed_client, test_campaign,
    ):
        r = authed_client.get(f"/api/campaigns/{test_campaign.id}")
        assert r.status_code == 200
        assert r.json()["compliance_controls"] == []
