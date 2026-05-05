"""PR 5 — compliance report generation.

Pins:
  - Snapshot includes framework + rollup + per-control state + per-finding
    rows with verdict and asset metadata.
  - CSV serializer emits one row per (control × finding); controls without
    findings still emit a row so passing controls show up in the export.
  - JSON serializer round-trips the snapshot dict.
  - Reports are reproducible: a re-download returns identical bytes even
    if compliance_finding_status changes after generation.
  - PDF returns 501 with an explanatory message.
  - Subscription required: report against an unsubscribed framework is rejected.
  - Tenant isolation: another org's report is 404, never readable.
  - Permission gating: viewer is rejected.
"""

import csv
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.auth import create_access_token, hash_password
from models.models import (
    Asset, ComplianceControl, ComplianceControlMapping, ComplianceFramework,
    ComplianceReportRun, Finding, Organization, OrgFrameworkSubscription, Scan, User,
)
from services.compliance_evaluator import evaluate as evaluate_compliance
from services.compliance_report import (
    build_snapshot, snapshot_to_csv, snapshot_to_json, generate_report,
)


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
        "conditions": [{"field": "finding.is_kev", "op": "is_true"}],
    }
    fw = ComplianceFramework(slug=slug, name=slug.upper(), version="1")
    db.add(fw); db.flush()
    c = ComplianceControl(framework_id=fw.id, ref=control_ref,
                          title="Test Control", domain="Test",
                          testability="automated")
    db.add(c); db.flush()
    m = ComplianceControlMapping(control_id=c.id, mapping_key=mapping_key,
                                  rule=rule, rule_version=1)
    db.add(m); db.flush()
    return fw, c


def _seed_subscribed_org_with_finding(db, org, *, slug="cis_v8"):
    fw, ctrl = _seed_framework_with_control(db, slug=slug,
                                              mapping_key=f"{slug}-m1")
    db.add(OrgFrameworkSubscription(
        org_id=org.id, framework_id=fw.id, enabled=True,
    )); db.flush()
    scan = Scan(filename="t.nessus", source_type="nessus", org_id=org.id)
    db.add(scan); db.flush()
    asset = Asset(scan_id=scan.id, ip="10.0.0.1", hostname="dc01.corp")
    db.add(asset); db.flush()
    f = _seed_finding(db, scan, asset,
                       plugin_id="100", plugin_name="Log4j RCE",
                       cves=["CVE-2021-44228"], cwe_ids=["CWE-502"], is_kev=True)
    evaluate_compliance(db, scan_id=scan.id)
    return fw, ctrl, f, asset


# ─── Snapshot fidelity ────────────────────────────────────────

class TestBuildSnapshot:
    def test_includes_framework_metadata(self, db_session, test_org):
        fw, _, _, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        snapshot = build_snapshot(db_session, org_id=test_org.id, framework=fw)
        assert snapshot["framework"]["slug"] == "cis_v8"
        assert snapshot["framework"]["name"] == "CIS_V8"
        assert snapshot["framework"]["version"] == "1"
        assert "generated_at" in snapshot

    def test_rollup_counts_failing(self, db_session, test_org):
        fw, _, _, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        snapshot = build_snapshot(db_session, org_id=test_org.id, framework=fw)
        rollup = snapshot["rollup"]
        assert rollup["total_controls"] == 1
        assert rollup["failing"] == 1
        assert rollup["total_failing_findings"] == 1
        assert rollup["total_failing_assets"] == 1

    def test_per_control_state_and_findings(self, db_session, test_org):
        fw, ctrl, f, asset = _seed_subscribed_org_with_finding(db_session, test_org)
        snapshot = build_snapshot(db_session, org_id=test_org.id, framework=fw)
        c = snapshot["controls"][0]
        assert c["ref"] == "C1"
        assert c["state"] == "failing"
        assert c["mapping_count"] == 1
        assert c["failing_finding_count"] == 1
        assert len(c["findings"]) == 1
        finding = c["findings"][0]
        assert finding["finding_id"] == f.id
        assert finding["plugin_id"] == "100"
        assert finding["plugin_name"] == "Log4j RCE"
        assert finding["cves"] == ["CVE-2021-44228"]
        assert finding["cwe_ids"] == ["CWE-502"]
        assert finding["is_kev"] is True
        assert finding["asset_hostname"] == "dc01.corp"
        assert finding["asset_ip"] == "10.0.0.1"
        assert finding["verdict"] == "failing"

    def test_passing_control_has_no_findings(self, db_session, test_org):
        # No matching finding → control passes.
        fw, ctrl = _seed_framework_with_control(db_session, slug="empty_fw")
        db_session.add(OrgFrameworkSubscription(
            org_id=test_org.id, framework_id=fw.id, enabled=True,
        )); db_session.flush()
        scan = Scan(filename="t.nessus", source_type="nessus", org_id=test_org.id)
        db_session.add(scan); db_session.flush()
        asset = Asset(scan_id=scan.id, ip="10.0.0.2"); db_session.add(asset); db_session.flush()
        # is_kev=False → KEV rule won't match.
        _seed_finding(db_session, scan, asset, cves=["CVE-1"], is_kev=False)
        evaluate_compliance(db_session, scan_id=scan.id)

        snapshot = build_snapshot(db_session, org_id=test_org.id, framework=fw)
        c = snapshot["controls"][0]
        assert c["state"] == "passing"
        assert c["findings"] == []


# ─── CSV serializer ────────────────────────────────────────────

class TestCsvSerializer:
    def test_emits_one_row_per_finding(self, db_session, test_org):
        fw, _, _, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        snapshot = build_snapshot(db_session, org_id=test_org.id, framework=fw)
        csv_text = snapshot_to_csv(snapshot)
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        assert len(rows) == 1
        row = rows[0]
        assert row["control_ref"] == "C1"
        assert row["control_state"] == "failing"
        assert row["plugin_id"] == "100"
        assert row["cves"] == "CVE-2021-44228"
        assert row["cwe_ids"] == "CWE-502"
        assert row["is_kev"] == "yes"
        assert row["verdict"] == "failing"
        assert row["asset_hostname"] == "dc01.corp"

    def test_passing_control_emits_empty_finding_row(self, db_session, test_org):
        fw, _ = _seed_framework_with_control(db_session, slug="empty_fw")
        db_session.add(OrgFrameworkSubscription(
            org_id=test_org.id, framework_id=fw.id, enabled=True,
        )); db_session.flush()
        snapshot = build_snapshot(db_session, org_id=test_org.id, framework=fw)
        csv_text = snapshot_to_csv(snapshot)
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        assert len(rows) == 1
        # Control row exists, finding columns empty.
        assert rows[0]["control_ref"] == "C1"
        assert rows[0]["finding_id"] == ""
        assert rows[0]["plugin_id"] == ""

    def test_csv_header_includes_all_columns(self, db_session, test_org):
        fw, _, _, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        snapshot = build_snapshot(db_session, org_id=test_org.id, framework=fw)
        csv_text = snapshot_to_csv(snapshot)
        header = csv_text.splitlines()[0].split(",")
        for required in ("framework_slug", "control_ref", "verdict", "cves",
                         "cwe_ids", "asset_ip"):
            assert required in header


# ─── JSON serializer ───────────────────────────────────────────

class TestJsonSerializer:
    def test_round_trip(self, db_session, test_org):
        fw, _, _, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        snapshot = build_snapshot(db_session, org_id=test_org.id, framework=fw)
        out = json.loads(snapshot_to_json(snapshot))
        assert out["framework"]["slug"] == "cis_v8"
        assert out["rollup"]["failing"] == 1


# ─── generate_report (service-level) ───────────────────────────

class TestGenerateReport:
    def test_persists_run_with_snapshot_and_sha(self, db_session, test_org):
        fw, _, _, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        run = generate_report(db_session, org_id=test_org.id, framework=fw, fmt="csv")
        assert run.id is not None
        assert run.status == "succeeded"
        assert run.format == "csv"
        assert run.sha256 and len(run.sha256) == 64
        assert run.snapshot["framework"]["slug"] == "cis_v8"
        assert run.generated_at is not None

    def test_unsupported_format_raises(self, db_session, test_org):
        fw, _, _, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        with pytest.raises(ValueError):
            generate_report(db_session, org_id=test_org.id, framework=fw, fmt="xml")

    def test_reproducibility_csv_bytes(self, db_session, test_org):
        # Two reports generated back-to-back over identical state must have
        # the same sha — the snapshot is the input to the hash.
        fw, _, _, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        a = generate_report(db_session, org_id=test_org.id, framework=fw, fmt="csv")
        b = generate_report(db_session, org_id=test_org.id, framework=fw, fmt="csv")
        # generated_at differs (snapshot["generated_at"] is timestamped) so
        # full sha may diff — but the body sans the timestamp must match.
        # Cheaper assertion: rebuild csv from each run and compare sans
        # generated_at line. Snapshots both contain rollup + controls — the
        # CSV doesn't include generated_at, so its bytes should match.
        from services.compliance_report import serialize_run
        assert serialize_run(a) == serialize_run(b)


# ─── API endpoints ─────────────────────────────────────────────

class TestPostReportEndpoint:
    def test_create_csv_report(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        r = authed_client.post(
            "/api/compliance/reports",
            json={"framework_slug": "cis_v8", "format": "csv"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["format"] == "csv"
        assert body["status"] == "succeeded"
        assert body["framework_slug"] == "cis_v8"
        assert body["rollup"]["failing"] == 1
        assert body["sha256"]

    def test_create_json_report(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        r = authed_client.post(
            "/api/compliance/reports",
            json={"framework_slug": "cis_v8", "format": "json"},
        )
        assert r.status_code == 200
        assert r.json()["format"] == "json"

    def test_pdf_returns_501(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        r = authed_client.post(
            "/api/compliance/reports",
            json={"framework_slug": "cis_v8", "format": "pdf"},
        )
        assert r.status_code == 501
        assert "PDF" in r.text or "pdf" in r.text

    def test_unknown_format_returns_400(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        r = authed_client.post(
            "/api/compliance/reports",
            json={"framework_slug": "cis_v8", "format": "xml"},
        )
        assert r.status_code == 400

    def test_unknown_framework_returns_404(self, authed_client):
        r = authed_client.post(
            "/api/compliance/reports",
            json={"framework_slug": "nope", "format": "csv"},
        )
        assert r.status_code == 404

    def test_unsubscribed_framework_returns_400(self, db_session, authed_client, test_org):
        # Framework exists, but org didn't subscribe.
        fw, _ = _seed_framework_with_control(db_session, slug="orphan_fw")
        db_session.commit()
        r = authed_client.post(
            "/api/compliance/reports",
            json={"framework_slug": "orphan_fw", "format": "csv"},
        )
        assert r.status_code == 400
        assert "subscribed" in r.text.lower()


class TestListReports:
    def test_returns_recent_runs(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        authed_client.post("/api/compliance/reports",
                           json={"framework_slug": "cis_v8", "format": "csv"})
        authed_client.post("/api/compliance/reports",
                           json={"framework_slug": "cis_v8", "format": "json"})
        r = authed_client.get("/api/compliance/reports")
        assert r.status_code == 200
        body = r.json()
        assert len(body) >= 2
        # Newest first.
        assert body[0]["created_at"] >= body[1]["created_at"]

    def test_filter_by_framework(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org, slug="cis_v8")
        _seed_subscribed_org_with_finding(db_session, test_org, slug="other_fw")
        db_session.commit()
        authed_client.post("/api/compliance/reports",
                           json={"framework_slug": "cis_v8", "format": "csv"})
        authed_client.post("/api/compliance/reports",
                           json={"framework_slug": "other_fw", "format": "csv"})
        r = authed_client.get("/api/compliance/reports?framework_slug=cis_v8")
        assert r.status_code == 200
        body = r.json()
        assert all(item["framework_slug"] == "cis_v8" for item in body)


class TestGetReport:
    def test_returns_snapshot(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        c = authed_client.post("/api/compliance/reports",
                                json={"framework_slug": "cis_v8", "format": "csv"})
        run_id = c.json()["id"]
        r = authed_client.get(f"/api/compliance/reports/{run_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["snapshot"]["framework"]["slug"] == "cis_v8"
        assert body["snapshot"]["rollup"]["failing"] == 1


class TestDownloadReport:
    def test_csv_download_returns_streaming_response(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        c = authed_client.post("/api/compliance/reports",
                                json={"framework_slug": "cis_v8", "format": "csv"})
        run_id = c.json()["id"]
        r = authed_client.get(f"/api/compliance/reports/{run_id}/download")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        assert "attachment" in r.headers["content-disposition"]
        assert "compliance_cis_v8_" in r.headers["content-disposition"]
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert any(row["plugin_id"] == "100" for row in rows)

    def test_json_download(self, db_session, authed_client, test_org):
        _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        c = authed_client.post("/api/compliance/reports",
                                json={"framework_slug": "cis_v8", "format": "json"})
        run_id = c.json()["id"]
        r = authed_client.get(f"/api/compliance/reports/{run_id}/download")
        assert r.status_code == 200
        assert "application/json" in r.headers["content-type"]
        body = json.loads(r.text)
        assert body["framework"]["slug"] == "cis_v8"

    def test_redownload_returns_identical_bytes(self, db_session, authed_client, test_org):
        # Generate report → mutate state → re-download → bytes unchanged
        # because download serializes from the frozen snapshot, not live data.
        fw, ctrl, f, _ = _seed_subscribed_org_with_finding(db_session, test_org)
        db_session.commit()
        c = authed_client.post("/api/compliance/reports",
                                json={"framework_slug": "cis_v8", "format": "csv"})
        run_id = c.json()["id"]
        first = authed_client.get(f"/api/compliance/reports/{run_id}/download").text

        # Resolve the finding — live state changes; snapshot must not.
        f.workflow_status = "resolved"
        db_session.commit()

        second = authed_client.get(f"/api/compliance/reports/{run_id}/download").text
        assert first == second


class TestTenantIsolation:
    def test_other_org_report_returns_404(self, db_session, authed_client, test_org):
        # Create a run under a different org.
        other = Organization(name="Other", slug="other-org")
        db_session.add(other); db_session.flush()
        fw, _ = _seed_framework_with_control(db_session, slug="cis_v8")
        run = ComplianceReportRun(
            org_id=other.id, framework_id=fw.id, format="csv",
            status="succeeded", snapshot={"framework": {"slug": "cis_v8"}},
        )
        db_session.add(run); db_session.flush()
        db_session.commit()

        r1 = authed_client.get(f"/api/compliance/reports/{run.id}")
        r2 = authed_client.get(f"/api/compliance/reports/{run.id}/download")
        assert r1.status_code == 404
        assert r2.status_code == 404


class TestPermissionGating:
    def test_viewer_rejected(self, db_session, client, test_org):
        viewer = User(
            email="viewer@test.com",
            hashed_password=hash_password("x"),
            display_name="Viewer", role="viewer", org_id=test_org.id,
            is_active=True,
        )
        db_session.add(viewer); db_session.flush()
        token = create_access_token(viewer.id, test_org.id, viewer.role)
        r = client.get("/api/compliance/reports", headers={
            "Authorization": f"Bearer {token}",
            "X-Org-Context": str(test_org.id),
        })
        assert r.status_code == 403
