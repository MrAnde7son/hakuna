"""API tests for reports and dashboard endpoints."""
import pytest


class TestDashboardSummary:
    def test_get_summary(self, authed_client, test_findings):
        resp = authed_client.get("/api/reports/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_get_summary_unauthenticated(self, client):
        resp = client.get("/api/reports/summary")
        assert resp.status_code == 401


class TestRiskGrade:
    def test_get_risk_grade(self, authed_client, test_findings):
        resp = authed_client.get("/api/reports/risk-grade")
        assert resp.status_code == 200


class TestMetricsTimeline:
    def test_metrics_timeline(self, authed_client, test_findings):
        resp = authed_client.get("/api/reports/metrics-timeline")
        assert resp.status_code == 200


class TestHeatmap:
    def test_default_family_severity(self, authed_client, test_findings):
        resp = authed_client.get("/api/reports/heatmap")
        assert resp.status_code == 200
        data = resp.json()
        assert data["row_dim"] == "family"
        assert data["col_dim"] == "severity"
        assert data["row_label"] == "Family"
        assert data["col_label"] == "Severity"
        assert isinstance(data["cols"], list)
        assert isinstance(data["rows"], list)
        # Severity columns are ordered Critical > High > Medium > Low (Info excluded)
        labels = [c["label"] for c in data["cols"]]
        assert "Info" not in labels
        for r in data["rows"]:
            assert "cells" in r and "total" in r and "label" in r

    def test_owner_by_kev(self, authed_client, test_findings):
        resp = authed_client.get("/api/reports/heatmap?rows=owner&cols=kev")
        assert resp.status_code == 200
        data = resp.json()
        assert data["row_dim"] == "owner"
        assert data["col_dim"] == "kev"
        col_labels = {c["label"] for c in data["cols"]}
        assert col_labels.issubset({"In KEV", "Not in KEV"})

    def test_asset_by_age(self, authed_client, test_findings):
        resp = authed_client.get("/api/reports/heatmap?rows=asset&cols=age_bucket&limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["row_dim"] == "asset"
        assert data["col_dim"] == "age_bucket"
        assert len(data["rows"]) <= 5

    def test_invalid_row_dim(self, authed_client, test_findings):
        resp = authed_client.get("/api/reports/heatmap?rows=bogus&cols=severity")
        assert resp.status_code == 400

    def test_invalid_col_dim(self, authed_client, test_findings):
        resp = authed_client.get("/api/reports/heatmap?rows=family&cols=bogus")
        assert resp.status_code == 400

    def test_unauthenticated(self, client):
        resp = client.get("/api/reports/heatmap")
        assert resp.status_code == 401
