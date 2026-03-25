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
