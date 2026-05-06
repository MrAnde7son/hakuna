"""API tests for findings endpoints."""
import pytest


class TestListFindings:
    def test_list_findings(self, authed_client, test_findings):
        resp = authed_client.get("/api/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data or "items" in data or isinstance(data, list)

    def test_list_findings_unauthenticated(self, client):
        resp = client.get("/api/findings")
        assert resp.status_code == 401

    def test_list_findings_filter_severity(self, authed_client, test_findings):
        resp = authed_client.get("/api/findings?severity=4")  # 4=Critical
        assert resp.status_code == 200

    def test_list_findings_pagination(self, authed_client, test_findings):
        resp = authed_client.get("/api/findings?page=1&page_size=5")
        assert resp.status_code == 200

    def test_list_findings_sort_by_priority(self, authed_client, test_findings):
        resp = authed_client.get("/api/findings?sort_by=priority_score&order=desc")
        assert resp.status_code == 200

    def test_list_findings_search(self, authed_client, test_findings):
        resp = authed_client.get("/api/findings?search=Critical")
        assert resp.status_code == 200

    def test_list_findings_ids_only(self, authed_client, test_findings):
        """ids_only=true returns IDs without heavy joinedload — used by Select All Matching."""
        resp = authed_client.get("/api/findings?ids_only=true")
        assert resp.status_code == 200
        data = resp.json()
        assert "ids" in data
        assert "total" in data
        assert "capped" in data
        assert "findings" not in data
        assert isinstance(data["ids"], list)
        assert all(isinstance(i, int) for i in data["ids"])
        assert data["total"] == len(data["ids"])
        assert data["capped"] is False

    def test_list_findings_ids_only_respects_filters(self, authed_client, test_findings):
        """ids_only must apply the same filters as the list endpoint."""
        full = authed_client.get("/api/findings?severity=4&ids_only=true").json()
        filtered = authed_client.get("/api/findings?severity=4").json()
        assert set(full["ids"]) == {f["id"] for f in filtered["findings"]}

    def test_list_findings_ids_filter(self, authed_client, test_findings):
        """ids=1,2,3 filter narrows the result set to that explicit list."""
        wanted = [f.id for f in test_findings[:2]]
        resp = authed_client.get(f"/api/findings?ids={','.join(str(i) for i in wanted)}")
        assert resp.status_code == 200
        data = resp.json()
        returned = {f["id"] for f in data["findings"]}
        assert returned == set(wanted)


class TestFindingDetail:
    def test_get_finding(self, authed_client, test_findings):
        finding = test_findings[0]
        resp = authed_client.get(f"/api/findings/{finding.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == finding.id

    def test_get_finding_not_found(self, authed_client):
        resp = authed_client.get("/api/findings/99999")
        assert resp.status_code == 404


class TestFindingTenantIsolation:
    def test_cannot_see_other_org_findings(self, client, db_session, test_findings):
        """Findings from org A should not be visible to org B."""
        from models.models import Organization
        from tests.conftest import make_auth_headers, create_user

        org_b = Organization(name="Other Org B", slug="other-org-b")
        db_session.add(org_b)
        db_session.flush()
        user_b = create_user(db_session, org_b, email="otherb@org.com", role="org_admin")
        headers = make_auth_headers(user_b, org_b)

        resp = client.get("/api/findings", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        items = data.get("findings", data.get("items", data)) if isinstance(data, dict) else data
        assert len(items) == 0
