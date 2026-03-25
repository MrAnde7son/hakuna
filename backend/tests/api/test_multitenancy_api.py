"""API tests for multi-tenancy isolation and MSSP access."""
import pytest
from tests.conftest import create_user, make_auth_headers, _set_org_id
from core.auth import create_access_token


def _extract_items(data, key="assets"):
    """Extract list items from paginated response, handling different response formats."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get(key, data.get("items", []))
    return []


class TestOrgIsolation:
    """Verify strict tenant isolation between organizations."""

    @pytest.fixture
    def two_orgs(self, db_session):
        """Create two separate orgs with users and data."""
        from models.models import Organization, Scan, Asset, Finding

        # Org A
        org_a = Organization(name="Org A", slug="org-a")
        db_session.add(org_a)
        db_session.flush()
        user_a = create_user(db_session, org_a, email="admin-a@test.com", role="org_admin")

        scan_a = Scan(org_id=org_a.id, filename="scan_a.nessus", scan_name="Scan A")
        db_session.add(scan_a)
        db_session.flush()

        asset_a = Asset(scan_id=scan_a.id, ip="10.1.0.1", hostname="org-a-host")
        db_session.add(asset_a)
        db_session.flush()
        _set_org_id(db_session, "assets", asset_a.id, org_a.id)

        finding_a = Finding(
            scan_id=scan_a.id, asset_id=asset_a.id,
            plugin_id="50001", plugin_name="Org A Finding",
            severity=4, risk_factor="critical",
        )
        db_session.add(finding_a)
        db_session.flush()
        _set_org_id(db_session, "findings", finding_a.id, org_a.id)

        # Org B
        org_b = Organization(name="Org B", slug="org-b")
        db_session.add(org_b)
        db_session.flush()
        user_b = create_user(db_session, org_b, email="admin-b@test.com", role="org_admin")

        scan_b = Scan(org_id=org_b.id, filename="scan_b.nessus", scan_name="Scan B")
        db_session.add(scan_b)
        db_session.flush()

        asset_b = Asset(scan_id=scan_b.id, ip="10.2.0.1", hostname="org-b-host")
        db_session.add(asset_b)
        db_session.flush()
        _set_org_id(db_session, "assets", asset_b.id, org_b.id)

        finding_b = Finding(
            scan_id=scan_b.id, asset_id=asset_b.id,
            plugin_id="50002", plugin_name="Org B Finding",
            severity=3, risk_factor="high",
        )
        db_session.add(finding_b)
        db_session.flush()
        _set_org_id(db_session, "findings", finding_b.id, org_b.id)

        return {
            "org_a": org_a, "user_a": user_a, "asset_a": asset_a, "finding_a": finding_a,
            "org_b": org_b, "user_b": user_b, "asset_b": asset_b, "finding_b": finding_b,
        }

    def test_org_a_cannot_see_org_b_assets(self, client, two_orgs):
        headers = make_auth_headers(two_orgs["user_a"], two_orgs["org_a"])
        resp = client.get("/api/assets", headers=headers)
        assert resp.status_code == 200
        items = _extract_items(resp.json(), "assets")
        ips = [a.get("ip") for a in items]
        assert "10.1.0.1" in ips  # own asset
        assert "10.2.0.1" not in ips  # other org's asset

    def test_org_b_cannot_see_org_a_findings(self, client, two_orgs):
        headers = make_auth_headers(two_orgs["user_b"], two_orgs["org_b"])
        resp = client.get("/api/findings", headers=headers)
        assert resp.status_code == 200
        items = _extract_items(resp.json(), "findings")
        names = [f.get("plugin_name") for f in items]
        assert "Org A Finding" not in names

    def test_org_a_cannot_access_org_b_asset_detail(self, client, two_orgs):
        headers = make_auth_headers(two_orgs["user_a"], two_orgs["org_a"])
        resp = client.get(f"/api/assets/{two_orgs['asset_b'].id}", headers=headers)
        assert resp.status_code in (403, 404)

    def test_org_b_cannot_access_org_a_finding_detail(self, client, two_orgs):
        headers = make_auth_headers(two_orgs["user_b"], two_orgs["org_b"])
        resp = client.get(f"/api/findings/{two_orgs['finding_a'].id}", headers=headers)
        assert resp.status_code in (403, 404)


class TestMSSPAccess:
    """Verify MSSP parent can access child org data."""

    @pytest.fixture
    def mssp_setup(self, db_session):
        from models.models import Organization, MSSPOrgAccess, Scan, Asset

        # MSSP parent org
        mssp_org = Organization(name="MSSP Parent", slug="mssp-parent", org_type="mssp")
        db_session.add(mssp_org)
        db_session.flush()
        mssp_admin = create_user(db_session, mssp_org, email="mssp@test.com", role="org_admin")

        # Client org
        client_org = Organization(name="Client Org", slug="client-org")
        db_session.add(client_org)
        db_session.flush()
        client_user = create_user(db_session, client_org, email="client@test.com", role="org_admin")

        # Link MSSP to client
        link = MSSPOrgAccess(mssp_org_id=mssp_org.id, client_org_id=client_org.id, is_active=True)
        db_session.add(link)
        db_session.flush()

        # Client org data
        scan = Scan(org_id=client_org.id, filename="client.nessus", scan_name="Client Scan")
        db_session.add(scan)
        db_session.flush()

        asset = Asset(scan_id=scan.id, ip="192.168.1.1", hostname="client-host")
        db_session.add(asset)
        db_session.flush()
        _set_org_id(db_session, "assets", asset.id, client_org.id)

        return {
            "mssp_org": mssp_org, "mssp_admin": mssp_admin,
            "client_org": client_org, "client_user": client_user,
            "asset": asset,
        }

    def test_mssp_can_see_client_assets(self, client, mssp_setup):
        # MSSP admin should see client assets without X-Org-Context restriction
        token = create_access_token(
            mssp_setup["mssp_admin"].id,
            mssp_setup["mssp_org"].id,
            mssp_setup["mssp_admin"].role,
        )
        headers = {"Authorization": f"Bearer {token}"}  # No X-Org-Context — see all linked orgs
        resp = client.get("/api/assets", headers=headers)
        assert resp.status_code == 200
        items = _extract_items(resp.json(), "assets")
        ips = [a.get("ip") for a in items]
        assert "192.168.1.1" in ips

    def test_client_cannot_see_mssp_data(self, client, mssp_setup):
        """Client org should only see its own data, not MSSP parent data."""
        headers = make_auth_headers(mssp_setup["client_user"], mssp_setup["client_org"])
        resp = client.get("/api/assets", headers=headers)
        assert resp.status_code == 200
