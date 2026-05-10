"""Tests for the domain-claim and join-request flow added in migration 069.

Covers:
  * `intent='create'` auto-claims a corporate email domain on first signup
  * Public email domains are never auto-claimed
  * `intent='join'` is rejected when the domain has no claim
  * `intent='join'` returns a pending_approval shape when mode='request'
  * `intent='join'` returns verification_required shape when mode='auto'
  * Public lookup endpoint hides orgs with mode='disabled'
  * Approve creates a real User; deny tombstones the request
"""

import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def _stub_easm():
    # trigger_easm_for_new_org talks to a remote service; stub it out so
    # registration tests stay hermetic.
    with patch("services.easm.trigger_easm_for_new_org", return_value=None):
        yield


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    # /api/auth/register is capped at 3/minute. Tests run faster than that
    # window, so reset the in-memory limiter between every test.
    from core.limiter import limiter
    try:
        limiter.reset()
    except Exception:
        pass
    yield


def _register(client, **overrides):
    body = {
        "org_name": overrides.pop("org_name", "Acme"),
        "email": overrides.pop("email", "alice@acme.com"),
        "password": overrides.pop("password", "passw0rd!ABC"),
        "display_name": overrides.pop("display_name", "Alice"),
        "intent": overrides.pop("intent", "create"),
    }
    body.update(overrides)
    return client.post("/api/auth/register", json=body)


class TestDomainAutoClaim:
    def test_corporate_signup_auto_claims_domain(self, client, db_session):
        from models.models import Organization

        r = _register(client, org_name="Acme", email="founder@acme.test")
        assert r.status_code == 200, r.text
        org = db_session.query(Organization).filter_by(slug="acme").first()
        assert org is not None
        assert org.claimed_domain == "acme.test"
        assert org.domain_join_mode == "auto"

    def test_public_email_signup_does_not_claim(self, client, db_session):
        from models.models import Organization

        r = _register(client, org_name="Personal", email="bob@gmail.com")
        assert r.status_code == 200, r.text
        org = db_session.query(Organization).filter_by(slug="personal").first()
        assert org.claimed_domain is None

    def test_second_corporate_signup_creates_separate_org_no_claim(self, client, db_session):
        # First signup claims the domain
        r1 = _register(client, org_name="Acme", email="founder@acme.test")
        assert r1.status_code == 200
        # Second signup with same domain (default intent='create') falls
        # through to a brand-new org but does NOT re-claim.
        r2 = _register(client, org_name="Acme Subsidiary", email="other@acme.test",
                       password="otherPass123!")
        assert r2.status_code == 200
        from models.models import Organization
        orgs = db_session.query(Organization).order_by(Organization.id).all()
        # First org keeps the claim; second org has no claim.
        assert orgs[0].claimed_domain == "acme.test"
        assert orgs[1].claimed_domain is None


class TestJoinIntent:
    def _seed_claimed_org(self, db_session, mode="request"):
        from models.models import Organization, User
        from core.auth import hash_password
        org = Organization(name="ACME Corp", slug="acme-corp",
                           claimed_domain="acme.test",
                           domain_join_mode=mode,
                           domain_join_default_role="viewer")
        db_session.add(org)
        db_session.flush()
        admin = User(email="admin@acme.test", hashed_password=hash_password("adminpass1!"),
                     display_name="Admin", role="org_admin", org_id=org.id, is_active=True)
        db_session.add(admin)
        db_session.flush()
        return org, admin

    def test_join_unknown_domain_rejected(self, client, db_session):
        r = _register(client, intent="join", email="x@nobody.test")
        assert r.status_code == 404

    def test_join_when_mode_disabled_rejected(self, client, db_session):
        org, _ = self._seed_claimed_org(db_session, mode="disabled")
        db_session.commit()
        r = _register(client, intent="join", email="newbie@acme.test")
        # Disabled orgs are hidden — same 404 as unknown domain.
        assert r.status_code == 404

    def test_join_request_mode_creates_pending_request_no_user(self, client, db_session):
        from models.models import OrgJoinRequest, User
        org, _ = self._seed_claimed_org(db_session, mode="request")
        db_session.commit()

        r = _register(client, intent="join", email="newbie@acme.test",
                      display_name="Newbie")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "pending_approval"
        assert body["joined_org_name"] == "ACME Corp"
        # No User row — only a pending join request.
        assert db_session.query(User).filter_by(email="newbie@acme.test").first() is None
        jr = db_session.query(OrgJoinRequest).filter_by(email="newbie@acme.test").first()
        assert jr is not None
        assert jr.status == "pending"
        assert jr.org_id == org.id

    def test_join_auto_mode_creates_unverified_user_no_token(self, client, db_session):
        from models.models import User
        org, _ = self._seed_claimed_org(db_session, mode="auto")
        db_session.commit()

        r = _register(client, intent="join", email="auto@acme.test")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "verification_required"
        # No JWT issued — they must verify before logging in.
        assert "access_token" not in body
        u = db_session.query(User).filter_by(email="auto@acme.test").first()
        assert u is not None
        assert u.org_id == org.id
        assert u.role == "viewer"
        assert u.email_verified is False
        assert u.email_verify_token is not None


class TestPublicLookup:
    def test_lookup_returns_match_when_join_enabled(self, client, db_session):
        from models.models import Organization
        db_session.add(Organization(
            name="ACME", slug="acme-pub-test",
            claimed_domain="lookup.test", domain_join_mode="request",
        ))
        db_session.commit()
        r = client.get("/api/auth/org-by-domain?email=user@lookup.test")
        assert r.status_code == 200
        body = r.json()
        assert body["matched"] is True
        assert body["org_name"] == "ACME"
        assert body["join_mode"] == "request"

    def test_lookup_hides_disabled_org(self, client, db_session):
        from models.models import Organization
        db_session.add(Organization(
            name="ACME", slug="acme-disabled-test",
            claimed_domain="disabled.test", domain_join_mode="disabled",
        ))
        db_session.commit()
        r = client.get("/api/auth/org-by-domain?domain=disabled.test")
        assert r.status_code == 200
        assert r.json() == {"matched": False}

    def test_lookup_ignores_public_email_domains(self, client):
        r = client.get("/api/auth/org-by-domain?email=anyone@gmail.com")
        assert r.status_code == 200
        assert r.json() == {"matched": False}


class TestJoinRequestApproveDeny:
    def _seed(self, db_session):
        from models.models import Organization, User, OrgJoinRequest
        from core.auth import hash_password
        from datetime import datetime, timedelta

        org = Organization(name="ACME", slug="acme-approve-test",
                           claimed_domain="approve.test", domain_join_mode="request",
                           domain_join_default_role="viewer")
        db_session.add(org)
        db_session.flush()
        admin = User(email="admin@approve.test", hashed_password=hash_password("adminpass1!"),
                     display_name="Admin", role="org_admin", org_id=org.id, is_active=True)
        db_session.add(admin)
        jr = OrgJoinRequest(
            org_id=org.id,
            email="pending@approve.test",
            hashed_password=hash_password("requesterpass1!"),
            display_name="Pending User",
            requested_role="viewer",
            status="pending",
            expires_at=datetime.utcnow() + timedelta(days=30),
        )
        db_session.add(jr)
        db_session.flush()
        return org, admin, jr

    def test_approve_creates_user_and_marks_request_approved(self, client, db_session):
        from core.auth import create_access_token
        from models.models import User, OrgJoinRequest

        org, admin, jr = self._seed(db_session)
        db_session.commit()
        token = create_access_token(admin.id, org.id, admin.role)
        headers = {"Authorization": f"Bearer {token}"}

        r = client.post(f"/api/auth/join-requests/{jr.id}/approve", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "approved"
        assert body["user"]["email"] == "pending@approve.test"
        assert body["user"]["role"] == "viewer"

        u = db_session.query(User).filter_by(email="pending@approve.test").first()
        assert u is not None
        assert u.org_id == org.id
        assert u.email_verified is True

        db_session.expire_all()
        jr2 = db_session.query(OrgJoinRequest).filter_by(id=jr.id).first()
        assert jr2.status == "approved"
        assert jr2.decided_by_user_id == admin.id

    def test_deny_marks_request_denied_no_user_created(self, client, db_session):
        from core.auth import create_access_token
        from models.models import User, OrgJoinRequest

        org, admin, jr = self._seed(db_session)
        db_session.commit()
        token = create_access_token(admin.id, org.id, admin.role)
        headers = {"Authorization": f"Bearer {token}"}

        r = client.post(
            f"/api/auth/join-requests/{jr.id}/deny",
            json={"reason": "Not affiliated"},
            headers=headers,
        )
        assert r.status_code == 200
        assert db_session.query(User).filter_by(email="pending@approve.test").first() is None
        db_session.expire_all()
        jr2 = db_session.query(OrgJoinRequest).filter_by(id=jr.id).first()
        assert jr2.status == "denied"
        assert jr2.denial_reason == "Not affiliated"


class TestDomainSettings:
    def test_admin_can_claim_their_own_domain(self, authed_client, test_user, test_org, db_session):
        # Force the user's email to a domain we want to claim.
        test_user.email = "admin@settings.test"
        db_session.commit()
        r = authed_client.patch("/api/auth/domain-settings", json={
            "claimed_domain": "settings.test",
            "domain_join_mode": "request",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["claimed_domain"] == "settings.test"
        assert body["domain_join_mode"] == "request"

    def test_admin_cannot_claim_public_domain(self, authed_client, test_user, db_session):
        test_user.email = "admin@gmail.com"
        db_session.commit()
        r = authed_client.patch("/api/auth/domain-settings", json={
            "claimed_domain": "gmail.com",
        })
        assert r.status_code == 400

    def test_admin_cannot_claim_other_companys_domain(self, authed_client, test_user, db_session):
        test_user.email = "admin@me.test"
        db_session.commit()
        r = authed_client.patch("/api/auth/domain-settings", json={
            "claimed_domain": "someone-else.test",
        })
        assert r.status_code == 403
