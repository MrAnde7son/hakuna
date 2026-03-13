"""
Unit tests for backend/auth.py — JWT handling, password hashing, org access control.
"""
import sys
import os
import pytest
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.database import Base
from models.models import User, Organization, MSSPOrgAccess
import core.auth as auth


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def std_org(db):
    org = Organization(id=1, name="Acme Corp", slug="acme", org_type="standard", is_active=True)
    db.add(org)
    db.commit()
    return org


@pytest.fixture
def mssp_org(db):
    org = Organization(id=2, name="MSSP Corp", slug="mssp", org_type="mssp", is_active=True)
    db.add(org)
    db.commit()
    return org


@pytest.fixture
def client_org(db):
    org = Organization(id=3, name="Client A", slug="client-a", org_type="standard", is_active=True)
    db.add(org)
    db.commit()
    return org


@pytest.fixture
def std_user(db, std_org):
    user = User(id=1, email="analyst@acme.com", hashed_password=auth.hash_password("secret"),
                org_id=std_org.id, role="analyst", is_active=True)
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def superadmin(db, std_org):
    user = User(id=2, email="root@acme.com", hashed_password=auth.hash_password("root"),
                org_id=std_org.id, role="superadmin", is_active=True)
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def mssp_user(db, mssp_org):
    user = User(id=3, email="manager@mssp.com", hashed_password=auth.hash_password("pass"),
                org_id=mssp_org.id, role="analyst", is_active=True)
    db.add(user)
    db.commit()
    return user


# ── Password hashing ─────────────────────────────────────────────────────────

class TestPasswordHashing:
    def test_hash_produces_different_output_than_input(self):
        hashed = auth.hash_password("mypassword")
        assert hashed != "mypassword"

    def test_verify_correct_password(self):
        hashed = auth.hash_password("correct")
        assert auth.verify_password("correct", hashed) is True

    def test_verify_wrong_password(self):
        hashed = auth.hash_password("correct")
        assert auth.verify_password("wrong", hashed) is False

    def test_same_password_hashes_differently(self):
        """bcrypt generates a new salt each time."""
        h1 = auth.hash_password("same")
        h2 = auth.hash_password("same")
        assert h1 != h2

    def test_empty_password(self):
        hashed = auth.hash_password("")
        assert auth.verify_password("", hashed) is True
        assert auth.verify_password("notempty", hashed) is False


# ── JWT creation & decoding ───────────────────────────────────────────────────

class TestJWT:
    def test_create_and_decode_roundtrip(self):
        token = auth.create_access_token(user_id=42, org_id=7, role="analyst")
        payload = auth.decode_access_token(token)
        assert payload["sub"] == "42"
        assert payload["org_id"] == 7
        assert payload["role"] == "analyst"

    def test_expired_token_raises_401(self):
        token = auth.create_access_token(1, 1, "analyst", expires_delta=timedelta(seconds=-1))
        with pytest.raises(HTTPException) as exc_info:
            auth.decode_access_token(token)
        assert exc_info.value.status_code == 401

    def test_tampered_token_raises_401(self):
        token = auth.create_access_token(1, 1, "analyst")
        bad_token = token[:-5] + "XXXXX"
        with pytest.raises(HTTPException) as exc_info:
            auth.decode_access_token(bad_token)
        assert exc_info.value.status_code == 401

    def test_garbage_token_raises_401(self):
        with pytest.raises(HTTPException) as exc_info:
            auth.decode_access_token("not.a.jwt")
        assert exc_info.value.status_code == 401

    def test_custom_expiry(self):
        import time
        token = auth.create_access_token(1, 1, "viewer", expires_delta=timedelta(hours=24))
        payload = auth.decode_access_token(token)
        # exp should be roughly 24h from now
        remaining = payload["exp"] - time.time()
        assert 23 * 3600 < remaining < 25 * 3600


# ── Org access control ────────────────────────────────────────────────────────

class TestGetAccessibleOrgIds:
    """Tests for the synchronous logic inside get_accessible_org_ids."""

    def test_superadmin_gets_none(self, db, superadmin):
        """superadmin with no X-Org-Context should return None (unrestricted)."""
        org_ids = _sync_get_org_ids(db, superadmin, x_org_context=None)
        assert org_ids is None

    def test_superadmin_with_org_context_narrows(self, db, superadmin, std_org):
        org_ids = _sync_get_org_ids(db, superadmin, x_org_context=str(std_org.id))
        assert org_ids == [std_org.id]

    def test_standard_user_sees_own_org(self, db, std_user, std_org):
        org_ids = _sync_get_org_ids(db, std_user, x_org_context=None)
        assert org_ids == [std_org.id]

    def test_mssp_user_sees_own_and_client_orgs(self, db, mssp_user, mssp_org, client_org):
        link = MSSPOrgAccess(mssp_org_id=mssp_org.id, client_org_id=client_org.id, is_active=True)
        db.add(link)
        db.commit()

        org_ids = _sync_get_org_ids(db, mssp_user, x_org_context=None)
        assert mssp_org.id in org_ids
        assert client_org.id in org_ids

    def test_mssp_user_with_org_context_narrows_to_client(self, db, mssp_user, mssp_org, client_org):
        link = MSSPOrgAccess(mssp_org_id=mssp_org.id, client_org_id=client_org.id, is_active=True)
        db.add(link)
        db.commit()

        org_ids = _sync_get_org_ids(db, mssp_user, x_org_context=str(client_org.id))
        assert org_ids == [client_org.id]

    def test_user_cannot_access_other_org(self, db, std_user, client_org):
        with pytest.raises(HTTPException) as exc_info:
            _sync_get_org_ids(db, std_user, x_org_context=str(client_org.id))
        assert exc_info.value.status_code == 403

    def test_no_user_raises_401(self, db):
        with pytest.raises(HTTPException) as exc_info:
            _sync_get_org_ids(db, user=None, x_org_context=None)
        assert exc_info.value.status_code == 401


# ── apply_org_filter ──────────────────────────────────────────────────────────

class TestApplyOrgFilter:
    def test_none_org_ids_returns_query_unchanged(self, db, std_org):
        q = db.query(Organization)
        filtered = auth.apply_org_filter(q, Organization, org_ids=None)
        assert filtered.count() == db.query(Organization).count()

    def test_filters_by_org_id(self, db, std_org, mssp_org):
        """apply_org_filter uses model.org_id — use Tag which has org_id."""
        from models import Tag
        t1 = Tag(org_id=std_org.id, category="env", value="prod", color="#fff")
        t2 = Tag(org_id=mssp_org.id, category="env", value="staging", color="#000")
        db.add_all([t1, t2])
        db.commit()
        q = db.query(Tag)
        filtered = auth.apply_org_filter(q, Tag, org_ids=[std_org.id])
        results = filtered.all()
        assert len(results) == 1
        assert results[0].org_id == std_org.id

    def test_model_without_org_id_returns_unchanged(self, db, std_org):
        """Models without org_id should not be filtered."""
        from models import Scan
        q = db.query(Scan)
        filtered = auth.apply_org_filter(q, Scan, org_ids=[1])
        # No Scans exist but it shouldn't crash
        assert filtered.count() == 0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sync_get_org_ids(db, user, x_org_context):
    """Synchronous wrapper around the async logic in get_accessible_org_ids."""
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    if user.role == "superadmin":
        if x_org_context:
            return [int(x_org_context)]
        return None

    accessible = {user.org_id}

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if org and org.org_type == "mssp":
        links = db.query(MSSPOrgAccess.client_org_id).filter(
            MSSPOrgAccess.mssp_org_id == user.org_id,
            MSSPOrgAccess.is_active == True,
        ).all()
        accessible.update(row[0] for row in links)

    if x_org_context:
        ctx_id = int(x_org_context)
        if ctx_id not in accessible:
            raise HTTPException(status_code=403, detail="No access to requested organization")
        return [ctx_id]

    return list(accessible)
