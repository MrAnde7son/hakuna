"""Tests for the generic upsert path on FindingException — idempotent import
of accepted risks / false positives from third-party VM tools via the
integration builder."""

import os
import secrets
import pytest
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))


@pytest.fixture
def db_session():
    from core.database import Base
    from models.models import Organization

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org = Organization(name="Test Org", slug="test-org")
    session.add(org)
    session.flush()

    yield session, org.id
    session.close()


class TestFindingExceptionUpsert:
    def test_insert_via_generic_upsert(self, db_session):
        session, org_id = db_session
        from services.upsert_handler import upsert
        from models.models import FindingException

        record = {
            "org_id": org_id,
            "source_system": "tenable_io",
            "source_id": "accept-12345",
            "plugin_id": "12345",
            "plugin_name": "OpenSSH Weak Ciphers",
            "asset_ip": "10.0.0.42",
            "exception_type": "accepted_risk",
            "reason": "Legacy jump host — mitigated by network segmentation",
            "approved_by": "secops@example.com",
        }

        result = upsert(
            session, "finding_exception", record,
            dedup_key=["org_id", "source_system", "source_id"],
            integration_id="int-1",
        )
        session.commit()

        assert result.action == "inserted"
        row = session.query(FindingException).filter_by(id=result.id).first()
        assert row.org_id == org_id
        assert row.source_system == "tenable_io"
        assert row.source_id == "accept-12345"
        assert row.plugin_id == "12345"
        assert row.asset_ip == "10.0.0.42"
        assert row.exception_type == "accepted_risk"
        assert row.reason.startswith("Legacy")

    def test_update_is_idempotent(self, db_session):
        session, org_id = db_session
        from services.upsert_handler import upsert
        from models.models import FindingException

        base = {
            "org_id": org_id,
            "source_system": "qualys",
            "source_id": "excp-789",
            "plugin_id": "qid-90210",
            "exception_type": "false_positive",
            "reason": "Initial reason",
        }

        r1 = upsert(session, "finding_exception", dict(base),
                    dedup_key=["org_id", "source_system", "source_id"],
                    integration_id="int-1")
        session.commit()
        assert r1.action == "inserted"

        # Simulate a second pull from the same source with an updated reason
        updated = dict(base, reason="Validated false positive by AppSec on 2025-04-10")
        r2 = upsert(session, "finding_exception", updated,
                    dedup_key=["org_id", "source_system", "source_id"],
                    integration_id="int-1")
        session.commit()

        assert r2.action == "updated"
        assert r2.id == r1.id

        rows = session.query(FindingException).filter_by(
            org_id=org_id, source_system="qualys", source_id="excp-789"
        ).all()
        assert len(rows) == 1
        assert rows[0].reason.startswith("Validated")

    def test_org_scoping_prevents_cross_tenant_match(self, db_session):
        session, org_id = db_session
        from services.upsert_handler import upsert
        from models.models import Organization, FindingException

        other_org = Organization(name="Other", slug="other")
        session.add(other_org)
        session.flush()

        shared_source_id = "excp-duplicate-id"

        upsert(session, "finding_exception", {
            "org_id": org_id,
            "source_system": "vulcan",
            "source_id": shared_source_id,
            "exception_type": "accepted_risk",
        }, dedup_key=["org_id", "source_system", "source_id"], integration_id="int-a")

        upsert(session, "finding_exception", {
            "org_id": other_org.id,
            "source_system": "vulcan",
            "source_id": shared_source_id,
            "exception_type": "accepted_risk",
        }, dedup_key=["org_id", "source_system", "source_id"], integration_id="int-b")
        session.commit()

        rows = session.query(FindingException).filter_by(source_id=shared_source_id).all()
        assert len(rows) == 2
        assert {r.org_id for r in rows} == {org_id, other_org.id}

    def test_registered_in_model_registry(self):
        from integrations.model_registry import get_model_meta

        meta = get_model_meta("finding_exception")
        assert meta is not None
        assert meta.slug == "finding_exception"
        assert meta.dedup_keys == ["org_id", "source_system", "source_id"]

        col_names = {c["name"] for c in meta.writable_columns}
        # org_id is auto-managed and must NOT appear as a mapping target
        assert "org_id" not in col_names
        # Provenance + business columns should be mappable
        for expected in ("source_system", "source_id", "plugin_id", "asset_ip",
                         "exception_type", "reason", "expires_at", "is_active"):
            assert expected in col_names, f"missing mappable column: {expected}"

    def test_normalized_schema_entry(self):
        from integrations.schema import get_schema

        fields = get_schema("finding_exception")
        assert fields, "finding_exception missing from NORMALIZED_SCHEMA"

        by_name = {f["name"]: f for f in fields}
        assert by_name["source_system"]["required"] is True
        assert by_name["source_id"]["required"] is True
        assert by_name["exception_type"]["required"] is True
        assert "accepted_risk" in by_name["exception_type"]["enum_values"]
