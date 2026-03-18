"""Tests for UpsertHandler — insert, update, dedup, user_edited_fields protection."""

import os
import secrets
import pytest
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Use in-memory SQLite for tests
TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))


@pytest.fixture
def db_session():
    """Create a fresh in-memory database for each test."""
    from core.database import Base
    from models.models import (
        Organization, User, Scan, Asset, Finding,
        IntegrationCredential, Integration, IntegrationRun, DiscoveredSpec,
    )
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create minimal required records
    org = Organization(name="Test Org", slug="test-org")
    session.add(org)
    session.flush()

    scan = Scan(org_id=org.id, filename="test.nessus", scan_name="Test Scan")
    session.add(scan)
    session.flush()

    yield session, org.id, scan.id
    session.close()


class TestUpsertAsset:
    def test_insert_new_asset(self, db_session):
        session, org_id, scan_id = db_session
        from services.upsert_handler import upsert
        from models.models import Asset

        result = upsert(session, "asset", {
            "source_id": "dev-1", "source_system": "test",
            "ip_address": "10.0.0.1", "hostname": "srv1", "os": "Linux",
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        assert result.action == "inserted"
        assert result.id is not None

        asset = session.query(Asset).filter(Asset.id == result.id).first()
        assert asset.ip == "10.0.0.1"
        assert asset.hostname == "srv1"
        assert asset.source_system == "test"
        assert asset.source_id == "dev-1"

    def test_update_existing_asset(self, db_session):
        session, org_id, scan_id = db_session
        from services.upsert_handler import upsert
        from models.models import Asset

        # First insert
        upsert(session, "asset", {
            "source_id": "dev-1", "source_system": "test",
            "ip_address": "10.0.0.1", "hostname": "srv1", "os": "Ubuntu 20.04",
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        # Update with new data
        result = upsert(session, "asset", {
            "source_id": "dev-1", "source_system": "test",
            "ip_address": "10.0.0.1", "hostname": "srv1-updated", "os": "Ubuntu 22.04",
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        assert result.action == "updated"
        asset = session.query(Asset).filter(Asset.id == result.id).first()
        assert asset.hostname == "srv1-updated"
        assert asset.os == "Ubuntu 22.04"

    def test_null_values_not_overwritten(self, db_session):
        session, org_id, scan_id = db_session
        from services.upsert_handler import upsert
        from models.models import Asset

        # Insert with full data
        upsert(session, "asset", {
            "source_id": "dev-1", "source_system": "test",
            "ip_address": "10.0.0.1", "hostname": "srv1", "os": "Linux",
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        # Update with null hostname — should NOT overwrite
        result = upsert(session, "asset", {
            "source_id": "dev-1", "source_system": "test",
            "ip_address": "10.0.0.1", "hostname": None, "os": "Ubuntu 22.04",
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        asset = session.query(Asset).filter(Asset.id == result.id).first()
        assert asset.hostname == "srv1"  # preserved
        assert asset.os == "Ubuntu 22.04"  # updated

    def test_user_edited_fields_protected(self, db_session):
        session, org_id, scan_id = db_session
        from services.upsert_handler import upsert
        from models.models import Asset

        # Insert
        r = upsert(session, "asset", {
            "source_id": "dev-1", "source_system": "test",
            "ip_address": "10.0.0.1", "hostname": "srv1",
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        # Simulate user editing hostname
        asset = session.query(Asset).filter(Asset.id == r.id).first()
        asset.user_edited_fields = ["hostname"]
        asset.hostname = "user-set-name"
        session.commit()

        # Integration tries to update hostname
        result = upsert(session, "asset", {
            "source_id": "dev-1", "source_system": "test",
            "ip_address": "10.0.0.1", "hostname": "integration-name",
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        asset = session.query(Asset).filter(Asset.id == result.id).first()
        assert asset.hostname == "user-set-name"  # protected


class TestUpsertFinding:
    def test_insert_new_finding(self, db_session):
        session, org_id, scan_id = db_session
        from services.upsert_handler import upsert

        result = upsert(session, "finding", {
            "source_id": "vuln-1", "source_system": "test",
            "title": "SQL Injection", "severity": "critical",
            "asset": {"ip_address": "10.0.0.1", "hostname": "web01"},
            "cvss_score": 9.8, "cve_id": "CVE-2024-1234",
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        assert result.action == "inserted"
        assert result.id is not None

    def test_auto_creates_asset(self, db_session):
        session, org_id, scan_id = db_session
        from services.upsert_handler import upsert
        from models.models import Asset

        upsert(session, "finding", {
            "source_id": "vuln-1", "source_system": "test",
            "title": "XSS", "severity": "high",
            "asset": {"ip_address": "192.168.1.50"},
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        # Asset should have been auto-created
        asset = session.query(Asset).filter(Asset.ip == "192.168.1.50").first()
        assert asset is not None

    def test_dedup_prevents_duplicate(self, db_session):
        session, org_id, scan_id = db_session
        from services.upsert_handler import upsert

        # Insert twice with same dedup key
        r1 = upsert(session, "finding", {
            "source_id": "vuln-1", "source_system": "test",
            "title": "RCE", "severity": "critical",
            "asset": {"ip_address": "10.0.0.1"},
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        r2 = upsert(session, "finding", {
            "source_id": "vuln-1", "source_system": "test",
            "title": "RCE Updated", "severity": "critical",
            "asset": {"ip_address": "10.0.0.1"},
        }, dedup_key=["source_system", "source_id"], integration_id="int-1", scan_id=scan_id)
        session.commit()

        assert r1.action == "inserted"
        assert r2.action == "updated"


class TestUpsertBatch:
    def test_batch_insert(self, db_session):
        session, org_id, scan_id = db_session
        from services.upsert_handler import upsert_batch

        records = [
            {"source_id": f"v-{i}", "source_system": "test", "title": f"Finding {i}",
             "severity": "medium", "asset": {"ip_address": f"10.0.0.{i}"}}
            for i in range(5)
        ]

        result = upsert_batch(session, "finding", records,
                               dedup_key=["source_system", "source_id"],
                               integration_id="int-1", scan_id=scan_id)
        assert result["inserted"] == 5
        assert result["updated"] == 0
