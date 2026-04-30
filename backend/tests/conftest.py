"""
Pytest configuration — shared fixtures for all backend tests.

Provides:
- In-memory SQLite test database with all tables
- FastAPI TestClient with dependency overrides
- Auth helpers (create users, generate tokens, get authenticated clients)
- Seed data factories (orgs, scans, assets, findings, campaigns)
"""
import os
import sys
import secrets

# Ensure backend/ and repo root are on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Set env vars BEFORE any app imports
os.environ.setdefault("INTEGRATION_SECRET_KEY", secrets.token_hex(32))
os.environ["TESTING"] = "1"
os.environ.setdefault("ENVIRONMENT", "test")

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient

from core.database import Base, get_db
from core.auth import create_access_token, hash_password


# ── Database fixtures ────────────────────────────────────────

@pytest.fixture(scope="session")
def engine():
    """Create a single in-memory SQLite engine for the test session."""
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

    @event.listens_for(eng, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Import all models so Base.metadata knows about them
    import models.models  # noqa: F401
    import models.threat_intel_models  # noqa: F401
    Base.metadata.create_all(bind=eng)

    # Run the same ALTER TABLE migrations that database._migrate_add_columns does
    # These add columns (org_id, first_seen, etc.) not in the ORM class definitions
    from sqlalchemy import inspect, text
    from core.database import _migrate_add_columns as _orig_migrate
    # We can't call _orig_migrate directly (it uses the production engine),
    # so replicate the migration dict and run against test engine
    migrations = {
        "assets": [
            ("org_id", "INTEGER"),
            ("inferred_primary_user", "VARCHAR"), ("inferred_admin_contacts", "JSON"),
            ("inferred_team", "VARCHAR"), ("owner_confidence", "VARCHAR DEFAULT 'low'"),
            ("environment_confirmed", "BOOLEAN DEFAULT FALSE"),
            ("business_context_confirmed", "BOOLEAN DEFAULT FALSE"),
            ("first_seen", "TIMESTAMP"), ("last_seen", "TIMESTAMP"),
            ("times_seen", "INTEGER DEFAULT 1"), ("asset_status", "VARCHAR DEFAULT 'active'"),
            ("stale_since", "TIMESTAMP"), ("system_type", "VARCHAR"),
            ("easm_data", "JSON"), ("internet_facing_confidence", "VARCHAR"),
            ("internet_facing_methods", "JSON"), ("source_id", "VARCHAR"),
            ("source_system", "VARCHAR"), ("user_edited_fields", "JSON"),
            ("device_type", "VARCHAR"), ("cpe", "JSON"),
            ("os_confidence", "INTEGER"), ("source_systems", "JSON"),
            ("asset_type", "VARCHAR DEFAULT 'host'"),
            ("asset_identity", "JSON"), ("asset_attributes", "JSON"),
            ("custom_fields", "JSON"),
        ],
        "findings": [
            ("org_id", "INTEGER"),
            ("first_seen", "TIMESTAMP"), ("last_seen", "TIMESTAMP"),
            ("times_seen", "INTEGER DEFAULT 1"),
            ("is_regression", "BOOLEAN DEFAULT FALSE"),
            ("auto_resolved", "BOOLEAN DEFAULT FALSE"),
            ("auto_resolved_at", "TIMESTAMP"),
            ("auto_resolved_by_scan_id", "INTEGER"),
            ("cvss4_score", "FLOAT"), ("cvss4_vector", "VARCHAR"),
            ("matched_ttps", "JSON"), ("aggregated_solution_id", "INTEGER"),
            ("source_type", "VARCHAR DEFAULT 'nessus'"),
            ("source_vuln_id", "VARCHAR"), ("normalized_id", "VARCHAR"),
            ("exploit_count", "INTEGER DEFAULT 0"),
            ("exploit_maturity_level", "VARCHAR"), ("ssvc_decision", "VARCHAR"),
            ("greynoise_seen", "BOOLEAN DEFAULT FALSE"),
            ("source_id", "VARCHAR"), ("source_system", "VARCHAR"),
            ("user_edited_fields", "JSON"), ("source_systems", "JSON"),
            ("custom_fields", "JSON"),
        ],
        "scans": [
            ("org_id", "INTEGER"),
            ("source_type", "VARCHAR DEFAULT 'nessus'"),
            ("source_version", "VARCHAR"), ("raw_metadata", "JSON"),
            ("schedule", "VARCHAR"), ("status", "VARCHAR DEFAULT 'completed'"),
            ("last_run_at", "DATETIME"), ("next_run_at", "DATETIME"),
            ("run_count", "INTEGER DEFAULT 0"),
        ],
        "tags": [("org_id", "INTEGER")],
        "auto_tag_rules": [("org_id", "INTEGER")],
        "campaigns": [("org_id", "INTEGER"), ("owner_id", "INTEGER"),
                      ("slack_channel_id", "VARCHAR"), ("slack_channel_name", "VARCHAR")],
        "workflows": [("org_id", "INTEGER")],
        "sla_configs": [("org_id", "INTEGER")],
        "integration_configs": [("org_id", "INTEGER")],
        "report_templates": [("org_id", "INTEGER")],
        "custom_roles": [("deny_permissions", "JSON")],
        "users": [("password_reset_token", "VARCHAR"), ("password_reset_expires", "TIMESTAMP"),
                  ("google_id", "VARCHAR")],
        "organizations": [
            ("stripe_customer_id", "VARCHAR"), ("stripe_subscription_id", "VARCHAR"),
            ("subscription_tier", "VARCHAR DEFAULT 'free'"), ("subscription_status", "VARCHAR"),
            ("trial_ends_at", "TIMESTAMP"), ("current_period_end", "TIMESTAMP"),
        ],
    }
    insp = inspect(eng)
    with eng.connect() as conn:
        for table, columns in migrations.items():
            try:
                existing = {c["name"] for c in insp.get_columns(table)}
            except Exception:
                continue
            for col_name, col_type in columns:
                if col_name not in existing:
                    try:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
                    except Exception:
                        pass
        # background_jobs is created by migration 058 in prod; replicate
        # the schema here so services.job_manager can be exercised live in
        # tests without going through the migration runner.
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS background_jobs ("
            "  id VARCHAR(64) PRIMARY KEY,"
            "  name VARCHAR(255) NOT NULL,"
            "  status VARCHAR(32) NOT NULL DEFAULT 'pending',"
            "  progress INTEGER,"
            "  result JSON,"
            "  error TEXT,"
            "  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "  started_at TIMESTAMP,"
            "  completed_at TIMESTAMP"
            ")"
        ))
        conn.commit()

    return eng


@pytest.fixture
def db_session(engine):
    """Per-test database session with automatic rollback."""
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def app(db_session):
    """FastAPI app with test database override and disabled schedulers."""
    from app import app as _app

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    _app.dependency_overrides[get_db] = _override_get_db

    # Remove startup event handlers to prevent schedulers from launching
    original_handlers = _app.router.on_startup.copy()
    _app.router.on_startup.clear()

    yield _app

    _app.dependency_overrides.clear()
    _app.router.on_startup = original_handlers


@pytest.fixture
def client(app):
    """Unauthenticated TestClient."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ── Auth helpers ─────────────────────────────────────────────

@pytest.fixture
def test_org(db_session):
    """Create a test organization."""
    from models.models import Organization
    org = Organization(name="Test Org", slug="test-org")
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def test_user(db_session, test_org):
    """Create an org_admin user in the test org."""
    from models.models import User
    user = User(
        email="admin@test.com",
        hashed_password=hash_password("testpass123"),
        display_name="Test Admin",
        role="org_admin",
        org_id=test_org.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def auth_headers(test_user, test_org):
    """Auth headers for the default test user."""
    token = create_access_token(test_user.id, test_org.id, test_user.role)
    return {
        "Authorization": f"Bearer {token}",
        "X-Org-Context": str(test_org.id),
    }


@pytest.fixture
def authed_client(client, auth_headers):
    """TestClient that sends auth headers with every request."""
    class AuthedClient:
        def __init__(self, client, headers):
            self._client = client
            self._headers = headers

        def get(self, url, **kwargs):
            kwargs.setdefault("headers", {}).update(self._headers)
            return self._client.get(url, **kwargs)

        def post(self, url, **kwargs):
            kwargs.setdefault("headers", {}).update(self._headers)
            return self._client.post(url, **kwargs)

        def put(self, url, **kwargs):
            kwargs.setdefault("headers", {}).update(self._headers)
            return self._client.put(url, **kwargs)

        def patch(self, url, **kwargs):
            kwargs.setdefault("headers", {}).update(self._headers)
            return self._client.patch(url, **kwargs)

        def delete(self, url, **kwargs):
            kwargs.setdefault("headers", {}).update(self._headers)
            return self._client.delete(url, **kwargs)

    return AuthedClient(client, auth_headers)


# ── User factories ───────────────────────────────────────────

def create_user(db_session, org, email="user@test.com", role="analyst", password="testpass123"):
    """Helper to create a user with a specific role."""
    from models.models import User
    user = User(
        email=email,
        hashed_password=hash_password(password),
        display_name=email.split("@")[0],
        role=role,
        org_id=org.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


def make_auth_headers(user, org):
    """Generate auth headers for any user."""
    token = create_access_token(user.id, org.id, user.role)
    return {
        "Authorization": f"Bearer {token}",
        "X-Org-Context": str(org.id),
    }


# ── Seed data factories ─────────────────────────────────────

@pytest.fixture
def test_scan(db_session, test_org):
    """Create a test scan."""
    from models.models import Scan
    scan = Scan(
        org_id=test_org.id,
        filename="test_scan.nessus",
        scan_name="Test Scan",
        status="completed",
    )
    db_session.add(scan)
    db_session.flush()
    return scan


def _set_org_id(db_session, table, record_id, org_id):
    """Set org_id via raw SQL since it's an ALTER TABLE column not in the ORM mapper."""
    from sqlalchemy import text
    db_session.execute(text(f"UPDATE {table} SET org_id = :org_id WHERE id = :id"),
                       {"org_id": org_id, "id": record_id})


@pytest.fixture
def test_assets(db_session, test_org, test_scan):
    """Create sample assets."""
    from models.models import Asset
    assets = []
    for i in range(3):
        asset = Asset(
            scan_id=test_scan.id,
            ip=f"10.0.0.{i+1}",
            hostname=f"host-{i+1}",
            os=f"Linux",
        )
        db_session.add(asset)
        db_session.flush()
        _set_org_id(db_session, "assets", asset.id, test_org.id)
        assets.append(asset)
    db_session.flush()
    return assets


@pytest.fixture
def test_findings(db_session, test_org, test_scan, test_assets):
    """Create sample findings linked to assets."""
    from models.models import Finding
    # severity is Integer: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    severity_map = [
        (4, "critical", "Critical"),
        (3, "high", "High"),
        (2, "medium", "Medium"),
    ]
    findings = []
    for i, asset in enumerate(test_assets):
        for j, (sev_int, risk_factor, label) in enumerate(severity_map):
            finding = Finding(
                scan_id=test_scan.id,
                asset_id=asset.id,
                plugin_id=str(10000 + i * 10 + j),
                plugin_name=f"Test Finding {label} {i}-{j}",
                severity=sev_int,
                severity_label=risk_factor,
                description=f"Test description for {risk_factor} finding",
                solution=f"Fix the {risk_factor} issue",
                risk_factor=risk_factor,
                priority_score=9.0 - j * 2,
            )
            db_session.add(finding)
            db_session.flush()
            _set_org_id(db_session, "findings", finding.id, test_org.id)
            findings.append(finding)
    db_session.flush()
    return findings


@pytest.fixture
def test_campaign(db_session, test_org, test_user, test_findings):
    """Create a test campaign with findings."""
    from models.models import Campaign, CampaignFinding
    campaign = Campaign(
        org_id=test_org.id,
        name="Test Campaign",
        description="A test remediation campaign",
        status="active",
        owner_id=test_user.id,
    )
    db_session.add(campaign)
    db_session.flush()

    for finding in test_findings[:3]:
        cf = CampaignFinding(campaign_id=campaign.id, finding_id=finding.id)
        db_session.add(cf)
    db_session.flush()
    return campaign


@pytest.fixture
def test_tags(db_session, test_org):
    """Create sample tags."""
    from models.models import Tag
    tags = []
    for value, category in [("production", "environment"), ("web-server", "role"), ("pci", "compliance")]:
        tag = Tag(org_id=test_org.id, value=value, category=category, color="#3b82f6")
        db_session.add(tag)
        tags.append(tag)
    db_session.flush()
    return tags
