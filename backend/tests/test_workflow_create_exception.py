"""Tests for the create_exception workflow action node."""

import secrets
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))


@pytest.fixture
def db_session():
    from core.database import Base
    from models.models import Organization

    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org = Organization(name="Test Org", slug="test-org")
    session.add(org)
    session.flush()

    yield session, org
    session.close()


@pytest.fixture
def findings(db_session):
    """Create 3 findings: 2 for plugin A on different assets, 1 for plugin B."""
    from models.models import Asset, Finding, Scan

    session, org = db_session

    scan = Scan(org_id=org.id, filename="test.nessus", status="completed")
    session.add(scan)
    session.flush()

    asset1 = Asset(scan_id=scan.id, ip="10.0.0.1", hostname="host-1")
    asset2 = Asset(scan_id=scan.id, ip="10.0.0.2", hostname="host-2")
    session.add_all([asset1, asset2])
    session.flush()

    f1 = Finding(
        scan_id=scan.id, asset_id=asset1.id,
        plugin_id="12345", plugin_name="CVE-2021-44228 Log4Shell",
        severity=4, severity_label="Critical", workflow_status="open",
    )
    f2 = Finding(
        scan_id=scan.id, asset_id=asset2.id,
        plugin_id="12345", plugin_name="CVE-2021-44228 Log4Shell",
        severity=4, severity_label="Critical", workflow_status="open",
    )
    f3 = Finding(
        scan_id=scan.id, asset_id=asset1.id,
        plugin_id="67890", plugin_name="OpenSSL Heartbleed",
        severity=3, severity_label="High", workflow_status="open",
    )
    session.add_all([f1, f2, f3])
    session.flush()

    items = [
        {"finding_id": f1.id, "asset_id": asset1.id, "asset_ip": "10.0.0.1",
         "plugin_id": "12345", "plugin_name": "CVE-2021-44228 Log4Shell"},
        {"finding_id": f2.id, "asset_id": asset2.id, "asset_ip": "10.0.0.2",
         "plugin_id": "12345", "plugin_name": "CVE-2021-44228 Log4Shell"},
        {"finding_id": f3.id, "asset_id": asset1.id, "asset_ip": "10.0.0.1",
         "plugin_id": "67890", "plugin_name": "OpenSSL Heartbleed"},
    ]
    return session, org, items, [f1, f2, f3]


class TestCreateExceptionAction:
    def _make_node(self, config):
        from unittest.mock import MagicMock
        node = MagicMock()
        node.node_type = "action"
        node.node_subtype = "create_exception"
        node.config = config
        return node

    def test_per_finding_scope_creates_one_exception_per_plugin_asset(self, findings):
        """scope=per_finding creates a distinct exception for each (plugin, asset) pair."""
        from models.models import FindingException
        from services.workflow_engine import _execute_action

        session, org, items, _ = findings

        node = self._make_node({
            "exception_type": "accepted_risk",
            "scope": "per_finding",
            "reason": "Accepted until Q3 patch cycle",
            "approved_by": "ciso@example.com",
            "expires_in_days": 30,
        })
        result = _execute_action(session, node, items)

        assert result["status"] == "success"
        assert result["output"]["affected"] == 3  # all 3 findings linked

        excs = session.query(FindingException).all()
        assert len(excs) == 3  # 2 for plugin 12345 (different IPs) + 1 for 67890
        for e in excs:
            assert e.org_id == org.id
            assert e.exception_type == "accepted_risk"
            assert e.reason == "Accepted until Q3 patch cycle"
            assert e.approved_by == "ciso@example.com"
            assert e.asset_ip in ("10.0.0.1", "10.0.0.2")
            assert e.expires_at is not None
            assert e.expires_at > datetime.utcnow() + timedelta(days=29)

    def test_per_plugin_scope_collapses_across_assets(self, findings):
        """scope=per_plugin creates one exception per unique plugin_id, asset_ip=None."""
        from models.models import FindingException
        from services.workflow_engine import _execute_action

        session, _, items, _ = findings

        node = self._make_node({
            "exception_type": "false_positive",
            "scope": "per_plugin",
            "reason": "Vendor confirmed FP",
        })
        result = _execute_action(session, node, items)

        assert result["output"]["affected"] == 3
        excs = session.query(FindingException).all()
        assert len(excs) == 2  # plugin 12345 + plugin 67890
        for e in excs:
            assert e.asset_ip is None
            assert e.exception_type == "false_positive"

    def test_links_findings_and_updates_workflow_status(self, findings):
        """Matched Finding rows get exception_id set and workflow_status = type."""
        from services.workflow_engine import _execute_action

        session, _, items, finding_rows = findings

        node = self._make_node({
            "exception_type": "compensating_control",
            "reason": "WAF rule deployed",
            "compensating_control_detail": "CloudFlare WAF blocks exploit pattern",
        })
        _execute_action(session, node, items)

        for f in finding_rows:
            session.refresh(f)
            assert f.exception_id is not None
            assert f.workflow_status == "compensating_control"
            assert f.status_changed_at is not None

    def test_compensating_control_detail_persists(self, findings):
        from models.models import FindingException
        from services.workflow_engine import _execute_action

        session, _, items, _ = findings

        node = self._make_node({
            "exception_type": "compensating_control",
            "compensating_control_detail": "Network segmentation isolates host",
        })
        _execute_action(session, node, items)

        exc = session.query(FindingException).first()
        assert exc.compensating_control_detail == "Network segmentation isolates host"

    def test_technical_debt_fields_persist(self, findings):
        from models.models import FindingException
        from services.workflow_engine import _execute_action

        session, _, items, _ = findings

        node = self._make_node({
            "exception_type": "technical_debt",
            "debt_category": "legacy_system",
            "mitigation_plan": "Migrate to new platform by 2027",
        })
        _execute_action(session, node, items)

        exc = session.query(FindingException).first()
        assert exc.debt_category == "legacy_system"
        assert exc.mitigation_plan == "Migrate to new platform by 2027"

    def test_zero_expiry_means_permanent(self, findings):
        from models.models import FindingException
        from services.workflow_engine import _execute_action

        session, _, items, _ = findings

        node = self._make_node({"exception_type": "accepted_risk", "expires_in_days": 0})
        _execute_action(session, node, items)

        exc = session.query(FindingException).first()
        assert exc.expires_at is None

    def test_skips_items_missing_plugin_or_finding_id(self, db_session):
        """Items without finding_id or plugin_id are silently skipped."""
        from models.models import FindingException
        from services.workflow_engine import _execute_action

        session, _ = db_session
        items = [
            {"asset_ip": "10.0.0.1"},  # no finding_id
            {"finding_id": 1},  # no plugin_id
        ]

        node = self._make_node({"exception_type": "accepted_risk"})
        result = _execute_action(session, node, items)

        assert result["output"]["affected"] == 0
        assert session.query(FindingException).count() == 0

    def test_only_type_specific_fields_populated(self, findings):
        """accepted_risk should not carry compensating/debt fields."""
        from models.models import FindingException
        from services.workflow_engine import _execute_action

        session, _, items, _ = findings

        node = self._make_node({
            "exception_type": "accepted_risk",
            # These should be ignored for accepted_risk:
            "compensating_control_detail": "ignored",
            "debt_category": "legacy_system",
            "mitigation_plan": "ignored",
        })
        _execute_action(session, node, items)

        exc = session.query(FindingException).first()
        assert exc.compensating_control_detail is None
        assert exc.debt_category is None
        assert exc.mitigation_plan is None


class TestCreateExceptionCatalog:
    def test_create_exception_in_catalog(self):
        from services.workflow_engine import NODE_CATALOG

        subtypes = [n["subtype"] for n in NODE_CATALOG["actions"]]
        assert "create_exception" in subtypes

    def test_catalog_exposes_exception_type_enum(self):
        from services.workflow_engine import NODE_CATALOG

        node_def = next(n for n in NODE_CATALOG["actions"] if n["subtype"] == "create_exception")
        schema = node_def["config_schema"]["exception_type"]
        values = [o["value"] for o in schema["options"]]
        assert set(values) == {"accepted_risk", "false_positive", "compensating_control", "technical_debt"}

    def test_catalog_exposes_scope_enum(self):
        from services.workflow_engine import NODE_CATALOG

        node_def = next(n for n in NODE_CATALOG["actions"] if n["subtype"] == "create_exception")
        schema = node_def["config_schema"]["scope"]
        values = [o["value"] for o in schema["options"]]
        assert set(values) == {"per_finding", "per_plugin"}
