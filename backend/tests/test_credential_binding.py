"""Tests for services.credential_binding — rule matching + resolve flow.

Uses the in-memory SQLite session from tests/conftest.py. Covers:
  - condition wildcards (NULL = any)
  - per-condition matchers: protocol, asset_type, device_type, cidr,
    hostname regex, tag
  - AND semantics across multiple conditions on one rule
  - priority ordering (lower number wins)
  - enabled flag is honored
  - cross-org credentials are rejected even if a stale rule references one
  - explain_rule_match returns per-check breakdown
"""
from __future__ import annotations

import pytest

from models.models import (
    Asset,
    CredentialBindingRule,
    IntegrationCredential,
    Organization,
)
from services.credential_binding import (
    explain_rule_match,
    resolve_credential_for_asset,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def org(db_session):
    o = Organization(name="Acme Corp")
    db_session.add(o)
    db_session.commit()
    db_session.refresh(o)
    return o


@pytest.fixture
def other_org(db_session):
    o = Organization(name="Other Corp")
    db_session.add(o)
    db_session.commit()
    db_session.refresh(o)
    return o


def _make_credential(db_session, org_id, *, name="cam-creds"):
    cred = IntegrationCredential(
        org_id=org_id, name=name, connector_id="http_basic",
        auth_type="basic",
        encrypted_values='{"ciphertext":"x","nonce":"y"}',
    )
    db_session.add(cred)
    db_session.commit()
    db_session.refresh(cred)
    return cred


def _make_asset(db_session, org_id, **kw):
    defaults = dict(
        org_id=org_id, ip="10.0.0.10", hostname="cam1",
        asset_type="host", device_type="ip_camera",
    )
    defaults.update(kw)
    asset = Asset(**defaults)
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)
    return asset


def _make_rule(db_session, org_id, credential_id, **kw):
    defaults = dict(
        org_id=org_id, credential_id=credential_id,
        name=kw.pop("name", "rule"),
        priority=kw.pop("priority", 100),
        enabled=kw.pop("enabled", True),
    )
    defaults.update(kw)
    rule = CredentialBindingRule(**defaults)
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)
    return rule


# ── Wildcards & single-condition matchers ────────────────────────────


class TestSingleConditionMatchers:
    def test_device_type_match(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, device_type="ip_camera")
        asset = _make_asset(db_session, org.id, device_type="ip_camera")

        resolved = resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        )
        assert resolved == cred.id

    def test_device_type_mismatch_returns_none(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, device_type="ip_camera")
        asset = _make_asset(db_session, org.id, device_type="printer")

        resolved = resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        )
        assert resolved is None

    def test_asset_type_match(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, asset_type="host")
        asset = _make_asset(db_session, org.id, asset_type="host")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="snmp", org_id=org.id,
        ) == cred.id

    def test_audit_protocol_match(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, audit_protocol="snmp")
        asset = _make_asset(db_session, org.id)

        assert resolve_credential_for_asset(
            db_session, asset, protocol="snmp", org_id=org.id,
        ) == cred.id
        # Different protocol → no match.
        assert resolve_credential_for_asset(
            db_session, asset, protocol="ssh", org_id=org.id,
        ) is None

    def test_cidr_match(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, cidr="10.0.0.0/24")
        asset = _make_asset(db_session, org.id, ip="10.0.0.42")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) == cred.id

    def test_cidr_outside_returns_none(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, cidr="10.0.0.0/24")
        asset = _make_asset(db_session, org.id, ip="10.0.1.5")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) is None

    def test_cidr_without_asset_ip_fails_safely(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, cidr="10.0.0.0/24")
        asset = _make_asset(db_session, org.id, ip=None)

        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) is None

    def test_hostname_regex_match(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, hostname_pattern=r"^cam-")
        asset = _make_asset(db_session, org.id, hostname="cam-floor3-04")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="rtsp", org_id=org.id,
        ) == cred.id

    def test_hostname_regex_mismatch(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, hostname_pattern=r"^printer-")
        asset = _make_asset(db_session, org.id, hostname="cam-floor3-04",
                            fqdn=None)

        assert resolve_credential_for_asset(
            db_session, asset, protocol="rtsp", org_id=org.id,
        ) is None

    def test_invalid_hostname_regex_is_safe(self, db_session, org):
        """An admin saving a bad regex via SQL shouldn't crash the resolver."""
        cred = _make_credential(db_session, org.id)
        _make_rule(db_session, org.id, cred.id, hostname_pattern=r"[")  # unbalanced
        asset = _make_asset(db_session, org.id, hostname="cam1")
        # Bad regex → no match (treated as if no hostname match), not an exception.
        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) is None


# ── AND semantics ────────────────────────────────────────────────────


class TestAndAcrossConditions:
    def test_all_conditions_match(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(
            db_session, org.id, cred.id,
            device_type="ip_camera",
            cidr="10.0.0.0/16",
            audit_protocol="http_auth",
        )
        asset = _make_asset(db_session, org.id, device_type="ip_camera",
                            ip="10.0.5.20")
        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) == cred.id

    def test_one_condition_failing_disqualifies(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        _make_rule(
            db_session, org.id, cred.id,
            device_type="ip_camera",
            cidr="10.0.0.0/16",
        )
        # Camera but outside the CIDR → no match.
        asset = _make_asset(db_session, org.id, device_type="ip_camera",
                            ip="192.168.1.5")
        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) is None


# ── Priority & enabled flag ──────────────────────────────────────────


class TestPriorityAndEnabled:
    def test_lower_priority_number_wins(self, db_session, org):
        cred_a = _make_credential(db_session, org.id, name="A")
        cred_b = _make_credential(db_session, org.id, name="B")
        _make_rule(db_session, org.id, cred_a.id,
                   device_type="ip_camera", priority=10, name="high-prio-A")
        _make_rule(db_session, org.id, cred_b.id,
                   device_type="ip_camera", priority=100, name="low-prio-B")
        asset = _make_asset(db_session, org.id, device_type="ip_camera")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) == cred_a.id

    def test_disabled_rule_is_skipped(self, db_session, org):
        cred_a = _make_credential(db_session, org.id, name="A")
        cred_b = _make_credential(db_session, org.id, name="B")
        _make_rule(db_session, org.id, cred_a.id,
                   device_type="ip_camera", priority=10, enabled=False)
        _make_rule(db_session, org.id, cred_b.id,
                   device_type="ip_camera", priority=100, enabled=True)
        asset = _make_asset(db_session, org.id, device_type="ip_camera")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) == cred_b.id

    def test_ties_broken_by_id_for_determinism(self, db_session, org):
        cred_a = _make_credential(db_session, org.id, name="A")
        cred_b = _make_credential(db_session, org.id, name="B")
        r1 = _make_rule(db_session, org.id, cred_a.id,
                        device_type="ip_camera", priority=50)
        _make_rule(db_session, org.id, cred_b.id,
                   device_type="ip_camera", priority=50)
        asset = _make_asset(db_session, org.id, device_type="ip_camera")

        # The earlier-created rule wins on tie.
        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) == r1.credential_id


# ── Cross-org safety ─────────────────────────────────────────────────


class TestCrossOrgSafety:
    def test_rule_with_cross_org_credential_is_rejected(
        self, db_session, org, other_org,
    ):
        # Build a rule in `org` that points at a credential owned by
        # `other_org`. Schema CASCADE normally prevents this, but the
        # resolver should still defend against stale data.
        foreign_cred = _make_credential(db_session, other_org.id, name="foreign")
        rule = CredentialBindingRule(
            org_id=org.id, credential_id=foreign_cred.id,
            name="leaky", priority=10, enabled=True,
            device_type="ip_camera",
        )
        db_session.add(rule)
        db_session.commit()
        asset = _make_asset(db_session, org.id, device_type="ip_camera")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) is None

    def test_rules_from_other_orgs_never_match(self, db_session, org, other_org):
        # Other org's credential + other org's rule pointing at it.
        foreign_cred = _make_credential(db_session, other_org.id)
        _make_rule(db_session, other_org.id, foreign_cred.id,
                   device_type="ip_camera")
        asset = _make_asset(db_session, org.id, device_type="ip_camera")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) is None

    def test_shared_credential_org_id_null_is_allowed(self, db_session, org):
        """Credentials with org_id=NULL are platform-wide shared. A rule in
        this org pointing at one of them should resolve cleanly."""
        cred = IntegrationCredential(
            org_id=None, name="shared", connector_id="http_basic",
            auth_type="basic",
            encrypted_values='{"ciphertext":"x"}',
        )
        db_session.add(cred)
        db_session.commit()
        db_session.refresh(cred)

        _make_rule(db_session, org.id, cred.id, device_type="ip_camera")
        asset = _make_asset(db_session, org.id, device_type="ip_camera")

        assert resolve_credential_for_asset(
            db_session, asset, protocol="http_auth", org_id=org.id,
        ) == cred.id


# ── Explain ──────────────────────────────────────────────────────────


class TestExplain:
    def test_explain_reports_each_check(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        rule = _make_rule(
            db_session, org.id, cred.id,
            device_type="ip_camera",
            cidr="10.0.0.0/24",
        )
        asset = _make_asset(db_session, org.id, device_type="ip_camera",
                            ip="10.0.0.5")
        explanation = explain_rule_match(rule, asset, protocol="http_auth")

        assert explanation["matched"] is True
        assert explanation["rule_id"] == rule.id
        checks = explanation["checks"]
        assert checks["device_type"]["matched"] is True
        assert checks["cidr"]["matched"] is True
        # Wildcards report matched + reason="wildcard".
        assert checks["asset_type"]["reason"] == "wildcard"
        assert checks["audit_protocol"]["reason"] == "wildcard"

    def test_explain_shows_which_check_failed(self, db_session, org):
        cred = _make_credential(db_session, org.id)
        rule = _make_rule(
            db_session, org.id, cred.id,
            device_type="ip_camera",
            cidr="10.0.0.0/24",
        )
        # Right device, wrong subnet.
        asset = _make_asset(db_session, org.id, device_type="ip_camera",
                            ip="192.168.1.10")
        explanation = explain_rule_match(rule, asset, protocol="http_auth")

        assert explanation["matched"] is False
        assert explanation["checks"]["device_type"]["matched"] is True
        assert explanation["checks"]["cidr"]["matched"] is False
        assert "not in" in explanation["checks"]["cidr"]["reason"]
