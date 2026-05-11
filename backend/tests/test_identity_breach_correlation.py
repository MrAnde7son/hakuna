"""Tests for identity breach correlation + email permutation.

The correlation is the first thing about identities that produces a real,
actionable finding (vs. enrichment). Two stakes-bearing invariants pinned
here:

1. **No breaches → no findings, ever.** The whole point of the correlation
   is the existing ``DomainBreach`` data. If the domain isn't breached,
   the identity list is just inventory.
2. **Severity ladder matches blast radius.** A breach exposing passwords
   must surface as High; a fabricated/spam-list breach must surface as
   Low even when "password" appears in data classes. The classifier owns
   this — caught by direct tests.
"""

from datetime import datetime, timedelta

import pytest

from models.models import (
    Asset,
    DataProcessingConsent,
    Finding,
    Organization,
    Scan,
)
from models.threat_intel_models import BreachRecord, DomainBreach
from services.identity_discovery import (
    IDENTITY_DISCOVERY_PURPOSE,
    apply_discovery_result,
)
from services.identity_discovery.breach_correlation import (
    _classify_severity,
    correlate_breaches_for_identities,
)
from services.identity_discovery.email_permutations import (
    permute_corporate_emails,
)
from services.identity_discovery.sources import IdentityRecord, SourceResult


# ── Email permutations ──────────────────────────────────────────────


def test_permute_basic_two_token_name():
    out = permute_corporate_emails("John Patton", "abirasecurity.com")
    assert "john.patton@abirasecurity.com" in out
    assert "jpatton@abirasecurity.com" in out
    assert "john@abirasecurity.com" in out
    # Most-likely-first ordering: first.last beats single-name beats last.
    assert out.index("john.patton@abirasecurity.com") < out.index("john@abirasecurity.com")
    assert out.index("john@abirasecurity.com") < out.index("patton@abirasecurity.com")


def test_permute_strips_diacritics():
    out = permute_corporate_emails("José Pérez", "acme.com")
    assert all("é" not in e and "í" not in e for e in out)
    assert "jose.perez@acme.com" in out


def test_permute_drops_initials_and_honorifics():
    """A title like 'Joseph South CISSP, CCSP' must become joseph.south,
    not joseph.cissp — credentials after a comma are not surnames."""
    out = permute_corporate_emails("Joseph South CISSP, CCSP", "acme.com")
    assert "joseph.south@acme.com" in out
    assert not any("cissp" in e for e in out)


def test_permute_handles_single_letter_surname_safely():
    """'Ben D.' has only an initial for a surname. We should NOT permute
    against the initial — that'd produce ben.d@, b.d@, etc. with no real
    signal. Treating the initial as a non-surname token is correct."""
    out = permute_corporate_emails("Ben D.", "acme.com")
    # Either a single first-only candidate or nothing — never a permutation
    # against the lone "d".
    assert all(not e.startswith("ben.d") for e in out)
    assert "ben@acme.com" in out


def test_permute_returns_empty_for_missing_data():
    assert permute_corporate_emails("", "acme.com") == []
    assert permute_corporate_emails("Jane Doe", "") == []
    assert permute_corporate_emails(None, "acme.com") == []


def test_permute_strips_www_prefix_on_domain():
    out = permute_corporate_emails("Jane Doe", "www.acme.com")
    assert all(e.endswith("@acme.com") for e in out)


def test_permute_caps_results():
    out = permute_corporate_emails("John Patton", "acme.com", max_results=3)
    assert len(out) == 3


# ── Severity classifier ─────────────────────────────────────────────


def _make_breach_record(**kwargs):
    defaults = dict(
        name=kwargs.get("name", "Test"),
        title=kwargs.get("title", "Test"),
        domain="example.com",
        breach_date="2020-01-01",
        pwn_count=1000,
        data_classes=kwargs.pop("data_classes", []),
        is_verified=True,
        is_fabricated=kwargs.pop("is_fabricated", False),
        is_sensitive=kwargs.pop("is_sensitive", False),
        is_spam_list=kwargs.pop("is_spam_list", False),
    )
    defaults.update(kwargs)
    return BreachRecord(**defaults)


def test_severity_high_when_passwords_in_breach():
    """A breach that exposed passwords means credential stuffing is a real
    immediate risk — must rate higher than 'just email was exposed'."""
    b = _make_breach_record(data_classes=["Email addresses", "Passwords"])
    assert _classify_severity(b) == "high"


def test_severity_high_when_sensitive_flag():
    """HIBP flags sensitive breaches (e.g. AshleyMadison) where being in
    the breach is itself reputational damage. Bump regardless of data."""
    b = _make_breach_record(is_sensitive=True, data_classes=["Email addresses"])
    assert _classify_severity(b) == "high"


def test_severity_low_for_fabricated_or_spam():
    """HIBP marks dubious sources as fabricated/spam-list. A low-signal
    breach must not trigger a high-severity finding even if data classes
    suggest otherwise."""
    b = _make_breach_record(
        is_fabricated=True, data_classes=["Email addresses", "Passwords"],
    )
    assert _classify_severity(b) == "low"
    b2 = _make_breach_record(
        is_spam_list=True, data_classes=["Email addresses", "Passwords"],
    )
    assert _classify_severity(b2) == "low"


def test_severity_medium_for_email_only_breach():
    b = _make_breach_record(data_classes=["Email addresses"])
    assert _classify_severity(b) == "medium"


def test_severity_medium_when_breach_record_missing():
    """DomainBreach rows can exist without a matching BreachRecord (sync
    skew). Default to medium rather than crashing."""
    assert _classify_severity(None) == "medium"


# ── Full correlation ────────────────────────────────────────────────


def _setup_org_with_easm_domain(db_session, test_org, domain="acme.com"):
    test_org.easm_domain = domain
    db_session.flush()
    return test_org


def _seed_domain_breach(db_session, org_id, domain, breach_name, *,
                        data_classes=None, exposed_count=1000,
                        is_sensitive=False, is_fabricated=False):
    db_session.add(_make_breach_record(
        name=breach_name,
        title=breach_name.title(),
        domain=domain,
        breach_date="2019-10-04",
        pwn_count=exposed_count,
        data_classes=data_classes or ["Email addresses", "Passwords"],
        is_sensitive=is_sensitive,
        is_fabricated=is_fabricated,
    ))
    db_session.add(DomainBreach(
        org_id=org_id, domain=domain, breach_name=breach_name,
        exposed_count=exposed_count,
    ))
    db_session.flush()


def _create_identity(db_session, org, scan_id, slug, display_name):
    asset = Asset(
        scan_id=scan_id,
        asset_type="identity",
        asset_identity={"source": "linkedin", "slug": slug},
        asset_attributes={"display_name": display_name, "title": "Director"},
        source_systems=["identity_discovery"],
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def test_no_breaches_produces_no_findings(db_session, test_org):
    _setup_org_with_easm_domain(db_session, test_org)
    scan = Scan(
        org_id=test_org.id, filename="x", scan_name="x",
        source_type="identity_discovery",
    )
    db_session.add(scan)
    db_session.flush()
    asset = _create_identity(db_session, test_org, scan.id, "jane", "Jane Doe")

    result = correlate_breaches_for_identities(
        db_session, org_id=test_org.id, scan_id=scan.id,
        identity_asset_ids=[asset.id],
    )
    assert result["created"] == 0
    assert result["breaches_checked"] == 0
    assert db_session.query(Finding).count() == 0


def test_one_breach_one_identity_produces_one_finding(db_session, test_org):
    _setup_org_with_easm_domain(db_session, test_org)
    _seed_domain_breach(db_session, test_org.id, "acme.com", "Adobe")
    scan = Scan(
        org_id=test_org.id, filename="x", scan_name="x",
        source_type="identity_discovery",
    )
    db_session.add(scan)
    db_session.flush()
    asset = _create_identity(db_session, test_org, scan.id, "jane", "Jane Doe")

    result = correlate_breaches_for_identities(
        db_session, org_id=test_org.id, scan_id=scan.id,
        identity_asset_ids=[asset.id],
    )
    assert result["created"] == 1
    findings = db_session.query(Finding).filter(Finding.asset_id == asset.id).all()
    assert len(findings) == 1
    f = findings[0]
    assert f.plugin_id == "EASM-IDENTITY-BREACHED-CORPORATE-EMAIL:Adobe"
    assert f.severity_label == "High"  # passwords in data_classes
    assert "Jane Doe" in f.synopsis
    assert "jane.doe@acme.com" in f.plugin_output  # primary candidate listed


def test_multiple_breaches_emit_distinct_findings(db_session, test_org):
    """Closing one finding (say Adobe) must not suppress others — each
    breach is its own finding via plugin_id suffix."""
    _setup_org_with_easm_domain(db_session, test_org)
    _seed_domain_breach(db_session, test_org.id, "acme.com", "Adobe")
    _seed_domain_breach(db_session, test_org.id, "acme.com", "LinkedIn")
    scan = Scan(
        org_id=test_org.id, filename="x", scan_name="x",
        source_type="identity_discovery",
    )
    db_session.add(scan)
    db_session.flush()
    asset = _create_identity(db_session, test_org, scan.id, "jane", "Jane Doe")

    result = correlate_breaches_for_identities(
        db_session, org_id=test_org.id, scan_id=scan.id,
        identity_asset_ids=[asset.id],
    )
    assert result["created"] == 2
    plugin_ids = {f.plugin_id for f in db_session.query(Finding).filter(
        Finding.asset_id == asset.id
    ).all()}
    assert plugin_ids == {
        "EASM-IDENTITY-BREACHED-CORPORATE-EMAIL:Adobe",
        "EASM-IDENTITY-BREACHED-CORPORATE-EMAIL:LinkedIn",
    }


def test_rerun_updates_existing_finding_not_duplicate(db_session, test_org):
    _setup_org_with_easm_domain(db_session, test_org)
    _seed_domain_breach(db_session, test_org.id, "acme.com", "Adobe")
    scan = Scan(
        org_id=test_org.id, filename="x", scan_name="x",
        source_type="identity_discovery",
    )
    db_session.add(scan)
    db_session.flush()
    asset = _create_identity(db_session, test_org, scan.id, "jane", "Jane Doe")

    r1 = correlate_breaches_for_identities(
        db_session, org_id=test_org.id, scan_id=scan.id,
        identity_asset_ids=[asset.id],
    )
    r2 = correlate_breaches_for_identities(
        db_session, org_id=test_org.id, scan_id=scan.id,
        identity_asset_ids=[asset.id],
    )
    assert r1["created"] == 1
    assert r2["created"] == 0
    assert r2["updated"] == 1
    assert db_session.query(Finding).filter(Finding.asset_id == asset.id).count() == 1


def test_identity_without_display_name_skipped(db_session, test_org):
    """Without a display_name we can't permute emails — emitting a finding
    that just says 'someone you discovered might be in this breach' is
    useless. Skip rather than guess."""
    _setup_org_with_easm_domain(db_session, test_org)
    _seed_domain_breach(db_session, test_org.id, "acme.com", "Adobe")
    scan = Scan(
        org_id=test_org.id, filename="x", scan_name="x",
        source_type="identity_discovery",
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, asset_type="identity",
        asset_identity={"source": "linkedin", "slug": "anon"},
        asset_attributes={},  # no display_name
        source_systems=["identity_discovery"],
    )
    db_session.add(asset)
    db_session.flush()

    result = correlate_breaches_for_identities(
        db_session, org_id=test_org.id, scan_id=scan.id,
        identity_asset_ids=[asset.id],
    )
    assert result["created"] == 0


def test_correlation_integrated_with_apply_discovery_result(db_session, test_org):
    """End-to-end: a discovery run on a domain with known breaches should
    emit identity-exposure findings automatically, without a separate call."""
    _setup_org_with_easm_domain(db_session, test_org)
    _seed_domain_breach(db_session, test_org.id, "acme.com", "Adobe")

    record = IdentityRecord(
        slug="jane-doe", source="linkedin",
        url="https://linkedin.com/in/jane-doe",
        display_name="Jane Doe", title="Director",
    )
    summary = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=SourceResult(records=[record]),
    )
    assert summary["breach_findings_created"] == 1
    findings = db_session.query(Finding).filter(
        Finding.plugin_id.like("EASM-IDENTITY-BREACHED-CORPORATE-EMAIL%")
    ).all()
    assert len(findings) == 1
    assert "Adobe" in findings[0].plugin_id


def test_correlation_runs_even_on_no_signal_does_nothing(db_session, test_org):
    """No-signal run must NOT generate findings (no upsert happened, no
    new identities to correlate). Safety check for the lifecycle wiring."""
    _setup_org_with_easm_domain(db_session, test_org)
    _seed_domain_breach(db_session, test_org.id, "acme.com", "Adobe")

    summary = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=SourceResult(records=None),
    )
    assert summary["no_signal"] is True
    assert summary.get("breach_findings_created", 0) == 0
    assert db_session.query(Finding).count() == 0
