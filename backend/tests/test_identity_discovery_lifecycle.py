"""Integration tests for identity discovery upsert + staleness + suppression
+ end-to-end orchestration.

These tests exercise the lifecycle module directly (no DDGS) so we can pin
the subtle bits: absence counters, the no-signal-doesn't-prune invariant,
the 3-run staleness threshold, and the GDPR suppression path.
"""

from datetime import datetime, timedelta

import pytest

from models.models import (
    Asset,
    DataProcessingConsent,
    IdentitySuppression,
    Scan,
)
from services.identity_discovery import (
    DdgLinkedInSource,
    IDENTITY_DISCOVERY_PURPOSE,
    STALE_AFTER_ABSENT_RUNS,
    apply_discovery_result,
    run_identity_discovery,
)
from services.identity_discovery.sources import IdentityRecord, SourceResult


# ── helpers ──────────────────────────────────────────────────────────


def _enable_identity_discovery(db, org):
    org.identity_discovery_enabled = True
    db.add(DataProcessingConsent(
        org_id=org.id,
        purpose=IDENTITY_DISCOVERY_PURPOSE,
        granted_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=365),
        acknowledgment_text="ack",
    ))
    db.flush()


def _record(slug, name="Jane Doe", title="Engineer", url=None):
    return IdentityRecord(
        slug=slug, source="linkedin",
        url=url or f"https://linkedin.com/in/{slug}",
        display_name=name, title=title,
    )


def _result(records):
    return SourceResult(records=records)


def _no_signal():
    return SourceResult(records=None, metadata={"empty": True})


def _identity_assets(db, scan_id):
    return (
        db.query(Asset)
        .filter(Asset.scan_id == scan_id, Asset.asset_type == "identity")
        .all()
    )


# ── upsert basics ────────────────────────────────────────────────────


def test_first_run_creates_assets_with_active_status(db_session, test_org):
    summary = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane"), _record("john")]),
    )
    assert summary["created"] == 2
    assert summary["updated"] == 0
    assets = _identity_assets(db_session, summary["scan_id"])
    assert len(assets) == 2
    assert all(a.asset_status == "active" for a in assets)
    assert all((a.easm_data or {}).get("identity_absent_count") == 0 for a in assets)
    assert all(a.hostname is None for a in assets)
    assert all(a.asset_identity["source"] == "linkedin" for a in assets)


def test_second_run_updates_existing_does_not_duplicate(db_session, test_org):
    """Same slug returning on a second run must update the existing row,
    not create a duplicate — otherwise dedup_config gets a parallel
    enforcement path it doesn't need."""
    apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane", title="Engineer")]),
    )
    summary = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane", title="Senior Engineer")]),
    )
    assert summary["created"] == 0
    assert summary["updated"] == 1
    assets = _identity_assets(db_session, summary["scan_id"])
    assert len(assets) == 1
    assert assets[0].asset_attributes["title"] == "Senior Engineer"
    assert assets[0].times_seen == 2


def test_rolling_scan_reused_across_runs(db_session, test_org):
    """One scan row per org for identity discovery, reused on every run —
    keeps the scans table from filling with empty per-run shells."""
    s1 = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane")]),
    )
    s2 = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane")]),
    )
    assert s1["scan_id"] == s2["scan_id"]
    scan = db_session.query(Scan).get(s1["scan_id"])
    assert scan.run_count == 2
    assert scan.last_run_at is not None


# ── absence + staleness ──────────────────────────────────────────────


def test_absent_identity_goes_stale_at_three_consecutive_runs(db_session, test_org):
    """The exact threshold matters — too low and one bad run pruning
    everyone; too high and stale records stick around forever. Pin it."""
    assert STALE_AFTER_ABSENT_RUNS == 3  # guard against silent retunes

    apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane"), _record("john")]),
    )

    def _present_jane_only():
        return apply_discovery_result(
            db_session, org_id=test_org.id, source="linkedin",
            result=_result([_record("jane")]),
        )

    # Run 2 — john absent for the first time
    s = _present_jane_only()
    john = next(a for a in _identity_assets(db_session, s["scan_id"])
                if a.asset_identity["slug"] == "john")
    assert john.asset_status == "active"
    assert john.easm_data["identity_absent_count"] == 1
    assert s["stale_now"] == 0

    # Run 3 — john absent twice
    s = _present_jane_only()
    john = next(a for a in _identity_assets(db_session, s["scan_id"])
                if a.asset_identity["slug"] == "john")
    assert john.asset_status == "active"
    assert john.easm_data["identity_absent_count"] == 2

    # Run 4 — john absent three times, flips to stale
    s = _present_jane_only()
    john = next(a for a in _identity_assets(db_session, s["scan_id"])
                if a.asset_identity["slug"] == "john")
    assert john.asset_status == "stale"
    assert john.stale_since is not None
    assert s["stale_now"] == 1

    # Run 5 — john still absent, but the transition only happens once
    s = _present_jane_only()
    assert s["stale_now"] == 0  # not counted again


def test_returning_identity_resets_absent_counter(db_session, test_org):
    """Someone reappearing after being absent should immediately reset to
    active — being temporarily off the SERP is not a status flip."""
    apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane"), _record("john")]),
    )
    # Two runs with john absent.
    for _ in range(2):
        apply_discovery_result(
            db_session, org_id=test_org.id, source="linkedin",
            result=_result([_record("jane")]),
        )

    s = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane"), _record("john")]),
    )
    john = next(a for a in _identity_assets(db_session, s["scan_id"])
                if a.asset_identity["slug"] == "john")
    assert john.asset_status == "active"
    assert john.easm_data["identity_absent_count"] == 0


def test_returning_after_stale_resets_to_active(db_session, test_org):
    """A previously-stale identity reappearing flips back to active — we
    don't keep ex-employees archived just because they ducked the SERP
    for a quarter."""
    apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane")]),
    )
    # Three absent runs → stale
    for _ in range(STALE_AFTER_ABSENT_RUNS):
        apply_discovery_result(
            db_session, org_id=test_org.id, source="linkedin",
            result=_result([]),
        )
    s = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane")]),
    )
    jane = _identity_assets(db_session, s["scan_id"])[0]
    assert jane.asset_status == "active"
    assert jane.stale_since is None


# ── no-signal invariant ──────────────────────────────────────────────


def test_no_signal_run_does_not_increment_absent_counters(db_session, test_org):
    """The crown jewel of this slice: a no-signal SourceResult (DDGS soft
    block) must never count as 'all identities are gone'. If it did, three
    bad days in a row would mark every identity for every org stale —
    silent mass-prune."""
    apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane"), _record("john")]),
    )
    for _ in range(5):  # five no-signal runs in a row
        s = apply_discovery_result(
            db_session, org_id=test_org.id, source="linkedin",
            result=_no_signal(),
        )
        assert s["no_signal"] is True
        assert s["stale_now"] == 0

    for a in _identity_assets(db_session, s["scan_id"]):
        assert a.asset_status == "active"
        assert a.easm_data["identity_absent_count"] == 0


def test_no_signal_run_still_bumps_scan_heartbeat(db_session, test_org):
    """We do want to know discovery 'ran' even when it returned nothing —
    last_run_at and run_count tick so operators can see attempts in the UI."""
    s = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_no_signal(),
    )
    scan = db_session.query(Scan).get(s["scan_id"])
    assert scan.run_count == 1
    assert scan.last_run_at is not None


# ── suppression / GDPR erasure ───────────────────────────────────────


def test_suppressed_slug_is_skipped_at_upsert(db_session, test_org):
    db_session.add(IdentitySuppression(
        org_id=test_org.id, source="linkedin", slug="jane",
    ))
    db_session.flush()
    s = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane"), _record("john")]),
    )
    assets = _identity_assets(db_session, s["scan_id"])
    assert {a.asset_identity["slug"] for a in assets} == {"john"}
    assert s["skipped_suppressed"] == 1


def test_suppression_added_later_hard_deletes_existing_asset(db_session, test_org):
    """GDPR Article 17 path: user requests erasure → suppression row added
    → next discovery run hard-deletes the existing asset, not just marks
    it stale. The user's name must actually leave the assets table."""
    s = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane"), _record("john")]),
    )
    db_session.add(IdentitySuppression(
        org_id=test_org.id, source="linkedin", slug="jane",
    ))
    db_session.flush()

    s = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane"), _record("john")]),  # jane still in SERP
    )
    assert s["deleted_suppressed"] == 1
    assert s["skipped_suppressed"] == 1
    assets = _identity_assets(db_session, s["scan_id"])
    assert {a.asset_identity["slug"] for a in assets} == {"john"}


def test_suppression_enforced_even_on_no_signal_run(db_session, test_org):
    """Erasure must not depend on DDGS returning data. If suppression is
    added and the next discovery is rate-limited, deletion still happens."""
    apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_result([_record("jane")]),
    )
    db_session.add(IdentitySuppression(
        org_id=test_org.id, source="linkedin", slug="jane",
    ))
    db_session.flush()

    s = apply_discovery_result(
        db_session, org_id=test_org.id, source="linkedin",
        result=_no_signal(),
    )
    assert s["deleted_suppressed"] == 1
    assert _identity_assets(db_session, s["scan_id"]) == []


# ── end-to-end orchestration ─────────────────────────────────────────


class _StaticSource:
    name = "linkedin"

    def __init__(self, result):
        self._result = result
        self.calls = []

    def discover(self, company_name, *, max_results=25):
        self.calls.append((company_name, max_results))
        return self._result


def test_run_skips_when_consent_missing(db_session, test_org):
    src = _StaticSource(_result([_record("jane")]))
    out = run_identity_discovery(db_session, test_org.id, source=src)
    assert out == {"status": "skipped_no_consent"}
    assert src.calls == []


def test_run_skips_when_consent_revoked(db_session, test_org):
    _enable_identity_discovery(db_session, test_org)
    # Revoke immediately.
    consent = db_session.query(DataProcessingConsent).first()
    consent.revoked_at = datetime.utcnow()
    db_session.flush()

    src = _StaticSource(_result([_record("jane")]))
    out = run_identity_discovery(db_session, test_org.id, source=src)
    assert out["status"] == "skipped_no_consent"
    assert src.calls == []


def test_run_end_to_end_creates_identities(db_session, test_org):
    test_org.name = "Acme Corp"
    _enable_identity_discovery(db_session, test_org)
    src = _StaticSource(_result([_record("jane"), _record("john")]))

    out = run_identity_discovery(db_session, test_org.id, source=src)
    assert out["status"] == "ok"
    assert out["created"] == 2
    assert src.calls == [("Acme Corp", 25)]
    assert out["company_name"] == "Acme Corp"


def test_run_falls_back_to_easm_domain_when_no_corp_entity(db_session, test_org):
    """The org display name is often a useless placeholder ("Other",
    "Test Org"). When no CorporateEntity is linked but EASM was pointed
    at a real domain, the resolver should use that domain's apex label
    as the search term — that's what DDGS actually finds employees with."""
    test_org.name = "Other"
    test_org.easm_domain = "abirasecurity.com"
    _enable_identity_discovery(db_session, test_org)
    src = _StaticSource(_result([_record("jane")]))
    out = run_identity_discovery(db_session, test_org.id, source=src)
    assert src.calls == [("abirasecurity", 25)]
    assert out["company_name"] == "abirasecurity"


def test_easm_domain_strips_www_prefix(db_session, test_org):
    test_org.name = "Other"
    test_org.easm_domain = "www.abirasecurity.com"
    _enable_identity_discovery(db_session, test_org)
    src = _StaticSource(_result([_record("jane")]))
    run_identity_discovery(db_session, test_org.id, source=src)
    assert src.calls == [("abirasecurity", 25)]


def test_corp_entity_legal_name_wins_over_easm_domain(db_session, test_org):
    """CorporateEntity.legal_name is Wikidata-verified — when both are
    available, the legal name should win since it's the cleaner signal."""
    from models.threat_intel_models import CorporateEntity

    test_org.name = "Other"
    test_org.easm_domain = "abirasecurity.com"
    _enable_identity_discovery(db_session, test_org)
    db_session.add(CorporateEntity(
        lei="Q1", legal_name="Abira Security Inc",
        org_id=test_org.id, category="parent",
    ))
    db_session.flush()

    src = _StaticSource(_result([_record("jane")]))
    run_identity_discovery(db_session, test_org.id, source=src)
    assert src.calls == [("Abira Security Inc", 25)]


def test_run_prefers_corporate_entity_legal_name(db_session, test_org):
    """Org display name is often abbreviated ('Acme'); the corporate
    entity's legal_name ('Acme Corporation') matches Wikidata better and
    therefore yields better LinkedIn results."""
    from models.threat_intel_models import CorporateEntity

    test_org.name = "Acme"
    _enable_identity_discovery(db_session, test_org)
    db_session.add(CorporateEntity(
        lei="Q1", legal_name="Acme Corporation",
        org_id=test_org.id, category="parent",
    ))
    db_session.flush()

    src = _StaticSource(_result([_record("jane")]))
    out = run_identity_discovery(db_session, test_org.id, source=src)
    assert src.calls == [("Acme Corporation", 25)]
    assert out["company_name"] == "Acme Corporation"


def test_run_propagates_no_signal(db_session, test_org):
    _enable_identity_discovery(db_session, test_org)
    src = _StaticSource(_no_signal())
    out = run_identity_discovery(db_session, test_org.id, source=src)
    assert out["status"] == "ok"
    assert out["no_signal"] is True
    assert out["created"] == 0
