"""Tests for the identity-discovery foundation: canonicalization,
the consent envelope check, and the DDGS-backed LinkedIn source.

This slice deliberately stops short of asset upsert / lifecycle — those
land in the next slice once the foundation is reviewed.
"""

from datetime import datetime, timedelta

import pytest

from models.models import DataProcessingConsent
from services.identity_discovery import (
    DdgLinkedInSource,
    IDENTITY_DISCOVERY_PURPOSE,
    canonicalize_linkedin_slug,
    extract_linkedin_slug,
    is_identity_discovery_permitted,
)
from services.identity_discovery.ddg_linkedin import _parse_title


# ── Canonicalization ────────────────────────────────────────────────


@pytest.mark.parametrize("value,expected", [
    ("https://www.linkedin.com/in/jane-doe-12345/", "jane-doe-12345"),
    ("http://linkedin.com/in/Jane-Doe-12345", "jane-doe-12345"),
    ("linkedin.com/in/jane-doe-12345?trk=public_profile", "jane-doe-12345"),
    ("https://il.linkedin.com/in/jane-doe-12345/", "jane-doe-12345"),
    ("https://www.linkedin.com/in/jos%C3%A9-perez/", "josé-perez"),
    ("/in/jane-doe-12345", "jane-doe-12345"),
    # Casing in the slug must be normalized — LinkedIn URLs are case-
    # insensitive in practice and treating them as distinct identities
    # produces duplicates.
    ("https://www.linkedin.com/in/JANE-DOE/", "jane-doe"),
])
def test_canonicalize_resolves_url_variants_to_same_slug(value, expected):
    assert canonicalize_linkedin_slug(value) == expected


@pytest.mark.parametrize("value", [
    None,
    "",
    "   ",
    "https://example.com/in/jane-doe",        # not LinkedIn
    "https://www.linkedin.com/company/acme/",  # company page, not /in/
    "https://www.linkedin.com/",
    "jane-doe",                                # bare slug, not a URL
])
def test_canonicalize_rejects_invalid_inputs(value):
    assert canonicalize_linkedin_slug(value) is None


def test_extract_slug_keeps_original_casing():
    """``extract`` is for "did we find a slug" — casing decisions belong
    to ``canonicalize``."""
    assert extract_linkedin_slug("https://linkedin.com/in/JANE-DOE/") == "JANE-DOE"


# ── Title parsing ───────────────────────────────────────────────────


@pytest.mark.parametrize("title,expected", [
    ("Jane Doe - Director of Engineering - LinkedIn",
     ("Jane Doe", "Director of Engineering")),
    ("Jane Doe – Director of Engineering – LinkedIn",
     ("Jane Doe", "Director of Engineering")),
    ("Jane Doe | LinkedIn", ("Jane Doe", None)),
    ("Jane Doe - Director of Eng - Acme - LinkedIn",
     # First " - " splits name from the rest; the rest becomes title.
     ("Jane Doe", "Director of Eng - Acme")),
    ("", (None, None)),
    (None, (None, None)),
])
def test_parse_title_extracts_name_and_title(title, expected):
    assert _parse_title(title) == expected


# ── DdgLinkedInSource ───────────────────────────────────────────────


class _FakeDDGS:
    """A drop-in DDGS replacement for tests — must be usable as a context
    manager. Configure via class attributes per test."""

    next_results: list[dict] | None = None
    raise_exc: Exception | None = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def text(self, query, max_results=None):
        if self.raise_exc:
            raise self.raise_exc
        return list(self.next_results or [])


def _make_source(results=None, exc=None):
    fake = _FakeDDGS()
    fake.next_results = results
    fake.raise_exc = exc
    return DdgLinkedInSource(ddgs_factory=lambda: fake)


def test_source_returns_records_on_success():
    src = _make_source(results=[
        {"title": "Jane Doe - Director of Eng - LinkedIn",
         "href": "https://www.linkedin.com/in/jane-doe/"},
        {"title": "John Roe – CTO – LinkedIn",
         "href": "https://linkedin.com/in/John-Roe"},
    ])
    result = src.discover("Acme")
    assert result.records is not None
    assert len(result.records) == 2
    assert result.records[0].slug == "jane-doe"
    assert result.records[0].display_name == "Jane Doe"
    assert result.records[0].title == "Director of Eng"
    assert result.records[1].slug == "john-roe"


def test_source_dedupes_by_canonical_slug():
    """Two SERP entries pointing at the same person via different URL
    shapes must collapse to one record — otherwise downstream upsert
    sees duplicates within a single run."""
    src = _make_source(results=[
        {"title": "Jane Doe - LinkedIn",
         "href": "https://www.linkedin.com/in/jane-doe/"},
        {"title": "Jane Doe - LinkedIn",
         "href": "https://il.linkedin.com/in/Jane-Doe?trk=foo"},
    ])
    result = src.discover("Acme")
    assert result.records is not None
    assert len(result.records) == 1


def test_empty_result_is_no_signal_not_empty_list():
    """Critical invariant: DDGS returning nothing must NOT be treated as
    'company has no employees'. This is the safeguard against silent
    pruning when DDGS soft-blocks us."""
    src = _make_source(results=[])
    result = src.discover("Acme")
    assert result.records is None
    assert result.is_no_signal
    assert result.metadata == {"empty": True}


def test_transport_error_is_no_signal():
    src = _make_source(exc=RuntimeError("rate limited"))
    result = src.discover("Acme")
    assert result.records is None
    assert result.is_no_signal
    assert result.error == "rate limited"


def test_unparseable_results_are_no_signal():
    """If DDGS reformulates our query server-side and returns hits that
    aren't LinkedIn profile URLs, we treat the run as no-signal — better
    to be silent than to skip pruning on noise."""
    src = _make_source(results=[
        {"title": "Acme - LinkedIn", "href": "https://www.linkedin.com/company/acme/"},
        {"title": "Acme blog", "href": "https://acme.example/blog"},
    ])
    result = src.discover("Acme")
    assert result.records is None
    assert result.is_no_signal


def test_empty_company_name_is_no_signal():
    src = _make_source(results=[{"title": "x", "href": "https://linkedin.com/in/x"}])
    assert src.discover("").is_no_signal
    assert src.discover("   ").is_no_signal


# ── Consent envelope ────────────────────────────────────────────────


def _grant_consent(db_session, org_id, *, expires_in_days=365, revoked=False):
    consent = DataProcessingConsent(
        org_id=org_id,
        purpose=IDENTITY_DISCOVERY_PURPOSE,
        granted_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=expires_in_days),
        revoked_at=datetime.utcnow() if revoked else None,
        acknowledgment_text="I acknowledge GDPR/LinkedIn ToS for identity discovery.",
    )
    db_session.add(consent)
    db_session.flush()
    return consent


def test_consent_blocks_when_flag_off(db_session, test_org):
    _grant_consent(db_session, test_org.id)
    # Flag still False (default).
    assert not is_identity_discovery_permitted(db_session, test_org.id)


def test_consent_blocks_when_no_consent_row(db_session, test_org):
    test_org.identity_discovery_enabled = True
    db_session.flush()
    assert not is_identity_discovery_permitted(db_session, test_org.id)


def test_consent_permits_when_flag_and_active_consent_both_present(db_session, test_org):
    test_org.identity_discovery_enabled = True
    _grant_consent(db_session, test_org.id)
    db_session.flush()
    assert is_identity_discovery_permitted(db_session, test_org.id)


def test_consent_blocks_when_consent_revoked(db_session, test_org):
    test_org.identity_discovery_enabled = True
    _grant_consent(db_session, test_org.id, revoked=True)
    db_session.flush()
    assert not is_identity_discovery_permitted(db_session, test_org.id)


def test_consent_blocks_when_consent_expired(db_session, test_org):
    test_org.identity_discovery_enabled = True
    _grant_consent(db_session, test_org.id, expires_in_days=-1)
    db_session.flush()
    assert not is_identity_discovery_permitted(db_session, test_org.id)


def test_consent_blocks_when_org_inactive(db_session, test_org):
    """An inactive org should fail the gate even when flag + consent are
    intact — protects the on-demand ``POST /run`` endpoint from doing
    personal-data processing for a suspended/closed tenant."""
    test_org.identity_discovery_enabled = True
    test_org.is_active = False
    _grant_consent(db_session, test_org.id)
    db_session.flush()
    assert not is_identity_discovery_permitted(db_session, test_org.id)


def test_consent_uses_most_recent_active_when_multiple_exist(db_session, test_org):
    """When admins grant fresh consent after one expires, the active row
    must take precedence — not the latest by id, but the latest active
    granted_at. Order_by granted_at DESC handles this."""
    test_org.identity_discovery_enabled = True
    # Older revoked.
    _grant_consent(db_session, test_org.id, revoked=True)
    # Newer active.
    _grant_consent(db_session, test_org.id)
    db_session.flush()
    # The query filters revoked_at IS NULL, so only the active one is
    # considered — guarantees permitted even though a revoked row also exists.
    assert is_identity_discovery_permitted(db_session, test_org.id)
