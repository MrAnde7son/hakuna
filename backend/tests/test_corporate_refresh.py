"""Tests for the monthly corporate-profile refresh job."""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from models.threat_intel_models import CorporateEntity
from services.corporate_refresh import refresh_all_corporate_profiles


@pytest.fixture
def _stale_entity(db_session, test_org):
    """Link a corporate entity that's older than the refresh cooldown."""
    e = CorporateEntity(
        lei="Q1",
        legal_name="Acme Corp",
        org_id=test_org.id,
        updated_at=datetime.utcnow() - timedelta(days=30),
    )
    db_session.add(e)
    db_session.flush()
    return e


def test_refresh_calls_wikidata_for_stale_orgs(db_session, _stale_entity):
    with patch("threat_intel.wikidata_sync.sync_corporate_tree_to_db") as m:
        m.return_value = {"root": "Q1", "subsidiaries": 0}
        result = refresh_all_corporate_profiles(db_session)

    assert result["refreshed"] == 1
    assert result["skipped"] == 0
    assert m.called
    _args, kwargs = m.call_args
    assert kwargs["org_id"] == _stale_entity.org_id


def test_refresh_skips_recently_synced(db_session, test_org):
    # Updated yesterday — well within the 14-day cooldown.
    fresh = CorporateEntity(
        lei="Q2", legal_name="Beta Inc",
        org_id=test_org.id,
        updated_at=datetime.utcnow() - timedelta(days=1),
    )
    db_session.add(fresh)
    db_session.flush()

    with patch("threat_intel.wikidata_sync.sync_corporate_tree_to_db") as m:
        result = refresh_all_corporate_profiles(db_session)

    assert result["refreshed"] == 0
    assert result["skipped"] == 1
    assert not m.called


def test_refresh_uses_legal_name_not_org_name(db_session, _stale_entity, test_org):
    """Wikidata lookup should use the corporate entity's legal name when
    available — orgs sometimes have abbreviated display names that wouldn't
    match Wikidata labels."""
    test_org.name = "Acme"  # shorter than the entity legal_name
    db_session.flush()

    with patch("threat_intel.wikidata_sync.sync_corporate_tree_to_db") as m:
        m.return_value = {"root": "Q1", "subsidiaries": 0}
        refresh_all_corporate_profiles(db_session)

    args, _kwargs = m.call_args
    # company_name is the second positional arg
    assert args[1] == "Acme Corp"


def test_refresh_continues_after_one_org_fails(db_session, test_org):
    """A Wikidata timeout for one org must not stop the others from refreshing."""
    from models.models import Organization

    org2 = Organization(name="Second Org", slug="second-org")
    db_session.add(org2)
    db_session.flush()

    for org_id, lei in [(test_org.id, "Q1"), (org2.id, "Q2")]:
        db_session.add(CorporateEntity(
            lei=lei, legal_name=f"Co {lei}",
            org_id=org_id,
            updated_at=datetime.utcnow() - timedelta(days=30),
        ))
    db_session.flush()

    call_count = {"n": 0}
    def _flaky_sync(db, name, org_id=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("Wikidata timeout")
        return {"root": "Q2", "subsidiaries": 0}

    with patch("threat_intel.wikidata_sync.sync_corporate_tree_to_db", side_effect=_flaky_sync):
        result = refresh_all_corporate_profiles(db_session)

    assert result["refreshed"] == 1
    assert result["failed"] == 1


def test_refresh_propagates_industry_into_org_memory(db_session, test_org, _stale_entity):
    """After a successful refresh, org_memory must reflect the new industry —
    otherwise agents keep seeing the old value until the next onboarding event."""
    from services import org_memory
    from services.org_memory import ORG_PROFILE_NAMESPACE

    # Simulate Wikidata writing a fresh industry into the linked entity.
    def _fake_sync(db, name, org_id=None):
        ce = db_session.query(type(_stale_entity)).get(_stale_entity.id)
        ce.industry = "cybersecurity"
        ce.updated_at = datetime.utcnow()
        db.flush()
        return {"root": "Q1", "subsidiaries": 0}

    with patch(
        "threat_intel.wikidata_sync.sync_corporate_tree_to_db",
        side_effect=_fake_sync,
    ):
        result = refresh_all_corporate_profiles(db_session)

    assert result["refreshed"] == 1
    facts = {f["key"]: f for f in
             org_memory.recall(db_session, _stale_entity.org_id, ORG_PROFILE_NAMESPACE)}
    assert facts["industry"]["value"] == "cybersecurity"


def test_refresh_continues_when_org_memory_sync_fails(db_session, _stale_entity):
    """A failure in org_memory mirroring must not roll back the successful
    Wikidata write — the refresh should be considered successful."""
    def _fake_sync(db, name, org_id=None):
        return {"root": "Q1", "subsidiaries": 0}

    with patch(
        "threat_intel.wikidata_sync.sync_corporate_tree_to_db",
        side_effect=_fake_sync,
    ), patch(
        "services.org_memory.sync_org_profile_to_memory",
        side_effect=RuntimeError("memory layer down"),
    ):
        result = refresh_all_corporate_profiles(db_session)

    assert result["refreshed"] == 1
    assert result["failed"] == 0


def test_refresh_skips_inactive_orgs(db_session, test_org):
    test_org.is_active = False
    db_session.flush()
    db_session.add(CorporateEntity(
        lei="Q1", legal_name="Acme Corp", org_id=test_org.id,
        updated_at=datetime.utcnow() - timedelta(days=30),
    ))
    db_session.flush()

    with patch("threat_intel.wikidata_sync.sync_corporate_tree_to_db") as m:
        result = refresh_all_corporate_profiles(db_session)

    assert result["refreshed"] == 0
    assert not m.called
