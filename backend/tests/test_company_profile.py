"""Tests for ``services.company_profile.effective_company_profile`` and the
Wikidata sync helpers it depends on."""

from sqlalchemy.orm.attributes import flag_modified

from models.threat_intel_models import CorporateEntity
from services.company_profile import effective_company_profile
from threat_intel.wikidata_sync import _band_employee_count, _year_from_inception


def _link_corp_entity(db_session, org_id, **kwargs):
    entity = CorporateEntity(
        lei=kwargs.pop("lei", "Q12345"),
        legal_name=kwargs.pop("legal_name", "Acme Corp"),
        org_id=org_id,
        **kwargs,
    )
    db_session.add(entity)
    db_session.flush()
    return entity


def _set_onboarding_profile(db_session, org, profile):
    org.settings = (org.settings or {}) | {"onboarding": {"profile": profile}}
    flag_modified(org, "settings")
    db_session.flush()


def test_sparql_escape_handles_dangerous_characters():
    """Org names can contain ``"`` (e.g. ``Foo "Bar" Inc``); without
    escaping the SPARQL literal closes early and the rest of the query
    is interpreted as syntax. Backslash-first ordering matters."""
    from threat_intel.wikidata_sync import _sparql_escape_literal

    assert _sparql_escape_literal('Foo "Bar" Inc') == 'Foo \\"Bar\\" Inc'
    assert _sparql_escape_literal('back\\slash') == 'back\\\\slash'
    # Combined: backslash must be doubled FIRST, then quotes — otherwise
    # a double-escape produces ``\\\"`` which is parsed as backslash-quote.
    assert _sparql_escape_literal('\\"') == '\\\\\\"'
    assert _sparql_escape_literal("line\nbreak") == "line\\nbreak"
    assert _sparql_escape_literal(None) == ""


def test_band_employee_count_buckets():
    assert _band_employee_count("5") == "1-10"
    assert _band_employee_count("50") == "11-50"
    assert _band_employee_count("199") == "51-200"
    assert _band_employee_count("999") == "201-1000"
    assert _band_employee_count("5000") == "1k-10k"
    assert _band_employee_count("99999") == "10k+"


def test_band_employee_count_handles_garbage():
    assert _band_employee_count("") is None
    assert _band_employee_count("not-a-number") is None
    assert _band_employee_count("0") is None


def test_year_from_inception_iso():
    assert _year_from_inception("1995-01-01T00:00:00Z") == 1995
    assert _year_from_inception("") is None
    assert _year_from_inception("abc") is None


def test_effective_profile_falls_through_to_corporate_entity(db_session, test_org):
    _link_corp_entity(
        db_session, test_org.id,
        industry="cybersecurity",
        employee_count_band="1k-10k",
        founded_year=2002,
        homepage_url="https://acme.example",
    )
    profile = effective_company_profile(db_session, test_org.id)

    assert profile["industry"] == "cybersecurity"
    assert profile["org_size"] == "1k-10k"
    assert profile["founded_year"] == 2002
    assert profile["homepage_url"] == "https://acme.example"
    assert profile["_sources"]["industry"] == "corporate_entity"
    assert profile["_sources"]["org_size"] == "corporate_entity"


def test_onboarding_value_wins_over_corporate_entity(db_session, test_org):
    _link_corp_entity(
        db_session, test_org.id,
        industry="cybersecurity",
        employee_count_band="1k-10k",
    )
    _set_onboarding_profile(db_session, test_org, {
        "industry": "Healthcare",
        "org_size": "51-200",
    })

    profile = effective_company_profile(db_session, test_org.id)
    assert profile["industry"] == "Healthcare"
    assert profile["org_size"] == "51-200"
    assert profile["_sources"]["industry"] == "onboarding"
    assert profile["_sources"]["org_size"] == "onboarding"


def test_blank_onboarding_field_falls_through(db_session, test_org):
    """Empty string on onboarding side is treated as 'not provided' so the
    corporate-entity fallback can fill it. This is the auto-fill path."""
    _link_corp_entity(
        db_session, test_org.id,
        industry="cybersecurity",
        employee_count_band="1k-10k",
    )
    _set_onboarding_profile(db_session, test_org, {
        "industry": "Healthcare",
        "org_size": "",  # user skipped this question
    })

    profile = effective_company_profile(db_session, test_org.id)
    assert profile["industry"] == "Healthcare"
    assert profile["org_size"] == "1k-10k"
    assert profile["_sources"]["industry"] == "onboarding"
    assert profile["_sources"]["org_size"] == "corporate_entity"


def test_no_corp_entity_returns_onboarding_only(db_session, test_org):
    _set_onboarding_profile(db_session, test_org, {"industry": "Healthcare"})
    profile = effective_company_profile(db_session, test_org.id)
    assert profile["industry"] == "Healthcare"
    assert profile["org_size"] is None
    assert profile["_sources"]["org_size"] is None


def test_no_data_returns_all_none(db_session, test_org):
    profile = effective_company_profile(db_session, test_org.id)
    assert profile["industry"] is None
    assert profile["org_size"] is None
    assert profile["founded_year"] is None
    assert profile["homepage_url"] is None
    assert all(v is None for v in profile["_sources"].values())


def test_sync_to_memory_uses_corporate_entity_fallback(db_session, test_org):
    """When onboarding is incomplete, ``sync_org_profile_to_memory`` should
    still write industry/org_size from the linked CorporateEntity so agents
    see auto-filled values."""
    from services import org_memory
    from services.org_memory import ORG_PROFILE_NAMESPACE, sync_org_profile_to_memory

    _link_corp_entity(
        db_session, test_org.id,
        industry="cybersecurity",
        employee_count_band="1k-10k",
    )
    # No onboarding blob — operator skipped the wizard.
    written = sync_org_profile_to_memory(db_session, test_org.id)
    assert written == 2  # industry + org_size from corporate entity

    facts = {f["key"]: f for f in
             org_memory.recall(db_session, test_org.id, ORG_PROFILE_NAMESPACE)}
    assert facts["industry"]["value"] == "cybersecurity"
    assert facts["org_size"]["value"] == "1k-10k"
    # Auto-filled values get lower confidence than operator-typed ones.
    assert facts["industry"]["confidence"] == 0.6


def test_sync_to_memory_onboarding_wins(db_session, test_org):
    """Operator-typed industry must not be overwritten by a stale Wikidata
    value — verifies the precedence at the sync boundary, not just the helper."""
    from services import org_memory
    from services.org_memory import ORG_PROFILE_NAMESPACE, sync_org_profile_to_memory

    _link_corp_entity(db_session, test_org.id, industry="cybersecurity")
    _set_onboarding_profile(db_session, test_org, {"industry": "Healthcare"})

    sync_org_profile_to_memory(db_session, test_org.id)
    facts = {f["key"]: f for f in
             org_memory.recall(db_session, test_org.id, ORG_PROFILE_NAMESPACE)}
    assert facts["industry"]["value"] == "Healthcare"
    assert facts["industry"]["confidence"] == 0.95


def test_parent_corp_entity_preferred_over_subsidiary(db_session, test_org):
    """When multiple corporate entities link to one org (parent + subsidiaries),
    the parent's profile should win since it represents the org's identity."""
    _link_corp_entity(
        db_session, test_org.id,
        lei="Q-SUB", legal_name="Sub Co", category="subsidiary",
        industry="logistics",
    )
    _link_corp_entity(
        db_session, test_org.id,
        lei="Q-PARENT", legal_name="Parent Co", category="parent",
        industry="finance",
    )
    profile = effective_company_profile(db_session, test_org.id)
    assert profile["industry"] == "finance"
