"""Tests for `sync_org_profile_to_memory` and the agent-prompt integration."""
from sqlalchemy.orm.attributes import flag_modified

from services import org_memory
from services.org_memory import (
    ORG_PROFILE_NAMESPACE,
    sync_org_profile_to_memory,
)


def _set_onboarding(db_session, org, blob):
    org.settings = (org.settings or {}) | {"onboarding": blob}
    flag_modified(org, "settings")
    db_session.flush()


def _profile_blob():
    return {
        "completed": True,
        "profile": {
            "industry": "Healthcare",
            "org_size": "201-1000",
            "team_size": "6-15",
            "team_functions": ["AppSec", "GRC"],
        },
        "objectives": ["reduce_critical_findings", "compliance_pci"],
    }


def test_sync_writes_expected_keys(db_session, test_org):
    _set_onboarding(db_session, test_org, _profile_blob())
    written = sync_org_profile_to_memory(db_session, test_org.id)
    assert written == 5

    facts = {f["key"]: f["value"] for f in
             org_memory.recall(db_session, test_org.id, ORG_PROFILE_NAMESPACE)}
    assert facts["industry"] == "Healthcare"
    assert facts["org_size"] == "201-1000"
    assert facts["team_size"] == "6-15"
    assert facts["team_functions"] == ["AppSec", "GRC"]
    assert facts["objectives"] == ["reduce_critical_findings", "compliance_pci"]


def test_sync_idempotent_unchanged_values_skipped(db_session, test_org):
    _set_onboarding(db_session, test_org, _profile_blob())
    first = sync_org_profile_to_memory(db_session, test_org.id)
    assert first == 5
    second = sync_org_profile_to_memory(db_session, test_org.id)
    assert second == 0  # nothing changed


def test_sync_supersedes_changed_value(db_session, test_org):
    _set_onboarding(db_session, test_org, _profile_blob())
    sync_org_profile_to_memory(db_session, test_org.id)

    blob = _profile_blob()
    blob["profile"]["industry"] = "Financial Services"
    _set_onboarding(db_session, test_org, blob)
    written = sync_org_profile_to_memory(db_session, test_org.id)
    assert written == 1

    actives = org_memory.recall(db_session, test_org.id, ORG_PROFILE_NAMESPACE, key="industry")
    assert len(actives) == 1
    assert actives[0]["value"] == "Financial Services"

    chain = org_memory.history(db_session, test_org.id, ORG_PROFILE_NAMESPACE, "industry")
    assert [c["value"] for c in chain] == ["Healthcare", "Financial Services"]


def test_sync_noop_when_no_onboarding(db_session, test_org):
    # No onboarding blob set → nothing to mirror
    assert sync_org_profile_to_memory(db_session, test_org.id) == 0
    assert org_memory.recall(db_session, test_org.id, ORG_PROFILE_NAMESPACE) == []


def test_sync_skips_empty_fields(db_session, test_org):
    _set_onboarding(db_session, test_org, {
        "completed": True,
        "profile": {"industry": "Healthcare", "org_size": "", "team_functions": []},
        "objectives": [],
    })
    written = sync_org_profile_to_memory(db_session, test_org.id)
    # Only `industry` is non-empty
    assert written == 1
    keys = [f["key"] for f in org_memory.recall(db_session, test_org.id, ORG_PROFILE_NAMESPACE)]
    assert keys == ["industry"]


def _patch_session_local(monkeypatch, db_session):
    """`build_context_section` opens its own `SessionLocal()` for read isolation —
    in tests that has to point at the in-memory engine, not the prod one."""
    import core.database as core_db
    import agents.agent_context as ac

    class _StubSession:
        def __init__(self, real):
            self._real = real
        def __getattr__(self, name):
            return getattr(self._real, name)
        def close(self):
            pass  # the real session is owned by the fixture

    factory = lambda: _StubSession(db_session)
    monkeypatch.setattr(core_db, "SessionLocal", factory)
    monkeypatch.setattr(ac, "SessionLocal" if hasattr(ac, "SessionLocal") else "SessionLocal",
                        factory, raising=False)


def test_agent_prompt_includes_org_profile(db_session, test_org, monkeypatch):
    """End-to-end: facts mirrored from onboarding land in an agent's system prompt."""
    from models.models import Agent
    from agents.agent_engine import _build_system_prompt

    _patch_session_local(monkeypatch, db_session)
    _set_onboarding(db_session, test_org, _profile_blob())
    sync_org_profile_to_memory(db_session, test_org.id)
    db_session.flush()

    agent = Agent(
        org_id=test_org.id,
        name="Test Agent",
        system_prompt="You triage findings.",
        tools=[],
        guardrails={},
    )
    db_session.add(agent)
    db_session.flush()

    prompt = _build_system_prompt(agent)
    assert "## Org Memory" in prompt
    assert "Healthcare" in prompt
    assert "AppSec" in prompt


def test_agent_can_opt_out_via_guardrails(db_session, test_org, monkeypatch):
    from models.models import Agent
    from agents.agent_engine import _build_system_prompt

    _patch_session_local(monkeypatch, db_session)
    _set_onboarding(db_session, test_org, _profile_blob())
    sync_org_profile_to_memory(db_session, test_org.id)
    db_session.flush()

    agent = Agent(
        org_id=test_org.id,
        name="Opted-out Agent",
        system_prompt="…",
        tools=[],
        guardrails={"org_memory_namespaces": []},
    )
    db_session.add(agent)
    db_session.flush()

    prompt = _build_system_prompt(agent)
    assert "## Org Memory" not in prompt
