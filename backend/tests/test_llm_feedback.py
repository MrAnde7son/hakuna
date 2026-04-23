"""Unit tests for the LLM feedback-loop logger and outcome linker."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import sessionmaker


@pytest.fixture(autouse=True)
def _clean_llm_feedback_tables(engine):
    """The logger commits via its own SessionLocal outside the db_session
    transaction, so we must scrub rows ourselves between tests. Scoped to
    this file only."""
    yield
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        from models.models import (
            LLMInteraction, LLMInteractionOutcome,
            AgentRun, Agent, Organization,
        )
        db.query(LLMInteractionOutcome).delete()
        db.query(LLMInteraction).delete()
        db.query(AgentRun).delete()
        db.query(Agent).delete()
        db.query(Organization).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


@pytest.fixture
def unique_org(engine):
    """Independent org created directly on the shared in-memory engine so
    it's visible to both db_session and the logger's SessionLocal."""
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        from models.models import Organization
        slug = f"org-{uuid.uuid4().hex[:8]}"
        org = Organization(name=f"Test {slug}", slug=slug)
        db.add(org)
        db.commit()
        db.refresh(org)
        return org
    finally:
        db.close()


# ── Redaction ─────────────────────────────────────────────────────────

def test_redact_strips_openai_key():
    from services.llm_feedback import redact

    text = "my key is sk-abcdefghijklmnopqrstuvwxyz1234567890 do not leak"
    out, did = redact(text)
    assert did is True
    assert "sk-abcdefghij" not in out
    assert "REDACTED" in out


def test_redact_strips_password_assignment():
    from services.llm_feedback import redact

    out, did = redact('login with password=supersecret123 and token=abc')
    assert did is True
    assert "supersecret123" not in out
    assert "abc" not in out or "token=[REDACTED]" in out


def test_redact_strips_jwt():
    from services.llm_feedback import redact

    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    out, did = redact(f"Authorization: {jwt}")
    assert did is True
    assert jwt not in out


def test_redact_is_idempotent():
    from services.llm_feedback import redact

    text = "password=foo"
    once, _ = redact(text)
    twice, _ = redact(once)
    assert once == twice


def test_redact_leaves_benign_text_alone():
    from services.llm_feedback import redact

    text = "Investigating finding 123 on host webapp-01"
    out, did = redact(text)
    assert did is False
    assert out == text


# ── Span state ────────────────────────────────────────────────────────

def _install_test_session_local(monkeypatch, engine):
    """Point services.llm_feedback.SessionLocal at the test engine so
    _flush() writes to the in-memory test DB instead of the file DB."""
    TestSession = sessionmaker(bind=engine, expire_on_commit=False)
    import services.llm_feedback as lf
    monkeypatch.setattr(lf, "SessionLocal", TestSession)


def test_span_writes_interaction_row(monkeypatch, engine, unique_org):
    from services import llm_feedback
    from models.models import LLMInteraction

    _install_test_session_local(monkeypatch, engine)

    with llm_feedback.span(
        surface="unit_test",
        org_id=unique_org.id,
        provider="anthropic",
        model="claude-test",
        system_prompt="You are a helpful agent.",
        messages=[{"role": "user", "content": "hello"}],
    ):
        llm_feedback.record_response("hi there", input_tokens=10, output_tokens=5)

    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        row = db.query(LLMInteraction).filter(LLMInteraction.surface == "unit_test").first()
        assert row is not None
        assert row.org_id == unique_org.id
        assert row.model == "claude-test"
        assert row.response_text == "hi there"
        assert row.input_tokens == 10
        assert row.output_tokens == 5
        assert row.status == "ok"
        assert row.latency_ms is not None and row.latency_ms >= 0
    finally:
        db.close()


def test_span_accumulates_tokens_across_steps(monkeypatch, engine, unique_org):
    from services import llm_feedback
    from models.models import LLMInteraction

    _install_test_session_local(monkeypatch, engine)

    with llm_feedback.span(
        surface="unit_test_tokens",
        org_id=unique_org.id,
    ):
        llm_feedback.record_response(None, input_tokens=100, output_tokens=50)
        llm_feedback.record_response(None, input_tokens=80, output_tokens=40)
        llm_feedback.record_response("final answer", input_tokens=60, output_tokens=30)

    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        row = db.query(LLMInteraction).filter(LLMInteraction.surface == "unit_test_tokens").first()
        assert row.input_tokens == 240
        assert row.output_tokens == 120
        assert row.response_text == "final answer"
    finally:
        db.close()


def test_span_records_tool_calls(monkeypatch, engine, unique_org):
    from services import llm_feedback
    from models.models import LLMInteraction

    _install_test_session_local(monkeypatch, engine)

    with llm_feedback.span(surface="unit_test_tools", org_id=unique_org.id):
        llm_feedback.record_tool_call(
            name="lookup_asset",
            args={"asset_id": 42},
            result={"hostname": "webapp-01"},
            ok=True,
            duration_ms=120,
        )
        llm_feedback.record_tool_call(
            name="risky_tool",
            args={"password": "leaked"},
            result={"error": "denied"},
            ok=False,
            duration_ms=5,
        )

    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        row = db.query(LLMInteraction).filter(LLMInteraction.surface == "unit_test_tools").first()
        assert len(row.tool_calls) == 2
        assert row.tool_calls[0]["name"] == "lookup_asset"
        assert row.tool_calls[0]["ok"] is True
        assert row.tool_calls[1]["ok"] is False
        # Redaction should have stripped the password from args.
        # The pattern "password=..." matches a string form. For key/value
        # dicts we rely on the serialized JSON regex catching it.
        assert "leaked" not in str(row.tool_calls[1]["args"])
    finally:
        db.close()


def test_span_is_nested_safely(monkeypatch, engine, unique_org):
    """Opening a span inside another span should merge, not double-log."""
    from services import llm_feedback
    from models.models import LLMInteraction

    _install_test_session_local(monkeypatch, engine)

    with llm_feedback.span(surface="outer_surface", org_id=unique_org.id):
        llm_feedback.record_response(None, input_tokens=10, output_tokens=5)
        # Inner span simulates a services.llm_provider.call_llm() issued
        # from within an agent tool — should attach to the outer span.
        with llm_feedback.span(surface="inner_should_merge", org_id=unique_org.id):
            llm_feedback.record_response(None, input_tokens=7, output_tokens=3)

    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        rows = db.query(LLMInteraction).filter(
            LLMInteraction.surface.in_(["outer_surface", "inner_should_merge"])
        ).all()
        # Only the outer span should produce a row.
        assert len(rows) == 1
        assert rows[0].surface == "outer_surface"
        assert rows[0].input_tokens == 17
        assert rows[0].output_tokens == 8
    finally:
        db.close()


def test_span_disabled_when_org_id_none(monkeypatch, engine):
    from services import llm_feedback
    from models.models import LLMInteraction

    _install_test_session_local(monkeypatch, engine)

    with llm_feedback.span(surface="no_org", org_id=None):
        llm_feedback.record_response("whatever", input_tokens=1, output_tokens=1)

    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        count = db.query(LLMInteraction).filter(LLMInteraction.surface == "no_org").count()
        assert count == 0
    finally:
        db.close()


def test_span_captures_error(monkeypatch, engine, unique_org):
    from services import llm_feedback
    from models.models import LLMInteraction

    _install_test_session_local(monkeypatch, engine)

    with pytest.raises(RuntimeError):
        with llm_feedback.span(surface="failing", org_id=unique_org.id):
            raise RuntimeError("provider exploded")

    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        row = db.query(LLMInteraction).filter(LLMInteraction.surface == "failing").first()
        assert row is not None
        assert row.status == "error"
        assert "provider exploded" in (row.error or "")
    finally:
        db.close()


# ── Outcome linker ────────────────────────────────────────────────────

def test_linker_scores_agent_run(monkeypatch, engine, unique_org):
    from services import llm_feedback, llm_outcome_linker
    from models.models import Agent, AgentRun, LLMInteraction, LLMInteractionOutcome

    _install_test_session_local(monkeypatch, engine)
    monkeypatch.setattr(llm_outcome_linker, "SessionLocal", llm_feedback.SessionLocal)

    # Seed: agent + completed run.
    Session = llm_feedback.SessionLocal
    db = Session()
    try:
        agent = Agent(org_id=unique_org.id, name="t-agent", system_prompt="sp")
        db.add(agent); db.flush()
        run = AgentRun(agent_id=agent.id, input="x", status="done", output="did it")
        db.add(run); db.flush()
        db.commit()
        agent_id = agent.id
        run_id = run.id
    finally:
        db.close()

    # Log an interaction tied to that run.
    with llm_feedback.span(
        surface="agent",
        org_id=unique_org.id,
        agent_id=agent_id,
        agent_run_id=run_id,
    ):
        llm_feedback.record_response("did it")

    linked = llm_outcome_linker.run_linker()
    assert linked >= 1

    db = Session()
    try:
        outcome = (
            db.query(LLMInteractionOutcome)
              .join(LLMInteraction, LLMInteraction.id == LLMInteractionOutcome.interaction_id)
              .filter(LLMInteraction.agent_run_id == run_id)
              .first()
        )
        assert outcome is not None
        assert outcome.outcome_score is not None
        assert outcome.outcome_score > 0  # 'done' is a positive signal
    finally:
        db.close()


def test_linker_scores_failed_run_negative(monkeypatch, engine, unique_org):
    from services import llm_feedback, llm_outcome_linker
    from models.models import Agent, AgentRun, LLMInteraction, LLMInteractionOutcome

    _install_test_session_local(monkeypatch, engine)
    monkeypatch.setattr(llm_outcome_linker, "SessionLocal", llm_feedback.SessionLocal)

    Session = llm_feedback.SessionLocal
    db = Session()
    try:
        agent = Agent(org_id=unique_org.id, name="t-agent-fail", system_prompt="sp")
        db.add(agent); db.flush()
        run = AgentRun(agent_id=agent.id, input="x", status="failed", error="boom")
        db.add(run); db.flush()
        db.commit()
        run_id = run.id
    finally:
        db.close()

    with llm_feedback.span(
        surface="agent",
        org_id=unique_org.id,
        agent_run_id=run_id,
    ):
        llm_feedback.record_response(None)

    llm_outcome_linker.run_linker()

    db = Session()
    try:
        outcome = (
            db.query(LLMInteractionOutcome)
              .join(LLMInteraction, LLMInteraction.id == LLMInteractionOutcome.interaction_id)
              .filter(LLMInteraction.agent_run_id == run_id)
              .first()
        )
        assert outcome is not None
        assert outcome.outcome_score < 0
    finally:
        db.close()


def test_retrieve_exemplars_returns_empty_when_unavailable(unique_org):
    """Retrieval needs pgvector + an embeddings key. Without either it no-ops.

    The test fixture runs on in-memory sqlite and has no OpenAI key, so this
    covers both degraded paths.
    """
    from services.llm_feedback import retrieve_exemplars

    out = retrieve_exemplars(
        org_id=unique_org.id,
        surface="agent",
        query_text="what about this finding?",
        k=5,
    )
    assert out == []
