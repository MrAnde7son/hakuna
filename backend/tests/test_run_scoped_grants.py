"""Tests for run-scoped bulk-approval grants.

Covers the auto-approval grant registered when an approval decision is
made with ``grant_scope='run'``:

* :func:`record_approval_decision` writes the tool name into
  ``AgentRun.auto_approved_tools``.
* :func:`_is_auto_approved_for_run` then short-circuits future gates.
* ``_maybe_inject_auto_approval`` injects ``_approved=True`` so the
  tool body's per-call NeedsApproval classifier is bypassed too.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from agents.agent_engine import (
    _is_auto_approved_for_run,
    _maybe_inject_auto_approval,
    record_approval_decision,
)
from models.models import Agent, AgentApproval, AgentRun


def _mk_paused_run(db, *, org_id, tool="ldap_modify"):
    agent = Agent(
        org_id=org_id, name="scratch", system_prompt="x",
        tools=[tool], guardrails={"approval_mode": "hitl"},
        model="claude-sonnet-4-6",
    )
    db.add(agent)
    db.flush()
    run = AgentRun(
        agent_id=agent.id, input="audit", status="awaiting_approval",
        auto_approved_tools=[],
    )
    db.add(run)
    db.flush()
    approval = AgentApproval(
        org_id=org_id, agent_run_id=run.id, agent_id=agent.id,
        tool_name=tool, tool_input={"asset_id": 1},
        provider="anthropic", model_name="claude-sonnet-4-6",
        current_step=1, tool_use_id="tu_1", status="pending",
        requested_at=datetime.utcnow(),
    )
    db.add(approval)
    db.commit()
    return agent, run, approval


def test_grant_scope_run_persists_tool_on_run(db_session, test_org):
    _, run, _ = _mk_paused_run(db_session, org_id=test_org.id)
    run_id = run.id

    record_approval_decision(
        run_id=run_id, decision="approved", reason=None,
        decider_id=None, db=db_session, grant_scope="run",
    )

    db_session.expire_all()
    refreshed = db_session.query(AgentRun).filter_by(id=run_id).first()
    assert refreshed.auto_approved_tools == ["ldap_modify"]
    assert refreshed.status == "running"


def test_grant_scope_omitted_does_not_create_grant(db_session, test_org):
    _, run, _ = _mk_paused_run(db_session, org_id=test_org.id)
    run_id = run.id

    record_approval_decision(
        run_id=run_id, decision="approved", reason=None,
        decider_id=None, db=db_session,
    )

    db_session.expire_all()
    refreshed = db_session.query(AgentRun).filter_by(id=run_id).first()
    assert refreshed.auto_approved_tools in (None, [])


def test_grant_scope_ignored_on_rejection(db_session, test_org):
    _, run, _ = _mk_paused_run(db_session, org_id=test_org.id)
    run_id = run.id

    record_approval_decision(
        run_id=run_id, decision="rejected", reason="nope",
        decider_id=None, db=db_session, grant_scope="run",
    )

    db_session.expire_all()
    refreshed = db_session.query(AgentRun).filter_by(id=run_id).first()
    assert refreshed.auto_approved_tools in (None, [])


def test_is_auto_approved_for_run_matches_granted_tool():
    run = AgentRun(auto_approved_tools=["nmap_scan", "smb_enum"])
    assert _is_auto_approved_for_run(run, "nmap_scan") is True
    assert _is_auto_approved_for_run(run, "smb_enum") is True
    assert _is_auto_approved_for_run(run, "ldap_modify") is False


def test_is_auto_approved_handles_missing_run_or_field():
    assert _is_auto_approved_for_run(None, "anything") is False
    assert _is_auto_approved_for_run(AgentRun(auto_approved_tools=None), "x") is False
    assert _is_auto_approved_for_run(AgentRun(auto_approved_tools=[]), "x") is False


def test_maybe_inject_auto_approval_adds_flag_when_granted():
    run = AgentRun(auto_approved_tools=["smb_write"])
    out = _maybe_inject_auto_approval(run, "smb_write", {"path": "/x"})
    assert out == {"path": "/x", "_approved": True}


def test_maybe_inject_auto_approval_passthrough_when_not_granted():
    run = AgentRun(auto_approved_tools=["smb_write"])
    out = _maybe_inject_auto_approval(run, "ssh_command", {"cmd": "ls"})
    assert out == {"cmd": "ls"}
    assert "_approved" not in out


def test_maybe_inject_auto_approval_does_not_mutate_input():
    run = AgentRun(auto_approved_tools=["smb_write"])
    original = {"path": "/x"}
    _maybe_inject_auto_approval(run, "smb_write", original)
    assert "_approved" not in original
