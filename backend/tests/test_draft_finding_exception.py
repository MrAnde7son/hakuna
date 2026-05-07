"""Tests for the ``draft_finding_exception`` tool + the activation
wiring that creates the FindingException on approve.

Mirrors the draft_campaign / draft_owner_notification shape:
  1. Tool body validates inputs, scopes by plugin_id + asset_ip, creates
     a paired AgentApproval(source='agent_draft',
     tool_name='create_finding_exception').
  2. Approve → _create_finding_exception inserts a real FindingException
     stamped with the approving user's email.
  3. Reject → no-op.
"""
from __future__ import annotations

import pytest

from agents.agent_tools import TOOL_REGISTRY
from models.models import (
    Agent, AgentApproval, Asset, Finding, FindingException, Scan,
)


def _draft(db, *, org_id, agent_id=None, **params):
    fn = TOOL_REGISTRY["draft_finding_exception"]["fn"]
    return fn(db, {"_org_id": org_id, "_agent_id": agent_id, **params})


@pytest.fixture
def scan(db_session, test_org):
    s = Scan(org_id=test_org.id, filename="t", status="completed")
    db_session.add(s)
    db_session.flush()
    return s


@pytest.fixture
def asset(db_session, scan):
    a = Asset(scan_id=scan.id, hostname="prod-web", asset_type="host", ip="10.0.0.5")
    db_session.add(a)
    db_session.flush()
    return a


def _mk_finding(db_session, scan, asset, *, plugin_id="42"):
    f = Finding(
        scan_id=scan.id, asset_id=asset.id, plugin_id=plugin_id,
        plugin_name="Outdated nginx", severity=3, severity_label="High",
    )
    db_session.add(f)
    db_session.flush()
    return f


# ── Tool body ──────────────────────────────────────────────────────


def test_draft_creates_approval_with_scope_fields(db_session, test_org, scan, asset):
    """Plugin_id + asset_ip captured at draft time so the activation
    handler doesn't need to re-resolve them later (defends against the
    finding being deleted/edited between draft and approval)."""
    f = _mk_finding(db_session, scan, asset, plugin_id="42")
    out = _draft(
        db_session, org_id=test_org.id, finding_id=f.id,
        exception_type="false_positive",
        reason="Banner shows nginx 1.25.4 (patched). Plugin matches on a header that changed format.",
    )
    assert out["approval_id"]
    assert out["scope"]["plugin_id"] == "42"
    assert out["scope"]["asset_ip"] == "10.0.0.5"

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    assert approval.source == "agent_draft"
    assert approval.tool_name == "create_finding_exception"
    ti = approval.tool_input
    assert ti["plugin_id"] == "42"
    assert ti["asset_ip"] == "10.0.0.5"
    assert ti["exception_type"] == "false_positive"
    assert ti["reason"].startswith("Banner shows")


def test_draft_rejects_invalid_exception_type(db_session, test_org, scan, asset):
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id, finding_id=f.id,
        exception_type="bogus", reason="x",
    )
    assert "error" in out


def test_draft_rejects_accepted_risk_without_expiry(db_session, test_org, scan, asset):
    """Accepted-risk exceptions must have an expiry — don't accept risk
    forever. False-positive and compensating-control don't need one."""
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id, finding_id=f.id,
        exception_type="accepted_risk", reason="x",
    )
    assert "error" in out
    assert "expires_at" in out["error"]


def test_draft_rejects_invalid_date_format(db_session, test_org, scan, asset):
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id, finding_id=f.id,
        exception_type="accepted_risk", reason="x", expires_at="next tuesday",
    )
    assert "error" in out


def test_draft_rejects_finding_from_other_org(db_session, test_org, scan, asset):
    """Cross-tenant guard."""
    from models.models import Organization
    other = Organization(name="Other", slug="other-fe")
    db_session.add(other)
    db_session.flush()
    other_scan = Scan(org_id=other.id, filename="t", status="completed")
    db_session.add(other_scan)
    db_session.flush()
    other_asset = Asset(scan_id=other_scan.id, hostname="x", asset_type="host", ip="1.2.3.4")
    db_session.add(other_asset)
    db_session.flush()
    foreign = _mk_finding(db_session, other_scan, other_asset, plugin_id="999")

    out = _draft(
        db_session, org_id=test_org.id, finding_id=foreign.id,
        exception_type="false_positive", reason="x",
    )
    assert "error" in out


# ── Approve → exception creation ───────────────────────────────────


def test_approve_creates_finding_exception(db_session, authed_client, test_org, scan, asset, test_user):
    f = _mk_finding(db_session, scan, asset, plugin_id="100")
    out = _draft(
        db_session, org_id=test_org.id, finding_id=f.id,
        exception_type="false_positive",
        reason="Plugin matches a stale header pattern; banner confirms patched build.",
    )

    resp = authed_client.post(
        f"/api/agents/approvals/{out['approval_id']}/decide",
        json={"decision": "approved"},
    )
    assert resp.status_code == 200, resp.text

    exc = (
        db_session.query(FindingException)
        .filter(
            FindingException.org_id == test_org.id,
            FindingException.plugin_id == "100",
            FindingException.asset_ip == "10.0.0.5",
        )
        .first()
    )
    assert exc is not None
    assert exc.exception_type == "false_positive"
    assert exc.is_active is True
    assert exc.approved_by == test_user.email
    assert exc.expires_at is None  # no expiry set for FP

    # Approval got stamped with the created exception id for audit.
    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    db_session.refresh(approval)
    assert approval.tool_input.get("created_exception_id") == exc.id


def test_approve_accepted_risk_with_expiry(db_session, authed_client, test_org, scan, asset):
    f = _mk_finding(db_session, scan, asset, plugin_id="200")
    out = _draft(
        db_session, org_id=test_org.id, finding_id=f.id,
        exception_type="accepted_risk", reason="Vendor patch ETA Q2.",
        expires_at="2026-06-30",
    )

    resp = authed_client.post(
        f"/api/agents/approvals/{out['approval_id']}/decide",
        json={"decision": "approved"},
    )
    assert resp.status_code == 200

    exc = (
        db_session.query(FindingException)
        .filter(FindingException.plugin_id == "200")
        .first()
    )
    assert exc is not None
    assert exc.exception_type == "accepted_risk"
    assert exc.expires_at is not None
    assert exc.expires_at.year == 2026


def test_reject_does_not_create_exception(db_session, authed_client, test_org, scan, asset):
    f = _mk_finding(db_session, scan, asset, plugin_id="300")
    out = _draft(
        db_session, org_id=test_org.id, finding_id=f.id,
        exception_type="false_positive", reason="x",
    )

    resp = authed_client.post(
        f"/api/agents/approvals/{out['approval_id']}/decide",
        json={"decision": "rejected", "reason": "not enough evidence"},
    )
    assert resp.status_code == 200

    count = db_session.query(FindingException).filter(
        FindingException.plugin_id == "300",
    ).count()
    assert count == 0


# ── action_registry classification ─────────────────────────────────


def test_draft_finding_exception_is_soft_write():
    from agents.action_registry import get_action, RiskTier
    spec = get_action("draft_finding_exception")
    assert spec is not None
    assert spec.risk_tier == RiskTier.SOFT_WRITE
