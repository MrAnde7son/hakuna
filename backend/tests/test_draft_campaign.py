"""Tests for the ``draft_campaign`` tool + the approval-decision wiring
that activates the draft on approve.

The loop the tests cover end-to-end:

  1. Agent (here, the tool body invoked directly) creates a Campaign in
     status='draft' plus an AgentApproval(source='agent_draft',
     tool_name='activate_campaign'). Returns ids synchronously — no
     pause-await.
  2. User (here, an authed test client) hits POST /api/agents/approvals/
     {id}/decide with decision=approved → server-side flips the campaign
     to status='active'.
  3. Reject path leaves the campaign in 'draft' so the operator can act
     on it later.
"""
from __future__ import annotations

import pytest

from agents.agent_tools import TOOL_REGISTRY
from models.models import Agent, AgentApproval, Asset, Campaign, CampaignFinding, Finding, Scan


def _draft(db, *, org_id, agent_id=None, **params):
    fn = TOOL_REGISTRY["draft_campaign"]["fn"]
    return fn(db, {"_org_id": org_id, "_agent_id": agent_id, **params})


@pytest.fixture
def scan(db_session, test_org):
    s = Scan(org_id=test_org.id, filename="t", status="completed")
    db_session.add(s)
    db_session.flush()
    return s


@pytest.fixture
def asset(db_session, scan):
    a = Asset(scan_id=scan.id, hostname="host-a", asset_type="host")
    db_session.add(a)
    db_session.flush()
    return a


def _mk_finding(db_session, scan, asset, *, plugin_id="42"):
    f = Finding(
        scan_id=scan.id,
        asset_id=asset.id,
        plugin_id=plugin_id,
        plugin_name="test",
        severity=3,
        severity_label="High",
    )
    db_session.add(f)
    db_session.flush()
    return f


# ── Tool body ──────────────────────────────────────────────────────


def test_draft_creates_campaign_in_draft_state(db_session, test_org, scan, asset):
    f1 = _mk_finding(db_session, scan, asset, plugin_id="100")
    f2 = _mk_finding(db_session, scan, asset, plugin_id="101")

    out = _draft(
        db_session, org_id=test_org.id,
        name="KEV cluster from scan", description="patch all KEV findings",
        finding_ids=[f1.id, f2.id],
    )

    campaign = db_session.query(Campaign).filter(Campaign.id == out["campaign_id"]).first()
    assert campaign is not None
    assert campaign.status == "draft"
    assert campaign.org_id == test_org.id
    assert campaign.finding_count == 2

    # Both findings linked.
    members = db_session.query(CampaignFinding).filter(
        CampaignFinding.campaign_id == campaign.id,
    ).all()
    assert {m.finding_id for m in members} == {f1.id, f2.id}


def test_draft_creates_paired_approval(db_session, test_org, scan, asset):
    f1 = _mk_finding(db_session, scan, asset)

    out = _draft(
        db_session, org_id=test_org.id,
        name="x", description="y", finding_ids=[f1.id],
    )

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    assert approval is not None
    assert approval.source == "agent_draft"
    assert approval.tool_name == "activate_campaign"
    assert approval.status == "pending"
    assert approval.tool_input["campaign_id"] == out["campaign_id"]
    # Mirrors MCP pattern — no run to resume on approval.
    assert approval.agent_run_id is None


def test_draft_strips_findings_from_other_orgs(db_session, test_org, scan, asset):
    """Cross-tenant isolation: passing a foreign finding id silently drops it."""
    from models.models import Organization
    other = Organization(name="Other", slug="other-draft")
    db_session.add(other)
    db_session.flush()
    other_scan = Scan(org_id=other.id, filename="t", status="completed")
    db_session.add(other_scan)
    db_session.flush()
    other_asset = Asset(scan_id=other_scan.id, hostname="x", asset_type="host")
    db_session.add(other_asset)
    db_session.flush()
    foreign = _mk_finding(db_session, other_scan, other_asset, plugin_id="999")
    mine = _mk_finding(db_session, scan, asset, plugin_id="42")

    out = _draft(
        db_session, org_id=test_org.id,
        name="x", description="y", finding_ids=[foreign.id, mine.id],
    )

    members = db_session.query(CampaignFinding).filter(
        CampaignFinding.campaign_id == out["campaign_id"],
    ).all()
    assert {m.finding_id for m in members} == {mine.id}
    assert out["finding_count"] == 1


def test_draft_rejects_empty_finding_ids(db_session, test_org):
    out = _draft(db_session, org_id=test_org.id, name="x", description="y", finding_ids=[])
    assert "error" in out


def test_draft_rejects_when_no_findings_match_org(db_session, test_org):
    out = _draft(db_session, org_id=test_org.id, name="x", description="y", finding_ids=[99999])
    assert "error" in out


def test_draft_requires_org_context(db_session):
    out = _draft(db_session, org_id=None, name="x", description="y", finding_ids=[1])
    assert "error" in out


# ── Approval → activation wiring ──────────────────────────────────


def test_approve_activates_the_draft_campaign(db_session, authed_client, test_org, scan, asset):
    f1 = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        name="x", description="y", finding_ids=[f1.id],
    )

    resp = authed_client.post(
        f"/api/agents/approvals/{out['approval_id']}/decide",
        json={"decision": "approved"},
    )
    assert resp.status_code == 200, resp.text

    campaign = db_session.query(Campaign).filter(Campaign.id == out["campaign_id"]).first()
    db_session.refresh(campaign)
    assert campaign.status == "active"


def test_reject_leaves_the_draft_in_draft_state(db_session, authed_client, test_org, scan, asset):
    f1 = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        name="x", description="y", finding_ids=[f1.id],
    )

    resp = authed_client.post(
        f"/api/agents/approvals/{out['approval_id']}/decide",
        json={"decision": "rejected", "reason": "not now"},
    )
    assert resp.status_code == 200, resp.text

    campaign = db_session.query(Campaign).filter(Campaign.id == out["campaign_id"]).first()
    db_session.refresh(campaign)
    assert campaign.status == "draft"


def test_approve_is_idempotent_on_already_active_campaign(db_session, authed_client, test_org, scan, asset):
    """If the operator clicks twice, or the campaign is already active
    via some other path, the second approve doesn't downgrade state."""
    f1 = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        name="x", description="y", finding_ids=[f1.id],
    )
    # Pretend the campaign moved past 'active' (e.g. completed).
    campaign = db_session.query(Campaign).filter(Campaign.id == out["campaign_id"]).first()
    campaign.status = "completed"
    db_session.commit()

    # The approval is still pending; approving it now shouldn't undo
    # the completed state.
    resp = authed_client.post(
        f"/api/agents/approvals/{out['approval_id']}/decide",
        json={"decision": "approved"},
    )
    assert resp.status_code == 200
    db_session.refresh(campaign)
    assert campaign.status == "completed"


# ── action_registry classification ─────────────────────────────────


def test_draft_campaign_is_soft_write_not_hard_write():
    """draft_campaign must be SOFT_WRITE so the agent doesn't pause on
    its own call — the HITL gate happens later, when the user decides
    on the paired approval. If someone bumps this to HARD_WRITE the
    whole loop breaks (agent pauses, never gets to post_feed_entry)."""
    from agents.action_registry import get_action, RiskTier
    spec = get_action("draft_campaign")
    assert spec is not None
    assert spec.risk_tier == RiskTier.SOFT_WRITE
