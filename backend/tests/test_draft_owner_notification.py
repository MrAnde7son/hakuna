"""Tests for the ``draft_owner_notification`` tool + the activation
wiring that sends the message on approve.

The loop:
  1. Agent calls the tool with finding_id + message_md → tool resolves
     the owner via existing ownership_inference, creates an
     AgentApproval(source='agent_draft', tool_name='send_owner_notification')
     and returns the approval id.
  2. User clicks Approve in the feed → POST /api/agents/approvals/{id}/decide
     → _send_owner_notification fires.
  3. Slack first if configured, in-app fallback otherwise. Outcome stamps
     onto approval.tool_input for audit.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from agents.agent_tools import TOOL_REGISTRY
from models.models import (
    Agent, AgentApproval, Asset, Finding, Notification, Scan,
)


def _draft(db, *, org_id, agent_id=None, **params):
    fn = TOOL_REGISTRY["draft_owner_notification"]["fn"]
    return fn(db, {"_org_id": org_id, "_agent_id": agent_id, **params})


@pytest.fixture
def scan(db_session, test_org):
    s = Scan(org_id=test_org.id, filename="t", status="completed")
    db_session.add(s)
    db_session.flush()
    return s


@pytest.fixture
def asset(db_session, scan):
    a = Asset(
        scan_id=scan.id, hostname="prod-db-01", asset_type="host",
        inferred_team="platform", inferred_primary_user="dba",
    )
    db_session.add(a)
    db_session.flush()
    return a


def _mk_finding(db_session, scan, asset, *, plugin_id="42", severity_label="High"):
    f = Finding(
        scan_id=scan.id, asset_id=asset.id, plugin_id=plugin_id,
        plugin_name="Outdated component", severity=3, severity_label=severity_label,
    )
    db_session.add(f)
    db_session.flush()
    return f


# ── Tool body ──────────────────────────────────────────────────────


def test_draft_creates_approval_with_inferred_owner(db_session, test_org, scan, asset):
    """Owner inferred from Asset.inferred_team flows through to the
    approval payload so the user can see who'd be notified."""
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        finding_id=f.id, message_md="Patch this asap.",
    )
    assert out["approval_id"]
    assert out["owner_team"] == "platform"

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    assert approval.source == "agent_draft"
    assert approval.tool_name == "send_owner_notification"
    assert approval.status == "pending"
    assert approval.agent_run_id is None
    assert approval.tool_input["finding_id"] == f.id
    assert approval.tool_input["message_md"] == "Patch this asap."
    assert approval.tool_input["context"]["asset_hostname"] == "prod-db-01"


def test_draft_rejects_finding_from_other_org(db_session, test_org, authed_client):
    """Cross-tenant guard: a finding in another org returns an error
    rather than leaking data into this org's feed."""
    from models.models import Organization
    other = Organization(name="Other", slug="other-notif")
    db_session.add(other)
    db_session.flush()
    other_scan = Scan(org_id=other.id, filename="t", status="completed")
    db_session.add(other_scan)
    db_session.flush()
    other_asset = Asset(scan_id=other_scan.id, hostname="x", asset_type="host")
    db_session.add(other_asset)
    db_session.flush()
    foreign = _mk_finding(db_session, other_scan, other_asset, plugin_id="99")

    out = _draft(
        db_session, org_id=test_org.id,
        finding_id=foreign.id, message_md="x",
    )
    assert "error" in out


def test_draft_rejects_empty_message(db_session, test_org, scan, asset):
    f = _mk_finding(db_session, scan, asset)
    out = _draft(db_session, org_id=test_org.id, finding_id=f.id, message_md="   ")
    assert "error" in out


def test_draft_truncates_long_message(db_session, test_org, scan, asset):
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        finding_id=f.id, message_md="x" * 5000,
    )
    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    assert len(approval.tool_input["message_md"]) == 4000


# ── Activation: send on approve ────────────────────────────────────


def test_approve_sends_via_slack_when_configured(db_session, authed_client, test_org, scan, asset):
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        finding_id=f.id, message_md="Critical exposure on prod-db-01.",
    )

    with patch("services.integrations.get_integration_config", return_value={"webhook_url": "https://hooks.slack/x"}), \
         patch("services.integrations.send_slack_notification") as mock_slack:
        resp = authed_client.post(
            f"/api/agents/approvals/{out['approval_id']}/decide",
            json={"decision": "approved"},
        )
    assert resp.status_code == 200, resp.text
    mock_slack.assert_called_once()

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    db_session.refresh(approval)
    assert approval.tool_input.get("sent_via") == "slack"


def test_approve_falls_back_to_in_app_when_slack_unconfigured(db_session, authed_client, test_org, scan, asset):
    """No Slack integration → in-app notification gets created. Demo
    works without external setup."""
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        finding_id=f.id, message_md="Heads up.",
    )

    with patch("services.integrations.get_integration_config", return_value=None):
        resp = authed_client.post(
            f"/api/agents/approvals/{out['approval_id']}/decide",
            json={"decision": "approved"},
        )
    assert resp.status_code == 200

    notif = (
        db_session.query(Notification)
        .filter(
            Notification.org_id == test_org.id,
            Notification.category == "agent_draft_notification",
        )
        .first()
    )
    assert notif is not None
    assert notif.entity_id == f.id

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    db_session.refresh(approval)
    assert approval.tool_input.get("sent_via") == "in_app"


def test_approve_falls_back_to_in_app_when_slack_send_raises(db_session, authed_client, test_org, scan, asset):
    """Slack configured but transient send error → still lands in-app
    so the message isn't lost."""
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        finding_id=f.id, message_md="x",
    )

    with patch("services.integrations.get_integration_config", return_value={"webhook_url": "https://hooks.slack/x"}), \
         patch("services.integrations.send_slack_notification", side_effect=ConnectionError("nope")):
        resp = authed_client.post(
            f"/api/agents/approvals/{out['approval_id']}/decide",
            json={"decision": "approved"},
        )
    assert resp.status_code == 200

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    db_session.refresh(approval)
    assert approval.tool_input.get("sent_via") == "in_app"
    assert "slack" in (approval.tool_input.get("sent_error") or "")


def test_reject_does_not_send(db_session, authed_client, test_org, scan, asset):
    """Reject path: no notification fires, sent_via stays unset."""
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id,
        finding_id=f.id, message_md="x",
    )

    with patch("services.integrations.send_slack_notification") as mock_slack, \
         patch("services.notifications.create_notification") as mock_notif:
        resp = authed_client.post(
            f"/api/agents/approvals/{out['approval_id']}/decide",
            json={"decision": "rejected", "reason": "not now"},
        )
    assert resp.status_code == 200
    mock_slack.assert_not_called()
    mock_notif.assert_not_called()


# ── action_registry classification ─────────────────────────────────


def test_draft_owner_notification_is_soft_write():
    """SOFT_WRITE classification is load-bearing — bumping to HARD_WRITE
    would pause the agent's run mid-call instead of returning the
    approval id, breaking the loop."""
    from agents.action_registry import get_action, RiskTier
    spec = get_action("draft_owner_notification")
    assert spec is not None
    assert spec.risk_tier == RiskTier.SOFT_WRITE
