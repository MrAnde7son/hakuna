"""Tests for the ``draft_jira_ticket`` tool + the activation wiring
that calls the Jira integration on approve.

Mirrors the draft_campaign / draft_owner_notification shape:
  1. Tool body validates that a Jira integration exists, snapshots the
     finding context (plugin_name, severity_label, asset_ip,
     asset_hostname, remediation) onto an AgentApproval(source='agent_draft',
     tool_name='create_jira_ticket') and returns the approval id.
  2. Approve → _create_jira_ticket calls services.integrations.create_jira_ticket
     with the snapshot + overrides; stamps the resulting ticket key/url
     back onto approval.tool_input.
  3. Reject → no Jira call, no_op.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from agents.agent_tools import TOOL_REGISTRY
from models.models import (
    AgentApproval, Asset, Finding, IntegrationConfig, Scan,
)


def _draft(db, *, org_id, agent_id=None, **params):
    fn = TOOL_REGISTRY["draft_jira_ticket"]["fn"]
    return fn(db, {"_org_id": org_id, "_agent_id": agent_id, **params})


@pytest.fixture
def jira_cfg(db_session):
    """Active Jira integration row — required by the tool's fail-fast guard."""
    cfg = IntegrationConfig(
        provider="jira",
        is_enabled=True,
        config={"base_url": "https://example.atlassian.net", "email": "x@x", "api_token": "t"},
    )
    db_session.add(cfg)
    db_session.flush()
    return cfg


@pytest.fixture
def scan(db_session, test_org):
    s = Scan(org_id=test_org.id, filename="t", status="completed")
    db_session.add(s)
    db_session.flush()
    return s


@pytest.fixture
def asset(db_session, scan):
    a = Asset(
        scan_id=scan.id, hostname="prod-web-01", asset_type="host", ip="10.0.0.42",
    )
    db_session.add(a)
    db_session.flush()
    return a


def _mk_finding(db_session, scan, asset, *, plugin_id="42", severity_label="High"):
    f = Finding(
        scan_id=scan.id, asset_id=asset.id, plugin_id=plugin_id,
        plugin_name="Outdated nginx", severity=3, severity_label=severity_label,
    )
    db_session.add(f)
    db_session.flush()
    return f


# ── Tool body ──────────────────────────────────────────────────────


def test_draft_creates_approval_with_finding_snapshot(
    db_session, test_org, scan, asset, jira_cfg,
):
    """Per-finding context (plugin_name, severity_label, asset_ip,
    asset_hostname) snapshots onto the approval at draft time so the
    activation handler doesn't re-resolve them later."""
    f = _mk_finding(db_session, scan, asset, plugin_id="100", severity_label="High")
    out = _draft(
        db_session, org_id=test_org.id,
        finding_ids=[f.id], priority="high", labels="agent-drafted,kev",
    )
    assert out["approval_id"]
    assert out["finding_count"] == 1

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    assert approval.source == "agent_draft"
    assert approval.tool_name == "create_jira_ticket"
    assert approval.status == "pending"
    items = approval.tool_input["items"]
    assert len(items) == 1
    assert items[0]["plugin_id"] == "100"
    assert items[0]["asset_ip"] == "10.0.0.42"
    assert items[0]["asset_hostname"] == "prod-web-01"
    assert items[0]["severity_label"] == "High"

    overrides = approval.tool_input["config_overrides"]
    assert overrides["priority"] == "high"
    assert overrides["labels"] == "agent-drafted,kev"


def test_draft_rejects_missing_finding_ids(db_session, test_org, jira_cfg):
    out = _draft(db_session, org_id=test_org.id, finding_ids=[])
    assert "error" in out


def test_draft_rejects_invalid_priority(db_session, test_org, scan, asset, jira_cfg):
    f = _mk_finding(db_session, scan, asset)
    out = _draft(
        db_session, org_id=test_org.id, finding_ids=[f.id], priority="urgent",
    )
    assert "error" in out
    assert "priority" in out["error"]


def test_draft_fails_fast_when_jira_not_configured(db_session, test_org, scan, asset):
    """No Jira integration row → fail at draft time so the agent can pick
    a different path rather than queuing an approval that would fail."""
    f = _mk_finding(db_session, scan, asset)
    out = _draft(db_session, org_id=test_org.id, finding_ids=[f.id])
    assert "error" in out
    assert "jira" in out["error"].lower()


def test_draft_fails_fast_when_jira_disabled(db_session, test_org, scan, asset):
    """Disabled Jira row counts as 'not configured'."""
    cfg = IntegrationConfig(
        provider="jira", is_enabled=False,
        config={"base_url": "https://example.atlassian.net"},
    )
    db_session.add(cfg)
    db_session.flush()
    f = _mk_finding(db_session, scan, asset)
    out = _draft(db_session, org_id=test_org.id, finding_ids=[f.id])
    assert "error" in out


def test_draft_rejects_finding_from_other_org(db_session, test_org, jira_cfg):
    """Cross-tenant guard: a finding in another org isn't draftable."""
    from models.models import Organization
    other = Organization(name="Other", slug="other-jira")
    db_session.add(other)
    db_session.flush()
    other_scan = Scan(org_id=other.id, filename="t", status="completed")
    db_session.add(other_scan)
    db_session.flush()
    other_asset = Asset(scan_id=other_scan.id, hostname="x", asset_type="host", ip="1.2.3.4")
    db_session.add(other_asset)
    db_session.flush()
    foreign = _mk_finding(db_session, other_scan, other_asset, plugin_id="999")

    out = _draft(db_session, org_id=test_org.id, finding_ids=[foreign.id])
    assert "error" in out


def test_draft_caps_finding_ids_at_50(db_session, test_org, scan, asset, jira_cfg):
    fs = [_mk_finding(db_session, scan, asset, plugin_id=str(i)) for i in range(60)]
    out = _draft(
        db_session, org_id=test_org.id,
        finding_ids=[f.id for f in fs],
    )
    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    assert len(approval.tool_input["items"]) == 50


# ── Approve → Jira call ────────────────────────────────────────────


def test_approve_calls_create_jira_ticket(
    db_session, authed_client, test_org, scan, asset, jira_cfg,
):
    f = _mk_finding(db_session, scan, asset, plugin_id="200")
    out = _draft(
        db_session, org_id=test_org.id, finding_ids=[f.id],
        title="[High] nginx outdated", priority="high",
    )

    fake_result = {
        "tickets_created": 1,
        "results": [{"key": "SEC-123", "id": "10001", "url": "https://example.atlassian.net/browse/SEC-123"}],
    }
    with patch("services.integrations.create_jira_ticket", return_value=fake_result) as mock_jira:
        resp = authed_client.post(
            f"/api/agents/approvals/{out['approval_id']}/decide",
            json={"decision": "approved"},
        )
    assert resp.status_code == 200, resp.text
    mock_jira.assert_called_once()

    # The integration was called with the snapshot + overrides built by
    # the activation handler.
    call_args = mock_jira.call_args
    cfg = call_args[0][1]
    items = call_args[0][2]
    assert cfg.get("priority") == "high"
    assert cfg.get("title_template") == "[High] nginx outdated"
    assert len(items) == 1
    assert items[0]["plugin_id"] == "200"

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    db_session.refresh(approval)
    assert approval.tool_input.get("created_ticket_key") == "SEC-123"
    assert "browse/SEC-123" in (approval.tool_input.get("created_ticket_url") or "")


def test_approve_records_error_when_jira_raises(
    db_session, authed_client, test_org, scan, asset, jira_cfg,
):
    """Transient Jira failure shouldn't roll back the approval — the
    error gets stamped onto the approval for the queue UI."""
    f = _mk_finding(db_session, scan, asset, plugin_id="201")
    out = _draft(db_session, org_id=test_org.id, finding_ids=[f.id])

    with patch(
        "services.integrations.create_jira_ticket",
        side_effect=ConnectionError("jira unreachable"),
    ):
        resp = authed_client.post(
            f"/api/agents/approvals/{out['approval_id']}/decide",
            json={"decision": "approved"},
        )
    assert resp.status_code == 200

    approval = db_session.query(AgentApproval).filter(
        AgentApproval.id == out["approval_id"],
    ).first()
    db_session.refresh(approval)
    assert "jira" in (approval.tool_input.get("create_error") or "").lower()
    assert approval.tool_input.get("created_ticket_key") is None


def test_reject_does_not_call_jira(
    db_session, authed_client, test_org, scan, asset, jira_cfg,
):
    f = _mk_finding(db_session, scan, asset, plugin_id="202")
    out = _draft(db_session, org_id=test_org.id, finding_ids=[f.id])

    with patch("services.integrations.create_jira_ticket") as mock_jira:
        resp = authed_client.post(
            f"/api/agents/approvals/{out['approval_id']}/decide",
            json={"decision": "rejected", "reason": "duplicate of SEC-100"},
        )
    assert resp.status_code == 200
    mock_jira.assert_not_called()


# ── action_registry classification ─────────────────────────────────


def test_draft_jira_ticket_is_soft_write():
    """SOFT_WRITE is load-bearing — bumping to HARD_WRITE would pause
    the agent's run on its own draft call instead of returning the
    approval id, breaking the feed loop."""
    from agents.action_registry import get_action, RiskTier
    spec = get_action("draft_jira_ticket")
    assert spec is not None
    assert spec.risk_tier == RiskTier.SOFT_WRITE
