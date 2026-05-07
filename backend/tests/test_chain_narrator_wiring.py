"""Tests for the chain_narrator wiring.

Covers:
  * ``chain_coordinator.tick`` fires ``event_bus.emit("validated_chain")``
    after each successful chain emit, AFTER the commit, with a payload
    containing finding_id and a chain_summary.
  * ``feed_agent_templates.json`` contains a ``chain_narrator`` template
    whose name matches ``EVENT_TO_AGENT_NAME["validated_chain"]``.
  * The bootstrap endpoint creates a chain_narrator agent in the caller's
    org and is idempotent; ``overwrite=true`` refreshes the prompt.
"""
from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from models.models import Agent, Asset, Finding, OrgFeedEntry, Scan
from services import agent_dispatcher


# ── Template / dispatcher consistency ──────────────────────────────


def test_chain_narrator_template_exists_and_matches_dispatcher():
    """The dispatcher's event map and the templates file must agree on
    ``chain_narrator``. Drift here would silently no-op the feature."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "feed_agent_templates.json",
    )
    with open(path) as f:
        data = json.load(f)
    names = {t["name"] for t in data["templates"]}
    assert "chain_narrator" in names
    assert agent_dispatcher.EVENT_TO_AGENT_NAME["validated_chain"] == "chain_narrator"

    # The template must include post_feed_entry — without it the agent
    # has no way to write the entry the user will read.
    chain = next(t for t in data["templates"] if t["name"] == "chain_narrator")
    assert "post_feed_entry" in chain["tools"]
    assert "query_findings" in chain["tools"]
    assert chain["system_prompt"]


# ── Bootstrap endpoint ─────────────────────────────────────────────


def test_bootstrap_creates_chain_narrator(db_session, authed_client, test_org, test_user):
    resp = authed_client.post(
        "/api/feed/agents/bootstrap",
        json={"only": ["chain_narrator"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert any(c["name"] == "chain_narrator" for c in body["created"])
    assert body["updated"] == []

    agent = (
        db_session.query(Agent)
        .filter(Agent.org_id == test_org.id, Agent.name == "chain_narrator")
        .first()
    )
    assert agent is not None
    assert "post_feed_entry" in (agent.tools or [])
    assert agent.system_prompt


def test_bootstrap_is_idempotent(db_session, authed_client, test_org):
    a = Agent(
        org_id=test_org.id, name="chain_narrator",
        system_prompt="(operator's edit)", tools=["post_feed_entry"],
    )
    db_session.add(a)
    db_session.flush()

    resp = authed_client.post(
        "/api/feed/agents/bootstrap",
        json={"only": ["chain_narrator"]},
    )
    assert resp.status_code == 200
    assert resp.json()["created"] == []
    assert resp.json()["updated"] == []
    assert any(s["name"] == "chain_narrator" for s in resp.json()["skipped"])

    # Operator edit preserved.
    db_session.refresh(a)
    assert a.system_prompt == "(operator's edit)"


def test_bootstrap_overwrite_refreshes_prompt(db_session, authed_client, test_org):
    a = Agent(
        org_id=test_org.id, name="chain_narrator",
        system_prompt="(stale)", tools=[],
    )
    db_session.add(a)
    db_session.flush()

    resp = authed_client.post(
        "/api/feed/agents/bootstrap",
        json={"only": ["chain_narrator"], "overwrite": True},
    )
    assert resp.status_code == 200
    assert any(u["name"] == "chain_narrator" for u in resp.json()["updated"])

    db_session.refresh(a)
    assert a.system_prompt != "(stale)"
    assert "post_feed_entry" in (a.tools or [])


def test_bootstrap_requires_admin(db_session, authed_client, test_user):
    test_user.role = "viewer"
    db_session.flush()
    resp = authed_client.post(
        "/api/feed/agents/bootstrap",
        json={"only": ["chain_narrator"]},
    )
    assert resp.status_code == 403


# ── chain_coordinator.tick fires the event ─────────────────────────


def _seed_minimal_chain_finding(db_session, org_id, scan_id):
    """Seed one already-emitted ValidatedChain finding the way
    ``_emit_validated_chain`` would, so we can assert that ``tick``'s
    post-commit emit loop picks it up."""
    asset = Asset(scan_id=scan_id, hostname="target", asset_type="host")
    db_session.add(asset)
    db_session.flush()
    f = Finding(
        scan_id=scan_id,
        asset_id=asset.id,
        source_type="hakuna_chain_coordinator",
        plugin_id="1,2,3",
        plugin_name="Validated chain: a → b (2 hops)",
        plugin_family="Chain",
        severity=3,
        severity_label="High",
        synopsis="test",
        custom_fields={
            "chain": {
                "entry_asset_id": 100,
                "target_asset_id": 200,
                "asset_ids": [100, 150, 200],
                "edge_ids": [10, 11],
                "source_systems": ["easm", "vm"],
                "score": 7.5,
                "signature": "10,11",
            },
        },
    )
    db_session.add(f)
    db_session.flush()
    return f


def test_tick_emits_validated_chain_event_after_commit(db_session, test_org):
    """Patch detect_closures + _emit_validated_chain so we don't have to
    spin up the whole graph; assert event_bus.emit is called for each
    emitted finding with the right payload shape."""
    scan = Scan(org_id=test_org.id, filename="test", status="completed")
    db_session.add(scan)
    db_session.flush()

    finding = _seed_minimal_chain_finding(db_session, test_org.id, scan.id)

    from services import chain_coordinator

    sentinel_chain = object()  # the real ClosedChain isn't needed — _emit is mocked

    with patch.object(chain_coordinator, "_recompute_affected_subgraph", return_value=set()), \
         patch.object(chain_coordinator, "enumerate_hypotheses", return_value=[]), \
         patch.object(chain_coordinator, "detect_closures", return_value=[sentinel_chain]), \
         patch.object(chain_coordinator, "_emit_validated_chain", return_value=finding) as mock_emit, \
         patch("services.event_bus.emit") as mock_bus:
        result = chain_coordinator.tick(db_session, org_id=test_org.id, scan_id=scan.id)

    assert result["validated_chains"] == 1
    mock_emit.assert_called_once()
    mock_bus.assert_called_once()
    _, kwargs = mock_bus.call_args
    assert kwargs["event_type"] == "validated_chain"
    assert kwargs["org_id"] == test_org.id
    payload = kwargs["payload"]
    assert payload["finding_id"] == finding.id
    assert payload["severity_label"] == "High"
    assert payload["chain_summary"]["entry_asset_id"] == 100
    assert payload["chain_summary"]["target_asset_id"] == 200
    assert payload["chain_summary"]["edge_count"] == 2
    assert payload["chain_summary"]["source_systems"] == ["easm", "vm"]


def test_tick_does_not_emit_when_no_chains_validated(db_session, test_org):
    """No validated chains → no event traffic. Defends against a noisy
    bus that wakes the narrator on every tick regardless of outcome."""
    from services import chain_coordinator

    with patch.object(chain_coordinator, "_recompute_affected_subgraph", return_value=set()), \
         patch.object(chain_coordinator, "enumerate_hypotheses", return_value=[]), \
         patch.object(chain_coordinator, "detect_closures", return_value=[]), \
         patch("services.event_bus.emit") as mock_bus:
        chain_coordinator.tick(db_session, org_id=test_org.id, scan_id=None)

    mock_bus.assert_not_called()
