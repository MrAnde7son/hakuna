"""Tests for the ``asset_created`` event emit in post_ingest.

Validates:
  * the picker prefers internet-facing + high-criticality assets,
  * the emit fires once with the chosen asset_id in the payload,
  * the emit no-ops when there are no new assets in the batch.

These tests exercise the picker + emit helpers in isolation; we don't
spin up the full finalize_scan pipeline here. The integration that
finalize_scan actually calls them is covered by inspection at the call
site (post_ingest.py:340-360) and by test_feed_routes / test_agent_dispatcher.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from models.models import Asset, Scan
from services import post_ingest


# ── Picker ranking ────────────────────────────────────────────────


@pytest.fixture
def scan(db_session, test_org):
    s = Scan(org_id=test_org.id, filename="test", status="completed")
    db_session.add(s)
    db_session.flush()
    return s


def _mk_asset(db_session, scan, *, hostname, internet_facing=False, criticality=0):
    a = Asset(
        scan_id=scan.id,
        hostname=hostname,
        asset_type="host",
        is_internet_facing=internet_facing,
        criticality=criticality,
    )
    db_session.add(a)
    db_session.flush()
    return a


def test_picker_prefers_internet_facing(db_session, scan):
    quiet = _mk_asset(db_session, scan, hostname="internal", internet_facing=False, criticality=8)
    exposed = _mk_asset(db_session, scan, hostname="dmz", internet_facing=True, criticality=4)
    chosen = post_ingest._pick_most_notable_asset_id(db_session, [quiet.id, exposed.id])
    assert chosen == exposed.id


def test_picker_breaks_internet_tie_by_criticality(db_session, scan):
    low = _mk_asset(db_session, scan, hostname="dmz-low", internet_facing=True, criticality=3)
    high = _mk_asset(db_session, scan, hostname="dmz-high", internet_facing=True, criticality=9)
    chosen = post_ingest._pick_most_notable_asset_id(db_session, [low.id, high.id])
    assert chosen == high.id


def test_picker_falls_back_to_id_when_all_equal(db_session, scan):
    a = _mk_asset(db_session, scan, hostname="a")
    b = _mk_asset(db_session, scan, hostname="b")
    chosen = post_ingest._pick_most_notable_asset_id(db_session, [a.id, b.id])
    assert chosen == max(a.id, b.id)


def test_picker_returns_none_for_empty(db_session):
    assert post_ingest._pick_most_notable_asset_id(db_session, []) is None


def test_picker_returns_none_for_unknown_ids(db_session):
    assert post_ingest._pick_most_notable_asset_id(db_session, [99_999]) is None


# ── Emit helper ───────────────────────────────────────────────────


def test_emit_skips_when_picker_returns_none(db_session, test_org):
    with patch("services.event_bus.emit") as mock_emit:
        out = post_ingest._emit_notable_asset_created(
            db_session, org_id=test_org.id, scan_id=1, new_asset_ids=[],
        )
    assert out == {"dispatched": False, "reason": "no_asset"}
    mock_emit.assert_not_called()


def test_emit_fires_with_chosen_asset(db_session, test_org, scan):
    a1 = _mk_asset(db_session, scan, hostname="quiet", internet_facing=False, criticality=2)
    a2 = _mk_asset(db_session, scan, hostname="dmz", internet_facing=True, criticality=8)

    with patch("services.event_bus.emit", return_value={"dispatched": True}) as mock_emit:
        post_ingest._emit_notable_asset_created(
            db_session, org_id=test_org.id, scan_id=scan.id, new_asset_ids=[a1.id, a2.id],
        )

    mock_emit.assert_called_once()
    _, kwargs = mock_emit.call_args
    assert kwargs["event_type"] == "asset_created"
    assert kwargs["org_id"] == test_org.id
    assert kwargs["payload"]["asset_id"] == a2.id
    assert kwargs["payload"]["scan_id"] == scan.id
    assert kwargs["payload"]["batch_size"] == 2


# ── Dispatcher mapping consistency ─────────────────────────────────


def test_asset_created_routes_to_triage_new_asset():
    from services.agent_dispatcher import EVENT_TO_AGENT_NAME
    assert EVENT_TO_AGENT_NAME["asset_created"] == "triage_new_asset"
