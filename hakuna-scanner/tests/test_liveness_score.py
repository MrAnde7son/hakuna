"""Tests for the decaying liveness_score introduced in migration 019.

The full validate_and_update_assets path needs a real DB; these tests
exercise the score-delta arithmetic through a recording fake session
that captures the parameters the function would have written.
"""

import asyncio
import uuid
from collections import namedtuple
from unittest.mock import patch

import pytest

from app.ingest import liveness
from app.ingest.liveness import (
    _LIVENESS_BUMP_ALIVE,
    _LIVENESS_DECAY_DEAD,
    _LIVENESS_DECAY_UNCONFIRMED,
    _LIVENESS_SUPPRESS_THRESHOLD,
    validate_and_update_assets,
)


_AssetRow = namedtuple(
    "AssetRow",
    "id hostname ip open_ports consecutive_failures liveness_state tags cdn_provider",
)


class _RecordingResult:
    def __init__(self, row=None, rows=None):
        self._row = row
        self._rows = rows or []

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._rows


class _RecordingSession:
    """Captures every SQL execute() so tests can assert on the SQL params."""

    def __init__(self, asset_rows: dict[uuid.UUID, _AssetRow]):
        self.asset_rows = asset_rows
        self.executed: list[tuple[str, dict]] = []
        self.commits = 0

    async def execute(self, stmt, params=None):
        sql = str(stmt)
        params = params or {}
        self.executed.append((sql, params))
        if "SELECT id, hostname" in sql:
            ids = params.get("ids") or []
            rows = [self.asset_rows[i] for i in ids if i in self.asset_rows]
            return _RecordingResult(rows=rows)
        return _RecordingResult()

    async def commit(self):
        self.commits += 1


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_row(*, hostname="ex.example.com", failures=0, state="unconfirmed", tags=None, cdn=None, ip="1.2.3.4"):
    return _AssetRow(
        id=uuid.uuid4(),
        hostname=hostname,
        ip=ip,
        open_ports=[80, 443],
        consecutive_failures=failures,
        liveness_state=state,
        tags=tags or [],
        cdn_provider=cdn,
    )


def _captured_updates(session: _RecordingSession) -> list[dict]:
    """Return per-asset update dicts from the bulk UPDATE assets statement.

    The production code issues one chunked `UPDATE … FROM (VALUES …)` with
    positional keys (`state_0`, `state_1`, …). Reassemble per-asset dicts
    so tests can assert on the same field names as before.
    """
    for sql, params in session.executed:
        if "UPDATE assets SET" in sql and "liveness_score" in sql:
            updates: list[dict] = []
            i = 0
            while f"state_{i}" in params:
                updates.append({
                    "id": params[f"id_{i}"],
                    "state": params[f"state_{i}"],
                    "failures": params[f"failures_{i}"],
                    "tags": params[f"tags_{i}"],
                    "did_resolve": params[f"did_resolve_{i}"],
                    "cloud_provider": params[f"cloud_provider_{i}"],
                    "score_delta": params[f"score_delta_{i}"],
                })
                i += 1
            return updates
    raise AssertionError("no UPDATE assets liveness_score statement was issued")


def _captured_update(session: _RecordingSession) -> dict:
    """Single-asset convenience wrapper used by all the score tests."""
    updates = _captured_updates(session)
    assert len(updates) == 1, f"expected 1 update, got {len(updates)}"
    return updates[0]


def test_score_bumps_on_confirmed_alive():
    row = _make_row()
    session = _RecordingSession({row.id: row})
    org_id = uuid.uuid4()

    # Mock DNS to succeed; port + http both pass → confirmed_alive.
    with patch("app.ingest.liveness.check_dns_resolution", return_value=["1.2.3.4"]):
        _run(validate_and_update_assets(
            session, org_id, [row.id],
            port_check_results={row.hostname: True},
            http_check_results={row.hostname: True},
        ))

    params = _captured_update(session)
    assert params["state"] == "confirmed_alive"
    assert params["score_delta"] == _LIVENESS_BUMP_ALIVE


def test_score_decays_on_unconfirmed():
    row = _make_row()
    session = _RecordingSession({row.id: row})
    org_id = uuid.uuid4()

    # DNS only — neither port nor HTTP probe passed (1 check passed total).
    with patch("app.ingest.liveness.check_dns_resolution", return_value=["1.2.3.4"]):
        _run(validate_and_update_assets(
            session, org_id, [row.id],
            port_check_results={row.hostname: False},
            http_check_results={row.hostname: False},
        ))

    params = _captured_update(session)
    assert params["state"] == "unconfirmed"
    assert params["score_delta"] == -_LIVENESS_DECAY_UNCONFIRMED


def test_score_decays_harder_on_likely_dead():
    """After 3+ consecutive zero-check failures the asset goes likely_dead
    and the bigger decay applies."""
    row = _make_row(failures=2)  # next miss = 3 → likely_dead
    session = _RecordingSession({row.id: row})
    org_id = uuid.uuid4()

    # DNS fails entirely — 0 checks pass.
    with patch("app.ingest.liveness.check_dns_resolution", return_value=[]):
        _run(validate_and_update_assets(
            session, org_id, [row.id],
            port_check_results={row.hostname: False},
            http_check_results={row.hostname: False},
        ))

    params = _captured_update(session)
    assert params["state"] == "likely_dead"
    assert params["score_delta"] == -_LIVENESS_DECAY_DEAD


def test_dns_failure_preserves_cloud_provider_classification():
    """When DNS doesn't resolve, the SQL leaves cloud_provider untouched
    via CASE WHEN :did_resolve."""
    row = _make_row()
    session = _RecordingSession({row.id: row})
    org_id = uuid.uuid4()

    with patch("app.ingest.liveness.check_dns_resolution", return_value=[]):
        _run(validate_and_update_assets(
            session, org_id, [row.id],
            port_check_results={row.hostname: False},
            http_check_results={row.hostname: False},
        ))

    params = _captured_update(session)
    assert params["did_resolve"] is False
    # Even with DNS failure, the score still decays — we have a signal
    # (the absence of an IP), so the score should reflect it.
    assert params["score_delta"] < 0


def test_threshold_constant_matches_backend_suppression():
    """Both halves of the contract — the scanner's score floor and the
    backend's suppression threshold — must agree."""
    # Importing here so the test doesn't pull the backend tree at module load.
    import importlib.util
    import os
    backend_easm = os.path.join(
        os.path.dirname(__file__), "..", "..", "backend", "services", "easm.py",
    )
    spec = importlib.util.spec_from_file_location("easm_backend", backend_easm)
    # We can't actually exec the backend module in this test env (it pulls
    # the whole backend tree). Read the source and assert the constant.
    with open(backend_easm) as f:
        src = f.read()
    assert f"_LIVENESS_SUPPRESS_THRESHOLD = {_LIVENESS_SUPPRESS_THRESHOLD}" in src, (
        "backend/services/easm.py threshold must match liveness._LIVENESS_SUPPRESS_THRESHOLD"
    )
