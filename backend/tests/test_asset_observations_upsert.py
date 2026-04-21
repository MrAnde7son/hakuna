"""Regression: record_observation must upsert cleanly under autoflush=False.

Production ``SessionLocal`` runs with ``autoflush=False``. Before the fix,
``record_observation`` queried the DB directly, missed rows added earlier
in the same transaction (they sat pending in ``db.new``), and then
``db.add()``'d a duplicate. At commit time SQLAlchemy's insertmany batch
would hit ``UniqueConstraint(asset_id, source_system)`` and roll back the
*entire* scan transaction — silently wiping the new asset and findings.

These tests exercise the two code paths that previously blew up:

  1. Multiple ``record_observation`` calls in one transaction for the
     same asset (the VM scanner's per-target fan-out: nuclei +
     content_discovery + agent each call the function).
  2. Multiple ``record_finding_observation`` calls for the same finding
     in one transaction (the FindingObservation parallel).

Both must produce exactly ONE row with ``times_seen == call_count``, and
must commit without error.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker

from models.models import AssetObservation, Finding, FindingObservation
from services.asset_observations import (
    record_finding_observation,
    record_observation,
)


@pytest.fixture
def noautoflush_session(engine):
    """A Session that mirrors production's ``autoflush=False`` setting.

    The default ``db_session`` fixture has autoflush enabled, which
    masks the bug this suite guards against. Each test gets its own
    connection + transaction so rollbacks don't leak between tests.
    """
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection, autoflush=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


def test_asset_observation_two_calls_collapse_to_one_row(
    noautoflush_session, test_assets,
):
    """Two record_observation calls in one txn → one row, times_seen=2."""
    asset = test_assets[0]

    record_observation(
        noautoflush_session,
        asset_id=asset.id,
        source_system="vm_scanner",
        raw_fields={"ip": "10.0.0.1"},
    )
    record_observation(
        noautoflush_session,
        asset_id=asset.id,
        source_system="vm_scanner",
        raw_fields={"ip": "10.0.0.2"},
    )
    noautoflush_session.commit()

    rows = (
        noautoflush_session.query(AssetObservation)
        .filter_by(asset_id=asset.id, source_system="vm_scanner")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].times_seen == 2
    # Second call's raw_fields wins — the per-source snapshot is a
    # live value, not an append log.
    assert rows[0].raw_fields == {"ip": "10.0.0.2"}


def test_asset_observation_three_calls_collapse_to_one_row(
    noautoflush_session, test_assets,
):
    """Mirrors the real VM scanner fan-out (nuclei + content_discovery + agent)."""
    asset = test_assets[0]

    for _ in range(3):
        record_observation(
            noautoflush_session,
            asset_id=asset.id,
            source_system="vm_scanner",
            raw_fields={"hostname": "dvwa"},
        )
    noautoflush_session.commit()

    rows = (
        noautoflush_session.query(AssetObservation)
        .filter_by(asset_id=asset.id, source_system="vm_scanner")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].times_seen == 3


def test_asset_observation_different_sources_stay_separate(
    noautoflush_session, test_assets,
):
    """The unique key is (asset_id, source_system) — different sources
    must still produce independent rows."""
    asset = test_assets[0]

    record_observation(
        noautoflush_session,
        asset_id=asset.id, source_system="vm_scanner",
        raw_fields={},
    )
    record_observation(
        noautoflush_session,
        asset_id=asset.id, source_system="nessus",
        raw_fields={},
    )
    noautoflush_session.commit()

    rows = (
        noautoflush_session.query(AssetObservation)
        .filter_by(asset_id=asset.id)
        .all()
    )
    assert {r.source_system for r in rows} == {"vm_scanner", "nessus"}


def test_finding_observation_two_calls_collapse_to_one_row(
    noautoflush_session, test_findings,
):
    """Parallel guarantee for FindingObservation — same bug shape."""
    finding = test_findings[0]

    record_finding_observation(
        noautoflush_session,
        finding_id=finding.id,
        source_system="vm_scanner",
        raw_fields={"template_id": "dvwa-login"},
    )
    record_finding_observation(
        noautoflush_session,
        finding_id=finding.id,
        source_system="vm_scanner",
        raw_fields={"template_id": "dvwa-login-v2"},
    )
    noautoflush_session.commit()

    rows = (
        noautoflush_session.query(FindingObservation)
        .filter_by(finding_id=finding.id, source_system="vm_scanner")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].times_seen == 2
    assert rows[0].raw_fields == {"template_id": "dvwa-login-v2"}


def test_existing_db_row_updated_not_duplicated(
    noautoflush_session, test_assets,
):
    """When a row already exists in the DB from a prior transaction,
    the next call must update it rather than INSERT a duplicate."""
    asset = test_assets[0]

    # First transaction: persist an observation.
    record_observation(
        noautoflush_session,
        asset_id=asset.id,
        source_system="vm_scanner",
        raw_fields={"ip": "1.1.1.1"},
    )
    noautoflush_session.commit()

    # Second transaction: another call in the same session — this is the
    # path that, before the fix, failed because autoflush=False left the
    # second call's DB query unable to see the first call's in-session
    # add. After commit between them the rows are persisted, but the
    # guard (checking db.new first) still applies when both happen in
    # the same uncommitted batch.
    record_observation(
        noautoflush_session,
        asset_id=asset.id,
        source_system="vm_scanner",
        raw_fields={"ip": "2.2.2.2"},
    )
    noautoflush_session.commit()

    rows = (
        noautoflush_session.query(AssetObservation)
        .filter_by(asset_id=asset.id, source_system="vm_scanner")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].times_seen == 2
    assert rows[0].raw_fields == {"ip": "2.2.2.2"}
