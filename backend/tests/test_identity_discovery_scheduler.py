"""Tests for the weekly identity-discovery dispatcher.

The dispatcher's job is small but stakes-sensitive: pick the right set of
orgs, jitter, respect the 7-day cooldown, swallow per-org exceptions so
one bad org doesn't poison the rest of the fan-out.
"""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from models.models import (
    DataProcessingConsent,
    Organization,
    Scan,
)
from services.identity_discovery import (
    IDENTITY_DISCOVERY_PURPOSE,
    run_weekly_dispatch,
)


def _opt_in(db, org, *, granted_ago=timedelta(0), revoked=False, expires_in=timedelta(days=365)):
    org.identity_discovery_enabled = True
    db.add(DataProcessingConsent(
        org_id=org.id,
        purpose=IDENTITY_DISCOVERY_PURPOSE,
        granted_at=datetime.utcnow() - granted_ago,
        expires_at=datetime.utcnow() + expires_in,
        revoked_at=datetime.utcnow() if revoked else None,
        acknowledgment_text="ack",
    ))
    db.flush()


def _make_org(db, name, *, active=True):
    org = Organization(name=name, slug=name.lower().replace(" ", "-"), is_active=active)
    db.add(org)
    db.flush()
    return org


def _no_sleep(_):
    return None


# ── Eligibility filter ──────────────────────────────────────────────


def test_dispatch_skips_orgs_without_consent(db_session, test_org):
    test_org.identity_discovery_enabled = True  # flag on, no consent row
    db_session.flush()
    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery"
    ) as runner:
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)
    assert result == {
        "queued": 0, "ran": 0, "skipped_cooldown": 0, "skipped_no_consent": 0,
    }
    assert not runner.called


def test_dispatch_skips_inactive_orgs(db_session, test_org):
    _opt_in(db_session, test_org)
    test_org.is_active = False
    db_session.flush()
    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery"
    ) as runner:
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)
    assert result["queued"] == 0
    assert not runner.called


def test_dispatch_skips_orgs_with_revoked_consent(db_session, test_org):
    _opt_in(db_session, test_org, revoked=True)
    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery"
    ) as runner:
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)
    assert result["queued"] == 0
    assert not runner.called


def test_dispatch_skips_orgs_with_expired_consent(db_session, test_org):
    _opt_in(db_session, test_org, expires_in=timedelta(days=-1))
    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery"
    ) as runner:
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)
    assert result["queued"] == 0
    assert not runner.called


# ── Cooldown ────────────────────────────────────────────────────────


def test_dispatch_skips_org_run_within_seven_days(db_session, test_org):
    _opt_in(db_session, test_org)
    # Existing scan from 2 days ago — well inside the cooldown.
    db_session.add(Scan(
        org_id=test_org.id,
        filename="identity-discovery",
        scan_name="Identity Discovery",
        source_type="identity_discovery",
        last_run_at=datetime.utcnow() - timedelta(days=2),
    ))
    db_session.flush()

    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery"
    ) as runner:
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)
    assert result["skipped_cooldown"] == 1
    assert result["ran"] == 0
    assert not runner.called


def test_dispatch_runs_orgs_past_cooldown(db_session, test_org):
    _opt_in(db_session, test_org)
    db_session.add(Scan(
        org_id=test_org.id,
        filename="identity-discovery",
        scan_name="Identity Discovery",
        source_type="identity_discovery",
        last_run_at=datetime.utcnow() - timedelta(days=10),
    ))
    db_session.flush()

    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery",
        return_value={"status": "ok", "no_signal": False, "created": 0},
    ) as runner:
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)
    assert result["ran"] == 1
    assert runner.call_count == 1


def test_dispatch_runs_org_with_no_prior_scan(db_session, test_org):
    _opt_in(db_session, test_org)
    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery",
        return_value={"status": "ok", "no_signal": False, "created": 2},
    ) as runner:
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)
    assert result["ran"] == 1
    runner.assert_called_once()


# ── Per-org failure isolation ───────────────────────────────────────


def test_one_org_exception_does_not_stop_others(db_session, test_org):
    """A wedged Wikidata/DDGS call for org A must not block discovery for
    org B. The dispatcher should log + rollback + continue."""
    _opt_in(db_session, test_org)
    other = _make_org(db_session, "Beta Inc")
    _opt_in(db_session, other)

    calls = []
    def _flaky(db, org_id, **kwargs):
        calls.append(org_id)
        if len(calls) == 1:
            raise RuntimeError("simulated DDGS death")
        return {"status": "ok", "no_signal": False, "created": 1}

    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery",
        side_effect=_flaky,
    ):
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)

    assert len(calls) == 2
    assert result["ran"] == 1  # only the successful one is counted


def test_dispatch_counts_orgs_that_return_no_consent_at_call_time(db_session, test_org):
    """Belt-and-suspenders: if consent expires *between* the prefilter
    query and the per-org run, ``run_identity_discovery`` returns
    ``skipped_no_consent``; the dispatcher tallies it separately."""
    _opt_in(db_session, test_org)
    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery",
        return_value={"status": "skipped_no_consent"},
    ):
        result = run_weekly_dispatch(db_session, sleep_fn=_no_sleep)
    assert result["skipped_no_consent"] == 1
    assert result["ran"] == 0


def test_dispatch_calls_jitter_before_each_run(db_session, test_org):
    """Pacing test — we want the jitter sleep to fire for each org so a
    bulk fan-out doesn't make N back-to-back DDGS queries in one second."""
    _opt_in(db_session, test_org)
    other = _make_org(db_session, "Beta Inc")
    _opt_in(db_session, other)

    sleep_calls = []
    def _fake_sleep(seconds):
        sleep_calls.append(seconds)

    with patch(
        "services.identity_discovery.scheduler.run_identity_discovery",
        return_value={"status": "ok"},
    ):
        run_weekly_dispatch(db_session, sleep_fn=_fake_sleep)

    assert len(sleep_calls) == 2
    # All jitter values are in the expected range.
    assert all(0 <= s <= 30 for s in sleep_calls)
