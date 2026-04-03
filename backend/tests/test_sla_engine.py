"""Tests for pure functions in services/sla_engine.py."""

from datetime import datetime, timedelta

import pytest

from services.sla_engine import parse_nessus_date, compute_sla_status


# ── parse_nessus_date ────────────────────────────────────────────────────────

def test_parse_iso_datetime_with_T():
    result = parse_nessus_date("2024-01-15T10:30:00")
    assert result == datetime(2024, 1, 15, 10, 30, 0)


def test_parse_iso_datetime_with_space():
    result = parse_nessus_date("2024-01-15 10:30:00")
    assert result == datetime(2024, 1, 15, 10, 30, 0)


def test_parse_date_only():
    result = parse_nessus_date("2024-01-15")
    assert result == datetime(2024, 1, 15, 0, 0, 0)


def test_parse_nessus_ctime_format():
    result = parse_nessus_date("Mon Jan 15 10:30:00 2024")
    assert result == datetime(2024, 1, 15, 10, 30, 0)


def test_parse_nessus_ctime_single_digit_day_extra_space():
    # Nessus uses double-space for single-digit day: "Mon Jan  5 ..."
    result = parse_nessus_date("Mon Jan  5 10:30:00 2024")
    assert result == datetime(2024, 1, 5, 10, 30, 0)


def test_parse_month_day_year():
    result = parse_nessus_date("Jan 15, 2024")
    assert result == datetime(2024, 1, 15, 0, 0, 0)


def test_parse_day_slash_month_slash_year():
    result = parse_nessus_date("15/01/2024")
    assert result == datetime(2024, 1, 15, 0, 0, 0)


def test_parse_empty_string_returns_none():
    assert parse_nessus_date("") is None


def test_parse_none_like_empty_returns_none():
    # Not passing None (function expects str) — whitespace-only is falsy after strip
    assert parse_nessus_date("   ") is None


def test_parse_invalid_string_returns_none():
    assert parse_nessus_date("not-a-date") is None


def test_parse_partial_garbage_returns_none():
    assert parse_nessus_date("2024-99-99") is None


# ── compute_sla_status ───────────────────────────────────────────────────────

def test_status_resolved_when_resolved_at_set():
    due = datetime.utcnow() - timedelta(days=1)  # already past
    resolved = datetime.utcnow() - timedelta(hours=2)
    assert compute_sla_status(due, resolved, warn_days=7) == "resolved"


def test_status_na_when_due_date_is_none():
    assert compute_sla_status(None, None, warn_days=7) == "n/a"


def test_status_on_track_far_future():
    due = datetime.utcnow() + timedelta(days=60)
    assert compute_sla_status(due, None, warn_days=7) == "on_track"


def test_status_at_risk_within_warn_days():
    due = datetime.utcnow() + timedelta(days=3)
    assert compute_sla_status(due, None, warn_days=7) == "at_risk"


def test_status_at_risk_exactly_at_warn_boundary():
    # Exactly warn_days away should be "at_risk" (delta <= warn_days)
    due = datetime.utcnow() + timedelta(days=7, seconds=1)
    assert compute_sla_status(due, None, warn_days=7) == "on_track"

    due_boundary = datetime.utcnow() + timedelta(days=7) - timedelta(seconds=1)
    assert compute_sla_status(due_boundary, None, warn_days=7) == "at_risk"


def test_status_breached_past_due():
    due = datetime.utcnow() - timedelta(days=1)
    assert compute_sla_status(due, None, warn_days=7) == "breached"


def test_status_resolved_overrides_breached():
    # Even if due date is in the past, resolved_at takes priority
    due = datetime.utcnow() - timedelta(days=10)
    resolved = datetime.utcnow() - timedelta(days=5)
    assert compute_sla_status(due, resolved, warn_days=7) == "resolved"
