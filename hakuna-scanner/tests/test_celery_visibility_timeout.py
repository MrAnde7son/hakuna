"""Regression test for the Celery+Redis visibility-timeout death loop.

In production we observed the EASM worker's 4 slots filling with re-delivered
ghost copies of the same `discovery.run_discovery_chain` tasks. Root cause:
the broker's `visibility_timeout` defaulted to 3600s while individual tasks
have `time_limit=14700s` (4h5min) — Redis re-delivered every long task once
per hour, and `task_acks_late=True` meant both the original and the
re-delivery executed in parallel. With 4 slots and one long org's worth of
work, the queue jammed within hours and stopped draining new scans.

The fix is the `broker_transport_options.visibility_timeout` setting in
[app/celery_app.py]. This test locks in the invariant: the broker timeout
must be ≥ the longest per-task time_limit anywhere in the app, so a long
task never gets re-delivered while still legitimately running.
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def celery_app():
    # Re-import so config changes during test session don't leak across modules.
    mod = importlib.import_module("app.celery_app")
    importlib.reload(mod)
    return mod.celery


def _max_task_time_limit() -> int:
    """Walk every registered task and return the largest `time_limit` value.

    This is the source of truth: any task with a longer time_limit than the
    broker's visibility_timeout will eventually trigger the re-delivery loop.
    """
    # Force-load all task modules so the registry is populated.
    for path in (
        "app.tasks.discovery",
        "app.tasks.enrichment",
        "app.tasks.nmap",
        "app.tasks.scheduler",
        "app.tasks.recovery",
        "app.tasks.github_attribution",
        "app.tasks.certstream_worker",
    ):
        try:
            importlib.import_module(path)
        except Exception:
            # Some task modules require runtime deps; skip if unimportable
            # in the test environment. The ones we care about (discovery,
            # enrichment) are always importable.
            pass

    from app.celery_app import celery

    longest = 0
    for name, task in celery.tasks.items():
        if name.startswith("celery."):
            continue  # built-in chord/group tasks
        limit = getattr(task, "time_limit", None)
        if isinstance(limit, int) and limit > longest:
            longest = limit
    return longest


def test_visibility_timeout_covers_longest_task(celery_app):
    """Broker visibility_timeout must be >= every task's time_limit.

    If a future task adds a longer time_limit without bumping
    visibility_timeout, this test fails — preventing the redelivery
    death loop from regressing into prod.
    """
    visibility = celery_app.conf.broker_transport_options.get("visibility_timeout")
    assert visibility is not None, (
        "broker_transport_options.visibility_timeout must be set explicitly. "
        "Default (3600s) is too short — long tasks get re-delivered and "
        "duplicated in the worker pool. See app/celery_app.py for context."
    )

    longest_task_limit = _max_task_time_limit()
    assert visibility >= longest_task_limit, (
        f"visibility_timeout={visibility}s is shorter than the longest task "
        f"time_limit={longest_task_limit}s. Tasks running between "
        f"{visibility}s and {longest_task_limit}s will be re-delivered by "
        "Redis while still running, jamming the worker pool. Either lower "
        "the offending task's time_limit or raise visibility_timeout in "
        "app/celery_app.py."
    )


def test_acks_late_implies_visibility_timeout_is_set(celery_app):
    """`task_acks_late=True` without an explicit visibility_timeout is the
    exact misconfiguration that caused the prod incident. Catch it directly.
    """
    if celery_app.conf.task_acks_late:
        assert "visibility_timeout" in celery_app.conf.broker_transport_options, (
            "task_acks_late=True requires broker_transport_options."
            "visibility_timeout to be set explicitly. Without it, every "
            "task running longer than 1h is re-delivered to a second worker "
            "while the first is still processing — both run, both eventually "
            "ack, and the worker pool fills with duplicates."
        )
