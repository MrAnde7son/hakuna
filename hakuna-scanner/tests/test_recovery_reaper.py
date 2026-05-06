"""Tests for the EASM scanner zombie-task reaper.

Same recovery mechanism the vm-scanner ships in ``2fadd6c`` — when an
easm-worker container is killed mid-scan, kombu's visibility_timeout-based
restore only acts on entries claimed by the *current* client_id, so
``unacked`` entries from a dead container never recover. Production
incident 2026-05-06: 3 of 4 worker slots pinned by redelivered ghosts of
the same scan_run, ``recover_orphaned_scans`` starved in queue behind them.
"""

import json
from unittest.mock import MagicMock, patch

import pytest


class TestZombieTaskReaper:
    def _fake_redis(self, entries):
        """Build a MagicMock redis client preloaded with `entries`.

        entries: list of (delivery_tag, score, body_dict_or_bytes).
        """
        unacked = {
            tag: (body if isinstance(body, bytes) else json.dumps(body).encode())
            for tag, _, body in entries
        }
        index = {tag: score for tag, score, _ in entries}

        client = MagicMock()
        client.zrangebyscore = MagicMock(
            side_effect=lambda key, lo, hi: [
                tag for tag, s in index.items() if s <= hi
            ]
        )
        client.hget = MagicMock(side_effect=lambda key, tag: unacked.get(tag))
        client.hdel = MagicMock(side_effect=lambda key, tag: unacked.pop(tag, None))
        client.zrem = MagicMock(side_effect=lambda key, tag: index.pop(tag, None))
        return client, unacked, index

    def test_no_stale_entries_returns_zero(self):
        from app.tasks.recovery import _reap_zombie_tasks_impl

        client, _, _ = self._fake_redis([])
        with patch("app.tasks.recovery.redis.from_url", return_value=client):
            result = _reap_zombie_tasks_impl(now=1_000_000.0)

        assert result == {"status": "ok", "reaped": 0}

    def test_reaps_stale_entry_and_marks_failure(self):
        """Entries older than the threshold must be marked FAILURE in the
        result backend AND removed from unacked / unacked_index — both
        halves matter, since downstream pollers key off result-meta status."""
        from app.celery_app import celery
        from app.tasks.recovery import _reap_zombie_tasks_impl

        body = [
            {"headers": {"id": "task-abc", "task": "discovery.run_discovery_chain"}},
            {}, {},
        ]
        # Stale: claimed 6h ago, threshold is 5h.
        client, unacked, index = self._fake_redis([(b"deliv-1", 0.0, body)])

        with patch("app.tasks.recovery.redis.from_url", return_value=client), \
             patch.object(celery.backend, "mark_as_failure") as mark_as_failure:
            result = _reap_zombie_tasks_impl(now=6 * 3600.0)

        assert result["status"] == "ok"
        assert result["reaped"] == 1
        assert result["tasks"] == [{
            "task_id": "task-abc",
            "task_name": "discovery.run_discovery_chain",
        }]
        mark_as_failure.assert_called_once()
        called_task_id, called_exc = mark_as_failure.call_args.args
        assert called_task_id == "task-abc"
        assert "abandoned" in str(called_exc).lower()
        assert not unacked
        assert not index

    def test_unparseable_body_is_dropped_without_crashing(self):
        """A malformed unacked entry must not block the reaper — drop it
        and continue. Better to leak one unrecoverable result-meta key
        than wedge the sweeper for every other entry."""
        from app.celery_app import celery
        from app.tasks.recovery import _reap_zombie_tasks_impl

        client, unacked, index = self._fake_redis([(b"deliv-bad", 0.0, b"not-json")])

        with patch("app.tasks.recovery.redis.from_url", return_value=client), \
             patch.object(celery.backend, "mark_as_failure") as mark_as_failure:
            result = _reap_zombie_tasks_impl(now=6 * 3600.0)

        assert result["reaped"] == 0
        mark_as_failure.assert_not_called()
        assert not unacked
        assert not index

    def test_fresh_entry_is_left_alone(self):
        """Entries inside the threshold may still belong to a live worker.
        Touching them would race with a real ack."""
        from app.celery_app import celery
        from app.tasks.recovery import _reap_zombie_tasks_impl

        body = [{"headers": {"id": "task-fresh", "task": "x"}}, {}, {}]
        # Fresh: claimed 1h ago, threshold is 5h.
        client, unacked, index = self._fake_redis(
            [(b"deliv-fresh", 4 * 3600.0, body)]
        )

        with patch("app.tasks.recovery.redis.from_url", return_value=client), \
             patch.object(celery.backend, "mark_as_failure") as mark_as_failure:
            result = _reap_zombie_tasks_impl(now=5 * 3600.0)

        assert result == {"status": "ok", "reaped": 0}
        mark_as_failure.assert_not_called()
        assert b"deliv-fresh" in unacked


class TestBeatSchedule:
    def test_zombie_reaper_registered(self):
        """Without this beat entry, orphaned `unacked` entries leak forever
        and `recover_orphaned_scans` starves behind them — that's the exact
        2026-05-06 production failure mode this fix addresses."""
        # Importing scheduler registers the beat schedule onto the celery app.
        from app import celery_app  # noqa: F401
        from app.tasks import scheduler  # noqa: F401
        from app.celery_app import celery

        job = celery.conf.beat_schedule["reap-zombie-tasks-every-30m"]
        assert job["task"] == "recovery.reap_zombie_tasks"

    def test_recovery_still_scheduled(self):
        """Regression guard: the existing 5-min orphan recovery beat must
        not be displaced by the new reaper entry."""
        from app import celery_app  # noqa: F401
        from app.tasks import scheduler  # noqa: F401
        from app.celery_app import celery

        job = celery.conf.beat_schedule["recover-orphaned-scans-5min"]
        assert job["task"] == "recovery.recover_orphaned_scans"
