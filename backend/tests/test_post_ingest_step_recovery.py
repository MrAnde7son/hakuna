"""Tests for post_ingest._step transaction-recovery semantics.

In production we observed cascading "This transaction is closed" warnings
during finalize_scan: a single mid-pipeline failure (typically a Cloud SQL
proxy connection drop) would close the session, and every subsequent step
would silently no-op while logging "non-fatal" — auto-tag, ownership,
threat-intel, and TTP matching all skipped, but the pipeline appeared to
succeed. _step now rolls back a closed session before opening its
savepoint so later steps can run on a fresh transaction.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.post_ingest import _step


class _FakeSavepoint:
    def __init__(self):
        self.committed = False
        self.rolled_back = False
        # SQLAlchemy savepoints expose `is_active` — False once committed,
        # rolled back, or RELEASEd by an enclosing `Session.commit()`.
        self.is_active = True

    def commit(self):
        self.committed = True
        self.is_active = False

    def rollback(self):
        self.rolled_back = True
        self.is_active = False


class _FakeSession:
    """Minimal Session double that tracks rollback calls and lets us simulate
    the "transaction closed" state without needing a real engine."""

    def __init__(self, *, active=True, begin_nested_raises=False):
        self._active = active
        self._begin_nested_raises = begin_nested_raises
        self.rollback_calls = 0
        self.savepoints = []

    @property
    def is_active(self):
        return self._active

    def rollback(self):
        self.rollback_calls += 1
        # A successful rollback resets the session.
        self._active = True
        self._begin_nested_raises = False

    def begin_nested(self):
        if self._begin_nested_raises:
            raise RuntimeError("This transaction is closed")
        sp = _FakeSavepoint()
        self.savepoints.append(sp)
        return sp

    def simulate_inner_commit(self):
        """Mimic what `session.commit()` inside a step body does: outer
        transaction commits and any active SAVEPOINT is RELEASEd, leaving
        the matching NestedTransaction object in `is_active=False`."""
        for sp in self.savepoints:
            if sp.is_active:
                sp.is_active = False


class TestStepRecovery:
    def test_inactive_session_is_recovered_before_begin_nested(self):
        """When the session arrived in the closed state, _step rolls back
        first, then opens the savepoint and runs the body."""
        db = _FakeSession(active=False)
        ran = []

        result = _step(db, "test step", lambda: ran.append("ran") or "ok")

        assert result == "ok"
        assert ran == ["ran"]
        # One pre-step rollback to recover, no error rollback.
        assert db.rollback_calls == 1
        assert db.savepoints[0].committed is True

    def test_begin_nested_failure_rolls_back_for_next_step(self):
        """If begin_nested itself raises (session in zombie state we couldn't
        detect), the error path still triggers a rollback so the *next*
        step can open a fresh savepoint."""
        # Session reports active=True but begin_nested raises — exactly the
        # symptom we saw in prod when the underlying connection had died but
        # SQLAlchemy hadn't observed it yet.
        db = _FakeSession(active=True, begin_nested_raises=True)

        result = _step(db, "test step", lambda: "should not run")

        assert result is None
        # Recovery rollback fired so the next step won't inherit the broken
        # state. Without this fix every subsequent step would no-op too.
        assert db.rollback_calls == 1

    def test_pipeline_continues_after_one_failed_step(self):
        """The whole point: a busted step doesn't poison the rest of the
        pipeline. After a step fails on a closed transaction, the next
        step runs successfully."""
        db = _FakeSession(active=True, begin_nested_raises=True)

        first = _step(db, "broken step", lambda: "n/a")
        # The pipeline drives us back into a healthy state via rollback.
        # Now a second step should execute.
        second = _step(db, "next step", lambda: "ok")

        assert first is None
        assert second == "ok"
        # One rollback from the failed first step, none needed from the second.
        assert db.rollback_calls == 1

    def test_healthy_step_does_not_rollback(self):
        """No spurious rollbacks on the happy path."""
        db = _FakeSession(active=True)

        result = _step(db, "happy step", lambda: 42)

        assert result == 42
        assert db.rollback_calls == 0
        assert db.savepoints[0].committed is True

    def test_body_that_commits_internally_does_not_log_failure(self, caplog):
        """Step bodies that call `db.commit()` themselves (os_software_tags,
        tags, ownership_inference, compliance_evaluator) RELEASE the SAVEPOINT
        as part of the commit. Before the fix, _step then tried to commit the
        already-released savepoint, raised "This transaction is closed", and
        logged a misleading "failed (non-fatal)" warning even though the work
        had succeeded. In prod this cascaded across the whole pipeline.
        """
        import logging

        db = _FakeSession(active=True)

        def step_that_commits():
            # Mid-body commit RELEASEs the savepoint, exactly like SQLAlchemy
            # does when a step calls `db.commit()` inside an active SAVEPOINT.
            db.simulate_inner_commit()
            return "work done"

        with caplog.at_level(logging.WARNING, logger="services.post_ingest"):
            result = _step(db, "committing step", step_that_commits)

        assert result == "work done"
        # The killer assertion: no spurious "failed" warning.
        assert not any("failed" in r.message for r in caplog.records), (
            f"unexpected warnings: {[r.message for r in caplog.records]}"
        )
        # And we didn't try to commit the released savepoint a second time.
        assert db.savepoints[0].committed is False
        assert db.savepoints[0].is_active is False
