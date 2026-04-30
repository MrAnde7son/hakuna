"""Tests for the Postgres-backed job manager.

The previous in-memory registry returned 404 in production whenever the
poll request landed on a different Cloud Run replica than the dispatch.
These tests pin the contract the move to Postgres unlocks: a job written
in one session is observable from a fresh session, mirroring the
cross-replica read path.

The dispatch path itself spawns a worker thread; under in-memory SQLite
each new connection gets its own database, so we drive the persistence
helpers directly rather than going through the executor. The threading
behavior is unchanged from the prior in-memory implementation.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy.orm import sessionmaker

import services.job_manager as job_manager
from services.job_manager import (
    JobStatus,
    _insert_job,
    _mark_completed,
    _mark_failed,
    _mark_running,
    get_job,
    list_jobs,
)


class TestJobManagerPersistence:
    def test_inserted_job_visible_to_fresh_session(self, engine, monkeypatch):
        """The poll-from-another-replica scenario: write here, read fresh."""
        monkeypatch.setattr(job_manager, "SessionLocal", sessionmaker(bind=engine))

        _insert_job("job-abc", "test_persist")

        job = get_job("job-abc")
        assert job is not None
        assert job.id == "job-abc"
        assert job.name == "test_persist"
        assert job.status == JobStatus.PENDING

    def test_status_transitions_persist(self, engine, monkeypatch):
        """pending → running → completed must each be observable."""
        monkeypatch.setattr(job_manager, "SessionLocal", sessionmaker(bind=engine))

        _insert_job("job-trans", "test_trans")

        _mark_running("job-trans")
        assert get_job("job-trans").status == JobStatus.RUNNING

        _mark_completed("job-trans", {"answer": 42})
        final = get_job("job-trans")
        assert final.status == JobStatus.COMPLETED
        assert final.result == {"answer": 42}
        assert final.completed_at is not None

    def test_failed_job_persists_error(self, engine, monkeypatch):
        monkeypatch.setattr(job_manager, "SessionLocal", sessionmaker(bind=engine))

        _insert_job("job-fail", "test_fail")
        _mark_running("job-fail")
        _mark_failed("job-fail", "kaboom")

        final = get_job("job-fail")
        assert final.status == JobStatus.FAILED
        assert final.error == "kaboom"

    def test_get_job_returns_none_for_unknown_id(self, engine, monkeypatch):
        monkeypatch.setattr(job_manager, "SessionLocal", sessionmaker(bind=engine))
        assert get_job("does-not-exist") is None

    def test_unserializable_result_falls_back_to_string(self, engine, monkeypatch):
        """Non-JSON-safe payloads get wrapped instead of failing the write."""
        monkeypatch.setattr(job_manager, "SessionLocal", sessionmaker(bind=engine))

        class Weird:
            def __repr__(self):
                return "weird-object"

        _insert_job("job-weird", "test_weird")
        _mark_completed("job-weird", Weird())

        final = get_job("job-weird")
        assert final.result == {"raw": "weird-object"}

    def test_list_jobs_orders_newest_first(self, engine, monkeypatch):
        """list_jobs is what post_ingest debounce reads — order matters."""
        monkeypatch.setattr(job_manager, "SessionLocal", sessionmaker(bind=engine))

        _insert_job("job-1", "alpha")
        _insert_job("job-2", "beta")
        _insert_job("job-3", "gamma")

        jobs = list_jobs(limit=10)
        names = [j["name"] for j in jobs if j["name"] in {"alpha", "beta", "gamma"}]
        # Newest first
        assert names[:3] == ["gamma", "beta", "alpha"]
