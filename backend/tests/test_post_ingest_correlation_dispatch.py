"""Tests for post_ingest._correlate_findings debounce + dispatch.

The function replaces an inline call to correlate_findings with a
background-job dispatch, guarded by a per-org debounce so EASM batches and
multi-scan uploads don't trigger a run per batch.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.post_ingest import _correlate_findings


class TestCorrelationDispatch:
    def test_dispatches_when_no_recent_job(self, db_session, test_org):
        """First call with no prior job should dispatch."""
        with patch("services.job_manager.list_jobs", return_value=[]), \
             patch("services.job_manager.dispatch") as mock_dispatch:
            mock_dispatch.return_value.id = "new-job-1"
            result = _correlate_findings(db_session, test_org.id)

        assert result["dispatched"] is True
        assert result["job_id"] == "new-job-1"
        mock_dispatch.assert_called_once()

    def test_skips_when_job_already_running(self, db_session, test_org):
        """If a correlation is pending/running for this org, skip dispatch."""
        running = [{
            "name": f"correlation_run_org{test_org.id}",
            "status": "running",
            "job_id": "running-1",
            "completed_at": None,
        }]
        with patch("services.job_manager.list_jobs", return_value=running), \
             patch("services.job_manager.dispatch") as mock_dispatch:
            result = _correlate_findings(db_session, test_org.id)

        assert result["dispatched"] is False
        assert result["reason"] == "already_running"
        mock_dispatch.assert_not_called()

    def test_skips_when_recent_completion(self, db_session, test_org):
        """A completion inside the debounce window suppresses re-dispatch."""
        recent = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        done = [{
            "name": f"correlation_run_org{test_org.id}",
            "status": "completed",
            "job_id": "done-1",
            "completed_at": recent,
        }]
        with patch("services.job_manager.list_jobs", return_value=done), \
             patch("services.job_manager.dispatch") as mock_dispatch:
            result = _correlate_findings(db_session, test_org.id)

        assert result["dispatched"] is False
        assert result["reason"] == "debounced"
        mock_dispatch.assert_not_called()

    def test_dispatches_when_completion_outside_debounce(self, db_session, test_org):
        """Completions older than the debounce window allow re-dispatch."""
        old = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        done = [{
            "name": f"correlation_run_org{test_org.id}",
            "status": "completed",
            "job_id": "done-1",
            "completed_at": old,
        }]
        with patch("services.job_manager.list_jobs", return_value=done), \
             patch("services.job_manager.dispatch") as mock_dispatch:
            mock_dispatch.return_value.id = "new-2"
            result = _correlate_findings(db_session, test_org.id)

        assert result["dispatched"] is True
        mock_dispatch.assert_called_once()

    def test_other_orgs_do_not_block(self, db_session, test_org):
        """A running job for org 99 must not suppress org N's dispatch."""
        other_running = [{
            "name": "correlation_run_org99",
            "status": "running",
            "job_id": "other-1",
            "completed_at": None,
        }]
        with patch("services.job_manager.list_jobs", return_value=other_running), \
             patch("services.job_manager.dispatch") as mock_dispatch:
            mock_dispatch.return_value.id = "new-3"
            result = _correlate_findings(db_session, test_org.id)

        assert result["dispatched"] is True
        mock_dispatch.assert_called_once()
