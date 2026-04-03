"""
In-memory background job manager for heavy operations.

Dispatches work to asyncio background tasks and tracks status via an
in-memory dict.  Returns a job_id immediately so callers can poll
GET /jobs/{job_id}/status.

TODO: Replace with Celery + Redis for production persistence, retries,
and distributed execution.  The tradeoff: this in-memory approach works
on a single process and loses state on restart, but requires zero infra.
Celery adds Redis as a dependency but gives you persistence, retry,
rate limiting, and multi-worker scaling.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Job:
    __slots__ = ("id", "name", "status", "progress", "result", "error",
                 "created_at", "started_at", "completed_at")

    def __init__(self, job_id: str, name: str):
        self.id = job_id
        self.name = name
        self.status = JobStatus.PENDING
        self.progress: Optional[int] = None
        self.result: Any = None
        self.error: Optional[str] = None
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.id,
            "name": self.name,
            "status": self.status.value,
            "progress": self.progress,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


# ── Global job registry ─────────────────────────────────────────────────

_jobs: dict[str, Job] = {}
_MAX_JOBS = 10_000  # prevent unbounded memory growth
_JOB_TTL = timedelta(hours=2)  # auto-evict finished jobs after 2h


def _evict_old_jobs():
    """Remove completed/failed jobs older than _JOB_TTL."""
    cutoff = datetime.utcnow() - _JOB_TTL
    stale = [
        jid for jid, j in _jobs.items()
        if j.status in (JobStatus.COMPLETED, JobStatus.FAILED)
        and j.completed_at and j.completed_at < cutoff
    ]
    for jid in stale:
        del _jobs[jid]


def get_job(job_id: str) -> Optional[Job]:
    return _jobs.get(job_id)


def list_jobs(limit: int = 50) -> list[dict]:
    """Return most recent jobs (newest first)."""
    sorted_jobs = sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)
    return [j.to_dict() for j in sorted_jobs[:limit]]


def dispatch(name: str, fn: Callable, *args, **kwargs) -> Job:
    """Dispatch a sync function to run in a background thread.

    Returns immediately with a Job that can be polled for status.
    The function `fn` is expected to be a regular (sync) function —
    it will be run via asyncio.to_thread to avoid blocking the event loop.
    """
    _evict_old_jobs()
    if len(_jobs) >= _MAX_JOBS:
        _evict_old_jobs()  # force cleanup

    job_id = str(uuid.uuid4())
    job = Job(job_id, name)
    _jobs[job_id] = job

    async def _run():
        job.status = JobStatus.RUNNING
        job.started_at = datetime.utcnow()
        try:
            result = await asyncio.to_thread(fn, *args, **kwargs)
            job.result = result
            job.status = JobStatus.COMPLETED
        except Exception as e:
            logger.error("Job %s (%s) failed: %s", job_id, name, e, exc_info=True)
            job.error = str(e)
            job.status = JobStatus.FAILED
        finally:
            job.completed_at = datetime.utcnow()

    # Schedule on the running event loop (FastAPI's uvicorn loop)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_run())
    except RuntimeError:
        # No running loop — fallback to creating one (shouldn't happen in FastAPI)
        logger.warning("No running event loop; creating new one for job %s", job_id)
        asyncio.run(_run())

    return job
