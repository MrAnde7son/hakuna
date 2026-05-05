"""Background job manager backed by Postgres.

Dispatches sync work to a dedicated thread pool and tracks status in the
`background_jobs` table so that polling (`GET /jobs/{job_id}/status`) works
across Cloud Run replicas — the request that creates the job and the
request that polls it can land on different instances.

A bounded ThreadPoolExecutor still scopes how many heavy jobs run on a
single replica so they cannot starve the default asyncio executor that
serves regular requests.

Public API is unchanged:
    dispatch(name, fn, *args, timeout=None, **kwargs) -> Job
    get_job(job_id) -> Optional[Job]
    list_jobs(limit=50) -> list[dict]
"""

import asyncio
import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Optional

from sqlalchemy import text

from core.database import SessionLocal

logger = logging.getLogger(__name__)

# Dedicated thread pool for background jobs — separate from the default
# asyncio executor so heavy jobs don't block regular request handling.
_JOB_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="job-worker")

# Default timeout for dispatched jobs (seconds).  Prevents leaked threads
# from holding DB connections forever.  Callers can override per-dispatch.
DEFAULT_JOB_TIMEOUT = 600  # 10 minutes

# Auto-evict finished rows after this window — keeps the table small while
# leaving plenty of headroom for slow polling clients to read final state.
_JOB_TTL = timedelta(hours=2)


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Job:
    """Lightweight read-only view of a background_jobs row.

    Keeps the same attribute surface the previous in-memory class exposed so
    callers (`job.id`, `job.status.value`, `job.to_dict()`) keep working.
    """

    __slots__ = ("id", "name", "status", "progress", "result", "error",
                 "created_at", "started_at", "completed_at")

    def __init__(self, row: dict):
        self.id = row["id"]
        self.name = row["name"]
        status_val = row["status"]
        self.status = JobStatus(status_val) if not isinstance(status_val, JobStatus) else status_val
        self.progress = row.get("progress")
        self.result = row.get("result")
        self.error = row.get("error")
        self.created_at = row.get("created_at")
        self.started_at = row.get("started_at")
        self.completed_at = row.get("completed_at")

    def to_dict(self) -> dict:
        return {
            "job_id": self.id,
            "name": self.name,
            "status": self.status.value,
            "progress": self.progress,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


# ── DB helpers ──────────────────────────────────────────────────────────

def _serialize_result(result: Any) -> Any:
    """Coerce a job result into something the JSON column will accept.

    Most callers already return dicts (`_run_to_dict`, correlation summaries).
    Strict JSON first; anything that doesn't round-trip natively gets wrapped
    in `{"raw": str(...)}` so the write never fails.
    """
    if result is None:
        return None
    try:
        json.dumps(result)
        return result
    except (TypeError, ValueError):
        return {"raw": str(result)}


def _coerce_dt(value):
    """SQLite returns timestamps as strings; Postgres returns datetime."""
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return value


def _row_to_dict(row) -> Optional[dict]:
    if row is None:
        return None
    # Postgres JSONB auto-deserializes; SQLite (used in tests) returns the
    # raw text. Normalize so callers always see a Python value.
    result = row.result
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (TypeError, ValueError):
            pass
    return {
        "id": row.id,
        "name": row.name,
        "status": row.status,
        "progress": row.progress,
        "result": result,
        "error": row.error,
        "created_at": _coerce_dt(row.created_at),
        "started_at": _coerce_dt(row.started_at),
        "completed_at": _coerce_dt(row.completed_at),
    }


def _insert_job(job_id: str, name: str) -> None:
    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO background_jobs (id, name, status, created_at) "
                "VALUES (:id, :name, :status, :created_at)"
            ),
            {
                "id": job_id,
                "name": name,
                "status": JobStatus.PENDING.value,
                "created_at": datetime.utcnow(),
            },
        )
        db.commit()
    finally:
        db.close()


def _mark_running(job_id: str) -> None:
    db = SessionLocal()
    try:
        db.execute(
            text(
                "UPDATE background_jobs "
                "SET status = :status, started_at = :started_at "
                "WHERE id = :id"
            ),
            {
                "id": job_id,
                "status": JobStatus.RUNNING.value,
                "started_at": datetime.utcnow(),
            },
        )
        db.commit()
    finally:
        db.close()


def _mark_completed(job_id: str, result: Any) -> None:
    db = SessionLocal()
    try:
        db.execute(
            text(
                "UPDATE background_jobs "
                "SET status = :status, result = :result, completed_at = :completed_at "
                "WHERE id = :id"
            ),
            {
                "id": job_id,
                "status": JobStatus.COMPLETED.value,
                "result": json.dumps(_serialize_result(result))
                if result is not None else None,
                "completed_at": datetime.utcnow(),
            },
        )
        db.commit()
    finally:
        db.close()


def _mark_failed(job_id: str, error: str) -> None:
    db = SessionLocal()
    try:
        db.execute(
            text(
                "UPDATE background_jobs "
                "SET status = :status, error = :error, completed_at = :completed_at "
                "WHERE id = :id"
            ),
            {
                "id": job_id,
                "status": JobStatus.FAILED.value,
                "error": error,
                "completed_at": datetime.utcnow(),
            },
        )
        db.commit()
    finally:
        db.close()


def _evict_old_jobs() -> None:
    """Delete completed/failed rows older than _JOB_TTL.

    Cheap enough to run on every dispatch — the index on `status` keeps the
    delete fast and the table never grows unbounded.
    """
    cutoff = datetime.utcnow() - _JOB_TTL
    db = SessionLocal()
    try:
        db.execute(
            text(
                "DELETE FROM background_jobs "
                "WHERE status IN ('completed', 'failed') "
                "AND completed_at IS NOT NULL "
                "AND completed_at < :cutoff"
            ),
            {"cutoff": cutoff},
        )
        db.commit()
    except Exception:
        # Eviction is best-effort — never let cleanup failure block dispatch.
        db.rollback()
        logger.exception("background_jobs eviction failed")
    finally:
        db.close()


# ── Public API ──────────────────────────────────────────────────────────

def get_job(job_id: str) -> Optional[Job]:
    db = SessionLocal()
    try:
        row = db.execute(
            text(
                "SELECT id, name, status, progress, result, error, "
                "created_at, started_at, completed_at "
                "FROM background_jobs WHERE id = :id"
            ),
            {"id": job_id},
        ).fetchone()
    finally:
        db.close()
    data = _row_to_dict(row)
    return Job(data) if data else None


def list_jobs(limit: int = 50) -> list[dict]:
    """Return most recent jobs (newest first), serialized as the route returns them."""
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                "SELECT id, name, status, progress, result, error, "
                "created_at, started_at, completed_at "
                "FROM background_jobs "
                "ORDER BY created_at DESC LIMIT :limit"
            ),
            {"limit": limit},
        ).fetchall()
    finally:
        db.close()
    return [Job(_row_to_dict(r)).to_dict() for r in rows]


def dispatch(name: str, fn: Callable, *args, timeout: Optional[int] = None, **kwargs) -> Job:
    """Dispatch a sync function to run in a background thread.

    Returns immediately with a Job that can be polled for status.  The job
    row is committed to Postgres before returning so any replica can serve
    the subsequent `GET /jobs/{id}/status` poll.

    Args:
        name: Human-readable job name.
        fn: Sync callable to execute.
        timeout: Max seconds before the job is marked as failed (async path
                 only — sync threads cannot be safely interrupted in Python).
                 Defaults to DEFAULT_JOB_TIMEOUT (600s).
    """
    _evict_old_jobs()

    job_id = str(uuid.uuid4())
    _insert_job(job_id, name)

    effective_timeout = timeout if timeout is not None else DEFAULT_JOB_TIMEOUT

    def _sync_run():
        _mark_running(job_id)
        try:
            result = fn(*args)
            _mark_completed(job_id, result)
        except Exception as e:
            logger.error("Job %s (%s) failed: %s", job_id, name, e, exc_info=True)
            _mark_failed(job_id, str(e))

    async def _async_run():
        _mark_running(job_id)
        try:
            loop = asyncio.get_running_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(_JOB_EXECUTOR, fn, *args),
                timeout=effective_timeout,
            )
            _mark_completed(job_id, result)
        except asyncio.TimeoutError:
            logger.error("Job %s (%s) timed out after %ds", job_id, name, effective_timeout)
            _mark_failed(job_id, f"Job timed out after {effective_timeout}s")
        except Exception as e:
            logger.error("Job %s (%s) failed: %s", job_id, name, e, exc_info=True)
            _mark_failed(job_id, str(e))

    # Prefer scheduling on the running event loop (async route handlers).
    # Sync route handlers run in a FastAPI threadpool worker that has no
    # loop of its own — submit directly to the executor instead. The old
    # asyncio.run() fallback blocked the worker thread until the job
    # completed, defeating the whole point of dispatching it.
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_async_run())
    except RuntimeError:
        _JOB_EXECUTOR.submit(_sync_run)

    # Re-read so the returned Job carries created_at + status as committed.
    job = get_job(job_id)
    if job is None:
        # Should be impossible — we just inserted. Fall back to a synthesized
        # view so callers don't NPE.
        return Job({
            "id": job_id,
            "name": name,
            "status": JobStatus.PENDING.value,
            "progress": None,
            "result": None,
            "error": None,
            "created_at": datetime.utcnow(),
            "started_at": None,
            "completed_at": None,
        })
    return job
