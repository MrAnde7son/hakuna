"""In-memory task store for async LLM extraction jobs.

Ephemeral — tasks are cleaned up after 30 minutes. Not persisted to DB
because these only live during the integration builder wizard flow.
"""

import time
import uuid
from typing import Optional

_tasks: dict[str, dict] = {}

MAX_AGE_SECONDS = 1800  # 30 minutes


def create_task() -> str:
    """Create a new pending extraction task and return its ID."""
    _cleanup()
    task_id = uuid.uuid4().hex[:16]
    _tasks[task_id] = {
        "status": "pending",
        "result": None,
        "error": None,
        "created_at": time.time(),
    }
    return task_id


def update_task(task_id: str, status: str, *, result: Optional[dict] = None, error: Optional[str] = None):
    """Update an existing task's status and optionally its result/error."""
    if task_id in _tasks:
        _tasks[task_id]["status"] = status
        if result is not None:
            _tasks[task_id]["result"] = result
        if error is not None:
            _tasks[task_id]["error"] = error


def get_task(task_id: str) -> Optional[dict]:
    """Return current state of a task, or None if not found."""
    return _tasks.get(task_id)


def _cleanup():
    """Remove tasks older than MAX_AGE_SECONDS."""
    now = time.time()
    stale = [tid for tid, t in _tasks.items() if now - t["created_at"] > MAX_AGE_SECONDS]
    for tid in stale:
        del _tasks[tid]
