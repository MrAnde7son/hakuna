"""Celery app for audit-runner background work.

Scope is narrow: long-running LLM-driven Protocol Audit jobs ([services/audit_runner.py])
were contending with the API's request path (relay ws heartbeat, detection
engine tick, agent step commits) because they ran in-process on uvicorn.
Moving them to a separate worker process eliminates that contention and lets
`uvicorn --reload` cycle the API without killing in-flight runs.

VM scanner has its own Celery app ([hakuna-vm-scanner/scanner/vm/celery_app.py]).
This one is deliberately independent — different broker DB, different queue —
so the two schedulers never fight for the same worker slots.
"""

import os

from celery import Celery


# Redis DB 2 is reserved for audit-runner. The VM scanner uses /0 and /1 on
# its own redis instance; sharing the URL is fine as long as DBs don't overlap.
CELERY_BROKER_URL = os.environ.get(
    "AUDIT_CELERY_BROKER_URL",
    os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/2"),
)
CELERY_RESULT_BACKEND = os.environ.get(
    "AUDIT_CELERY_RESULT_BACKEND",
    os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/2"),
)


celery_app = Celery(
    "hakuna_audit",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Fire-and-forget semantics. The worker writes AgentRun + Finding rows
    # directly to the shared DB; the backend never calls `.get()` on the
    # AsyncResult. With result tracking on, Celery's redis backend opens a
    # pubsub subscription on dispatch and spams reconnect errors the moment
    # redis goes away (e.g. when the `audits` compose profile is stopped).
    # Setting ignore_result cancels the subscription per task and keeps the
    # producer quiet when the worker isn't running.
    task_ignore_result=True,
    # acks_late + prefetch=1: an LLM run can take several minutes. If a worker
    # dies mid-run we want the task to requeue, and we don't want a worker to
    # hoard tasks it won't get to for 10+ minutes.
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_concurrency=int(os.environ.get("AUDIT_WORKER_CONCURRENCY", "4")),
    # Hard cap above the runner's default wallclock_s (600). A task hitting
    # this limit indicates a stuck LLM or runaway loop; we'd rather kill it.
    task_time_limit=900,
    task_soft_time_limit=720,
    # Don't retry forever when the broker drops out. The producer side of this
    # app only enqueues on user action; if redis is gone the dispatch should
    # fail fast (mapped to 503 by the route) rather than hang a request for 20s.
    broker_connection_retry_on_startup=False,
    broker_connection_max_retries=2,
    include=["services.audit_worker"],
)
