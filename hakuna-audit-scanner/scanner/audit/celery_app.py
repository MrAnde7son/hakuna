"""Standalone Celery app for the audit scanner service.

Scoped to this service — does NOT import from the Hakuna backend.
Mirrors hakuna-vm-scanner/scanner/vm/celery_app.py so operators see a
familiar shape across the two services.
"""

from celery import Celery

from scanner.audit.config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

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
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_concurrency=2,
    # Audit runs are wallclock-bounded by AUDIT_DEFAULT_WALLCLOCK_S (600s
    # default). 2h visibility leaves headroom for the LLM's worst-case
    # tail latency without letting truly-stuck tasks linger.
    broker_transport_options={"visibility_timeout": 2 * 3600},
    include=[
        "scanner.audit.audit_worker",
    ],
)
