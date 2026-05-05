"""Standalone Celery app for the VM scanner service.

Scoped to this service — does NOT import from Pipeline A.
"""

from celery import Celery

from scanner.vm.config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

celery_app = Celery(
    "hakuna_vm",
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
    worker_concurrency=4,
    # Celery default is 1 day. The backend learns "task succeeded" only by
    # polling AsyncResult.status; once the result key TTLs out it returns
    # PENDING again, and the orphan-reaper marks the scan failed with
    # "scanner broker lost the job queue" — even though the work actually
    # finished. Keep results for 7 days so a scan that nobody opens for a
    # weekend still resolves correctly.
    result_expires=7 * 24 * 3600,
    # Must exceed the longest nuclei run; observed ~1.5h in prod and the
    # backend reaps at 3h, so 4h leaves headroom without letting truly-stuck
    # tasks linger. Kombu's redis default is 1h, which caused acks_late tasks
    # to be re-delivered mid-run (same job id succeeded twice).
    broker_transport_options={"visibility_timeout": 4 * 3600},
    include=[
        "scanner.vm.nuclei_worker",
        "scanner.vm.schemathesis_worker",
        "scanner.vm.agent_worker",
        "scanner.vm.content_discovery_worker",
        "scanner.vm.scheduler",
        "scanner.vm.code_repo_worker",
    ],
)
