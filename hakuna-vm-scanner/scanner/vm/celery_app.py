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
    include=[
        "scanner.vm.nuclei_worker",
        "scanner.vm.scheduler",
        "scanner.vm.code_repo_worker",
    ],
)
