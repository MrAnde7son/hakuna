from celery import Celery

from app.config import settings

celery = Celery(
    "hakuna",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_concurrency=settings.celery_concurrency,
    task_soft_time_limit=settings.task_soft_time_limit,
    task_time_limit=settings.task_time_limit,
    beat_schedule={},  # populated by scheduler module
)

celery.conf.update(
    include=[
        "app.tasks.discovery",
        "app.tasks.enrichment",
        "app.tasks.nmap",
        "app.tasks.scheduler",
    ],
    task_routes={
        "nmap.nmap_enrich_asset": {"queue": "nmap_queue"},
    },
)
