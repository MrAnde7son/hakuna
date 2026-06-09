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
    # Requeue tasks if a worker child dies without acking (SIGKILL from the
    # hard time limit, OOM, manual `kill -9`). Without this we've seen
    # half-killed children wedge after a SoftTimeLimitExceeded: the child
    # survives the soft kill but its asyncio/subprocess state is poisoned,
    # so the next prefetched task sits in its slot forever (observed: gov.il
    # rerun stuck for 1h+ with no progress, while peer children processed
    # other scans normally).
    task_reject_on_worker_lost=True,
    # Recycle every child after N tasks so a child that survived a soft
    # time limit but accumulated leaked state (zombie httpx/naabu/dnsx
    # subprocesses, async resources held by the dead event loop) gets
    # retired before it accepts a new long-running scan. Recovery beat
    # tasks fire every 5 min, so this caps a child's lifetime at roughly
    # 100 minutes of idle time — fast enough to recover from a poisoned
    # state without churning workers during steady-state scanning.
    worker_max_tasks_per_child=20,
    worker_prefetch_multiplier=1,
    worker_concurrency=settings.celery_concurrency,
    task_soft_time_limit=settings.task_soft_time_limit,
    task_time_limit=settings.task_time_limit,
    # Redis broker visibility timeout MUST be at least as long as the
    # longest task_time_limit in this app — otherwise Redis re-delivers
    # the task to another worker mid-flight, the original keeps running,
    # and `task_acks_late=True` means both grind on the same task. With
    # 4 worker slots and ~3-4h scans, the slots fill with re-delivered
    # ghosts within hours and no new work drains. Set to match the
    # longest per-task override (14700s on `discovery.run_discovery_chain`
    # and `enrichment.*`).
    # ── Redis connection resilience ──────────────────────────────────────
    # Memorystore resets idle TCP connections during maintenance/failover.
    # On 2026-05-27 a "connection reset by peer" on the result backend raised
    # an unhandled ConnectionError that wedged the worker's consumer loop; the
    # container stayed "Up" (PID 1 alive but not consuming) for 13 days with no
    # auto-restart, so every queued scan piled up behind a dead worker (4.4k
    # broker messages, recovery beat tasks among them never ran). These options
    # make redis-py detect a stale socket via TCP keepalive + a periodic
    # health-check PING and transparently reconnect instead of dying. Paired
    # with the worker `healthcheck` + autoheal in terraform/compute_scanners.tf
    # as defense-in-depth.
    broker_connection_retry_on_startup=True,
    redis_socket_keepalive=True,
    redis_socket_connect_timeout=30,
    redis_retry_on_timeout=True,
    # `health_check_interval` is a redis-py connection kwarg (not a top-level
    # Celery setting); it goes in the transport-options dicts so it reaches the
    # broker AND result-backend connection pools. redis-py PINGs a connection
    # idle longer than this before reusing it, so a silently-dropped Memorystore
    # socket is detected and reconnected instead of erroring mid-command.
    broker_transport_options={
        "visibility_timeout": 14700,
        "socket_keepalive": True,
        "health_check_interval": 30,
        "retry_on_timeout": True,
    },
    result_backend_transport_options={
        "visibility_timeout": 14700,
        "health_check_interval": 30,
    },
    beat_schedule={},  # populated by scheduler module
)

celery.conf.update(
    include=[
        "app.tasks.discovery",
        "app.tasks.enrichment",
        "app.tasks.nmap",
        "app.tasks.scheduler",
        "app.tasks.recovery",
        "app.tasks.github_attribution",
        "app.tasks.cloud_ranges",
    ],
    task_routes={
        "nmap.nmap_enrich_asset": {"queue": "nmap_queue"},
        "easm.run_github_npm_attribution": {"queue": "easm_queue"},
    },
)

# Side-effect import: registers the worker_ready signal handler that checks
# every Pipeline A tool dependency is in PATH at boot. Without this import
# the handler is never connected, so don't remove it.
from app.runner import tool_health  # noqa: E402, F401
