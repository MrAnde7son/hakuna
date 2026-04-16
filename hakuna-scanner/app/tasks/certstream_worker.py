"""Long-running Celery task that runs the CertStream consumer.

The consumer is a single persistent task per worker. It reconnects on
websocket failures internally — on process-level crash, celery restarts
the task via the beat schedule (best-effort).

No output/return value — this task runs until cancelled. It's idempotent
in the sense that a second concurrent invocation would just open another
websocket connection; operators should ensure only one worker holds this
task at a time (typically achieved via a dedicated 'certstream_queue'
with concurrency=1).
"""

import asyncio
import logging

from app.celery_app import celery
from app.config import settings
from app.database import get_task_session
from app.ingest.certstream import run_certstream_consumer

logger = logging.getLogger(__name__)


@celery.task(
    bind=True,
    name="certstream.run_consumer",
    # Keep running forever; no soft/hard time limit.
    soft_time_limit=None,
    time_limit=None,
    # Don't retry — the consumer handles reconnects internally. If the
    # task dies entirely, beat re-enqueues it on the next tick.
    max_retries=0,
    queue="certstream_queue",
)
def run_consumer(self) -> dict:
    """Run the CertStream consumer. Blocks until cancelled or disabled."""
    if not settings.certstream_enabled:
        logger.info("certstream.run_consumer: disabled, exiting")
        return {"status": "disabled"}

    sf = get_task_session()
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(run_certstream_consumer(sf))
    except Exception as exc:
        logger.exception("certstream.run_consumer failed: %s", exc)
        return {"status": "error", "error": str(exc)}
    finally:
        loop.close()

    return {"status": "stopped"}
