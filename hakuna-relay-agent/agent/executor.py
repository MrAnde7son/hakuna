"""Task executor — receives task envelopes from the cloud and runs them locally."""

import json
import logging

from .transport import LocalApiTransport
from .config import AgentConfig

logger = logging.getLogger(__name__)


async def handle_task(task: dict, ws, config: AgentConfig):
    """Execute a task received from the Hakuna cloud broker."""
    task_id = task.get("task_id")
    method = task.get("method")
    transport_config = task.get("transport_config", {})
    params = task.get("params", {})
    payload = task.get("payload")

    # Resolve credentials: cloud-provided or agent-local
    credentials = task.get("credentials") or {}
    if not credentials:
        credentials = _resolve_local_credentials(transport_config, config)

    transport = LocalApiTransport(
        timeout=config.request_timeout,
        verify_ssl=config.verify_ssl,
    )

    try:
        if method == "connect":
            result = await transport.connect(transport_config, credentials)
            await ws.send(json.dumps({
                "type": "task_complete",
                "task_id": task_id,
                "result": result,
            }))

        elif method == "fetch_all":
            batch = []
            batch_index = 0
            total = 0

            async for record in transport.fetch_all(transport_config, credentials, params):
                batch.append(record)
                total += 1

                if len(batch) >= config.batch_size:
                    await ws.send(json.dumps({
                        "type": "records",
                        "task_id": task_id,
                        "batch": batch,
                        "batch_index": batch_index,
                        "done": False,
                    }))
                    batch = []
                    batch_index += 1

            # Flush remaining records
            if batch:
                await ws.send(json.dumps({
                    "type": "records",
                    "task_id": task_id,
                    "batch": batch,
                    "batch_index": batch_index,
                    "done": False,
                }))

            await ws.send(json.dumps({
                "type": "task_complete",
                "task_id": task_id,
                "total_records": total,
            }))

        elif method == "push":
            result = await transport.push(transport_config, credentials, payload or {})
            await ws.send(json.dumps({
                "type": "task_complete",
                "task_id": task_id,
                "result": result,
            }))

        else:
            await ws.send(json.dumps({
                "type": "task_error",
                "task_id": task_id,
                "error": f"Unknown method: {method}",
            }))

    except Exception as e:
        logger.exception("Task %s failed", task_id)
        await ws.send(json.dumps({
            "type": "task_error",
            "task_id": task_id,
            "error": str(e),
        }))


def _resolve_local_credentials(transport_config: dict, config: AgentConfig) -> dict:
    """Match the transport_config's base_url to locally stored credentials."""
    base_url = transport_config.get("base_url", "")

    # If base_url is a template like {{instance_url}}, try to match by product key
    if "{{" in base_url:
        # Try each known product's credentials
        for product_key, creds in config.local_credentials.items():
            instance_url = creds.get("instance_url", "")
            if instance_url:
                return creds
        # No match — return empty (task will likely fail with a clear error)
        return {}

    # If base_url is a literal URL, match against known instance_urls
    for product_key, creds in config.local_credentials.items():
        instance_url = creds.get("instance_url", "")
        if instance_url and base_url.rstrip("/").startswith(instance_url.rstrip("/")):
            return creds

    return {}
