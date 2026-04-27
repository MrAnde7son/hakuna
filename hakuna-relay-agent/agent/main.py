"""Hakuna Relay Agent — entry point.

Connects to the Hakuna cloud via WebSocket, receives integration tasks,
executes them locally against on-prem services, and streams results back.

Usage:
    python -m agent.main

Environment variables:
    HAKUNA_AGENT_TOKEN   - Agent authentication token (required)
    HAKUNA_CLOUD_URL     - WebSocket URL (required, e.g. wss://app.hakuna.io/ws/relay)
    HAKUNA_LOG_LEVEL     - Log level (default: INFO)
    HAKUNA_RECONNECT_MAX - Max reconnect delay in seconds (default: 60)

    # On-prem product credentials (add as needed)
    JIRA_BASE_URL, JIRA_USERNAME, JIRA_PASSWORD
    SERVICENOW_BASE_URL, SERVICENOW_USERNAME, SERVICENOW_PASSWORD
    CROWDSTRIKE_BASE_URL, CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET
"""

import asyncio
import json
import logging
import sys
import time

import websockets

from .config import load_config
from .executor import handle_task
from .local_interfaces import enumerate_local_cidrs

__version__ = "0.1.0"

logger = logging.getLogger("hakuna-relay-agent")


async def run_agent():
    config = load_config()

    # Validate required config
    if not config.agent_token:
        logger.error("HAKUNA_AGENT_TOKEN is required")
        sys.exit(1)
    if not config.cloud_url:
        logger.error("HAKUNA_CLOUD_URL is required")
        sys.exit(1)

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("Hakuna Relay Agent v%s starting", __version__)
    logger.info("Cloud URL: %s", config.cloud_url)
    logger.info("Local credentials discovered: %s",
                list(config.local_credentials.keys()) or "(none)")

    start_time = time.time()
    reconnect_delay = 1

    while True:
        try:
            url = config.cloud_url
            # Append token as query param (WebSocket clients can't always set headers)
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}token={config.agent_token}"

            logger.info("Connecting to %s ...", config.cloud_url)

            async with websockets.connect(
                url,
                ping_interval=config.heartbeat_interval,
                ping_timeout=config.heartbeat_interval * 2,
                close_timeout=10,
                max_size=50 * 1024 * 1024,  # 50MB max message
            ) as ws:
                # Reset backoff on successful connection
                reconnect_delay = 1
                logger.info("Connected successfully")

                # Wait for welcome message
                welcome_raw = await asyncio.wait_for(ws.recv(), timeout=10)
                welcome = json.loads(welcome_raw)

                if welcome.get("type") == "error":
                    logger.error("Server rejected connection: %s", welcome.get("message"))
                    sys.exit(1)

                if welcome.get("type") == "welcome":
                    logger.info("Authenticated as agent '%s' (id=%s, mode=%s)",
                                welcome.get("agent_name"),
                                welcome.get("agent_id"),
                                welcome.get("credentials_mode"))

                # Send registration metadata so the backend can populate
                # RelayAgent.labels — currently consumed by _lan_local_predicate
                # (NetBIOS/LLMNR/mDNS audits) but reusable for future
                # subnet-scoped families.
                local_cidrs = enumerate_local_cidrs()
                if local_cidrs:
                    logger.info("Reporting %d local IPv4 network(s): %s",
                                len(local_cidrs), ", ".join(local_cidrs))
                else:
                    logger.info("No local IPv4 networks detected — "
                                "LAN-local audits will only fire via manual dispatch")
                await ws.send(json.dumps({
                    "type": "register",
                    "agent_version": __version__,
                    "local_interfaces": local_cidrs,
                }))

                # Main message loop
                async for raw_msg in ws:
                    msg = json.loads(raw_msg)
                    msg_type = msg.get("type")

                    if msg_type == "ping":
                        uptime = int(time.time() - start_time)
                        await ws.send(json.dumps({
                            "type": "pong",
                            "agent_version": __version__,
                            "uptime_s": uptime,
                        }))

                    elif msg_type == "task":
                        # Run task in a separate asyncio task so we can handle
                        # multiple concurrent tasks
                        asyncio.create_task(
                            _safe_handle_task(msg, ws, config)
                        )

                    else:
                        logger.debug("Unknown message type: %s", msg_type)

        except websockets.ConnectionClosed as e:
            logger.warning("Connection closed: %s", e)
        except ConnectionRefusedError:
            logger.warning("Connection refused by server")
        except Exception as e:
            logger.warning("Connection error: %s", e)

        # Exponential backoff reconnect
        logger.info("Reconnecting in %ds...", reconnect_delay)
        await asyncio.sleep(reconnect_delay)
        reconnect_delay = min(reconnect_delay * 2, config.reconnect_max)


async def _safe_handle_task(task: dict, ws, config):
    """Wrapper to catch and log task execution errors."""
    task_id = task.get("task_id", "?")
    try:
        logger.info("Executing task %s (method=%s)", task_id, task.get("method"))
        await handle_task(task, ws, config)
        logger.info("Task %s completed", task_id)
    except Exception as e:
        logger.exception("Task %s failed with unhandled error", task_id)
        try:
            await ws.send(json.dumps({
                "type": "task_error",
                "task_id": task_id,
                "error": f"Unhandled error: {e}",
            }))
        except Exception:
            pass


def main():
    asyncio.run(run_agent())


if __name__ == "__main__":
    main()
