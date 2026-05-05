"""Hakuna Relay Agent — entry point.

Two modes:

* ``agent`` (default) — on-prem deployment. One process holds one WebSocket
  to the Hakuna cloud, authenticated by ``HAKUNA_AGENT_TOKEN``. Reaches
  internal targets the cloud cannot.

* ``cloud`` — Hakuna-managed scanner running in GCP. One process holds N
  WebSockets, one per org's ``relay_type='cloud_scanner'`` row. Auth is via
  ``INTERNAL_SHARED_SECRET`` against ``/ws/relay/cloud``. Registrations are
  fetched from ``/internal/cloud-relay/registrations`` and refreshed
  periodically so newly-created orgs get a connection without a redeploy.

Common envs:
    HAKUNA_LOG_LEVEL, HAKUNA_RECONNECT_MAX

Agent-mode envs:
    HAKUNA_AGENT_TOKEN, HAKUNA_CLOUD_URL

Cloud-mode envs:
    HAKUNA_RELAY_MODE=cloud, HAKUNA_BACKEND_URL, INTERNAL_SHARED_SECRET,
    HAKUNA_REGISTRATION_REFRESH_S
"""

import asyncio
import json
import logging
import sys
import time

import httpx
import websockets

from .config import AgentConfig, load_config
from .executor import handle_task
from .local_interfaces import enumerate_local_cidrs

__version__ = "0.2.0"

logger = logging.getLogger("hakuna-relay-agent")


# ─────────────────────────────────────────────────────────────────
# Per-connection loop (shared by agent mode and each cloud-mode org)
# ─────────────────────────────────────────────────────────────────

async def _run_connection(
    ws_url: str,
    config: AgentConfig,
    label: str,
    send_local_interfaces: bool = True,
) -> None:
    """Open a WebSocket to ``ws_url``, dispatch tasks, reconnect on drop.

    Runs forever. Exits only on permanent auth failure (server sends
    ``{"type": "error"}``) — caller decides whether to retry the whole
    orchestrator or move on.
    """
    start_time = time.time()
    reconnect_delay = 1

    while True:
        try:
            logger.info("[%s] connecting to %s ...", label, ws_url.split("?")[0])
            async with websockets.connect(
                ws_url,
                ping_interval=config.heartbeat_interval,
                ping_timeout=config.heartbeat_interval * 2,
                close_timeout=10,
                max_size=50 * 1024 * 1024,
            ) as ws:
                reconnect_delay = 1
                logger.info("[%s] connected", label)

                welcome_raw = await asyncio.wait_for(ws.recv(), timeout=10)
                welcome = json.loads(welcome_raw)
                if welcome.get("type") == "error":
                    logger.error("[%s] server rejected: %s", label, welcome.get("message"))
                    return  # permanent — caller may decide to give up on this label

                if welcome.get("type") == "welcome":
                    logger.info(
                        "[%s] authenticated as '%s' (id=%s, mode=%s)",
                        label,
                        welcome.get("agent_name"),
                        welcome.get("agent_id"),
                        welcome.get("credentials_mode"),
                    )

                local_cidrs = enumerate_local_cidrs() if send_local_interfaces else []
                await ws.send(json.dumps({
                    "type": "register",
                    "agent_version": __version__,
                    "local_interfaces": local_cidrs,
                }))

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
                        asyncio.create_task(_safe_handle_task(msg, ws, config))
                    else:
                        logger.debug("[%s] unknown message type: %s", label, msg_type)

        except websockets.ConnectionClosed as e:
            logger.warning("[%s] connection closed: %s", label, e)
        except ConnectionRefusedError:
            logger.warning("[%s] connection refused", label)
        except Exception as e:
            logger.warning("[%s] connection error: %s", label, e)

        logger.info("[%s] reconnecting in %ds...", label, reconnect_delay)
        await asyncio.sleep(reconnect_delay)
        reconnect_delay = min(reconnect_delay * 2, config.reconnect_max)


async def _safe_handle_task(task: dict, ws, config: AgentConfig) -> None:
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


# ─────────────────────────────────────────────────────────────────
# Mode: agent (on-prem) — one connection, one token
# ─────────────────────────────────────────────────────────────────

async def _run_agent_mode(config: AgentConfig) -> None:
    if not config.agent_token:
        logger.error("HAKUNA_AGENT_TOKEN is required in agent mode")
        sys.exit(1)
    if not config.cloud_url:
        logger.error("HAKUNA_CLOUD_URL is required in agent mode")
        sys.exit(1)

    sep = "&" if "?" in config.cloud_url else "?"
    ws_url = f"{config.cloud_url}{sep}token={config.agent_token}"
    await _run_connection(ws_url, config, label="agent", send_local_interfaces=True)


# ─────────────────────────────────────────────────────────────────
# Mode: cloud (GCP-managed) — N connections, one per org
# ─────────────────────────────────────────────────────────────────

def _ws_url_from_backend(backend_url: str) -> str:
    """Convert https://api.example.com → wss://api.example.com/ws/relay/cloud."""
    if backend_url.startswith("https://"):
        return "wss://" + backend_url[len("https://"):] + "/ws/relay/cloud"
    if backend_url.startswith("http://"):
        return "ws://" + backend_url[len("http://"):] + "/ws/relay/cloud"
    return backend_url.rstrip("/") + "/ws/relay/cloud"


async def _fetch_registrations(config: AgentConfig) -> list[dict]:
    """GET /internal/cloud-relay/registrations with X-Internal-Token."""
    url = f"{config.backend_url}/internal/relay/cloud-relay/registrations"
    headers = {"X-Internal-Token": config.internal_secret}
    async with httpx.AsyncClient(timeout=30, verify=True) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            return []
        return data


async def _run_cloud_mode(config: AgentConfig) -> None:
    if not config.backend_url:
        logger.error("HAKUNA_BACKEND_URL is required in cloud mode")
        sys.exit(1)
    if not config.internal_secret:
        logger.error("INTERNAL_SHARED_SECRET is required in cloud mode")
        sys.exit(1)

    ws_base = _ws_url_from_backend(config.backend_url)
    logger.info("Cloud mode: ws_base=%s", ws_base)

    # agent_id → asyncio.Task running _run_connection for that org
    connections: dict[str, asyncio.Task] = {}

    async def _refresh_loop():
        while True:
            try:
                registrations = await _fetch_registrations(config)
                wanted = {r["agent_id"]: r for r in registrations}

                # Start connections for new agent_ids
                for agent_id, reg in wanted.items():
                    if agent_id in connections and not connections[agent_id].done():
                        continue
                    label = f"org={reg['org_id']}/{reg['name']}"
                    sep = "&" if "?" in ws_base else "?"
                    ws_url = (
                        f"{ws_base}{sep}agent_id={agent_id}"
                        f"&token={config.internal_secret}"
                    )
                    task = asyncio.create_task(
                        _run_connection(
                            ws_url, config, label=label,
                            send_local_interfaces=False,
                        )
                    )
                    connections[agent_id] = task
                    logger.info("Started cloud connection for %s", label)

                # Cancel connections for removed agent_ids
                for agent_id in list(connections.keys()):
                    if agent_id not in wanted:
                        task = connections.pop(agent_id)
                        task.cancel()
                        logger.info("Cancelled cloud connection for agent_id=%s", agent_id)

            except Exception as e:
                logger.warning("Registration refresh failed: %s", e)

            await asyncio.sleep(config.registration_refresh_s)

    await _refresh_loop()


# ─────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────

async def run_agent():
    config = load_config()

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("Hakuna Relay Agent v%s starting (mode=%s)", __version__, config.mode)
    if config.mode != "cloud":
        logger.info("Local credentials discovered: %s",
                    list(config.local_credentials.keys()) or "(none)")

    if config.mode == "cloud":
        await _run_cloud_mode(config)
    else:
        await _run_agent_mode(config)


def main():
    asyncio.run(run_agent())


if __name__ == "__main__":
    main()
