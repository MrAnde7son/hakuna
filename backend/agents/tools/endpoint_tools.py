"""Endpoint discovery tool palette — SIP, RTSP, ONVIF WS-Discovery.

Three anonymous read-only probes for endpoint device discovery not
handled by the SSH/WMI/SNMP/HTTP families:

  - ``sip_options(asset_id)``    — SIP OPTIONS to an IP phone; returns
                                    vendor + firmware via User-Agent
                                    and any auth realm from a 401 reply
  - ``rtsp_describe(asset_id)``  — RTSP DESCRIBE to an IP camera;
                                    returns vendor via Server header and
                                    stream metadata via SDP
  - ``onvif_ws_discovery()``     — WS-Discovery Probe multicast on the
                                    relay's broadcast domain; enumerates
                                    every ONVIF camera + its service URL

All three dispatch ``method=endpoint_probe`` to the relay; op-allowlist
is enforced relay-side. Anonymous by spec — no credential required.
WS-Discovery is only useful when the relay is on the same broadcast
domain as the cameras, mirroring netbios_local_tools.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Optional

from models.models import Asset
from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target, split_host_port
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_PROBE_TIMEOUT_S = 8


# ── Dispatch helpers ─────────────────────────────────────────────────


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_PROBE_TIMEOUT_S + 15)
    return asyncio.run(coro)


def _ctx(params: dict) -> Optional[str]:
    return params.get("_relay_agent_id") or params.get("relay_agent_id")


async def _dispatch_unicast(
    db,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: Optional[str],
    default_port: int,
    port_override: Optional[int] = None,
) -> tuple[Asset, dict]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")
    raw_target = asset.ip or asset.fqdn or asset.hostname
    if not raw_target:
        raise ValueError(f"asset {asset_id} has no ip or hostname")
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")

    target, target_port = split_host_port(raw_target)
    if target_port is None:
        _, target_port = resolve_asset_target(asset)
    port = port_override or target_port or default_port

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="endpoint_probe",
        config={"target": target, "port": port},
        credentials={},
        params={"op": op, "op_params": op_params, "timeout_s": _PROBE_TIMEOUT_S},
    )
    return asset, (result or {})


async def _dispatch_multicast(
    op: str,
    op_params: dict,
    relay_agent_id: Optional[str],
) -> dict:
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")
    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")
    return await broker.send_task(
        agent_id=relay_agent_id,
        method="endpoint_probe",
        config={},                # WS-Discovery is multicast — no target
        credentials={},
        params={"op": op, "op_params": op_params, "timeout_s": _PROBE_TIMEOUT_S},
    ) or {}


# ── Tools ─────────────────────────────────────────────────────────────


@agent_tool(
    "sip_options",
    "Send a SIP OPTIONS request to an IP phone or PBX (default UDP 5060). "
    "Anonymous — no credential required. RFC 3261 §11. Returns vendor + "
    "firmware via the User-Agent header and the auth scheme + realm via "
    "any 401/407 challenge. Use to confirm a discovered SIP endpoint is "
    "actually a phone and to fingerprint vendor/model. Supports both "
    "UDP and TCP via the `transport` parameter.",
    {
        "asset_id": {"type": "integer"},
        "transport": {
            "type": "string",
            "description": "udp (default) or tcp",
        },
        "port": {
            "type": "integer",
            "description": "Override port. Defaults to 5060.",
        },
    },
)
def sip_options_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay = _ctx(params)
    op_params = {"transport": (params.get("transport") or "udp").lower()}
    _, result = _run_async(_dispatch_unicast(
        db, asset_id, "sip_options", op_params, relay,
        default_port=5060, port_override=params.get("port"),
    ))
    return result


@agent_tool(
    "rtsp_describe",
    "Send an RTSP DESCRIBE to a camera or NVR (default TCP 554). "
    "Anonymous — no credential required. RFC 7826 §13.2. Returns vendor "
    "via the Server header, stream metadata via SDP in the body, and the "
    "auth scheme + realm via any 401 challenge. Use to confirm a "
    "discovered RTSP endpoint is a live camera and to fingerprint "
    "vendor/model. Defaults to path '/'; many cameras use vendor-"
    "specific paths (e.g. '/cam/realmonitor' on Dahua) — pass `path` to "
    "target one.",
    {
        "asset_id": {"type": "integer"},
        "path": {
            "type": "string",
            "description": "URL path on the RTSP server. Defaults to '/'.",
        },
        "port": {
            "type": "integer",
            "description": "Override port. Defaults to 554.",
        },
    },
)
def rtsp_describe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay = _ctx(params)
    op_params = {"path": params.get("path") or "/"}
    _, result = _run_async(_dispatch_unicast(
        db, asset_id, "rtsp_describe", op_params, relay,
        default_port=554, port_override=params.get("port"),
    ))
    return result


@agent_tool(
    "onvif_ws_discovery",
    "Multicast WS-Discovery Probe (UDP 3702, ONVIF Core §7). Enumerates "
    "every ONVIF camera on the relay's broadcast domain. Returns each "
    "device's service URL (XAddrs), advertised types, scopes (which "
    "carry vendor + model + serial hints), and endpoint reference. "
    "LAN-only — the auto-trigger predicate enforces same-broadcast-"
    "domain. No asset_id required because this enumerates the local "
    "subnet. Set `iface_ip` to pin the source interface when the relay "
    "host is multi-homed.",
    {
        "iface_ip": {
            "type": "string",
            "description": "Optional source IP to bind the multicast probe to.",
        },
    },
)
def onvif_ws_discovery_tool(db, params: dict) -> dict:
    relay = _ctx(params)
    op_params = {}
    if params.get("iface_ip"):
        op_params["iface_ip"] = params["iface_ip"]
    return _run_async(_dispatch_multicast("ws_discovery", op_params, relay))


# ── Registry ──────────────────────────────────────────────────────────


_ENDPOINT_TOOL_NAMES = [
    "sip_options",
    "rtsp_describe",
    "onvif_ws_discovery",
    # Shared agent context
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="endpoint_discovery",
    label="Endpoint Discovery",
    description=(
        "Anonymous endpoint discovery for SIP IP phones, RTSP IP cameras, "
        "and ONVIF cameras. Three protocols: SIP OPTIONS reveals phone "
        "vendor + firmware; RTSP DESCRIBE reveals camera vendor + stream "
        "info; ONVIF WS-Discovery multicast enumerates every ONVIF camera "
        "on the local broadcast domain in a single shot. Read-only — no "
        "credential required, no protocol writes."
    ),
    supported_os=["ip_camera", "ip_phone", "iot_sensor",
                  "network_device", "unknown"],
    auth_modes=["anonymous"],
    relay_method="endpoint_probe",
    credential_connector_ids=[],
    tool_names=_ENDPOINT_TOOL_NAMES,
    required_ports=(554, 5060, 5061, 3702),
    safety_class="anon_lan_local",
    auto_trigger_policy="auto_org_opt_in",
    cooldown_hours=24,
    compliance_tags=("cis_benchmarks",),
    missions=[
        MissionTemplate(
            key="endpoint_fingerprint",
            label="Endpoint Fingerprint",
            description=(
                "Discover and fingerprint IP cameras and IP phones on the "
                "broadcast domain: WS-Discovery to enumerate ONVIF cameras "
                "in bulk, then targeted SIP OPTIONS / RTSP DESCRIBE against "
                "each candidate to confirm vendor + firmware. Emits findings "
                "for any endpoint that returns a Server / User-Agent header "
                "matching a known-vulnerable firmware string."
            ),
            prompt_key="endpoint_discovery_audit_endpoint_fingerprint",
            suggested_budget=15,
            cost_hint="low",
        ),
    ],
))
