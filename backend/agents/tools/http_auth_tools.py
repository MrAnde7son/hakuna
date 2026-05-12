"""HTTP credentialed audit tool palette.

Covers web admin panels on devices that the SSH/WMI/SNMP families miss:
IP cameras, network printers, IP phone provisioning UIs, building-automation
gateways, generic IoT admin consoles.

Auth schemes supported (handled by the relay via httpx):
  - HTTP Basic
  - HTTP Digest
  - Bearer token
  - Anonymous (empty credentials)

The relay enforces:
  - GET / HEAD only (no POST, PUT, DELETE)
  - No redirect following across origins
  - 10s per-request timeout default
  - Hardcoded admin-path list — the agent cannot supply arbitrary paths
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging

from models.models import Asset
from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target, split_host_port
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_HTTP_TIMEOUT_S = 12


# ── Dispatch helpers ─────────────────────────────────────────────────


def _run_async(coro):
    # Mirrors snmp_tools._run_async — see that module for the cross-loop
    # future rationale.
    from core.event_loop import get_main_loop, is_on_main_loop
    main_loop = get_main_loop()
    if main_loop is not None and main_loop.is_running() and not is_on_main_loop():
        fut = asyncio.run_coroutine_threadsafe(coro, main_loop)
        return fut.result(timeout=_HTTP_TIMEOUT_S + 15)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_HTTP_TIMEOUT_S + 15)
    return asyncio.run(coro)


def _ctx(params: dict) -> tuple[str | None, str | None]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


def _infer_scheme(port: int | None) -> str:
    return "https" if port in (443, 8443, 9443) else "http"


async def _build_http_credentials(db, org_id: int, credential_id: str | None,
                                  scheme_override: str | None = None) -> dict:
    """Decrypt credentials and shape them for the relay handler.

    Anonymous probes are legal — if no credential_id is provided, returns an
    empty dict and the relay sends requests without an Authorization header.
    """
    if not credential_id:
        return {}
    raw = await load_credentials(db, credential_id, org_id)
    if not raw:
        raise ValueError(f"credential {credential_id} not found")
    auth_type = (raw.get("_auth_type") or "basic").lower()
    out: dict = {"_auth_type": auth_type}
    if scheme_override:
        out["scheme"] = scheme_override
    if auth_type == "bearer" or raw.get("token") or raw.get("bearer_token"):
        out["scheme"] = "bearer"
        out["token"] = raw.get("token") or raw.get("bearer_token") or ""
        return out
    out["scheme"] = scheme_override or ("digest" if auth_type == "digest" else "basic")
    out["username"] = raw.get("username") or ""
    out["password"] = raw.get("password") or ""
    return out


async def _dispatch_http(
    db,
    org_id: int,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: str | None,
    credential_id: str | None,
    scheme_override: str | None = None,
    port_override: int | None = None,
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

    port = port_override or target_port or 80
    scheme = scheme_override or _infer_scheme(port)

    creds = await _build_http_credentials(db, org_id, credential_id, scheme_override)

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="http_auth_probe",
        config={"target": target, "port": port, "scheme": scheme},
        credentials=creds,
        params={"op": op, "op_params": op_params, "timeout_s": _HTTP_TIMEOUT_S},
    )
    return asset, (result or {})


# ── Tools ─────────────────────────────────────────────────────────────


@agent_tool(
    "http_probe",
    "Fetch one path on the target's web admin panel. Supports HTTP Basic, "
    "Digest, and Bearer auth (uses the credential bound to the audit) or "
    "anonymous if no credential is provided. GET or HEAD only — never POSTs. "
    "Returns status, response headers, page title, product fingerprint "
    "(e.g. 'axis_camera', 'hp_printer', 'polycom_phone'), and a body "
    "excerpt. Use as the primary tool to fingerprint a device's web UI and "
    "to confirm whether the supplied credential is accepted (classification "
    "'open' = accepted, 'auth_required' = rejected or still challenged).",
    {
        "asset_id": {"type": "integer"},
        "path": {
            "type": "string",
            "description": "URL path starting with '/'. Defaults to '/'.",
        },
        "method": {
            "type": "string",
            "description": "GET or HEAD. Defaults to GET.",
        },
        "port": {
            "type": "integer",
            "description": "Override port. Defaults to the asset's primary port.",
        },
        "scheme": {
            "type": "string",
            "description": "http or https. Defaults inferred from port.",
        },
    },
)
def http_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    op_params = {
        "path": params.get("path") or "/",
        "method": (params.get("method") or "GET").upper(),
    }
    _, result = _run_async(_dispatch_http(
        db, org_id, asset_id, "probe", op_params, relay, cred,
        scheme_override=params.get("scheme"),
        port_override=params.get("port"),
    ))
    return result


@agent_tool(
    "http_discover_admin",
    "Probe a fixed list of common web admin paths in parallel (printer EWS, "
    "camera ONVIF / ISAPI, IP-phone provisioning, generic /admin, /login). "
    "Returns each path classified as 'open', 'auth_required', "
    "'redirected_to_login', 'not_found', or 'error'. The path list is "
    "hardcoded on the relay — this tool takes no path parameter so prompt "
    "injection cannot expand the probe. Run once to map a device's exposed "
    "admin surface before targeted http_probe calls.",
    {
        "asset_id": {"type": "integer"},
        "port": {
            "type": "integer",
            "description": "Override port. Defaults to the asset's primary port.",
        },
        "scheme": {
            "type": "string",
            "description": "http or https. Defaults inferred from port.",
        },
    },
)
def http_discover_admin_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_http(
        db, org_id, asset_id, "discover_admin", {}, relay, cred,
        scheme_override=params.get("scheme"),
        port_override=params.get("port"),
    ))
    return result


# ── Registry ──────────────────────────────────────────────────────────


_HTTP_AUTH_TOOL_NAMES = [
    "http_probe",
    "http_discover_admin",
    # Shared agent context
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="http_auth",
    label="HTTP Auth Audit",
    description=(
        "Credentialed audit of web admin panels exposed by devices not "
        "covered by SSH/WMI/SNMP — IP cameras (Axis/Hikvision/Dahua), "
        "network printers (HP/Canon/Xerox/Brother EWS), IP phone "
        "provisioning UIs (Polycom/Yealink/Grandstream), building-"
        "automation gateways, generic IoT admin consoles. Supports HTTP "
        "Basic, Digest, and Bearer auth. Read-only — GET/HEAD only, never "
        "writes."
    ),
    supported_os=["ip_camera", "ip_phone", "printer", "iot_sensor",
                  "access_control", "wap", "router", "switch", "firewall",
                  "network_device", "linux", "windows"],
    auth_modes=["basic", "digest", "bearer", "anonymous"],
    relay_method="http_auth_probe",
    credential_connector_ids=["http_basic", "http_digest", "http_bearer",
                              "http-basic", "http-digest", "http-bearer"],
    tool_names=_HTTP_AUTH_TOOL_NAMES,
    required_ports=(80, 443, 8080, 8443, 631, 9100),
    safety_class="credentialed",
    auto_trigger_policy="manual",
    cooldown_hours=24,
    compliance_tags=("cis_benchmarks", "nist_csf_pr_ac"),
    missions=[
        MissionTemplate(
            key="admin_panel_audit",
            label="Admin Panel Audit",
            description=(
                "Discover which admin paths are exposed on the device's web "
                "UI, confirm whether the bound credential is accepted, "
                "fingerprint the product (vendor + model line) from "
                "Server header + page title + WWW-Authenticate, and emit "
                "findings for any open (no-auth) admin path."
            ),
            prompt_key="http_auth_admin_panel_audit",
            suggested_budget=15,
            cost_hint="low",
        ),
    ],
))
