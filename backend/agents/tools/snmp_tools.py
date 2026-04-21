"""SNMP tool palette for the SNMP Audit ReAct agent.

Each tool dispatches a `method=snmp_query` task to the relay. The relay handler
(hakuna-relay-agent/agent/snmp_query.py) wraps pysnmp's sync hlapi per op:

  - `op="sys_info"`        — sysDescr / sysObjectID / sysUpTime / contact / location
  - `op="interfaces"`      — ifTable walk (descr, type, speed, admin/oper status)
  - `op="arp_table"`       — ipNetToMedia walk (L2/L3 neighbor discovery)
  - `op="ip_addrs"`        — ipAddrTable (local addresses + masks)
  - `op="routing_table"`   — ipRouteTable walk
  - `op="community_probe"` — try a short list of default community strings
  - `op="get"`             — single OID GET (escape hatch)
  - `op="walk"`            — bounded GETNEXT walk (escape hatch)

All tool results summarize rather than dump — raw varBinds stay on the relay.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any

from models.models import Asset
from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_SNMP_TIMEOUT_S = 30


# ── Dispatch helper ───────────────────────────────────────────────────


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_SNMP_TIMEOUT_S + 15)
    return asyncio.run(coro)


async def _dispatch_snmp(
    db,
    org_id: int,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: str | None,
    credential_id: str | None,
    unauthenticated: bool = False,
) -> tuple[Asset, dict]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")
    target = asset.ip or asset.fqdn or asset.hostname
    if not target:
        raise ValueError(f"asset {asset_id} has no ip or hostname")
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    if unauthenticated:
        # community_probe op needs no creds — the relay sweeps defaults itself.
        snmp_creds: dict = {}
    else:
        if not credential_id:
            raise ValueError("credential_id missing from audit context")
        raw_creds = await load_credentials(db, credential_id, org_id)
        if not raw_creds:
            raise ValueError(f"credential {credential_id} not found")
        snmp_creds = {
            "version": raw_creds.get("version") or "v2c",
            "community": raw_creds.get("community") or "",
            "username": raw_creds.get("username") or "",
            "auth_protocol": raw_creds.get("auth_protocol") or "none",
            "auth_key": raw_creds.get("auth_key") or "",
            "priv_protocol": raw_creds.get("priv_protocol") or "none",
            "priv_key": raw_creds.get("priv_key") or "",
        }

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="snmp_query",
        config={"target": target, "port": 161},
        credentials=snmp_creds,
        params={"op": op, "op_params": op_params, "timeout_s": _SNMP_TIMEOUT_S},
    )
    return asset, (result or {})


def _ctx(params: dict) -> tuple[str | None, str | None]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


def _trim(rows: list, limit: int = 40) -> list:
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [{"_truncated": True, "_total": len(rows)}]


# ── Orientation ───────────────────────────────────────────────────────


@agent_tool(
    "snmp_get_system_info",
    "Return the device's MIB-2 system group: sysDescr (vendor/model/firmware), "
    "sysObjectID, sysName, sysContact, sysLocation, sysUpTime. Call once at "
    "the start of every audit — sysDescr reveals what kind of device you're "
    "talking to and shapes the rest of the audit.",
    {"asset_id": {"type": "integer"}},
)
def snmp_get_system_info_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(db, org_id, asset_id, "sys_info", {}, relay, cred))
    return result


@agent_tool(
    "snmp_probe_default_communities",
    "Try a short, hardcoded list of common default community strings "
    "(public, private, cisco, manager, community, admin, monitor, default) "
    "and return any that answer. Every accepted community is a finding — "
    "weak/default community = unauthenticated read of the entire device. "
    "READ-ONLY; this is not a brute-force.",
    {"asset_id": {"type": "integer"}},
)
def snmp_probe_default_communities_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(
        db, org_id, asset_id, "community_probe", {}, relay, cred, unauthenticated=True,
    ))
    return result


# ── Inventory / topology ──────────────────────────────────────────────


@agent_tool(
    "snmp_list_interfaces",
    "Walk ifTable and return every interface with descr, type, speed, MAC, "
    "and admin/oper status. Useful for inventorying physical ports, spotting "
    "admin-down interfaces that are still plugged in, or odd types "
    "(tunnel/loopback proliferation).",
    {"asset_id": {"type": "integer"}},
)
def snmp_list_interfaces_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(db, org_id, asset_id, "interfaces", {}, relay, cred))
    ifaces = result.get("interfaces") or []
    return {
        "total": len(ifaces),
        "up_count": sum(1 for i in ifaces if i.get("oper") == "up"),
        "interfaces": _trim(ifaces, 60),
    }


@agent_tool(
    "snmp_get_arp_table",
    "Walk ipNetToMediaTable and return ARP/neighbor cache entries (ip, mac, "
    "type). Excellent for asset discovery — every MAC in this table is a host "
    "the device has recently seen on its L2 segments.",
    {"asset_id": {"type": "integer"}},
)
def snmp_get_arp_table_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(db, org_id, asset_id, "arp_table", {}, relay, cred))
    entries = result.get("entries") or []
    return {"total": len(entries), "entries": _trim(entries, 80)}


@agent_tool(
    "snmp_get_ip_addresses",
    "Walk ipAddrTable and return local IP addresses + masks per interface. "
    "Use to map the device's L3 presence — transit/management/service VLANs.",
    {"asset_id": {"type": "integer"}},
)
def snmp_get_ip_addresses_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(db, org_id, asset_id, "ip_addrs", {}, relay, cred))
    addrs = result.get("addresses") or []
    return {"total": len(addrs), "addresses": _trim(addrs, 40)}


@agent_tool(
    "snmp_get_routing_table",
    "Walk ipRouteTable and return destination / mask / next-hop triplets. "
    "Flags: unexpected default routes, routes to RFC1918 space that shouldn't "
    "exist on a public device, or routes to management networks leaking into "
    "user-facing devices.",
    {"asset_id": {"type": "integer"}},
)
def snmp_get_routing_table_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(db, org_id, asset_id, "routing_table", {}, relay, cred))
    routes = result.get("routes") or []
    return {"total": len(routes), "routes": _trim(routes, 60)}


# ── Escape hatch ──────────────────────────────────────────────────────


@agent_tool(
    "snmp_get",
    "Fetch a single OID by GET. Use for vendor-specific OIDs the focused "
    "tools don't cover (e.g. a Cisco running-config MIB, a PDU load sensor). "
    "READ-ONLY — never invokes SET.",
    {
        "asset_id": {"type": "integer"},
        "oid": {"type": "string", "description": "Dotted OID, e.g. '1.3.6.1.2.1.1.1.0'"},
    },
)
def snmp_get_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    oid = (params.get("oid") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(db, org_id, asset_id, "get", {"oid": oid}, relay, cred))
    return result


@agent_tool(
    "snmp_walk",
    "GETNEXT walk rooted at an OID. Capped at 500 rows. Use for arbitrary "
    "subtree exploration. READ-ONLY.",
    {
        "asset_id": {"type": "integer"},
        "oid": {"type": "string", "description": "Base OID to walk"},
    },
)
def snmp_walk_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    oid = (params.get("oid") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(db, org_id, asset_id, "walk", {"oid": oid}, relay, cred))
    rows = result.get("rows") or []
    return {
        "base_oid": result.get("base_oid"),
        "total": len(rows),
        "rows": _trim(rows, 60),
    }


# ── Registry ──────────────────────────────────────────────────────────


_SNMP_TOOL_NAMES = [
    # Orientation
    "snmp_get_system_info", "snmp_probe_default_communities",
    # Inventory / topology
    "snmp_list_interfaces", "snmp_get_arp_table",
    "snmp_get_ip_addresses", "snmp_get_routing_table",
    # Escape hatch
    "snmp_get", "snmp_walk",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="snmp",
    label="SNMP Audit",
    description=(
        "Credentialed SNMP audit for network devices (routers, switches, "
        "firewalls, printers) and legacy systems. Hunts weak community "
        "strings, outdated firmware, exposed services, and uses ARP/routing "
        "tables as a passive asset-discovery signal."
    ),
    supported_os=["network_device", "linux", "windows"],
    auth_modes=["community", "usm"],
    relay_method="snmp_query",
    credential_connector_ids=["snmp_device", "snmp-device"],
    tool_names=_SNMP_TOOL_NAMES,
    missions=[
        MissionTemplate(
            key="device_posture",
            label="Device Posture",
            description="Weak community strings, default credentials, outdated firmware in sysDescr, exposed management surfaces.",
            prompt_key="snmp_audit_device_posture",
            suggested_budget=10,
            cost_hint="low",
        ),
        MissionTemplate(
            key="inventory_discovery",
            label="Inventory & Discovery",
            description="Use ARP/routing tables to discover adjacent hosts; map interfaces; surface L3 presence.",
            prompt_key="snmp_audit_inventory_discovery",
            suggested_budget=15,
            cost_hint="low",
        ),
        MissionTemplate(
            key="explore",
            label="Explore (creative)",
            description="No fixed checklist — agent reasons freely about SNMP-surface exposures given the device type.",
            prompt_key="snmp_audit_explore",
            suggested_budget=20,
            cost_hint="medium",
        ),
    ],
))
