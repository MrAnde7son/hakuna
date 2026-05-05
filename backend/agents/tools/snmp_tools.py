"""SNMP tool palette for the SNMP Audit ReAct agent.

Three primitives. The relay handler (hakuna-relay-agent/agent/snmp_query.py)
wraps pysnmp's ``getCmd`` / ``nextCmd`` only — it never invokes ``setCmd``,
so the protocol enforces read-only end-to-end:

  - ``snmp_get(oid)``                — single OID GET
  - ``snmp_walk(base_oid)``          — bounded GETNEXT walk
  - ``snmp_probe_default_communities`` — credential-less sweep of common
    default community strings; if any answers, it's stashed in run_ctx so
    subsequent get/walk calls work without an explicit credential

Mission-specific recipes (sysDescr, ifTable, ipNetToMedia, hrSWInstalled,
etc.) live in the prompts — the agent picks the OID for the question.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging

from models.models import Asset
from agents.agent_tools import agent_tool, NeedsApproval
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target, split_host_port
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_SNMP_TIMEOUT_S = 30


# ── Dispatch helper ───────────────────────────────────────────────────


def _run_async(coro):
    # See agents/tools/ssh_tools.py for the cross-loop-future rationale.
    from core.event_loop import get_main_loop, is_on_main_loop
    main_loop = get_main_loop()
    if main_loop is not None and main_loop.is_running() and not is_on_main_loop():
        fut = asyncio.run_coroutine_threadsafe(coro, main_loop)
        return fut.result(timeout=_SNMP_TIMEOUT_S + 15)
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
    fallback_community: str | None = None,
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

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    if unauthenticated:
        snmp_creds: dict = {}
    elif credential_id:
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
    elif fallback_community:
        snmp_creds = {
            "version": "v2c",
            "community": fallback_community,
            "username": "",
            "auth_protocol": "none",
            "auth_key": "",
            "priv_protocol": "none",
            "priv_key": "",
        }
    else:
        raise ValueError(
            "no SNMP credential available — call snmp_probe_default_communities "
            "first; if it accepts a community, subsequent SNMP tools will use it"
        )

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="snmp_query",
        config={"target": target, "port": target_port or 161},
        credentials=snmp_creds,
        params={"op": op, "op_params": op_params, "timeout_s": _SNMP_TIMEOUT_S},
    )
    return asset, (result or {})


def _ctx(params: dict) -> tuple[str | None, str | None, str | None]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    community = params.get("_snmp_community")
    return relay, cred, community


def _trim(rows: list, limit: int = 60) -> list:
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [{"_truncated": True, "_total": len(rows)}]


# ── Generic primitives ───────────────────────────────────────────────


@agent_tool(
    "snmp_probe_default_communities",
    "Try a short, hardcoded list of common default community strings "
    "(public, private, cisco, manager, community, admin, monitor, default) "
    "and return any that answer. Every accepted community is a finding — "
    "weak/default community = unauthenticated read of the entire device. "
    "READ-ONLY. If a community is accepted, it's stashed in run_ctx so "
    "subsequent snmp_get/snmp_walk calls use it automatically.",
    {"asset_id": {"type": "integer"}},
)
def snmp_probe_default_communities_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred, _ = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(
        db, org_id, asset_id, "community_probe", {}, relay, cred, unauthenticated=True,
    ))
    accepted = (result or {}).get("accepted_communities") or []
    agent_id = params.get("_agent_id")
    if accepted and agent_id:
        from agents.agent_engine import update_run_ctx
        update_run_ctx(db, agent_id, {"_snmp_community": accepted[0]})
    return result


@agent_tool(
    "snmp_get",
    "Fetch a single OID by GET. READ-ONLY — never invokes SET. Use for any "
    "scalar value: sysDescr (1.3.6.1.2.1.1.1.0), sysObjectID "
    "(1.3.6.1.2.1.1.2.0), sysName (1.3.6.1.2.1.1.5.0), sysContact "
    "(1.3.6.1.2.1.1.4.0), sysLocation (1.3.6.1.2.1.1.6.0), sysUpTime "
    "(1.3.6.1.2.1.1.3.0), or any vendor-specific OID (Cisco config-copy, "
    "PDU sensors, etc.).",
    {
        "asset_id": {"type": "integer"},
        "oid": {"type": "string", "description": "Dotted OID, e.g. '1.3.6.1.2.1.1.1.0'"},
    },
)
def snmp_get_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    oid = (params.get("oid") or "").strip()
    relay, cred, community = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(
        db, org_id, asset_id, "get", {"oid": oid}, relay, cred,
        fallback_community=community,
    ))
    return result


@agent_tool(
    "snmp_walk",
    "GETNEXT walk rooted at an OID. READ-ONLY. Capped at 500 rows on the "
    "relay. Use for arbitrary subtree exploration. Common subtrees:\n"
    "  • System group: 1.3.6.1.2.1.1 (sysDescr/Name/Contact/Location/UpTime)\n"
    "  • Interfaces (ifTable): 1.3.6.1.2.1.2.2.1 (descr/type/speed/admin/oper)\n"
    "  • IP addresses (ipAddrTable): 1.3.6.1.2.1.4.20\n"
    "  • Routing table (ipRouteTable): 1.3.6.1.2.1.4.21\n"
    "  • ARP / neighbor cache (ipNetToMedia): 1.3.6.1.2.1.4.22\n"
    "  • TCP listeners (tcpConnTable): 1.3.6.1.2.1.6.13\n"
    "  • UDP bound ports (udpTable): 1.3.6.1.2.1.7.5\n"
    "  • Host resources — installed software (hrSWInstalled): 1.3.6.1.2.1.25.6.3\n"
    "  • Host resources — running processes (hrSWRun): 1.3.6.1.2.1.25.4.2\n"
    "  • Host resources — devices (hrDevice): 1.3.6.1.2.1.25.3.2\n"
    "  • Cisco running-config copy MIB: 1.3.6.1.4.1.9.9.96 (vendor-specific)",
    {
        "asset_id": {"type": "integer"},
        "oid": {"type": "string", "description": "Base OID to walk"},
    },
)
def snmp_walk_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    oid = (params.get("oid") or "").strip()
    relay, cred, community = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(
        db, org_id, asset_id, "walk", {"oid": oid}, relay, cred,
        fallback_community=community,
    ))
    rows = result.get("rows") or []
    return {
        "base_oid": result.get("base_oid"),
        "total": len(rows),
        "rows": _trim(rows, 60),
    }


# ── Write op (always behind NeedsApproval) ───────────────────────────


@agent_tool(
    "snmp_set",
    "SNMP SET — write one or more OID values. ALWAYS PAUSES for user "
    "approval. Each entry: `{oid, value, type?}`. `type` selects the SNMP "
    "datatype (`Integer`, `OctetString`, `Unsigned32`, `Counter32`, "
    "`Counter64`, `Gauge32`, `IpAddress`, `ObjectIdentifier`, `TimeTicks`); "
    "defaults to `Integer` for ints and `OctetString` for strings. Common "
    "uses: change sysContact / sysLocation, toggle an interface admin status "
    "(ifAdminStatus.<idx> = 1 up / 2 down), reload a Cisco config "
    "(ccCopyEntryRowStatus = 4 for createAndGo). The remote device must "
    "permit SNMP writes (separate read/write community or v3 user with "
    "write-perm).",
    {
        "asset_id": {"type": "integer"},
        "values": {
            "type": "array",
            "description": "List of {oid, value, type?} entries to SET",
            "items": {
                "type": "object",
                "properties": {
                    "oid": {"type": "string"},
                    "value": {},
                    "type": {"type": "string"},
                },
                "required": ["oid", "value"],
            },
        },
    },
)
def snmp_set_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    values = params.get("values") or []
    if not isinstance(values, list) or not values:
        return {"error": "values must be a non-empty list of {oid, value, type?}"}
    if not params.get("_approved"):
        summary = ", ".join(
            f"{v.get('oid')}={v.get('value')!r}" for v in values
        )
        raise NeedsApproval(
            reason=f"SNMP SET on {len(values)} OID(s): {summary}",
            category="snmp_set",
            details={"values": values},
        )
    relay, cred, community = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_snmp(
        db, org_id, asset_id, "set", {"values": values}, relay, cred,
        fallback_community=community,
    ))
    return result


# ── Registry ──────────────────────────────────────────────────────────


_SNMP_TOOL_NAMES = [
    "snmp_probe_default_communities",
    "snmp_get",
    "snmp_walk",
    # Write primitive — every call routes through user approval.
    "snmp_set",
    # CVE correlation — deterministic inventory→CVE matching pass
    "correlate_software_to_cves",
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
    required_ports=(161,),
    safety_class="anon_standard",
    auto_trigger_policy="auto_org_opt_in",
    cooldown_hours=24,
    compliance_tags=("cis_benchmarks", "nist_csf_pr_ac"),
    missions=[
        MissionTemplate(
            key="exposure_audit",
            label="Exposure Audit",
            description=(
                "End-to-end SNMP exposure hunt: device posture (weak "
                "communities, default credentials, EOL firmware in sysDescr, "
                "missing contact/location), inventory + topology (interfaces, "
                "ARP / routing / IP tables, listening ports), and host "
                "resources (installed software, running processes) when "
                "HOST-RESOURCES-MIB is reachable."
            ),
            prompt_key="snmp_audit_exposure_audit",
            suggested_budget=25,
            cost_hint="medium",
        ),
    ],
))
