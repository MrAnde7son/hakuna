"""NetBIOS / LLMNR / mDNS local-LAN audit tool palette (Phase 4.3).

Single audit family for legacy LAN name-resolution + service-discovery
protocols that should be disabled on hardened modern networks:

  - NBNS (NetBIOS Name Service) on UDP 137
  - LLMNR (Link-Local Multicast Name Resolution) on UDP 5355
  - mDNS (Multicast DNS / DNS-SD) on UDP 5353

These protocols are not internet-routable; the audit only makes sense
when the relay is on the same broadcast domain as the asset. The
auto-trigger rule's predicate enforces that — the rule fires only when
the relay reports a local-interface CIDR that contains the asset's IP.

## Tools

  - `nbns_probe(asset_id)` — NBSTAT query for the host's NetBIOS name
    table. Reveals workgroup, machine name, signed-on user.
  - `llmnr_probe(asset_id)` — LLMNR query for the host's name. A reply
    confirms LLMNR is enabled — exploitable for credential theft via
    poisoning attacks.
  - `mdns_probe(asset_id)` — mDNS query for `_services._dns-sd._udp`
    (RFC 6763 service enumeration). Lists advertised services.

All three dispatch ``method=netbios_probe`` to the relay; op-allowlist
enforced relay-side. Anonymous by spec.
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


_PROBE_TIMEOUT_S = 6  # UDP probes; LAN-local so latency is low


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_PROBE_TIMEOUT_S + 15)
    return asyncio.run(coro)


def _ctx(params: dict) -> tuple[Optional[str], Optional[str]]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


async def _dispatch_probe(
    db,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: Optional[str],
    default_port: int,
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
    port = target_port or default_port

    # Forward the asset hostname so LLMNR/NBNS probes can build a query
    # for the right name. mDNS uses a service-enum query so the name
    # doesn't matter there.
    extended_params = dict(op_params or {})
    extended_params.setdefault("hostname", asset.hostname or asset.fqdn or "")

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="netbios_probe",
        config={"target": target, "port": port},
        credentials={},
        params={"op": op, "op_params": extended_params, "timeout_s": _PROBE_TIMEOUT_S},
    )
    return asset, (result or {})


# ── NBNS ─────────────────────────────────────────────────────────────


@agent_tool(
    "nbns_probe",
    "Probe a host (default UDP 137) for NetBIOS Name Service exposure. "
    "Sends an NBSTAT query (`*` name) and parses the response's name "
    "table. A reply confirms NBT-NS is enabled — Microsoft has disabled "
    "this by default since Windows 11 24H2; exposure on a modern network "
    "is a misconfig. The name table reveals workgroup/domain, machine "
    "name, and (for Windows hosts in interactive sessions) the signed-on "
    "user. Returns: `{nbns_enabled: bool, names: [{name, type, flags}], "
    "_errors?: dict}`. ``nbns_enabled: true`` is the finding lead.",
    {"asset_id": {"type": "integer"}},
)
def nbns_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "nbns", {}, relay, 137))
    return result


# ── LLMNR ────────────────────────────────────────────────────────────


@agent_tool(
    "llmnr_probe",
    "Probe a host (default UDP 5355) for Link-Local Multicast Name "
    "Resolution exposure. Sends a unicast LLMNR query for the host's "
    "own name; if the host replies, LLMNR is enabled. LLMNR is a "
    "well-documented credential-theft vector via poisoning attacks "
    "(Responder, Inveigh) — disabling it is a baseline hardening step "
    "on Windows. Returns: `{llmnr_enabled: bool, resolved_ip: str | "
    "null, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def llmnr_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "llmnr", {}, relay, 5355))
    return result


# ── mDNS ─────────────────────────────────────────────────────────────


@agent_tool(
    "mdns_probe",
    "Probe a host (default UDP 5353) for mDNS service-discovery exposure. "
    "Sends a unicast DNS-SD `_services._dns-sd._udp.local` PTR query and "
    "parses the response. The advertised service list (`_smb._tcp`, "
    "`_ssh._tcp`, `_workstation._tcp`, etc.) reveals the host's role and "
    "is often more than the operator intended. Returns: `{mdns_enabled: "
    "bool, advertised_services: [str], _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def mdns_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "mdns", {}, relay, 5353))
    return result


# ── Registry ─────────────────────────────────────────────────────────


_NETBIOS_LOCAL_TOOL_NAMES = [
    "nbns_probe",
    "llmnr_probe",
    "mdns_probe",
    "emit_finding",
    "emit_edge",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="netbios_local",
    label="NetBIOS / LLMNR / mDNS Local Audit",
    description=(
        "LAN-local audit for legacy name-resolution and service-discovery "
        "protocols (NBNS/LLMNR/mDNS) that should be disabled on hardened "
        "networks. Anonymous; only valid when the relay shares a broadcast "
        "domain with the target. Read-only — never poisons or spoofs."
    ),
    supported_os=["windows", "linux", "macos", "appliance"],
    auth_modes=["anonymous"],
    relay_method="netbios_probe",
    credential_connector_ids=[],
    tool_names=_NETBIOS_LOCAL_TOOL_NAMES,
    required_ports=(137, 5355, 5353),
    safety_class="anon_lan_local",
    auto_trigger_policy="auto_org_opt_in",
    cooldown_hours=24,
    compliance_tags=("cis_benchmarks", "nist_csf_pr_ac"),
    missions=[
        MissionTemplate(
            key="triage",
            label="LAN-Local Name-Resolution Triage",
            description=(
                "For each LAN-local protocol the host responds to "
                "(NBNS/LLMNR/mDNS), emit one finding documenting the "
                "exposure. Skip if no protocol responds (normal hardened "
                "Windows / fully-disabled mDNS Linux)."
            ),
            prompt_key="netbios_local_audit_triage",
            suggested_budget=6,
            cost_hint="low",
        ),
    ],
))
