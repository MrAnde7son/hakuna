"""Exposed anonymous-protocol tool palette (Phase 4.1).

Single audit family covering the legacy anon-misconfig protocols that
don't slot into the datastore family but share the same triage shape:

  - FTP                (TCP 21)   — `ftp_anon_probe`
  - VNC                (TCP 5900) — `vnc_anon_probe`
  - DNS zone transfer  (TCP 53)   — `dns_axfr_probe`
  - Kerberos KDC       (TCP 88)   — `kerberos_anon_probe`
  - TFTP common-files  (UDP 69)   — `tftp_anon_probe`

Each tool dispatches a `method=anon_protocol_probe` task to the relay.
The relay handler picks a per-op probe by the `op` param, mirroring the
exposed_datastore pattern. Op selection is allowlisted relay-side in
``_OP_HANDLERS`` so an unknown op never reaches network code.

## Safety stance

Every op is **read-only** and bounded:
  - FTP: anonymous login attempt + LIST cap of 5 names
  - VNC: RFB version + security-type enumeration only — no auth attempt
  - DNS AXFR: a single zone-transfer attempt against the asset's apex,
    capped at 50 records
  - Kerberos: TCP reachability fingerprint only — no AS-REQ. Username
    enumeration / AS-REP roasting belongs in a separate consent-gated
    mission, not in `triage`.
  - TFTP: hardcoded common-filename probe list (no LLM-supplied paths),
    capped at 8 attempts, first 256 bytes per hit

The audit's purpose is *exposure triage*: confirm whether the service is
listening anonymously (or, for AXFR, mis-permissioned), classify what an
unauthenticated caller would see, emit a finding sized to impact.
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


def _run_async(coro):
    # See agents/tools/ssh_tools.py for the cross-loop-future rationale.
    from core.event_loop import get_main_loop, is_on_main_loop
    main_loop = get_main_loop()
    if main_loop is not None and main_loop.is_running() and not is_on_main_loop():
        fut = asyncio.run_coroutine_threadsafe(coro, main_loop)
        return fut.result(timeout=_PROBE_TIMEOUT_S + 15)
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

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    # The DNS-AXFR probe needs the zone name; default to the asset's fqdn
    # apex when not supplied.
    extended_params = dict(op_params or {})
    if op == "dns_axfr" and "zone" not in extended_params:
        zone = asset.fqdn or asset.hostname
        if zone:
            extended_params["zone"] = zone

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="anon_protocol_probe",
        config={"target": target, "port": port},
        credentials={},  # all ops are anonymous by spec
        params={"op": op, "op_params": extended_params, "timeout_s": _PROBE_TIMEOUT_S},
    )
    return asset, (result or {})


# ── FTP ──────────────────────────────────────────────────────────────


@agent_tool(
    "ftp_anon_probe",
    "Probe an exposed FTP server (default 21) for anonymous-login access. "
    "Reads the 220 banner, sends `USER anonymous` + `PASS anonymous@hakuna`, "
    "and reports whether the server returned 230 (login successful). On "
    "success, also returns a small `LIST` sample (cap 5 names) so the "
    "finding evidence shows what an unauthenticated caller could see. "
    "NEVER downloads files. Returns: "
    "`{anonymous_login_allowed: bool, banner: str, sample_listing: [str], "
    "_errors?: dict}`. Anonymous-login allowed = the finding lead.",
    {"asset_id": {"type": "integer"}},
)
def ftp_anon_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "ftp", {}, relay, 21))
    return result


# ── VNC ──────────────────────────────────────────────────────────────


@agent_tool(
    "vnc_anon_probe",
    "Probe an exposed VNC server (default 5900) for an unauthenticated "
    "security type. Speaks the RFB handshake far enough to read the "
    "advertised protocol version and security-type list — if security "
    "type 1 (None) is offered, the server accepts authless screen-sharing "
    "(full keyboard + mouse + screen). NEVER attempts to authenticate or "
    "read framebuffer pixels. Returns: "
    "`{auth_required: bool, rfb_version: str, security_types: [int], "
    "_errors?: dict}`. ``auth_required: false`` is the finding lead.",
    {"asset_id": {"type": "integer"}},
)
def vnc_anon_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "vnc", {}, relay, 5900))
    return result


# ── DNS AXFR ─────────────────────────────────────────────────────────


@agent_tool(
    "dns_axfr_probe",
    "Probe a DNS server (default TCP 53) for unauthorized zone-transfer "
    "(AXFR) access. The zone name is derived from the asset's fqdn apex "
    "when not supplied. AXFR exposes every record in the zone — internal "
    "subdomains, mail servers, IP plan — and is the textbook misconfig "
    "for self-hosted authoritative servers. Returns at most 50 records "
    "for evidence. Returns: `{axfr_allowed: bool, zone: str, "
    "record_count: int, sample_records: [str], _errors?: dict}`.",
    {"asset_id": {"type": "integer"}, "zone": {"type": "string"}},
)
def dns_axfr_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    zone = params.get("zone")
    op_params = {"zone": zone} if zone else {}
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "dns_axfr", op_params, relay, 53))
    return result


# ── Kerberos ─────────────────────────────────────────────────────────


@agent_tool(
    "kerberos_anon_probe",
    "Probe a Kerberos KDC (default TCP 88) for reachability and realm "
    "fingerprint. Sends a deliberately malformed AS-REQ-shaped TCP "
    "message and parses the resulting KRB-ERROR for the server's realm "
    "string. NEVER performs username enumeration or AS-REP roasting — "
    "that's a separate consent-gated mission. Returns: "
    "`{kdc_reachable: bool, realm: str | null, _errors?: dict}`. The "
    "presence of a reachable KDC outside the corporate perimeter is the "
    "finding lead.",
    {"asset_id": {"type": "integer"}},
)
def kerberos_anon_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "kerberos", {}, relay, 88))
    return result


# ── TFTP ─────────────────────────────────────────────────────────────


@agent_tool(
    "tftp_anon_probe",
    "Probe a TFTP server (default UDP 69) for unauthenticated read access "
    "to common bootstrap files. Sends RRQ for a hardcoded short list of "
    "filenames typically found on misconfigured network gear and PXE "
    "servers (`running-config`, `startup-config`, `boot.cfg`, "
    "`pxelinux.cfg/default`, etc.). The filename list is fixed at the "
    "relay — the agent cannot supply paths. Returns the names of any "
    "files that responded with DATA (no contents). Returns: "
    "`{readable_files: [str], probed_count: int, _errors?: dict}`. "
    "Any non-empty `readable_files` list is the finding lead.",
    {"asset_id": {"type": "integer"}},
)
def tftp_anon_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "tftp", {}, relay, 69))
    return result


# ── Registry ─────────────────────────────────────────────────────────


_EXPOSED_ANON_PROTOCOL_TOOL_NAMES = [
    "ftp_anon_probe",
    "vnc_anon_probe",
    "dns_axfr_probe",
    "kerberos_anon_probe",
    "tftp_anon_probe",
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="exposed_anon_protocol",
    label="Exposed Anon-Protocol Audit",
    description=(
        "Anonymous-probe audit for legacy network protocols whose default "
        "or mis-administered configuration exposes data or control to "
        "unauthenticated callers (FTP anon, VNC None-auth, DNS AXFR, "
        "Kerberos KDC reachability fingerprint, TFTP common-files). "
        "Read-only; never authenticates, never enumerates users, never "
        "downloads file contents."
    ),
    supported_os=["linux", "windows", "network"],
    auth_modes=["anonymous"],
    relay_method="anon_protocol_probe",
    credential_connector_ids=[],
    tool_names=_EXPOSED_ANON_PROTOCOL_TOOL_NAMES,
    required_ports=(21, 53, 88, 69, 5900),
    safety_class="anon_standard",
    auto_trigger_policy="auto_org_opt_in",
    cooldown_hours=24,
    compliance_tags=("cis_benchmarks", "nist_csf_pr_ac", "pci_dss_4"),
    missions=[
        MissionTemplate(
            key="triage",
            label="Anon-Protocol Triage",
            description=(
                "For each exposed legacy protocol port, confirm whether "
                "the service accepts anonymous access (or, for DNS, allows "
                "AXFR) and emit a single sized finding."
            ),
            prompt_key="exposed_anon_protocol_audit_triage",
            suggested_budget=8,
            cost_hint="low",
        ),
    ],
))
