"""IPMI BMC audit tool palette (Phase 4.2).

Single audit family targeting two devastating BMC misconfigurations on
UDP 623:

  - Cipher Suite 0 acceptance — auth=none + integ=none + conf=none. An
    attacker can authenticate as ANY local user with NO password. Full
    out-of-band hardware control.
  - RAKP-3 hash leak (CVE-2013-4786) — BMC returns the user's password
    HMAC during RAKP-2 *before* verifying the client's RAKP-3 HMAC.
    The hash is offline-crackable. Spec-compliant; every IPMI 2.0 BMC
    is technically vulnerable.

## Tools

  - `ipmi_cipher_zero_probe(asset_id)` — sends a Cipher Suite 0 Open
    Session Request and reports whether the BMC accepts it.
  - `ipmi_rakp_hash_probe(asset_id, username)` — opens a session then
    sends RAKP-1 with the supplied username (default ``admin``); if the
    BMC returns a RAKP-2 with a non-zero KEAC, the hash leaked. The
    handler does NOT brute-force the hash — that's a separate offline
    workflow.

Both probes dispatch ``method=ipmi_probe`` to the relay; op-allowlist
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


_PROBE_TIMEOUT_S = 10  # IPMI BMCs can be sluggish; 8s is too tight


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
    port = target_port or 623  # IPMI BMC default UDP port

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="ipmi_probe",
        config={"target": target, "port": port},
        credentials={},
        params={"op": op, "op_params": op_params, "timeout_s": _PROBE_TIMEOUT_S},
    )
    return asset, (result or {})


# ── Cipher Zero ──────────────────────────────────────────────────────


@agent_tool(
    "ipmi_cipher_zero_probe",
    "Probe an IPMI BMC (default UDP 623) for Cipher Suite 0 acceptance. "
    "Sends an RMCP+ Open Session Request with auth=NONE, integrity=NONE, "
    "confidentiality=NONE. If the BMC returns success status with the "
    "same null cipher echoed back, it accepts cipher zero — meaning any "
    "local IPMI user can authenticate with NO password and gain full "
    "out-of-band control of the host (power, console, virtual media). "
    "Returns: `{cipher_zero_accepted: bool, bmc_responded: bool, "
    "session_id: str | null, status_code: int | null, _errors?: dict}`. "
    "``cipher_zero_accepted: true`` is a critical finding.",
    {"asset_id": {"type": "integer"}},
)
def ipmi_cipher_zero_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "cipher_zero", {}, relay))
    return result


# ── RAKP-3 hash leak ─────────────────────────────────────────────────


@agent_tool(
    "ipmi_rakp_hash_probe",
    "Probe an IPMI BMC (default UDP 623) for the RAKP-3 hash-disclosure "
    "vulnerability (CVE-2013-4786). Sends RAKP message 1 with the supplied "
    "username (default `admin`); if the BMC returns RAKP-2 with status 0 "
    "and a non-zero Key Exchange Authentication Code, the response leaks "
    "an HMAC of the user's password — offline-crackable. The probe DOES "
    "NOT crack the hash; downstream credential-recovery workflows do that. "
    "All IPMI 2.0 BMCs are technically vulnerable per spec; the finding "
    "documents exposure surface, not a bug to patch. Returns: "
    "`{hash_leaked: bool, username_tested: str, keac_hex: str | null, "
    "auth_algo: int | null, _errors?: dict}`.",
    {
        "asset_id": {"type": "integer"},
        "username": {"type": "string"},
    },
)
def ipmi_rakp_hash_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    username = params.get("username") or "admin"
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(
        db, asset_id, "rakp_hash", {"username": username}, relay,
    ))
    return result


# ── Registry ─────────────────────────────────────────────────────────


_IPMI_TOOL_NAMES = [
    "ipmi_cipher_zero_probe",
    "ipmi_rakp_hash_probe",
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="ipmi_bmc",
    label="IPMI BMC Audit",
    description=(
        "Anonymous-probe audit for BMC (Baseboard Management Controller) "
        "exposure via IPMI/RMCP+ on UDP 623. Detects Cipher Suite 0 "
        "acceptance (any user, no password → full host control) and the "
        "RAKP-3 hash-leak (CVE-2013-4786, spec-compliant disclosure). "
        "Read-only; no power, console, or virtual-media commands."
    ),
    supported_os=["bmc", "appliance"],
    auth_modes=["anonymous"],
    relay_method="ipmi_probe",
    credential_connector_ids=[],
    tool_names=_IPMI_TOOL_NAMES,
    required_ports=(623,),
    safety_class="anon_ipmi",
    auto_trigger_policy="auto_org_opt_in",
    cooldown_hours=24,
    compliance_tags=("nist_csf_pr_ac", "cis_benchmarks"),
    missions=[
        MissionTemplate(
            key="triage",
            label="BMC Exposure Triage",
            description=(
                "Probe for Cipher Suite 0 + RAKP-3 hash leak; emit one "
                "finding per misconfiguration found. Skip if BMC is not "
                "reachable on UDP 623."
            ),
            prompt_key="ipmi_bmc_audit_triage",
            suggested_budget=6,
            cost_hint="low",
        ),
    ],
))
