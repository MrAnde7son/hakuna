"""OT/ICS passive-only audit tool palette (Phase 5).

Companion to ``ot_protocol_tools`` for protocols where any PDU we craft
risks side effects we don't want to own — Yokogawa Vnet/IP (a JP DCS
control bus, not a polling protocol) and CC-Link IE (a Mitsubishi-led
industrial Ethernet fieldbus).

## Safety class

``ot_passive_only`` — the relay never crafts a protocol-level PDU. The
sole op is ``passive_listen``: bind a UDP socket on a well-known
fingerprint port, capture frames for a bounded window (≤10s), match
against a closed allowlist of vendor signatures, and report what was
seen. No active query is sent; no broadcast is initiated.

## Why so restrictive

Yokogawa Vnet/IP traffic is critical-path DCS control. Even a benign
identification request is a violation of the contract we sign with
plant operators. CC-Link IE is fundamentally L2; a relay running in
userspace on a shared subnet can sometimes observe broadcast / EAPoL-
shaped beacons without doing anything. That's the entire scope of
this audit.

## Op palette

| Op                        | What it does                                                   |
|---------------------------|----------------------------------------------------------------|
| ``passive_listen``        | Bind UDP, listen ≤10s, match captured frames vs. signature DB |

The signature DB is **closed** at the relay — the LLM cannot supply
arbitrary regexes. The tool layer offers a fixed set of named
profiles (``yokogawa_vnetip``, ``cclink_ie``); any other profile name
is rejected at the tool layer and again at the relay.
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


_PASSIVE_TIMEOUT_S = 15
_MAX_LISTEN_S = 10  # absolute cap; relay clamps to this regardless of params

# Closed allowlist of passive-listen profiles. Names map at the relay to
# (port, signatures). The LLM picks a name; it cannot pass arbitrary
# bytes-to-match regexes.
_PROFILE_NAMES = ("yokogawa_vnetip", "cclink_ie")


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_PASSIVE_TIMEOUT_S + 30)
    return asyncio.run(coro)


def _ctx(params: dict) -> tuple[Optional[str], Optional[str]]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


async def _dispatch(
    db,
    asset_id: int,
    profile: str,
    duration_s: int,
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
    if profile not in _PROFILE_NAMES:
        raise ValueError(f"unknown profile {profile!r}; allowed: {_PROFILE_NAMES}")

    target, target_port = split_host_port(raw_target)
    if target_port is None:
        _, target_port = resolve_asset_target(asset)

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    duration_clamped = max(1, min(int(duration_s or 5), _MAX_LISTEN_S))

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="ot_passive_probe",
        config={"target": target, "port": target_port or 0},
        credentials={},
        params={
            "op": "passive_listen",
            "op_params": {
                "profile": profile,
                "duration_s": duration_clamped,
            },
            "timeout_s": _PASSIVE_TIMEOUT_S,
        },
    )
    return asset, (result or {})


@agent_tool(
    "ot_passive_listen",
    "Passively listen for a vendor-specific OT broadcast / identifying "
    "traffic on the relay's local interfaces. The relay binds a UDP "
    "socket on the profile's well-known port, captures frames for a "
    "bounded window (≤10s), and returns whether the vendor signature "
    "appeared. NO PDU IS SENT — this is a pure receive-only listener. "
    "Profiles supported: `yokogawa_vnetip` (Yokogawa Vnet/IP DCS, UDP "
    "12289–12298 range), `cclink_ie` (CC-Link IE Field, UDP 61450). "
    "Unknown profiles are rejected. Returns: `{profile: str, presence: "
    "bool, frames_observed: int, peers: list[str], duration_s: int, "
    "_errors?: dict}`.",
    {
        "asset_id": {"type": "integer"},
        "profile": {"type": "string"},
        "duration_s": {"type": "integer"},
    },
)
def ot_passive_listen_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    profile = (params.get("profile") or "").strip()
    duration_s = params.get("duration_s") or 5
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, profile, duration_s, relay))
    return result


_OT_PASSIVE_TOOL_NAMES = [
    "ot_passive_listen",
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="ot_passive",
    label="OT/ICS Passive Audit",
    description=(
        "Passive-only OT/ICS audit. The relay never crafts a protocol "
        "PDU; it binds a UDP socket and listens for vendor-signature "
        "frames within a bounded time window. Targets Yokogawa Vnet/IP "
        "and CC-Link IE — protocols where any active probe is a "
        "violation of plant-operator contracts. Per-asset OT consent "
        "required, 7-day cooldown."
    ),
    supported_os=["dcs", "plc", "appliance"],
    auth_modes=["anonymous"],
    relay_method="ot_passive_probe",
    credential_connector_ids=[],
    tool_names=_OT_PASSIVE_TOOL_NAMES,
    # No required_ports — the listener binds whatever the profile dictates,
    # and presence isn't gated on a specific scanner-reported open port.
    required_ports=(),
    safety_class="ot_passive_only",
    auto_trigger_policy="per_asset_consent",
    cooldown_hours=168,
    compliance_tags=("iec_62443_3_3", "meti_ot_security_guideline_v3"),
    missions=[
        MissionTemplate(
            key="triage",
            label="OT Passive Presence Triage",
            description=(
                "Run one ot_passive_listen per profile the operator "
                "asked about. Emit one finding per profile that produced "
                "a positive presence signal; do not emit anything for a "
                "negative result (absence is not evidence — it's just "
                "silence in the listening window)."
            ),
            prompt_key="ot_passive_audit_triage",
            suggested_budget=4,
            cost_hint="low",
        ),
    ],
))
