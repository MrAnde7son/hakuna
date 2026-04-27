"""OT/ICS active-probe audit tool palette (Phase 5).

A single ``ot_protocol`` audit registration covering ten read-only
fingerprint probes across the major industrial control families. Every
op the LLM can call dispatches one specific PDU at the relay; the relay
enforces a hard op-allowlist plus a per-handler rate limiter (1 RPS
default, ≥2s minimum inter-PDU delay) so a buggy or prompt-injected loop
cannot hammer a PLC.

## Why a single audit, not ten

Same architectural pattern as ``exposed_datastore`` / ``exposed_anon_protocol``
/ ``netbios_local``: one ``ProtocolAudit``, one relay method, op-dispatch
inside the relay. Keeps the LLM's tool surface small (each tool exposes
exactly one ``op``), keeps the kickoff UI simple (one card per family,
not ten), and keeps compliance tagging coherent (every finding from the
family lights up the same IEC 62443 / METI v3 controls).

## Safety class

``ot_safe`` — read-only PDUs only. Dispatch refuses without a fresh
``Asset.easm_data['ot_audit_consent']`` record (90-day TTL); no
org-level switch can override per-asset consent. Cooldown raised to
7 days vs. the 24h default for everything else — PLCs are not the kind
of asset to re-poke daily.

## Op palette

Read-only fingerprints. Anything that would write a coil, change a
register, set a chassis state, or open a control session is OUT —
both at the tool layer (no such tool exists) and at the relay layer
(``_OP_HANDLERS`` is the closed set).

| Op                              | Port      | Family          | What it asks                              |
|---------------------------------|-----------|-----------------|-------------------------------------------|
| ``modbus_read_device_id``       | TCP 502   | Modbus          | FC 43 / MEI 14: vendor + product + rev    |
| ``modbus_read_holding``         | TCP 502   | Modbus          | FC 3: read N holding regs (≤16, ≤unit 1)  |
| ``s7_read_szl``                 | TCP 102   | Siemens S7      | COTP CR + Setup + Read SZL 0x0011 (CPU id)|
| ``enip_list_identity``          | TCP 44818 | EtherNet/IP CIP | ListIdentity                              |
| ``bacnet_read_property``        | UDP 47808 | BACnet/IP       | ReadProperty Object-Name on Device 0      |
| ``opcua_hello``                 | TCP 4840  | OPC UA          | Hello + ACK; reports protocol version     |
| ``melsec_read_cpu_info``        | TCP 5007  | Mitsubishi SLMP | Cmd 0x0101 / Sub 0x0000: CPU model name   |
| ``omron_fins_read_cpu_unit``    | UDP 9600  | Omron FINS      | MRC/SRC 0x05/0x01: CPU unit data read     |
| ``iec104_interrogate``          | TCP 2404  | IEC 60870-5-104 | U-format STARTDT + I-format C_IC_NA_1 (100)|
| ``profinet_dcp_unicast``        | UDP 34962 | PROFINET DCP    | Best-effort unicast DCP IDENTIFY          |

PROFINET DCP is canonically L2 multicast; relay-side raw L2 sockets
require root/CAP_NET_RAW which we don't want to require. The unicast
op is opportunistic — it works against PROFINET stacks that accept
unicast IDENTIFY (some Siemens IO-Devices do); skips silently otherwise.

## Tool naming convention

Tools mirror the op names with an ``_probe`` suffix where it reads
better. The relay only ever sees ``op``; tool names are LLM-facing.
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


_PROBE_TIMEOUT_S = 15  # OT devices can be sluggish; safer slack than the IPMI/datastore default


# Per-op default port. The relay accepts an explicit port from
# transport_config so an asset on a non-standard port still routes correctly,
# but the dispatcher fills these in by default.
_DEFAULT_PORTS: dict[str, int] = {
    "modbus_read_device_id": 502,
    "modbus_read_holding": 502,
    "s7_read_szl": 102,
    "enip_list_identity": 44818,
    "bacnet_read_property": 47808,
    "opcua_hello": 4840,
    "melsec_read_cpu_info": 5007,
    "omron_fins_read_cpu_unit": 9600,
    "iec104_interrogate": 2404,
    "profinet_dcp_unicast": 34962,
}


def _run_async(coro):
    """Run ``coro`` from a sync tool; if a loop is already running, hop to a
    thread (mirrors the IPMI/NetBIOS pattern — keeps tools sync from the
    LLM's perspective regardless of where the engine calls them from)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_PROBE_TIMEOUT_S + 30)
    return asyncio.run(coro)


def _ctx(params: dict) -> tuple[Optional[str], Optional[str]]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


async def _dispatch(
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
    port = target_port or _DEFAULT_PORTS.get(op) or 0

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="ot_protocol_probe",
        config={"target": target, "port": port},
        credentials={},
        params={"op": op, "op_params": op_params, "timeout_s": _PROBE_TIMEOUT_S},
    )
    return asset, (result or {})


# ── Modbus ───────────────────────────────────────────────────────────


@agent_tool(
    "modbus_read_device_id",
    "Send a Modbus TCP Read Device Identification (FC 43, MEI 14, code 0x01) "
    "to TCP 502 and parse the vendor / product code / revision strings the "
    "device reports. Read-only fingerprint; no coil writes, no register "
    "writes. Returns: `{reachable: bool, vendor: str | null, product_code: "
    "str | null, revision: str | null, _errors?: dict}`. Use this first "
    "when triaging a Modbus exposure — the vendor + product strings drive "
    "downstream CVE correlation.",
    {"asset_id": {"type": "integer"}},
)
def modbus_read_device_id_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "modbus_read_device_id", {}, relay))
    return result


@agent_tool(
    "modbus_read_holding",
    "Issue a single Modbus FC 3 Read Holding Registers request to TCP 502. "
    "Parameters: `start_addr` (0–65535), `count` (1–16; capped relay-side), "
    "`unit_id` (default 1, 0–247). The relay rate-limits this op like every "
    "other Modbus call and refuses unit_ids above 247. Read-only — there is "
    "no FC 6/16 / write tool in the palette. Use this when the device "
    "responds but the operator wants a small evidence sample (e.g. process "
    "values from a known register block) attached to the finding. Returns: "
    "`{reachable: bool, registers: list[int], unit_id: int, _errors?: dict}`.",
    {
        "asset_id": {"type": "integer"},
        "start_addr": {"type": "integer"},
        "count": {"type": "integer"},
        "unit_id": {"type": "integer"},
    },
)
def modbus_read_holding_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    op_params = {
        "start_addr": int(params.get("start_addr") or 0),
        "count": min(int(params.get("count") or 4), 16),
        "unit_id": int(params.get("unit_id") or 1),
    }
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "modbus_read_holding", op_params, relay))
    return result


# ── Siemens S7 ───────────────────────────────────────────────────────


@agent_tool(
    "s7_read_szl",
    "Open a TCP/102 COTP connection to a Siemens S7 PLC and request the "
    "System Status List (SZL) entry 0x0011 (Module Identification — CPU "
    "type, MLFB order code, firmware version). Read-only S7 diagnostic "
    "service; the handler does NOT issue Run/Stop, does NOT touch data "
    "blocks, and does NOT enumerate other slots. Returns: `{reachable: "
    "bool, module_type: str | null, mlfb: str | null, firmware: str | "
    "null, rack: int, slot: int, _errors?: dict}`.",
    {
        "asset_id": {"type": "integer"},
        "rack": {"type": "integer"},
        "slot": {"type": "integer"},
    },
)
def s7_read_szl_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    op_params = {
        "rack": int(params.get("rack") or 0),
        "slot": int(params.get("slot") or 2),
    }
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "s7_read_szl", op_params, relay))
    return result


# ── EtherNet/IP CIP ──────────────────────────────────────────────────


@agent_tool(
    "enip_list_identity",
    "Send a CIP ListIdentity command to TCP 44818 and parse the identity "
    "object (vendor ID, product code, revision, product name, serial "
    "number, device status). Read-only encapsulation-layer query — does "
    "NOT register a session, does NOT walk the CIP object tree. Returns: "
    "`{reachable: bool, vendor_id: int | null, product_code: int | null, "
    "revision: str | null, product_name: str | null, serial: str | null, "
    "_errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def enip_list_identity_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "enip_list_identity", {}, relay))
    return result


# ── BACnet/IP ────────────────────────────────────────────────────────


@agent_tool(
    "bacnet_read_property",
    "Send a BACnet/IP ReadProperty for the Object-Name property of Device "
    "object 0 over UDP 47808. Read-only confirmed-request service; the "
    "device replies with its configured device name (often the controller "
    "label / location). Does NOT issue Who-Is broadcast, does NOT iterate "
    "object IDs, does NOT subscribe to any COV (change-of-value) feed. "
    "Returns: `{reachable: bool, object_name: str | null, device_id: int "
    "| null, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def bacnet_read_property_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "bacnet_read_property", {}, relay))
    return result


# ── OPC UA ───────────────────────────────────────────────────────────


@agent_tool(
    "opcua_hello",
    "Open a TCP connection to an OPC UA server (default 4840) and exchange "
    "the OPC UA TCP Hello/Acknowledge frame pair. Reports the negotiated "
    "protocol version + send/receive buffer sizes — enough to confirm the "
    "service and its banner without opening a SecureChannel. Deeper "
    "GetEndpoints / SecurityPolicy=None enumeration is intentionally a "
    "separate op (not in this palette) so consent stays bounded to "
    "fingerprint reads. Returns: `{reachable: bool, protocol_version: int "
    "| null, max_message_size: int | null, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def opcua_hello_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "opcua_hello", {}, relay))
    return result


# ── Mitsubishi MELSEC SLMP (JP) ──────────────────────────────────────


@agent_tool(
    "melsec_read_cpu_info",
    "Send a SLMP (SeamLess Message Protocol) Read CPU Type request "
    "(command 0x0101 / subcommand 0x0000) to a Mitsubishi MELSEC PLC on "
    "TCP 5007. Returns the CPU model name + a fixed-width CPU code. "
    "Read-only diagnostic; the handler refuses every other SLMP command "
    "code (0x1401 device write, 0x1601 random write, 0x1820 file ops, "
    "etc.). Returns: `{reachable: bool, cpu_model: str | null, cpu_code: "
    "str | null, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def melsec_read_cpu_info_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "melsec_read_cpu_info", {}, relay))
    return result


# ── Omron FINS (JP) ──────────────────────────────────────────────────


@agent_tool(
    "omron_fins_read_cpu_unit",
    "Send a FINS (Factory Interface Network Service) UDP/9600 command "
    "MRC=0x05 / SRC=0x01 (CPU UNIT DATA READ) to an Omron PLC. Returns the "
    "controller model + version strings. Read-only; the FINS handler "
    "rejects every MRC except the 0x05 family and refuses 0x05/0x05+ "
    "(parameter writes). Returns: `{reachable: bool, model: str | null, "
    "version: str | null, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def omron_fins_read_cpu_unit_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "omron_fins_read_cpu_unit", {}, relay))
    return result


# ── IEC 60870-5-104 ──────────────────────────────────────────────────


@agent_tool(
    "iec104_interrogate",
    "Open a TCP/2404 IEC 60870-5-104 connection, send a U-format STARTDT "
    "ACT, await STARTDT CON, then send one I-format General Interrogation "
    "(C_IC_NA_1, type 100, COT 6 activation) and collect the immediate "
    "ASDU stream for ≤ 2 seconds before sending STOPDT and closing. "
    "Read-only telemetry only — the handler refuses every type ID >= 45 "
    "(C_SC_NA_1 single command, C_DC_NA_1 double command, C_RC_NA_1 "
    "regulating step, C_SE_NA_1 set-point, etc.). Returns: `{reachable: "
    "bool, common_address: int | null, asdu_count: int, type_ids_seen: "
    "list[int], _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def iec104_interrogate_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "iec104_interrogate", {}, relay))
    return result


# ── PROFINET DCP (best-effort unicast) ───────────────────────────────


@agent_tool(
    "profinet_dcp_unicast",
    "Send a best-effort PROFINET DCP IDENTIFY-ALL frame as UDP unicast "
    "to port 34962 and parse any reply. PROFINET DCP is canonically a "
    "Layer-2 multicast protocol; raw L2 access requires root on the "
    "relay so we send the same frame body wrapped in UDP. Some Siemens "
    "IO-Devices respond; many do not. A negative result is "
    "INCONCLUSIVE — not evidence the device is absent. Read-only "
    "identification frame; the handler refuses every DCP service ID "
    "other than IDENTIFY. Returns: `{reachable: bool, station_name: str "
    "| null, vendor_id: int | null, device_id: int | null, ip: str | "
    "null, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def profinet_dcp_unicast_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _ = _ctx(params)
    _, result = _run_async(_dispatch(db, asset_id, "profinet_dcp_unicast", {}, relay))
    return result


# ── Registry ─────────────────────────────────────────────────────────


_OT_PROTOCOL_TOOL_NAMES = [
    "modbus_read_device_id",
    "modbus_read_holding",
    "s7_read_szl",
    "enip_list_identity",
    "bacnet_read_property",
    "opcua_hello",
    "melsec_read_cpu_info",
    "omron_fins_read_cpu_unit",
    "iec104_interrogate",
    "profinet_dcp_unicast",
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="ot_protocol",
    label="OT/ICS Protocol Audit (Read-Only)",
    description=(
        "Active-probe OT/ICS audit covering Modbus, Siemens S7, "
        "EtherNet/IP CIP, BACnet/IP, OPC UA, Mitsubishi MELSEC SLMP, "
        "Omron FINS, IEC 60870-5-104, and PROFINET DCP. Every tool "
        "issues a single read-only fingerprint PDU; the relay handler "
        "enforces an op-allowlist plus a ≥2-second inter-PDU delay so "
        "a runaway loop cannot stress a PLC. Dispatch refuses without "
        "a fresh per-asset OT consent record (90-day TTL)."
    ),
    supported_os=["plc", "scada", "rtu", "dcs", "appliance"],
    auth_modes=["anonymous"],
    relay_method="ot_protocol_probe",
    credential_connector_ids=[],
    tool_names=_OT_PROTOCOL_TOOL_NAMES,
    required_ports=(502, 102, 44818, 47808, 4840, 5007, 9600, 2404, 34962),
    safety_class="ot_safe",
    auto_trigger_policy="per_asset_consent",
    cooldown_hours=168,  # 7 days — explicit OT raise from the 24h default
    compliance_tags=("iec_62443_3_3", "meti_ot_security_guideline_v3", "nist_csf_pr_ac"),
    missions=[
        MissionTemplate(
            key="triage",
            label="OT Fingerprint Triage",
            description=(
                "For each protocol the asset advertises, run the "
                "single read-only fingerprint op (vendor/model/firmware) "
                "and emit one finding per reachable service. Bounded: "
                "one PDU per protocol per run, no loops, no deeper "
                "enumeration."
            ),
            prompt_key="ot_protocol_audit_triage",
            suggested_budget=12,
            cost_hint="medium",
        ),
    ],
))
