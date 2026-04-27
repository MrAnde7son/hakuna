"""OT/ICS active-probe executor for the Hakuna relay agent (Phase 5).

Read-only fingerprint probes for ten industrial-control protocols. The
relay enforces a hard op-allowlist plus a per-call rate limiter so a
buggy or prompt-injected loop cannot stress a PLC.

## Op allowlist

Exactly the set declared in ``_OP_HANDLERS`` below. Any unknown op is
rejected before a single byte hits the wire. The corresponding tools at
the backend each only emit one ``op`` value — the allowlist is the
defense-in-depth backstop.

## Rate limiting

Per protocol family (handler-local primitive in ``_RateLimiter``):
  - ≥2-second minimum inter-PDU delay (``_MIN_INTER_PDU_S``)
  - 1 RPS default; configurable down to 0.2 RPS via the
    ``HAKUNA_OT_RPS`` env var on the relay (cautious JP factories)

Within a single probe call (e.g. S7's CR + Setup + ReadSZL chain), the
limiter spaces sequential PDUs ≥2s apart. Across probe calls in the same
relay process, the limiter shares a single state so concurrent ops can't
gang up.

## Read-only enforcement

Each handler builds its packet in-place — the LLM cannot pass arbitrary
bytes. Where a request takes parameters (Modbus FC3 register block,
S7 rack/slot), the handler clamps to a documented range:
  - Modbus FC3 ``count`` capped at 16
  - Modbus FC3 ``unit_id`` capped at 247 (the spec ceiling)
  - S7 ``slot`` capped at 31 (rack/slot byte field)
  - SLMP/FINS/IEC-104: no LLM-supplied PDU bytes at all — function codes
    are hardcoded constants in this file.

## Why no third-party libs

`pyipmi`, `pyghmi`, `pymodbus`, `python-snap7`, `bacpypes3`, `asyncua` —
all maintained but each adds a dependency just to send 1–2 PDUs. The
relay already has too many transitive deps; rolling 50–100 LoC per
protocol is faster to audit than reading another library's source for
"does this *actually* never write?" guarantees.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
import time
from typing import Any, Callable

from .method_registry import register_method

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 15
_MIN_INTER_PDU_S = 2.0


def _resolve_rps() -> float:
    """Read the relay-process-global rate limit.

    1.0 default; allow down-tuning (cautious JP factories) to ≥0.2 via env."""
    raw = os.environ.get("HAKUNA_OT_RPS")
    if not raw:
        return 1.0
    try:
        v = float(raw)
    except ValueError:
        return 1.0
    return max(0.2, min(v, 5.0))  # clamp; never above 5 RPS regardless of env


class _RateLimiter:
    """Process-global per-protocol-family rate limiter with a minimum
    inter-PDU delay floor.

    Two clocks: the RPS budget (1 token = 1 PDU) and the minimum gap.
    The slower of the two governs each call. ``acquire()`` blocks (sync
    sleep) until the next slot is available.
    """

    def __init__(self) -> None:
        self._last_send = 0.0

    def acquire(self) -> None:
        rps = _resolve_rps()
        now = time.monotonic()
        gap_for_rps = 1.0 / rps
        gap_required = max(gap_for_rps, _MIN_INTER_PDU_S)
        wait = (self._last_send + gap_required) - now
        if wait > 0:
            time.sleep(wait)
        self._last_send = time.monotonic()


_LIMITER = _RateLimiter()


class OtProbeError(Exception):
    """Any OT probe failure surfaced back to the backend."""


@register_method("ot_protocol_probe")
async def ot_protocol_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    """Dispatch one OT probe based on ``params.op``."""
    target = (transport_config or {}).get("target")
    if not target:
        raise OtProbeError("transport_config.target is required")
    port = int((transport_config or {}).get("port") or 0)
    op = (params or {}).get("op") or ""
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    handler = _OP_HANDLERS.get(op)
    if handler is None:
        raise OtProbeError(
            f"unknown ot probe op {op!r}; allowed: {sorted(_OP_HANDLERS.keys())}"
        )

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(handler, target, port, op_params, timeout_s),
            # Each protocol may issue multiple PDUs back-to-back with the
            # ≥2s rate-limit floor between them; allow generous slack on
            # the outer wrapper so a 3-PDU chain at 2s spacing doesn't
            # spuriously time out (3 PDUs * 2s = 6s minimum just on rate
            # limits, plus per-PDU socket time).
            timeout=timeout_s + 15,
        )
    except asyncio.TimeoutError:
        return {"_errors": {op: f"probe timed out after {timeout_s}s for {target}:{port}"}}


# ── Generic socket helpers ───────────────────────────────────────────


def _tcp_send_recv(target: str, port: int, payload: bytes, timeout_s: int, max_read: int = 4096) -> bytes | None:
    _LIMITER.acquire()
    try:
        with socket.create_connection((target, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            sock.sendall(payload)
            chunks: list[bytes] = []
            total = 0
            while total < max_read:
                try:
                    data = sock.recv(min(2048, max_read - total))
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                # If we've read at least a header's worth, peek-stop on common
                # termination signals: TCP servers that send-and-stay-open
                # would otherwise hold us until the outer timeout.
                if total >= 32:
                    break
            return b"".join(chunks) if chunks else None
    except (socket.timeout, OSError) as e:
        logger.debug("tcp probe %s:%s failed: %s", target, port, e)
        return None


def _udp_send_recv(target: str, port: int, payload: bytes, timeout_s: int, max_read: int = 4096) -> bytes | None:
    _LIMITER.acquire()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        logger.debug("udp socket alloc failed: %s", e)
        return None
    try:
        sock.settimeout(timeout_s)
        sock.sendto(payload, (target, port))
        try:
            data, _peer = sock.recvfrom(max_read)
            return data
        except socket.timeout:
            return None
    except OSError as e:
        logger.debug("udp probe %s:%s failed: %s", target, port, e)
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ── Modbus TCP ───────────────────────────────────────────────────────


def _build_modbus_read_device_id() -> bytes:
    """FC 43 / MEI 14 / Object 0 — vendor / product / revision sweep."""
    return bytes([
        0x00, 0x01,  # Transaction ID
        0x00, 0x00,  # Protocol ID
        0x00, 0x05,  # Length
        0x00,        # Unit ID
        0x2B,        # FC 43
        0x0E,        # MEI type 14
        0x01,        # Read Device ID code: Basic
        0x00,        # Object ID 0
    ])


def _parse_modbus_device_id(data: bytes) -> dict:
    out: dict[str, Any] = {}
    if len(data) < 14 or data[7] != 0x2B or data[8] != 0x0E:
        return out
    num_objects = data[12] if len(data) > 12 else 0
    field_names = {0: "vendor", 1: "product_code", 2: "revision"}
    offset = 13
    for _ in range(min(num_objects, 3)):
        if offset + 2 > len(data):
            break
        obj_id = data[offset]
        obj_len = data[offset + 1]
        end = offset + 2 + obj_len
        if end > len(data):
            break
        obj_val = data[offset + 2:end].decode("ascii", errors="replace").strip()
        if obj_id in field_names:
            out[field_names[obj_id]] = obj_val
        offset = end
    return out


def _probe_modbus_read_device_id(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 502
    out: dict[str, Any] = {"reachable": False, "vendor": None, "product_code": None, "revision": None}
    data = _tcp_send_recv(target, p, _build_modbus_read_device_id(), timeout_s)
    if not data:
        return {**out, "_errors": {"modbus_read_device_id": "no reply"}}
    parsed = _parse_modbus_device_id(data)
    out["reachable"] = True
    out.update(parsed)
    return out


def _build_modbus_read_holding(unit_id: int, start: int, count: int) -> bytes:
    return (
        struct.pack(">HHHB", 0x0001, 0x0000, 0x0006, unit_id & 0xFF)
        + bytes([0x03])
        + struct.pack(">HH", start & 0xFFFF, count & 0xFFFF)
    )


def _probe_modbus_read_holding(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 502
    unit_id = max(0, min(int(op_params.get("unit_id") or 1), 247))
    start = max(0, min(int(op_params.get("start_addr") or 0), 0xFFFF))
    count = max(1, min(int(op_params.get("count") or 4), 16))
    out: dict[str, Any] = {"reachable": False, "registers": [], "unit_id": unit_id}
    data = _tcp_send_recv(target, p, _build_modbus_read_holding(unit_id, start, count), timeout_s)
    if not data:
        return {**out, "_errors": {"modbus_read_holding": "no reply"}}
    out["reachable"] = True
    if len(data) < 9 or data[7] != 0x03:
        # Exception responses set FC high bit (0x83). Surface the code.
        if len(data) >= 9 and data[7] == 0x83:
            out["_errors"] = {"modbus_read_holding": f"exception code 0x{data[8]:02x}"}
        return out
    byte_count = data[8]
    body = data[9:9 + byte_count]
    regs: list[int] = []
    for i in range(0, len(body), 2):
        if i + 2 <= len(body):
            regs.append(struct.unpack(">H", body[i:i + 2])[0])
    out["registers"] = regs
    return out


# ── Siemens S7 ───────────────────────────────────────────────────────

# COTP Connection Request — same as protocol_probe.py but rebuilt with
# parameterised rack/slot since we want the Read SZL on the right CPU.

def _build_s7_cotp_cr(rack: int, slot: int) -> bytes:
    rack = max(0, min(rack, 7))
    slot = max(0, min(slot, 31))
    dst_tsap_low = ((rack & 0x07) << 5) | (slot & 0x1F)
    return bytes([
        0x03, 0x00, 0x00, 0x16,          # TPKT
        0x11,                            # COTP length
        0xE0,                            # CR
        0x00, 0x00,                      # Dst ref
        0x00, 0x01,                      # Src ref
        0x00,                            # Class 0
        0xC0, 0x01, 0x0A,                # TPDU size
        0xC1, 0x02, 0x01, 0x00,          # Source TSAP
        0xC2, 0x02, 0x01, dst_tsap_low,  # Dest TSAP
    ])


# S7 Setup Communication — required after COTP CC before any S7 user-data
# request. Magic numbers per S7 protocol; not LLM-controlled.
_S7_SETUP_COMMS = bytes([
    0x03, 0x00, 0x00, 0x19,                          # TPKT len 25
    0x02, 0xF0, 0x80,                                # COTP DT
    0x32,                                            # S7 protocol id
    0x01,                                            # ROSCTR=Job
    0x00, 0x00,                                      # reserved
    0x04, 0x00,                                      # PDU ref
    0x00, 0x08,                                      # param length
    0x00, 0x00,                                      # data length
    0xF0, 0x00,                                      # Function: Setup Comm
    0x00, 0x01,                                      # Max AmQ Calling
    0x00, 0x01,                                      # Max AmQ Called
    0x03, 0xC0,                                      # PDU length 960
])


# ReadSZL request for SZL ID 0x0011 (Module Identification), index 0.
# Returns the CPU MLFB (order code) + firmware version.
_S7_READ_SZL_0011 = bytes([
    0x03, 0x00, 0x00, 0x21,                          # TPKT len 33
    0x02, 0xF0, 0x80,                                # COTP DT
    0x32,                                            # S7 protocol id
    0x07,                                            # ROSCTR=UserData
    0x00, 0x00,                                      # reserved
    0x05, 0x00,                                      # PDU ref
    0x00, 0x08,                                      # param length
    0x00, 0x08,                                      # data length
    0x00, 0x01, 0x12,                                # marker
    0x04,                                            # plen
    0x11,                                            # type
    0x44, 0x01,                                      # subfunction Read SZL
    0x00,                                            # seq
    0xFF, 0x09, 0x00, 0x04,                          # return code etc
    0x00, 0x11,                                      # SZL ID 0x0011
    0x00, 0x00,                                      # SZL Index
])


def _parse_s7_szl_response(data: bytes) -> dict:
    """Best-effort parse of a Read SZL 0x0011 response. Module ID record
    is at a fixed offset after the SZL header; treat fields as ASCII with
    trailing NUL/space stripped."""
    out: dict[str, Any] = {}
    # Look for the SZL data block start. The response has a wrapping S7
    # header; after the marker 00 01 12 we expect param + data sections.
    marker = b"\x00\x01\x12"
    idx = data.find(marker)
    if idx == -1 or idx + 28 > len(data):
        return out
    # The Module Identification record format (per S7 spec):
    #   Index (2)  | MLFB (20 bytes ASCII) | BGTyp (2) | Ausbg1 (2) | Ausbg2 (2)
    # The data segment starts ~22 bytes past the marker; we scan a window.
    window = data[idx + 22:idx + 22 + 64]
    # Heuristic extract: longest run of printable ASCII = MLFB.
    printable = []
    for b in window:
        if 0x20 <= b < 0x7F:
            printable.append(chr(b))
        else:
            printable.append("\x00")
    text = "".join(printable)
    parts = [p.strip() for p in text.split("\x00") if p.strip() and len(p.strip()) >= 4]
    if parts:
        out["mlfb"] = parts[0]
    return out


def _probe_s7_read_szl(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 102
    rack = max(0, min(int(op_params.get("rack") or 0), 7))
    slot = max(0, min(int(op_params.get("slot") or 2), 31))
    out: dict[str, Any] = {
        "reachable": False, "module_type": None, "mlfb": None,
        "firmware": None, "rack": rack, "slot": slot,
    }

    _LIMITER.acquire()
    try:
        sock = socket.create_connection((target, p), timeout=timeout_s)
    except (socket.timeout, OSError) as e:
        return {**out, "_errors": {"s7_read_szl": f"connect: {e}"}}
    try:
        sock.settimeout(timeout_s)
        # Step 1: COTP Connection Request → expect CC (0xD0)
        sock.sendall(_build_s7_cotp_cr(rack, slot))
        cc = sock.recv(2048)
        if not cc or len(cc) < 6 or cc[5] != 0xD0:
            return {**out, "_errors": {"s7_read_szl": "no COTP confirm"}}
        out["reachable"] = True

        # Step 2: S7 Setup Communication → expect Ack-Data ROSCTR=3
        _LIMITER.acquire()
        sock.sendall(_S7_SETUP_COMMS)
        setup = sock.recv(2048)
        if not setup or len(setup) < 19:
            return {**out, "_errors": {"s7_read_szl": "no S7 Setup ACK"}}
        if setup[8] != 0x03:
            return {**out, "_errors": {"s7_read_szl": f"unexpected ROSCTR 0x{setup[8]:02x}"}}

        # Step 3: Read SZL 0x0011 → parse response
        _LIMITER.acquire()
        sock.sendall(_S7_READ_SZL_0011)
        szl = sock.recv(4096)
        if szl:
            out.update(_parse_s7_szl_response(szl))
            if out.get("mlfb"):
                out["module_type"] = "S7 CPU"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ── EtherNet/IP ListIdentity (TCP) ───────────────────────────────────


_ENIP_LIST_IDENTITY = bytes(
    [
        0x63, 0x00,                  # Cmd: ListIdentity
        0x00, 0x00,                  # Length
        0x00, 0x00, 0x00, 0x00,      # Session
        0x00, 0x00, 0x00, 0x00,      # Status
    ]
    + [0x00] * 8                     # Sender ctx
    + [0x00] * 4                     # Options
)


def _parse_enip_identity(data: bytes) -> dict:
    out: dict[str, Any] = {}
    if len(data) < 44:
        return out
    # Item header at offset 30 (after encap 24 + item_count 2 + item_type 2 +
    # item_length 2). Identity item starts after that.
    # Simpler: encoding per CIP spec table 2-4.6
    try:
        # vendor_id @ offset 38 (LE u16)
        out["vendor_id"] = struct.unpack("<H", data[38:40])[0]
        out["product_code"] = struct.unpack("<H", data[40:42])[0]
        major = data[42]
        minor = data[43]
        out["revision"] = f"{major}.{minor}"
        # status @ 44, serial @ 46, product name length @ 50
        if len(data) >= 51:
            out["serial"] = f"{struct.unpack('<I', data[46:50])[0]:08x}"
            name_len = data[50]
            name_start = 51
            if name_start + name_len <= len(data):
                out["product_name"] = data[name_start:name_start + name_len].decode(
                    "ascii", errors="replace",
                ).strip()
    except (struct.error, IndexError):
        return out
    return out


def _probe_enip_list_identity(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 44818
    out: dict[str, Any] = {
        "reachable": False, "vendor_id": None, "product_code": None,
        "revision": None, "product_name": None, "serial": None,
    }
    data = _tcp_send_recv(target, p, _ENIP_LIST_IDENTITY, timeout_s, max_read=512)
    if not data:
        return {**out, "_errors": {"enip_list_identity": "no reply"}}
    out["reachable"] = True
    out.update(_parse_enip_identity(data))
    return out


# ── BACnet/IP ReadProperty (UDP) ─────────────────────────────────────


_BACNET_READ_PROP = bytes([
    0x81, 0x0A,                              # BVLC type, Original-Unicast-NPDU
    0x00, 0x11,                              # Length 17
    0x01, 0x04,                              # NPDU
    0x00,                                    # APDU type
    0x05,                                    # Max APDU
    0x01,                                    # Invoke ID
    0x0C,                                    # Service: ReadProperty
    0x0C, 0x02, 0x00, 0x00, 0x00,            # Object: Device 0
    0x19, 0x4D,                              # Property: Object-Name (77)
])


def _parse_bacnet_object_name(data: bytes) -> dict:
    out: dict[str, Any] = {}
    if len(data) < 6 or data[0] != 0x81:
        return out
    # Look for property identifier 0x4D (Object-Name) followed by char-string tag.
    # Char-string in BACnet starts with 0x75 (context-tagged) or 0x65, then
    # length, then encoding byte (0=ASCII, 4=UTF-8), then bytes.
    idx = data.find(b"\x4d")
    if idx == -1:
        return out
    # Walk forward looking for a char-string tag.
    for i in range(idx, min(idx + 16, len(data) - 2)):
        b = data[i]
        if b in (0x74, 0x75, 0x76, 0x77, 0x65):  # opening or simple string tag
            length = data[i + 1]
            if length and i + 2 + length <= len(data):
                # encoding byte at i+2; payload from i+3
                payload = data[i + 3:i + 2 + length]
                try:
                    out["object_name"] = payload.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
                break
    return out


def _probe_bacnet_read_property(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 47808
    out: dict[str, Any] = {"reachable": False, "object_name": None, "device_id": 0}
    data = _udp_send_recv(target, p, _BACNET_READ_PROP, timeout_s)
    if not data:
        return {**out, "_errors": {"bacnet_read_property": "no reply"}}
    if data[0] != 0x81:
        return {**out, "_errors": {"bacnet_read_property": "non-BVLC reply"}}
    out["reachable"] = True
    out.update(_parse_bacnet_object_name(data))
    return out


# ── OPC UA Hello ─────────────────────────────────────────────────────


def _build_opcua_hello() -> bytes:
    endpoint = b"opc.tcp://localhost:4840"
    body = (
        struct.pack("<I", 0)              # protocol version
        + struct.pack("<I", 65535)        # recv buffer
        + struct.pack("<I", 65535)        # send buffer
        + struct.pack("<I", 0)            # max message
        + struct.pack("<I", 0)            # max chunk
        + struct.pack("<I", len(endpoint))
        + endpoint
    )
    header = b"HELF" + struct.pack("<I", 8 + len(body))
    return header + body


def _parse_opcua_ack(data: bytes) -> dict:
    out: dict[str, Any] = {}
    if len(data) < 28 or data[:3] != b"ACK":
        return out
    try:
        out["protocol_version"] = struct.unpack("<I", data[8:12])[0]
        out["recv_buffer_size"] = struct.unpack("<I", data[12:16])[0]
        out["send_buffer_size"] = struct.unpack("<I", data[16:20])[0]
        out["max_message_size"] = struct.unpack("<I", data[20:24])[0]
    except struct.error:
        pass
    return out


def _probe_opcua_hello(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 4840
    out: dict[str, Any] = {
        "reachable": False, "protocol_version": None, "max_message_size": None,
    }
    data = _tcp_send_recv(target, p, _build_opcua_hello(), timeout_s, max_read=128)
    if not data:
        return {**out, "_errors": {"opcua_hello": "no reply"}}
    if data[:3] != b"ACK":
        # Could be ERR — surface it for triage.
        if data[:3] == b"ERR" and len(data) >= 12:
            err_code = struct.unpack("<I", data[8:12])[0]
            return {**out, "_errors": {"opcua_hello": f"OPC UA ERR 0x{err_code:08x}"}}
        return {**out, "_errors": {"opcua_hello": "non-ACK reply"}}
    out["reachable"] = True
    out.update(_parse_opcua_ack(data))
    return out


# ── Mitsubishi MELSEC SLMP (JP) ──────────────────────────────────────

# 3E binary format Read CPU Type request (command 0x0101 / subcommand 0x0000).
# Bytes are little-endian per SLMP convention.
_SLMP_READ_CPU_TYPE = bytes([
    0x50, 0x00,              # Subheader: request, serial# 0
    0x00,                    # Network # (own station)
    0xFF,                    # PC # (own station)
    0xFF, 0x03,              # Module I/O # (CPU module, LE = 0x03FF)
    0x00,                    # Module station #
    0x06, 0x00,              # Request data length (6 bytes follow)
    0x10, 0x00,              # Monitoring timer (16 * 250ms = 4s)
    0x01, 0x01,              # Command (0x0101 Read CPU Type)
    0x00, 0x00,              # Subcommand (0x0000)
])


def _parse_slmp_response(data: bytes) -> dict:
    out: dict[str, Any] = {}
    if len(data) < 11:
        return out
    if data[:2] != b"\xD0\x00":
        return out
    end_code = struct.unpack("<H", data[9:11])[0]
    if end_code != 0:
        out["_end_code"] = f"0x{end_code:04x}"
        return out
    body = data[11:]
    # CPU model (16 ASCII) + CPU code (2 bytes)
    if len(body) >= 18:
        out["cpu_model"] = body[:16].decode("ascii", errors="replace").rstrip("\x00 ").strip()
        out["cpu_code"] = body[16:18].hex()
    elif len(body) >= 16:
        out["cpu_model"] = body[:16].decode("ascii", errors="replace").rstrip("\x00 ").strip()
    return out


def _probe_melsec_read_cpu_info(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 5007
    out: dict[str, Any] = {"reachable": False, "cpu_model": None, "cpu_code": None}
    data = _tcp_send_recv(target, p, _SLMP_READ_CPU_TYPE, timeout_s, max_read=256)
    if not data:
        return {**out, "_errors": {"melsec_read_cpu_info": "no reply"}}
    parsed = _parse_slmp_response(data)
    if "_end_code" in parsed:
        return {**out, "_errors": {"melsec_read_cpu_info": f"end code {parsed['_end_code']}"}}
    out["reachable"] = True
    out.update({k: v for k, v in parsed.items() if not k.startswith("_")})
    return out


# ── Omron FINS UDP (JP) ──────────────────────────────────────────────


def _build_fins_cpu_unit_data_read() -> bytes:
    """FINS UDP frame: ICF + reserved + GCT + DNA/DA1/DA2 + SNA/SA1/SA2 + SID
    + MRC/SRC + 1 byte command-data (0=all)."""
    return bytes([
        0x80,        # ICF: response required, command frame
        0x00,        # Reserved
        0x02,        # GCT (gateway count)
        0x00,        # DNA (destination network)
        0x00,        # DA1 (destination node — 0 means same network)
        0x00,        # DA2 (destination unit — 0 = CPU)
        0x00,        # SNA (source network)
        0x01,        # SA1 (source node)
        0x00,        # SA2 (source unit)
        0x00,        # SID
        0x05, 0x01,  # MRC=0x05 / SRC=0x01 (CPU UNIT DATA READ)
        0x00,        # 0 = all data
    ])


def _parse_fins_cpu_unit_data(data: bytes) -> dict:
    out: dict[str, Any] = {}
    if len(data) < 14:
        return out
    if data[10:12] != b"\x05\x01":
        return out
    end_code = struct.unpack(">H", data[12:14])[0]
    if end_code != 0:
        out["_end_code"] = f"0x{end_code:04x}"
        return out
    body = data[14:]
    # Model (20 bytes ASCII) + Version (20 bytes ASCII), plus more — only
    # surface the first two strings and stop.
    if len(body) >= 20:
        out["model"] = body[:20].decode("ascii", errors="replace").rstrip("\x00 ").strip()
    if len(body) >= 40:
        out["version"] = body[20:40].decode("ascii", errors="replace").rstrip("\x00 ").strip()
    return out


def _probe_omron_fins_read_cpu_unit(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 9600
    out: dict[str, Any] = {"reachable": False, "model": None, "version": None}
    data = _udp_send_recv(target, p, _build_fins_cpu_unit_data_read(), timeout_s)
    if not data:
        return {**out, "_errors": {"omron_fins_read_cpu_unit": "no reply"}}
    parsed = _parse_fins_cpu_unit_data(data)
    if "_end_code" in parsed:
        return {**out, "_errors": {"omron_fins_read_cpu_unit": f"end code {parsed['_end_code']}"}}
    out["reachable"] = True
    out.update({k: v for k, v in parsed.items() if not k.startswith("_")})
    return out


# ── IEC 60870-5-104 ──────────────────────────────────────────────────


_IEC104_STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
_IEC104_STARTDT_CON_CTRL = 0x0B  # first byte of ctrl on STARTDT_CON
_IEC104_STOPDT_ACT = bytes([0x68, 0x04, 0x13, 0x00, 0x00, 0x00])


def _build_iec104_general_interrogation(send_seq: int = 0, recv_seq: int = 0, coa: int = 1) -> bytes:
    """I-format APCI + ASDU type 100 (C_IC_NA_1) station interrogation."""
    apci = bytes([
        0x68, 0x0E,
        (send_seq << 1) & 0xFF, (send_seq >> 7) & 0xFF,
        (recv_seq << 1) & 0xFF, (recv_seq >> 7) & 0xFF,
    ])
    asdu = bytes([
        0x64,                             # Type ID 100
        0x01,                             # VSQ: 1 IO, no SQ
        0x06, 0x00,                       # COT 6 (activation), no originator
        coa & 0xFF, (coa >> 8) & 0xFF,    # Common address (2 bytes LE)
        0x00, 0x00, 0x00,                 # IO address (3 bytes)
        0x14,                             # QOI 0x14: station interrogation (group 0)
    ])
    return apci + asdu


def _parse_iec104_apci(buf: bytes, off: int) -> tuple[int, int, bytes] | None:
    """Return (frame_total_length, ctrl_first_byte, asdu_payload) at offset
    or None on malformed."""
    if off + 2 > len(buf) or buf[off] != 0x68:
        return None
    length = buf[off + 1]
    if off + 2 + length > len(buf):
        return None
    ctrl = buf[off + 2]
    asdu = buf[off + 6:off + 2 + length] if length >= 4 else b""
    return 2 + length, ctrl, asdu


def _probe_iec104_interrogate(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 2404
    out: dict[str, Any] = {
        "reachable": False, "common_address": None,
        "asdu_count": 0, "type_ids_seen": [],
    }
    _LIMITER.acquire()
    try:
        sock = socket.create_connection((target, p), timeout=timeout_s)
    except (socket.timeout, OSError) as e:
        return {**out, "_errors": {"iec104_interrogate": f"connect: {e}"}}
    try:
        sock.settimeout(timeout_s)
        sock.sendall(_IEC104_STARTDT_ACT)
        first = sock.recv(2048)
        if not first or len(first) < 6:
            return {**out, "_errors": {"iec104_interrogate": "no STARTDT response"}}
        parsed = _parse_iec104_apci(first, 0)
        if parsed is None:
            return {**out, "_errors": {"iec104_interrogate": "malformed APCI"}}
        _len, ctrl, _asdu = parsed
        if ctrl != _IEC104_STARTDT_CON_CTRL:
            return {**out, "_errors": {"iec104_interrogate": f"expected STARTDT CON, got ctrl=0x{ctrl:02x}"}}
        out["reachable"] = True

        # Send general interrogation
        _LIMITER.acquire()
        sock.sendall(_build_iec104_general_interrogation())

        # Collect frames for ≤ 2s — short collection window so we don't
        # hold the socket open against a chatty RTU.
        sock.settimeout(2.0)
        buffer = b""
        deadline = time.monotonic() + 2.0
        type_ids: set[int] = set()
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buffer += chunk
            offset = 0
            while offset < len(buffer):
                p2 = _parse_iec104_apci(buffer, offset)
                if p2 is None:
                    break
                frame_len, _ctrl, asdu = p2
                if asdu:
                    type_ids.add(asdu[0])
                    if len(asdu) >= 6 and out["common_address"] is None:
                        out["common_address"] = asdu[4] | (asdu[5] << 8)
                    out["asdu_count"] += 1
                offset += frame_len
            buffer = buffer[offset:]

        out["type_ids_seen"] = sorted(type_ids)

        # Polite close: STOPDT then socket close. Best-effort.
        try:
            _LIMITER.acquire()
            sock.sendall(_IEC104_STOPDT_ACT)
        except OSError:
            pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ── PROFINET DCP (best-effort UDP unicast) ───────────────────────────


def _build_profinet_dcp_identify_all() -> bytes:
    """Bare DCP IDENTIFY-ALL frame body. Canonically multicast over L2 with
    EtherType 0x8892; we emit the body inside UDP as a best-effort. Many
    stacks ignore this; some Siemens IO-Devices (and some softstacks) reply.
    """
    xid = os.urandom(4)
    return (
        b"\xFE\xFE"                          # Frame ID: Identify Multi
        + b"\x05"                            # Service ID: Identify
        + b"\x00"                            # Service Type: Request
        + xid
        + b"\x00\x00"                        # Response delay
        + b"\x00\x04"                        # DCP DataLength
        + b"\xFF\xFF\x00\x00"                # All Selector block
    )


def _parse_profinet_dcp_response(data: bytes) -> dict:
    out: dict[str, Any] = {}
    if len(data) < 16:
        return out
    # Look for known sub-option tags inside the data block.
    # Tag 02/02 = NameOfStation; 02/03 = DeviceID; 02/05 = IPAddress
    for i in range(8, min(len(data), 1024) - 4):
        opt, sub = data[i], data[i + 1]
        if opt == 0x02 and sub in (0x02, 0x03, 0x05):
            length = struct.unpack(">H", data[i + 2:i + 4])[0]
            if length == 0 or i + 4 + length > len(data):
                continue
            blk = data[i + 4:i + 4 + length]
            if sub == 0x02 and "station_name" not in out:
                # 2-byte BlockInfo prefix per spec
                out["station_name"] = blk[2:].decode("ascii", errors="replace").rstrip("\x00 ").strip()
            elif sub == 0x03 and "vendor_id" not in out and length >= 6:
                out["vendor_id"] = struct.unpack(">H", blk[2:4])[0]
                out["device_id"] = struct.unpack(">H", blk[4:6])[0]
            elif sub == 0x05 and "ip" not in out and length >= 6:
                out["ip"] = ".".join(str(b) for b in blk[2:6])
    return out


def _probe_profinet_dcp_unicast(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    p = port or 34962
    out: dict[str, Any] = {
        "reachable": False, "station_name": None, "vendor_id": None,
        "device_id": None, "ip": None,
    }
    data = _udp_send_recv(target, p, _build_profinet_dcp_identify_all(), timeout_s)
    if not data:
        return {**out, "_errors": {"profinet_dcp_unicast": "no reply (PROFINET DCP is canonically L2 multicast; absence is inconclusive)"}}
    out["reachable"] = True
    out.update(_parse_profinet_dcp_response(data))
    return out


# ── Relay-side allowlist ─────────────────────────────────────────────


_OP_HANDLERS: dict[str, Callable[..., dict]] = {
    "modbus_read_device_id": _probe_modbus_read_device_id,
    "modbus_read_holding": _probe_modbus_read_holding,
    "s7_read_szl": _probe_s7_read_szl,
    "enip_list_identity": _probe_enip_list_identity,
    "bacnet_read_property": _probe_bacnet_read_property,
    "opcua_hello": _probe_opcua_hello,
    "melsec_read_cpu_info": _probe_melsec_read_cpu_info,
    "omron_fins_read_cpu_unit": _probe_omron_fins_read_cpu_unit,
    "iec104_interrogate": _probe_iec104_interrogate,
    "profinet_dcp_unicast": _probe_profinet_dcp_unicast,
}
