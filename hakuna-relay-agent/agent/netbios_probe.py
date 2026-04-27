"""NetBIOS / LLMNR / mDNS LAN-local probe executor (Phase 4.3).

Three LAN-local name-resolution / service-discovery protocols, all
unicast UDP queries from the relay to the target asset:

  - op="nbns"  — NetBIOS Name Service NBSTAT query (UDP 137)
  - op="llmnr" — LLMNR standard query for the host's own name (UDP 5355)
  - op="mdns"  — DNS-SD `_services._dns-sd._udp.local` query (UDP 5353)

We send unicast directly to the asset's IP rather than multicast — that
way the probe is a targeted check rather than a network-wide solicitation.
The trade-off: a host that *only* responds to multicast queries
(rare in practice) won't show up here. That's fine for triage — the
finding bar is "the host actively responds when asked."

## Wire formats

NBNS / LLMNR / mDNS all share the DNS message format (RFC 1035 header
+ question section), with protocol-specific tweaks:

  - NBNS uses the "encoded NetBIOS name" representation: each ASCII byte
    is split into two nibbles, each remapped to the range 'A'..'P'.
    For NBSTAT specifically, the name is ``*`` padded with NULs to 16
    bytes, encoded into 32 ASCII bytes.
  - LLMNR is a normal DNS query but the C bit is set in flags.
  - mDNS for service enumeration uses the well-known QNAME
    ``_services._dns-sd._udp.local``.

Stdlib `socket` + `struct` only — no `dnspython` dependency for these.
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


_DEFAULT_TIMEOUT_S = 6


class NetbiosProbeError(Exception):
    """Any LAN-local probe failure surfaced back to the backend."""


@register_method("netbios_probe")
async def netbios_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    target = (transport_config or {}).get("target")
    if not target:
        raise NetbiosProbeError("transport_config.target is required")
    port = int((transport_config or {}).get("port") or 0)
    op = (params or {}).get("op") or ""
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    handler = _OP_HANDLERS.get(op)
    if handler is None:
        raise NetbiosProbeError(
            f"unknown netbios probe op {op!r}; allowed: {sorted(_OP_HANDLERS.keys())}"
        )

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(handler, target, port, op_params, timeout_s),
            timeout=timeout_s + 2,
        )
    except asyncio.TimeoutError:
        return {"_errors": {op: f"probe timed out after {timeout_s}s for {target}:{port}"}}


# ── NBNS ─────────────────────────────────────────────────────────────


def _encode_netbios_name(name: str) -> bytes:
    """RFC 1002 NetBIOS name encoding: pad to 16 bytes, then encode each
    byte as two ASCII chars in 'A'..'P'."""
    padded = name.ljust(16, "\x00")[:16].encode("latin-1", "replace")
    out = bytearray()
    for b in padded:
        out.append(0x41 + ((b >> 4) & 0x0F))
        out.append(0x41 + (b & 0x0F))
    return bytes(out)


def _decode_netbios_name(encoded: bytes) -> str:
    """Inverse of `_encode_netbios_name` — used for response parsing in
    tests; the actual NBSTAT response carries names in their already-
    decoded form so we don't use this in `_probe_nbns`."""
    if len(encoded) < 32:
        return ""
    out = bytearray()
    for i in range(0, 32, 2):
        hi = encoded[i] - 0x41
        lo = encoded[i + 1] - 0x41
        out.append(((hi & 0x0F) << 4) | (lo & 0x0F))
    return out.rstrip(b"\x00 ").decode("ascii", "replace")


def _build_nbstat_query(transaction_id: int) -> bytes:
    """NBSTAT query (NetBIOS NS query for ``*``, type NBSTAT=0x21,
    class IN=0x0001)."""
    header = struct.pack(
        ">HHHHHH",
        transaction_id,  # transaction id
        0x0010,          # flags: standard query, B-type bcast (set 0x0010 per Wireshark dissector)
        1, 0, 0, 0,      # qdcount=1, ancount=0, nscount=0, arcount=0
    )
    qname = bytes([0x20]) + _encode_netbios_name("*") + b"\x00"
    qtype = struct.pack(">H", 0x0021)  # NBSTAT
    qclass = struct.pack(">H", 0x0001)  # IN
    return header + qname + qtype + qclass


def _parse_nbstat_response(buf: bytes) -> list[dict]:
    """Parse the answer section of an NBSTAT response.

    The response carries: header(12) + question echo (variable) + answer
    section. The answer's RDATA starts with a 1-byte name count, followed
    by N entries of: 16-byte name + 1-byte name_type + 1-byte flags.
    """
    if len(buf) < 12:
        return []
    # Skip the question echo: the qname is ``\x20<32 encoded>\x00``,
    # i.e., 1 + 32 + 1 = 34 bytes, plus 4 bytes for type + class.
    pos = 12 + 34 + 4
    # Skip the answer name (compressed pointer 0xc00c) + type(2) + class(2)
    # + ttl(4) + rdlength(2) = 12 bytes before RDATA.
    pos += 12
    if pos >= len(buf):
        return []
    name_count = buf[pos]
    pos += 1
    out: list[dict] = []
    for _ in range(min(name_count, 32)):
        if pos + 18 > len(buf):
            break
        raw_name = buf[pos:pos + 15]
        name_type = buf[pos + 15]
        flags = struct.unpack(">H", buf[pos + 16:pos + 18])[0]
        pos += 18
        try:
            name = raw_name.rstrip(b"\x00 ").decode("ascii", "replace")
        except Exception:
            name = ""
        out.append({"name": name, "type": name_type, "flags": flags})
    return out


def _probe_nbns(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    port = port or 137
    out: dict[str, Any] = {"nbns_enabled": False, "names": []}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
    except OSError as e:
        return {"_errors": {"nbns": f"socket: {e}"}}
    try:
        tid = struct.unpack(">H", os.urandom(2))[0] or 0x4242
        sock.sendto(_build_nbstat_query(tid), (target, port))
        try:
            data, _peer = sock.recvfrom(2048)
        except socket.timeout:
            return out  # silent host = NBT-NS not enabled (or dropped)
        if len(data) < 12:
            return {"_errors": {"nbns": f"short reply ({len(data)} bytes)"}}
        # Confirm the response transaction id matches our query
        resp_tid = struct.unpack(">H", data[:2])[0]
        if resp_tid != tid:
            return {"_errors": {"nbns": f"transaction id mismatch ({resp_tid:#x} vs {tid:#x})"}}
        out["nbns_enabled"] = True
        out["names"] = _parse_nbstat_response(data)[:20]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ── LLMNR ────────────────────────────────────────────────────────────


def _build_dns_query(transaction_id: int, qname: str, qtype: int = 1) -> bytes:
    """Standard DNS query packet builder (RFC 1035). LLMNR and mDNS share
    the same wire format for simple A queries; only the destination port +
    flags differ.
    """
    header = struct.pack(
        ">HHHHHH",
        transaction_id, 0x0000, 1, 0, 0, 0,
    )
    qname_bytes = bytearray()
    for label in qname.split("."):
        if not label:
            continue
        encoded = label.encode("ascii", "replace")
        if len(encoded) > 63:
            encoded = encoded[:63]
        qname_bytes.append(len(encoded))
        qname_bytes.extend(encoded)
    qname_bytes.append(0)
    return header + bytes(qname_bytes) + struct.pack(">HH", qtype, 0x0001)


def _parse_dns_a_answer(buf: bytes) -> str | None:
    """Extract the first A record from a DNS-formatted response. Used for
    LLMNR (which always returns a single A or AAAA). Returns dotted-quad
    or None if no A record present."""
    if len(buf) < 12:
        return None
    ancount = struct.unpack(">H", buf[6:8])[0]
    if ancount == 0:
        return None
    # Skip the question section: scan past labels until 0x00, then skip
    # type+class (4 bytes).
    pos = 12
    while pos < len(buf):
        ll = buf[pos]
        if ll == 0:
            pos += 1
            break
        if ll & 0xC0 == 0xC0:
            pos += 2
            break
        pos += 1 + ll
    pos += 4  # qtype + qclass
    # First answer: name (compressed), type(2), class(2), ttl(4),
    # rdlength(2), rdata.
    if pos + 12 > len(buf):
        return None
    if buf[pos] & 0xC0 == 0xC0:
        pos += 2  # compressed pointer
    else:
        while pos < len(buf):
            ll = buf[pos]
            if ll == 0:
                pos += 1
                break
            pos += 1 + ll
    rtype = struct.unpack(">H", buf[pos:pos + 2])[0]
    pos += 8  # type + class + ttl
    rdlength = struct.unpack(">H", buf[pos:pos + 2])[0]
    pos += 2
    if rtype == 1 and rdlength == 4 and pos + 4 <= len(buf):
        return ".".join(str(b) for b in buf[pos:pos + 4])
    return None


def _probe_llmnr(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Send a unicast LLMNR query to the host for its own short name.

    LLMNR's wire shape is identical to DNS over UDP. The host's short
    name is preferred (LLMNR is short-name resolution); if not provided,
    fall back to a placeholder that the host wouldn't recognize — a
    response with NXDOMAIN-shape still proves the protocol is enabled.
    """
    port = port or 5355
    out: dict[str, Any] = {"llmnr_enabled": False, "resolved_ip": None}
    hostname = (op_params or {}).get("hostname") or "wpad"
    short = hostname.split(".")[0] if hostname else "wpad"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
    except OSError as e:
        return {"_errors": {"llmnr": f"socket: {e}"}}
    try:
        tid = struct.unpack(">H", os.urandom(2))[0] or 0x1234
        sock.sendto(_build_dns_query(tid, short, qtype=1), (target, port))
        try:
            data, _peer = sock.recvfrom(2048)
        except socket.timeout:
            return out
        if len(data) < 12:
            return {"_errors": {"llmnr": f"short reply ({len(data)} bytes)"}}
        resp_tid = struct.unpack(">H", data[:2])[0]
        if resp_tid != tid:
            return {"_errors": {"llmnr": f"transaction id mismatch"}}
        out["llmnr_enabled"] = True
        out["resolved_ip"] = _parse_dns_a_answer(data)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ── mDNS ─────────────────────────────────────────────────────────────


def _parse_mdns_service_list(buf: bytes) -> list[str]:
    """Extract PTR record names from a DNS-SD response.

    The full DNS pointer-chasing dance is overkill for our purposes —
    we just scan the buffer for valid label runs that look like a
    DNS-SD service name (``_<name>._tcp`` or ``_<name>._udp``).
    """
    out: list[str] = []
    seen: set[str] = set()
    i = 12  # skip header
    while i < len(buf):
        ll = buf[i]
        if ll == 0 or ll & 0xC0:
            i += 1
            continue
        if not (1 <= ll <= 63) or i + 1 + ll > len(buf):
            i += 1
            continue
        label = buf[i + 1:i + 1 + ll].decode("ascii", "replace")
        if label.startswith("_"):
            # Look ahead for the next label: should be _tcp or _udp.
            j = i + 1 + ll
            if j < len(buf):
                ll2 = buf[j]
                if 1 <= ll2 <= 63 and j + 1 + ll2 <= len(buf):
                    label2 = buf[j + 1:j + 1 + ll2].decode("ascii", "replace")
                    if label2 in ("_tcp", "_udp"):
                        full = f"{label}.{label2}"
                        if full not in seen:
                            seen.add(full)
                            out.append(full)
        i += 1
    return out[:50]


def _probe_mdns(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Send a unicast DNS-SD service-enumeration query and parse the reply."""
    port = port or 5353
    out: dict[str, Any] = {"mdns_enabled": False, "advertised_services": []}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
    except OSError as e:
        return {"_errors": {"mdns": f"socket: {e}"}}
    try:
        tid = struct.unpack(">H", os.urandom(2))[0]
        # qtype 12 = PTR
        query = _build_dns_query(tid, "_services._dns-sd._udp.local", qtype=12)
        sock.sendto(query, (target, port))
        try:
            data, _peer = sock.recvfrom(4096)
        except socket.timeout:
            return out
        if len(data) < 12:
            return {"_errors": {"mdns": f"short reply ({len(data)} bytes)"}}
        out["mdns_enabled"] = True
        out["advertised_services"] = _parse_mdns_service_list(data)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ── Relay-side allowlist ─────────────────────────────────────────────


_OP_HANDLERS: dict[str, Any] = {
    "nbns": _probe_nbns,
    "llmnr": _probe_llmnr,
    "mdns": _probe_mdns,
}
