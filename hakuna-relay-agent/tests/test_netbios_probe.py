"""Unit tests for agent.netbios_probe (Phase 4.3).

UDP socket layer is mocked; we verify wire-format query construction +
response parsing for NBNS, LLMNR, mDNS without binding to UDP/137 etc.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from unittest.mock import patch

import pytest

from agent import netbios_probe


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Allowlist ────────────────────────────────────────────────────────


def test_handler_rejects_unknown_op():
    with pytest.raises(netbios_probe.NetbiosProbeError, match="unknown netbios probe op"):
        _run(netbios_probe.netbios_probe_handler(
            ws=None, task={}, transport_config={"target": "x", "port": 137},
            credentials={}, params={"op": "responder_poison"},
        ))


def test_handler_op_allowlist_matches_phase_4_3_scope():
    assert set(netbios_probe._OP_HANDLERS.keys()) == {"nbns", "llmnr", "mdns"}


# ── NBNS encoding helpers ────────────────────────────────────────────


def test_encode_netbios_name_pads_and_splits_nibbles():
    """RFC 1002 encoding: each byte → two ASCII chars in 'A'..'P'.
    The classic NBSTAT name ``*`` (0x2A) → 'C' (0x43, hi-nibble 0x42+2)
    + 'K' (0x4B, lo-nibble 0x4A+1)."""
    encoded = netbios_probe._encode_netbios_name("*")
    assert len(encoded) == 32
    assert encoded[0:2] == b"CK"
    # Padding NULs: each 0x00 → 'AA'
    assert encoded[2:32] == b"AA" * 15


def test_decode_netbios_name_inverts_encode():
    for name in ["*", "WORKGROUP", "DC1", "FILE-SRV"]:
        assert netbios_probe._decode_netbios_name(
            netbios_probe._encode_netbios_name(name),
        ) == name


# ── NBNS probe ───────────────────────────────────────────────────────


def _fake_udp_oneshot(response: bytes, captured: list | None = None):
    captured = captured if captured is not None else []
    state = {"sent": False}

    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr):
            captured.append(data)
            state["sent"] = True
        def recvfrom(self, n):
            if not state["sent"]:
                raise socket.timeout("nothing sent")
            return response, ("h", 137)
        def close(self): pass

    return _UDP()


def _build_fake_nbstat_response(transaction_id: int, names: list[tuple[str, int]]) -> bytes:
    """Build a minimal NBSTAT response containing N (name, name_type) entries.

    Layout: header(12) + question echo(34+4=38) + answer header(12) +
    rdata(name_count + N * 18 bytes).
    """
    header = struct.pack(">HHHHHH", transaction_id, 0x8500, 1, 1, 0, 0)
    question = bytes([0x20]) + netbios_probe._encode_netbios_name("*") + b"\x00"
    question += struct.pack(">HH", 0x0021, 0x0001)
    # Answer name (compressed pointer to question), type=0x21, class=0x01,
    # ttl=0, rdlength=N*18+1 (we'll set later).
    rdata = bytearray([len(names)])
    for name, name_type in names:
        padded = name.ljust(15, "\x00")[:15].encode("ascii", "replace")
        rdata.extend(padded)
        rdata.append(name_type)
        rdata.extend(b"\x00\x00")  # flags
    answer_header = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 0x0021, 0x0001, 0, len(rdata))
    )
    return header + question + answer_header + bytes(rdata)


def test_nbns_probe_flags_enabled_when_response_received():
    captured: list = []

    # We don't know the random transaction_id ahead of time; build the
    # probe, then read the tid out of the captured packet to construct
    # a matching response. Two-step pattern.
    fake_resp_holder: dict = {"resp": b""}

    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr):
            captured.append(data)
            tid = struct.unpack(">H", data[:2])[0]
            fake_resp_holder["resp"] = _build_fake_nbstat_response(
                tid, [("WORKGROUP", 0x00), ("WS-01", 0x20), ("alice", 0x03)],
            )
        def recvfrom(self, n):
            if not fake_resp_holder["resp"]:
                raise socket.timeout("no send yet")
            return fake_resp_holder["resp"], ("h", 137)
        def close(self): pass

    with patch("agent.netbios_probe.socket.socket", return_value=_UDP()):
        out = netbios_probe._probe_nbns("h", 137, {}, 5)

    assert out["nbns_enabled"] is True
    found = {n["name"] for n in out["names"]}
    assert "WORKGROUP" in found
    assert "alice" in found  # signed-on user (name type 0x03)
    # Verify the question section in the sent packet uses the encoded ``*``.
    sent = captured[0]
    assert b"CK" + b"AA" * 15 in sent  # encoded ``*`` padded to 16 bytes


def test_nbns_probe_treats_silent_host_as_disabled():
    """A host that doesn't reply on UDP 137 — the expected modern-Windows
    behavior — must be reported as ``nbns_enabled: false`` without an
    error key."""
    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr): pass
        def recvfrom(self, n): raise socket.timeout("silent")
        def close(self): pass

    with patch("agent.netbios_probe.socket.socket", return_value=_UDP()):
        out = netbios_probe._probe_nbns("h", 137, {}, 1)

    assert out["nbns_enabled"] is False
    assert "_errors" not in out


def test_nbns_probe_rejects_response_with_mismatched_transaction_id():
    """An off-tid reply (replay attack? misrouted UDP?) must surface as an
    error rather than be parsed as legitimate."""
    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr): pass
        def recvfrom(self, n):
            # Wrong transaction id (0xdead)
            return _build_fake_nbstat_response(0xdead, [("WORKGROUP", 0)]), ("h", 137)
        def close(self): pass

    with patch("agent.netbios_probe.socket.socket", return_value=_UDP()):
        out = netbios_probe._probe_nbns("h", 137, {}, 1)

    assert "_errors" in out and "nbns" in out["_errors"]


# ── LLMNR probe ──────────────────────────────────────────────────────


def _build_fake_llmnr_response(tid: int, ip_bytes: bytes) -> bytes:
    """Minimal DNS-format A response: header(12) + question + 1 answer."""
    header = struct.pack(">HHHHHH", tid, 0x8000, 1, 1, 0, 0)
    qname = b"\x04wpad\x00"  # length=4, "wpad", terminator
    question = qname + struct.pack(">HH", 0x0001, 0x0001)
    answer = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 0x0001, 0x0001, 0, 4)
        + ip_bytes
    )
    return header + question + answer


def test_llmnr_probe_flags_enabled_when_host_answers():
    fake_resp_holder: dict = {"resp": b""}

    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr):
            tid = struct.unpack(">H", data[:2])[0]
            fake_resp_holder["resp"] = _build_fake_llmnr_response(
                tid, bytes([10, 0, 0, 50]),
            )
        def recvfrom(self, n):
            if not fake_resp_holder["resp"]:
                raise socket.timeout("no send yet")
            return fake_resp_holder["resp"], ("h", 5355)
        def close(self): pass

    with patch("agent.netbios_probe.socket.socket", return_value=_UDP()):
        out = netbios_probe._probe_llmnr("h", 5355, {"hostname": "wpad"}, 5)

    assert out["llmnr_enabled"] is True
    assert out["resolved_ip"] == "10.0.0.50"


def test_llmnr_probe_silent_host_reports_disabled():
    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr): pass
        def recvfrom(self, n): raise socket.timeout("silent")
        def close(self): pass

    with patch("agent.netbios_probe.socket.socket", return_value=_UDP()):
        out = netbios_probe._probe_llmnr("h", 5355, {"hostname": "wpad"}, 1)

    assert out["llmnr_enabled"] is False


def test_llmnr_probe_falls_back_to_short_name_from_fqdn():
    """If the asset's hostname is a fully-qualified `ws01.corp.local`,
    the LLMNR query should use just `ws01` — LLMNR is short-name
    resolution."""
    captured: list = []

    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr): captured.append(data)
        def recvfrom(self, n): raise socket.timeout("silent")
        def close(self): pass

    with patch("agent.netbios_probe.socket.socket", return_value=_UDP()):
        netbios_probe._probe_llmnr("h", 5355, {"hostname": "ws01.corp.local"}, 1)

    # The question name in the sent packet must contain "ws01" but not
    # "corp" or "local" — confirms short-name extraction.
    sent = captured[0]
    assert b"\x04ws01\x00" in sent
    assert b"corp" not in sent


# ── mDNS probe ───────────────────────────────────────────────────────


def _build_fake_mdns_response(tid: int, services: list[str]) -> bytes:
    """Minimal mDNS response: header + dummy question + N PTR answers
    whose names look like ``_<service>._tcp.local``."""
    header = struct.pack(">HHHHHH", tid, 0x8400, 1, len(services), 0, 0)
    qname = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    question = qname + struct.pack(">HH", 0x000c, 0x0001)
    answers = bytearray()
    for svc in services:
        # Build a name: _<svc>._tcp.local (or _udp). Choose tcp.
        rdata = b"\xc0\x0c"  # pointer; not parsed by our scanner
        answers.extend(b"\xc0\x0c")  # answer name compressed pointer
        answers.extend(struct.pack(">HHIH", 0x000c, 0x0001, 0, len(rdata)))
        answers.extend(rdata)
        # Append the actual service-shape labels somewhere in the buffer
        # so the scanner picks them up.
        if svc.startswith("_"):
            base = svc.encode("ascii")
            answers.extend(bytes([len(base)]) + base + b"\x04_tcp\x05local\x00")
    return header + question + bytes(answers)


def test_mdns_probe_extracts_advertised_services_from_response():
    fake_resp_holder: dict = {"resp": b""}

    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr):
            tid = struct.unpack(">H", data[:2])[0]
            fake_resp_holder["resp"] = _build_fake_mdns_response(
                tid, ["_smb", "_ssh", "_workstation"],
            )
        def recvfrom(self, n):
            if not fake_resp_holder["resp"]:
                raise socket.timeout("no send yet")
            return fake_resp_holder["resp"], ("h", 5353)
        def close(self): pass

    with patch("agent.netbios_probe.socket.socket", return_value=_UDP()):
        out = netbios_probe._probe_mdns("h", 5353, {}, 5)

    assert out["mdns_enabled"] is True
    services = set(out["advertised_services"])
    assert "_smb._tcp" in services
    assert "_ssh._tcp" in services


def test_mdns_probe_silent_host_reports_disabled():
    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr): pass
        def recvfrom(self, n): raise socket.timeout("silent")
        def close(self): pass

    with patch("agent.netbios_probe.socket.socket", return_value=_UDP()):
        out = netbios_probe._probe_mdns("h", 5353, {}, 1)

    assert out["mdns_enabled"] is False


def test_mdns_service_list_parser_dedupes():
    """Two PTR records pointing at the same service name shouldn't show
    up twice in the result list."""
    buf = (
        b"\x00" * 12
        + b"\x04_smb\x04_tcp\x05local\x00"
        + b"\x04_smb\x04_tcp\x05local\x00"
    )
    out = netbios_probe._parse_mdns_service_list(buf)
    assert out.count("_smb._tcp") == 1
