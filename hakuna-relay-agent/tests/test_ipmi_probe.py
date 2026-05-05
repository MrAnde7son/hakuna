"""Unit tests for agent.ipmi_probe (Phase 4.2).

UDP socket layer is mocked; we verify packet construction + response
parsing without binding to UDP/623.

What's under test:
  - Op-allowlist rejects unknown ops.
  - Cipher Zero probe builds an Open Session Request whose auth/integ/conf
    algorithms are all 0x00 — and reports `cipher_zero_accepted: true` only
    when the BMC echoes status=0 + algo=0 in all three slots.
  - RAKP-3 probe completes the two-step handshake (Open Session → RAKP-1)
    and reports `hash_leaked: true` when RAKP-2 returns status=0 with a
    non-zero KEAC.
  - Connection failures surface as `_errors` rather than raising.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from unittest.mock import patch

import pytest

from agent import ipmi_probe


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Allowlist ────────────────────────────────────────────────────────


def test_handler_rejects_unknown_op():
    with pytest.raises(ipmi_probe.IpmiProbeError, match="unknown ipmi probe op"):
        _run(ipmi_probe.ipmi_probe_handler(
            ws=None, task={}, transport_config={"target": "x", "port": 623},
            credentials={}, params={"op": "chassis_power_off"},
        ))


def test_handler_op_allowlist_matches_phase_4_2_scope():
    assert set(ipmi_probe._OP_HANDLERS.keys()) == {"cipher_zero", "rakp_hash"}


# ── RMCP+ packet builders ────────────────────────────────────────────


def test_build_ipmi_session_header_layout():
    """The session header is the contract the relay's wire packet relies on:
    auth_type, payload_type, session_id (LE), session_seq (LE), payload_len (LE),
    then payload bytes."""
    out = ipmi_probe._build_ipmi_session(
        payload_type=0x10, session_id=0, session_seq=0, payload=b"abcd",
    )
    assert out[0] == 0x06  # AUTH_TYPE_RMCPP
    assert out[1] == 0x10  # payload_type = Open Session Req
    assert out[2:6] == b"\x00\x00\x00\x00"  # session_id LE
    assert out[6:10] == b"\x00\x00\x00\x00"  # session_seq LE
    assert out[10:12] == b"\x04\x00"  # payload_len LE = 4
    assert out[12:] == b"abcd"


def test_open_session_req_cipher_zero_carries_all_zero_algos():
    """The cipher-zero detection hinges on auth=integ=conf=0 in the request.
    The bytes at offsets 12, 20, 28 of the 32-byte payload are the algo IDs."""
    pl = ipmi_probe._build_open_session_req_cipher_zero(0xa1a2a3a4)
    assert len(pl) == 32
    # Auth payload: type=0x00, reserved x2, length=0x08, algo=0x00, reserved x3
    assert pl[8:16] == bytes([0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
    # Integrity payload: type=0x01, reserved x2, length=0x08, algo=0x00, reserved x3
    assert pl[16:24] == bytes([0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
    # Confidentiality: type=0x02, reserved x2, length=0x08, algo=0x00, reserved x3
    assert pl[24:32] == bytes([0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])


def test_open_session_req_hmac_sha1_carries_algo_one():
    """The RAKP probe negotiates SHA1 (algo=0x01) so the BMC actually goes
    through the RAKP exchange with us."""
    pl = ipmi_probe._build_open_session_req_hmac_sha1(0xb1b2b3b4)
    assert pl[12] == 0x01  # auth algo
    assert pl[20] == 0x01  # integ algo
    assert pl[28] == 0x01  # conf algo


def test_build_rakp1_username_length_and_layout():
    """RAKP-1 layout per spec: msg tag, reserved x3, managed SID LE,
    console random (16), priv (1), reserved x2, username length (1),
    username bytes."""
    rand = b"\xa1" * 16
    pl = ipmi_probe._build_rakp1(0xdeadbeef, rand, "admin")
    assert pl[0] == 0x00  # message tag
    # Managed session ID (LE) at offset 4
    assert struct.unpack("<I", pl[4:8])[0] == 0xdeadbeef
    # Console random at offset 8
    assert pl[8:24] == rand
    # priv role at 24
    assert pl[24] == 0x14
    assert pl[27] == 5  # username length
    assert pl[28:33] == b"admin"


def test_rakp1_truncates_long_usernames_to_16_bytes():
    """IPMI usernames are bounded at 16 bytes; the builder enforces it so a
    misconfigured tool call can't overrun the BMC's parse buffer."""
    pl = ipmi_probe._build_rakp1(0, b"\x00" * 16, "X" * 32)
    assert pl[27] == 16
    assert pl[28:44] == b"X" * 16


# ── Parsers ──────────────────────────────────────────────────────────


def test_parse_session_header_rejects_non_rmcp_buffers():
    assert ipmi_probe._parse_ipmi_session_header(b"GET / HTTP/1.1\r\n") is None
    assert ipmi_probe._parse_ipmi_session_header(b"") is None
    # Wrong RMCP version byte
    bad = b"\x05\x00\xff\x07" + b"\x06" + b"\x00" * 11
    assert ipmi_probe._parse_ipmi_session_header(bad) is None


def test_parse_session_header_extracts_payload_type_and_payload():
    pkt = (
        ipmi_probe._RMCP_HEADER
        + bytes([0x06, 0x11])           # auth=RMCP+, payload=Open Session Resp
        + struct.pack("<I", 0)          # session id
        + struct.pack("<I", 0)          # session seq
        + struct.pack("<H", 4)          # payload len
        + b"\xaa\xbb\xcc\xdd"
    )
    parsed = ipmi_probe._parse_ipmi_session_header(pkt)
    assert parsed is not None
    payload_type, sid, seq, payload = parsed
    assert payload_type == 0x11
    assert sid == 0
    assert seq == 0
    assert payload == b"\xaa\xbb\xcc\xdd"


def test_parse_open_session_resp_extracts_status_and_algos():
    """Open Session Response: msg_tag(1) + status(1) + priv(1) + res(1) +
    console_sid(4) + managed_sid(4) + auth_payload(8) + integ_payload(8)
    + conf_payload(8). Algos at offsets 16, 24, 32 of the payload."""
    payload = (
        bytes([0x00, 0x00, 0x04, 0x00])
        + struct.pack("<I", 0xa1a2a3a4)
        + struct.pack("<I", 0xb1b2b3b4)
        + bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])  # auth algo=1
        + bytes([0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])  # integ
        + bytes([0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])  # conf
    )
    info = ipmi_probe._parse_open_session_resp(payload)
    assert info["status"] == 0
    assert info["console_session_id"] == 0xa1a2a3a4
    assert info["managed_session_id"] == 0xb1b2b3b4
    assert info["chosen_auth_algo"] == 1
    assert info["chosen_integ_algo"] == 1
    assert info["chosen_conf_algo"] == 1


def test_parse_rakp2_extracts_keac():
    keac = b"\xde\xad\xbe\xef" * 5  # 20 bytes (HMAC-SHA1)
    payload = (
        bytes([0x00, 0x00, 0x00, 0x00])
        + struct.pack("<I", 0xdeadbeef)
        + b"\x42" * 16  # managed random
        + b"\x69" * 16  # managed guid
        + keac
    )
    info = ipmi_probe._parse_rakp2(payload)
    assert info["status"] == 0
    assert info["keac"] == keac


# ── Cipher Zero probe ────────────────────────────────────────────────


def _fake_udp(scripted_response: bytes, capture: list | None = None):
    """Build a fake UDP socket that returns ``scripted_response`` once on
    recvfrom. Captures sent packets in ``capture`` if given."""
    capture = capture if capture is not None else []
    state = {"sent_count": 0}

    class _UDP:
        def settimeout(self, t):
            pass

        def sendto(self, data, addr):
            capture.append((data, addr))
            state["sent_count"] += 1

        def recvfrom(self, n):
            if state["sent_count"] == 0:
                raise socket.timeout("no send yet")
            return scripted_response, ("h", 623)

        def close(self):
            pass

    return _UDP()


def _build_open_session_resp_packet(status: int, algos: tuple[int, int, int],
                                     managed_sid: int = 0xb1b2b3b4) -> bytes:
    """Construct an RMCP+ Open Session Response packet for the BMC's reply."""
    payload = (
        bytes([0x00, status, 0x04, 0x00])
        + struct.pack("<I", 0xa1a2a3a4)  # console SID
        + struct.pack("<I", managed_sid)
        + bytes([0x00, 0x00, 0x00, 0x08, algos[0], 0x00, 0x00, 0x00])
        + bytes([0x01, 0x00, 0x00, 0x08, algos[1], 0x00, 0x00, 0x00])
        + bytes([0x02, 0x00, 0x00, 0x08, algos[2], 0x00, 0x00, 0x00])
    )
    return ipmi_probe._RMCP_HEADER + ipmi_probe._build_ipmi_session(
        payload_type=0x11, session_id=0, session_seq=0, payload=payload,
    )


def test_cipher_zero_probe_flags_vulnerable_when_status_zero_and_algos_all_zero():
    pkt = _build_open_session_resp_packet(status=0, algos=(0, 0, 0))
    captured: list = []

    with patch("agent.ipmi_probe.socket.socket", return_value=_fake_udp(pkt, captured)):
        out = ipmi_probe._probe_cipher_zero("h", 623, {}, 5)

    assert out["cipher_zero_accepted"] is True
    assert out["bmc_responded"] is True
    assert out["status_code"] == 0
    # Verify we actually sent an Open Session Request (payload_type 0x10)
    sent_pkt, _addr = captured[0]
    assert sent_pkt[5] == 0x10  # IPMI 2.0 payload type byte


def test_cipher_zero_probe_flags_safe_when_bmc_downgrades_to_real_cipher():
    """Status 0 but auth algo non-zero = BMC accepted the session but
    chose a non-NONE cipher — not vulnerable to cipher zero."""
    pkt = _build_open_session_resp_packet(status=0, algos=(1, 1, 1))

    with patch("agent.ipmi_probe.socket.socket", return_value=_fake_udp(pkt)):
        out = ipmi_probe._probe_cipher_zero("h", 623, {}, 5)

    assert out["cipher_zero_accepted"] is False
    assert out["bmc_responded"] is True
    assert out["status_code"] == 0


def test_cipher_zero_probe_flags_safe_when_bmc_returns_error_status():
    """A non-zero status (e.g. 0x12 = unsupported cipher suite) means the
    BMC explicitly refused — not vulnerable."""
    pkt = _build_open_session_resp_packet(status=0x12, algos=(0, 0, 0))

    with patch("agent.ipmi_probe.socket.socket", return_value=_fake_udp(pkt)):
        out = ipmi_probe._probe_cipher_zero("h", 623, {}, 5)

    assert out["cipher_zero_accepted"] is False
    assert out["status_code"] == 0x12


def test_cipher_zero_probe_handles_recv_timeout():
    """Unreachable BMC → timeout → structured error, not a crash."""
    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr): pass
        def recvfrom(self, n): raise socket.timeout("no reply")
        def close(self): pass

    with patch("agent.ipmi_probe.socket.socket", return_value=_UDP()):
        out = ipmi_probe._probe_cipher_zero("h", 623, {}, 1)

    assert "_errors" in out and "cipher_zero" in out["_errors"]


# ── RAKP-3 hash probe ────────────────────────────────────────────────


def _build_rakp2_packet(status: int, keac: bytes,
                        console_sid: int = 0xa1a2a3a4) -> bytes:
    payload = (
        bytes([0x00, status, 0x00, 0x00])
        + struct.pack("<I", console_sid)
        + b"\x55" * 16  # managed random
        + b"\x66" * 16  # managed guid
        + keac
    )
    return ipmi_probe._RMCP_HEADER + ipmi_probe._build_ipmi_session(
        payload_type=0x13, session_id=0, session_seq=0, payload=payload,
    )


def _scripted_udp(packets: list[bytes], capture: list | None = None):
    """Return packets[0] on first recvfrom, packets[1] on second, etc."""
    capture = capture if capture is not None else []
    state = {"recv_idx": 0}

    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, data, addr): capture.append(data)
        def recvfrom(self, n):
            i = state["recv_idx"]
            if i >= len(packets):
                raise socket.timeout("out of scripted replies")
            state["recv_idx"] += 1
            return packets[i], ("h", 623)
        def close(self): pass

    return _UDP()


def test_rakp_hash_probe_flags_leak_on_status_zero_with_non_zero_keac():
    open_resp = _build_open_session_resp_packet(status=0, algos=(1, 1, 1))
    keac = b"\xde\xad\xbe\xef" * 5  # 20-byte HMAC-SHA1
    rakp2 = _build_rakp2_packet(status=0, keac=keac)
    captured: list = []

    with patch("agent.ipmi_probe.socket.socket",
               return_value=_scripted_udp([open_resp, rakp2], captured)):
        out = ipmi_probe._probe_rakp_hash("h", 623, {"username": "admin"}, 5)

    assert out["hash_leaked"] is True
    assert out["keac_hex"] == keac.hex()
    assert out["username_tested"] == "admin"
    assert out["auth_algo"] == 1
    # Verify the second send was a RAKP-1 (payload_type 0x12 at byte 5).
    assert captured[1][5] == 0x12


def test_rakp_hash_probe_no_leak_when_bmc_returns_unauthorized_username():
    """Status 0x0d ('Invalid name') means the username doesn't exist on
    the BMC. The RAKP-2 still parses but no hash is disclosed."""
    open_resp = _build_open_session_resp_packet(status=0, algos=(1, 1, 1))
    rakp2 = _build_rakp2_packet(status=0x0d, keac=b"\x00" * 20)

    with patch("agent.ipmi_probe.socket.socket",
               return_value=_scripted_udp([open_resp, rakp2])):
        out = ipmi_probe._probe_rakp_hash("h", 623, {"username": "bogus"}, 5)

    assert out["hash_leaked"] is False
    assert out.get("status_code") == 0x0d


def test_rakp_hash_probe_handles_open_session_denial():
    """If the BMC refuses the Open Session (e.g. cipher mismatch), the
    probe surfaces a clean error and never sends RAKP-1."""
    open_resp = _build_open_session_resp_packet(status=0x12, algos=(0, 0, 0))
    captured: list = []

    with patch("agent.ipmi_probe.socket.socket",
               return_value=_scripted_udp([open_resp], captured)):
        out = ipmi_probe._probe_rakp_hash("h", 623, {}, 5)

    assert "_errors" in out and "rakp_hash" in out["_errors"]
    # Only one packet was sent — the Open Session Request. No RAKP-1.
    assert len(captured) == 1
