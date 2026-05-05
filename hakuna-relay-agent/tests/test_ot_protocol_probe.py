"""Unit tests for agent.ot_protocol_probe (Phase 5).

Socket layer is mocked. We verify:
  - Op-allowlist rejects unknown ops.
  - Each protocol's request packet matches the spec at the byte level.
  - Each protocol's response parser handles the canonical happy path
    plus malformed input (no exceptions, just _errors / Nones).
  - Rate limiter spaces back-to-back PDUs by ≥2s.
  - Modbus FC3 clamps unit_id and count to spec ceilings.
  - SLMP/FINS read-only command codes are wired correctly.
"""

from __future__ import annotations

import asyncio
import struct
import time
from unittest.mock import MagicMock, patch

import pytest

from agent import ot_protocol_probe


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Allowlist ────────────────────────────────────────────────────────


def test_handler_rejects_unknown_op():
    with pytest.raises(ot_protocol_probe.OtProbeError, match="unknown ot probe op"):
        _run(ot_protocol_probe.ot_protocol_probe_handler(
            ws=None, task={},
            transport_config={"target": "x", "port": 502},
            credentials={}, params={"op": "modbus_write_coil"},
        ))


def test_op_allowlist_matches_phase_5_scope():
    expected = {
        "modbus_read_device_id", "modbus_read_holding",
        "s7_read_szl", "enip_list_identity", "bacnet_read_property",
        "opcua_hello", "melsec_read_cpu_info",
        "omron_fins_read_cpu_unit", "iec104_interrogate",
        "profinet_dcp_unicast",
    }
    assert set(ot_protocol_probe._OP_HANDLERS.keys()) == expected


# ── Modbus packet builders ───────────────────────────────────────────


def test_modbus_read_device_id_payload_is_fc43_mei14_object0():
    pkt = ot_protocol_probe._build_modbus_read_device_id()
    assert pkt[7] == 0x2B  # FC 43
    assert pkt[8] == 0x0E  # MEI 14
    assert pkt[9] == 0x01  # Read Device ID code Basic
    assert pkt[10] == 0x00  # Object ID 0


def test_modbus_read_holding_packet_layout():
    pkt = ot_protocol_probe._build_modbus_read_holding(unit_id=5, start=100, count=8)
    assert pkt[0:2] == b"\x00\x01"  # Transaction ID
    assert pkt[2:4] == b"\x00\x00"  # Protocol ID
    assert pkt[4:6] == b"\x00\x06"  # Length
    assert pkt[6] == 5               # Unit ID
    assert pkt[7] == 0x03            # FC 3 (Read Holding Registers)
    assert struct.unpack(">H", pkt[8:10])[0] == 100
    assert struct.unpack(">H", pkt[10:12])[0] == 8


def test_modbus_parse_device_id_extracts_three_strings():
    # Build a synthetic FC 43 response with three objects.
    body = (
        b"\x00\x01\x00\x00\x00\x10\x00\x2B\x0E"  # MBAP + FC + MEI
        b"\x01\x01\x00\x03"                        # codes + num_objects = 3
        + b"\x00\x09" + b"Schneider"             # vendor
        + b"\x01\x04" + b"M580"                   # product code
        + b"\x02\x03" + b"V01"                    # revision
    )
    parsed = ot_protocol_probe._parse_modbus_device_id(body)
    assert parsed.get("vendor") == "Schneider"
    assert parsed.get("product_code") == "M580"
    assert parsed.get("revision") == "V01"


def test_modbus_parse_device_id_handles_garbage():
    assert ot_protocol_probe._parse_modbus_device_id(b"") == {}
    assert ot_protocol_probe._parse_modbus_device_id(b"\x00" * 8) == {}


def test_modbus_read_holding_clamps_count_relay_side():
    """Even if the backend tool was bypassed, the relay still caps count
    at 16 (the FC 3 byte_count field can't address more than 252/2 = 125
    registers but our policy is 16)."""
    with patch.object(ot_protocol_probe, "_tcp_send_recv", return_value=None):
        result = ot_protocol_probe._probe_modbus_read_holding(
            "1.2.3.4", 502, {"start_addr": 0, "count": 99999, "unit_id": 999}, 5,
        )
    # No reply → _errors set; but the input should have been clamped before
    # reaching the wire. Verify by re-running with a recording stub.
    sent: list[bytes] = []

    def capture(host, port, payload, timeout, max_read=4096):
        sent.append(payload)
        return None

    with patch.object(ot_protocol_probe, "_tcp_send_recv", side_effect=capture):
        ot_protocol_probe._probe_modbus_read_holding(
            "1.2.3.4", 502, {"start_addr": 0, "count": 99999, "unit_id": 999}, 5,
        )
    assert len(sent) == 1
    pkt = sent[0]
    # unit_id clamped to 247
    assert pkt[6] == 247
    # count clamped to 16
    assert struct.unpack(">H", pkt[10:12])[0] == 16


# ── S7 packet builders ───────────────────────────────────────────────


def test_s7_cotp_cr_encodes_rack_slot_in_dest_tsap():
    pkt = ot_protocol_probe._build_s7_cotp_cr(rack=2, slot=3)
    # Dest TSAP low byte at offset 21: ((rack & 7) << 5) | (slot & 0x1F)
    assert pkt[21] == ((2 & 7) << 5) | (3 & 0x1F)
    assert pkt[5] == 0xE0  # CR


def test_s7_setup_communication_constant_is_well_formed():
    pkt = ot_protocol_probe._S7_SETUP_COMMS
    assert pkt[0] == 0x03  # TPKT
    assert pkt[7] == 0x32  # S7 magic
    assert pkt[8] == 0x01  # ROSCTR=Job
    assert pkt[17:19] == b"\xF0\x00"  # Function: Setup Communication


def test_s7_read_szl_request_targets_szl_id_0011():
    """The Read SZL request must explicitly target SZL ID 0x0011 (Module
    Identification) — NOT 0x0017 (writes) or any data-block read."""
    pkt = ot_protocol_probe._S7_READ_SZL_0011
    assert pkt[0] == 0x03
    assert pkt[8] == 0x07  # ROSCTR=UserData
    # SZL ID is at the tail before the trailing index bytes.
    assert pkt[-4:-2] == b"\x00\x11"  # SZL ID 0x0011


# ── EtherNet/IP ──────────────────────────────────────────────────────


def test_enip_list_identity_command_code():
    assert ot_protocol_probe._ENIP_LIST_IDENTITY[:2] == b"\x63\x00"  # ListIdentity


def test_enip_parse_identity_extracts_vendor_product():
    """Synthesize a ListIdentity reply with the parser's expected layout:
    vendor at offset 38, product_code at 40, revision at 42-43,
    status at 44-45, serial at 46-49, name_len at 50, name at 51+."""
    payload = (
        b"\x00" * 38          # encap header + item header + sockaddr padding
        + b"\x01\x00"         # vendor_id (LE) = 1 (offset 38)
        + b"\x0E\x00"         # product_code = 14 (offset 40)
        + bytes([1, 5])       # revision major.minor (offset 42-43)
        + b"\x00\x00"         # status (offset 44-45)
        + struct.pack("<I", 0xDEADBEEF)  # serial (offset 46-49)
        + b"\x06"             # name length (offset 50)
        + b"PLC-AB"           # name (offset 51+)
        + b"\x00"
    )
    out = ot_protocol_probe._parse_enip_identity(payload)
    assert out["vendor_id"] == 1
    assert out["product_code"] == 14
    assert out["revision"] == "1.5"
    assert out["product_name"] == "PLC-AB"
    assert out["serial"] == "deadbeef"


# ── BACnet ───────────────────────────────────────────────────────────


def test_bacnet_read_prop_packet_targets_object_name_of_device_0():
    pkt = ot_protocol_probe._BACNET_READ_PROP
    assert pkt[0] == 0x81  # BVLC
    # Object identifier tag (0x0C) → device 0
    assert pkt[10] == 0x0C
    # Property identifier 77 = Object-Name
    assert pkt[15:17] == b"\x19\x4D"


# ── OPC UA ───────────────────────────────────────────────────────────


def test_opcua_hello_starts_with_helf():
    pkt = ot_protocol_probe._build_opcua_hello()
    assert pkt[:4] == b"HELF"
    # protocol version field at offset 8, little-endian u32 = 0
    assert pkt[8:12] == b"\x00\x00\x00\x00"


def test_opcua_parse_ack_reads_buffer_sizes():
    # Synthetic ACK: "ACKF" + length(8) + version + recv + send + max_msg + max_chunk
    ack = (
        b"ACKF"
        + struct.pack("<I", 28)
        + struct.pack("<I", 0)         # protocol version
        + struct.pack("<I", 65536)     # recv buffer
        + struct.pack("<I", 65536)     # send buffer
        + struct.pack("<I", 524288)    # max message
        + struct.pack("<I", 0)         # max chunk
    )
    out = ot_protocol_probe._parse_opcua_ack(ack)
    assert out["protocol_version"] == 0
    assert out["recv_buffer_size"] == 65536
    assert out["max_message_size"] == 524288


# ── MELSEC SLMP ──────────────────────────────────────────────────────


def test_slmp_read_cpu_type_command_is_0101_subcmd_0000():
    """The hardcoded SLMP request must be exactly Read CPU Type — the read-
    only family. Any drift toward 0x1401 (device write) etc. is a
    catastrophic regression."""
    pkt = ot_protocol_probe._SLMP_READ_CPU_TYPE
    assert pkt[:2] == b"\x50\x00"           # Subheader request
    # Command at offset 11, subcommand at 13
    assert pkt[11:13] == b"\x01\x01"        # 0x0101 Read CPU Type (LE)
    assert pkt[13:15] == b"\x00\x00"        # Subcommand 0x0000


def test_slmp_parse_response_extracts_cpu_model():
    body = (
        b"\xD0\x00"              # Response subheader
        + b"\x00\xFF\xFF\x03\x00"  # net/PC/IO/station
        + b"\x14\x00"            # response data length
        + b"\x00\x00"            # end code = 0
        + b"Q03UDECPU\x00\x00\x00\x00\x00\x00\x00"  # 16-byte CPU model
        + b"\x12\x34"            # CPU code
    )
    out = ot_protocol_probe._parse_slmp_response(body)
    assert out["cpu_model"] == "Q03UDECPU"
    assert out["cpu_code"] == "1234"


def test_slmp_parse_response_surfaces_error_code():
    body = (
        b"\xD0\x00\x00\xFF\xFF\x03\x00\x04\x00\x55\xC0"
    )
    out = ot_protocol_probe._parse_slmp_response(body)
    assert out["_end_code"] == "0xc055"


# ── Omron FINS ───────────────────────────────────────────────────────


def test_fins_request_uses_read_only_command_05_01():
    """FINS handler must hardcode MRC=0x05 / SRC=0x01 (CPU UNIT DATA READ).
    Any other command code is a security regression."""
    pkt = ot_protocol_probe._build_fins_cpu_unit_data_read()
    assert pkt[10:12] == b"\x05\x01"


def test_fins_parse_cpu_unit_data_extracts_model():
    body = (
        b"\xC0" + b"\x00" * 9        # response header (12 bytes of FINS header)
        + b"\x05\x01"                # MRC/SRC echo
        + b"\x00\x00"                # End code success
        + b"CJ2M-CPU33".ljust(20, b"\x00")
        + b"V1.04".ljust(20, b"\x00")
    )
    out = ot_protocol_probe._parse_fins_cpu_unit_data(body)
    assert out["model"] == "CJ2M-CPU33"
    assert out["version"] == "V1.04"


# ── IEC 60870-5-104 ──────────────────────────────────────────────────


def test_iec104_startdt_act_is_canonical_six_bytes():
    assert ot_protocol_probe._IEC104_STARTDT_ACT == b"\x68\x04\x07\x00\x00\x00"


def test_iec104_general_interrogation_is_type_100_cot_6():
    pkt = ot_protocol_probe._build_iec104_general_interrogation()
    # APCI: 6 bytes. ASDU starts at offset 6.
    assert pkt[0] == 0x68
    assert pkt[1] == 0x0E             # length
    assert pkt[6] == 0x64             # Type ID 100 (C_IC_NA_1)
    assert pkt[7] == 0x01             # VSQ: 1 IO, no SQ
    assert pkt[8] == 0x06             # COT activation
    # IO addr (3 bytes) + QOI 0x14
    assert pkt[-1] == 0x14            # QOI station-interrogation


def test_iec104_apci_parser_handles_startdt_con():
    parsed = ot_protocol_probe._parse_iec104_apci(b"\x68\x04\x0B\x00\x00\x00", 0)
    assert parsed is not None
    total, ctrl, asdu = parsed
    assert total == 6
    assert ctrl == 0x0B  # STARTDT CON
    assert asdu == b""


def test_iec104_apci_parser_rejects_non_start_byte():
    assert ot_protocol_probe._parse_iec104_apci(b"\xFF\x04\x07\x00\x00\x00", 0) is None


# ── PROFINET DCP ─────────────────────────────────────────────────────


def test_profinet_dcp_identify_is_service_id_5_request():
    pkt = ot_protocol_probe._build_profinet_dcp_identify_all()
    assert pkt[:2] == b"\xFE\xFE"      # Frame ID Identify Multi
    assert pkt[2] == 0x05               # Service ID Identify
    assert pkt[3] == 0x00               # Service Type Request


# ── Rate limiter ─────────────────────────────────────────────────────


def test_rate_limiter_enforces_two_second_floor():
    """Two acquire() calls back-to-back must be spaced ≥ _MIN_INTER_PDU_S
    (default 2s). Use a fresh limiter so prior tests don't influence state."""
    lim = ot_protocol_probe._RateLimiter()
    lim.acquire()
    start = time.monotonic()
    lim.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= ot_protocol_probe._MIN_INTER_PDU_S - 0.05  # tiny slop for sleep granularity


def test_rate_limiter_respects_env_rps_cap(monkeypatch):
    """Setting HAKUNA_OT_RPS=0.5 means a 2s gap from RPS plus the 2s floor =
    still 2s. Setting it absurdly high (10) is clamped to 5 RPS = 0.2s gap,
    but the 2s floor wins. The floor is the real safety contract."""
    monkeypatch.setenv("HAKUNA_OT_RPS", "10")
    assert ot_protocol_probe._resolve_rps() <= 5.0
    monkeypatch.setenv("HAKUNA_OT_RPS", "0.05")  # below clamp floor 0.2
    assert ot_protocol_probe._resolve_rps() == 0.2


# ── End-to-end probe with mocked sockets ─────────────────────────────


def test_modbus_read_device_id_returns_reachable_on_valid_reply():
    body = (
        b"\x00\x01\x00\x00\x00\x10\x00\x2B\x0E"
        b"\x01\x01\x00\x01"
        + b"\x00\x05" + b"Vendr"
    )
    with patch.object(ot_protocol_probe, "_tcp_send_recv", return_value=body):
        result = ot_protocol_probe._probe_modbus_read_device_id(
            "10.1.2.3", 502, {}, 5,
        )
    assert result["reachable"] is True
    assert result["vendor"] == "Vendr"


def test_modbus_read_device_id_returns_no_reply_error_when_socket_silent():
    with patch.object(ot_protocol_probe, "_tcp_send_recv", return_value=None):
        result = ot_protocol_probe._probe_modbus_read_device_id(
            "10.1.2.3", 502, {}, 5,
        )
    assert result["reachable"] is False
    assert "modbus_read_device_id" in result["_errors"]


def test_profinet_dcp_returns_inconclusive_error_message():
    """Critical for triage: a negative DCP unicast reply must say `inconclusive`
    so the LLM doesn't claim the device is absent."""
    with patch.object(ot_protocol_probe, "_udp_send_recv", return_value=None):
        result = ot_protocol_probe._probe_profinet_dcp_unicast(
            "10.1.2.3", 34962, {}, 5,
        )
    assert "inconclusive" in result["_errors"]["profinet_dcp_unicast"]
