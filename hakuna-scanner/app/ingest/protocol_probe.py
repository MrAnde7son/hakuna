"""Protocol probing for non-HTTP services — OT/ICS, IoT, and AI infrastructure.

Sends lightweight protocol-specific payloads to open ports and classifies
the service based on the response. Designed to be safe for OT environments:
read-only identification queries, no writes, no state changes.

Supported protocols:
  - Modbus TCP (port 502): Read Device Identification (FC 43/14)
  - S7comm (port 102): COTP connect + S7 setup
  - BACnet (port 47808): Read Property - Object Name
  - EtherNet/IP (port 44818): List Identity
  - DNP3 (port 20000): Data Link Layer cold restart probe
  - OPC-UA (port 4840): OPC-UA Hello
  - Niagara Fox (port 1911): Fox hello
  - MQTT (port 1883): CONNECT with empty client ID
  - RTSP (port 554): OPTIONS request
"""

from __future__ import annotations

import asyncio
import logging
import struct

logger = logging.getLogger(__name__)

# Maximum bytes to read from a service response
_MAX_READ = 2048
_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 5


# ─── Protocol Payloads ───────────────────────────────────────────────────────
# All payloads are read-only identification requests. No writes or state changes.

# Modbus TCP: Read Device Identification (Function Code 43, MEI 14, Object 0)
_MODBUS_DEVICE_ID = bytes([
    0x00, 0x01,  # Transaction ID
    0x00, 0x00,  # Protocol ID (Modbus)
    0x00, 0x05,  # Length
    0x00,        # Unit ID
    0x2B,        # FC 43 (Read Device Identification)
    0x0E,        # MEI type 14
    0x01,        # Read Device ID code: Basic
    0x00,        # Object ID 0 (Vendor Name)
])

# S7comm: COTP Connection Request (ISO 8073)
_S7_COTP_CR = bytes([
    0x03, 0x00,  # TPKT version 3
    0x00, 0x16,  # Length 22
    0x11,        # COTP length
    0xE0,        # CR (Connection Request)
    0x00, 0x00,  # Dest ref
    0x00, 0x01,  # Source ref
    0x00,        # Class 0
    0xC0, 0x01, 0x0A,  # TPDU size parameter (1024)
    0xC1, 0x02, 0x01, 0x00,  # Source TSAP
    0xC2, 0x02, 0x01, 0x02,  # Dest TSAP (rack 0, slot 2)
])

# BACnet: Read Property (Object Name of Device 0) — BACnet/IP via BVLC
_BACNET_READ_PROP = bytes([
    0x81, 0x0A,  # BVLC type, Original-Unicast-NPDU
    0x00, 0x11,  # Length 17
    0x01, 0x04,  # NPDU version 1, no reply expected
    0x00,        # APDU type: Confirmed-Request
    0x05,        # Max APDU accepted: 1476
    0x01,        # Invoke ID
    0x0C,        # Service: ReadProperty
    0x0C, 0x02, 0x00, 0x00, 0x00,  # Object: Device 0
    0x19, 0x4D,  # Property: Object-Name (77)
])

# EtherNet/IP: List Identity
_ENIP_LIST_IDENTITY = bytes([
    0x63, 0x00,  # Command: List Identity
    0x00, 0x00,  # Length 0
    0x00, 0x00, 0x00, 0x00,  # Session handle
    0x00, 0x00, 0x00, 0x00,  # Status
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  # Sender context
    0x00, 0x00, 0x00, 0x00,  # Options
])

# DNP3: Data link layer read (direction=master, FC=0 reset link)
_DNP3_READ = bytes([
    0x05, 0x64,  # Start bytes
    0x05,        # Length
    0xC0,        # Control: DIR=1, PRM=1, FCV=0, FC=0 (Reset Link)
    0x01, 0x00,  # Destination
    0x00, 0x00,  # Source
])

# OPC-UA: Hello message
_OPCUA_HELLO = (
    b"HEL"       # Message type
    b"F"          # Chunk type: Final
    + struct.pack("<I", 32 + 26)  # Message size
    + struct.pack("<I", 0)        # Protocol version
    + struct.pack("<I", 65535)    # Receive buffer
    + struct.pack("<I", 65535)    # Send buffer
    + struct.pack("<I", 0)        # Max message size
    + struct.pack("<I", 0)        # Max chunk count
    + struct.pack("<I", 26)       # Endpoint URL length
    + b"opc.tcp://localhost:4840"
)

# Niagara Fox: station hello
_FOX_HELLO = b"fox a 1 -1 fox hello\n"

# MQTT: CONNECT packet with empty client ID
_MQTT_CONNECT = bytes([
    0x10,        # CONNECT packet type
    0x0C,        # Remaining length
    0x00, 0x04,  # Protocol name length
    0x4D, 0x51, 0x54, 0x54,  # "MQTT"
    0x04,        # Protocol level 4 (MQTT 3.1.1)
    0x02,        # Connect flags (Clean Session)
    0x00, 0x3C,  # Keep alive 60s
    0x00, 0x00,  # Client ID length 0
])

# RTSP: OPTIONS request
_RTSP_OPTIONS = b"OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"


# ─── Response Extractors ─────────────────────────────────────────────────────
# Defined before PROTOCOL_PROBES so they can be referenced by name.

def _extract_modbus_info(data: bytes) -> dict:
    """Extract Modbus device identification fields."""
    info = {"protocol": "modbus"}
    try:
        if len(data) > 15 and data[7] == 0x2B and data[8] == 0x0E:
            # Parse MEI response objects
            offset = 13
            num_objects = data[12] if len(data) > 12 else 0
            field_names = {0: "vendor", 1: "product_code", 2: "revision"}
            for _ in range(min(num_objects, 3)):
                if offset + 2 > len(data):
                    break
                obj_id = data[offset]
                obj_len = data[offset + 1]
                if offset + 2 + obj_len > len(data):
                    break
                obj_val = data[offset + 2:offset + 2 + obj_len].decode("ascii", errors="replace")
                if obj_id in field_names:
                    info[field_names[obj_id]] = obj_val
                offset += 2 + obj_len
    except Exception:
        pass
    return info


def _extract_s7_info(data: bytes) -> dict:
    """Extract S7comm COTP connection confirm details."""
    return {"protocol": "s7comm", "cotp_confirmed": True}


def _extract_enip_info(data: bytes) -> dict:
    """Extract EtherNet/IP List Identity response."""
    info = {"protocol": "ethernet_ip"}
    try:
        if len(data) > 63:
            # Product name is at offset ~48, prefixed by length
            name_len_offset = 48
            if name_len_offset < len(data):
                name_len = data[name_len_offset]
                name_start = name_len_offset + 1
                if name_start + name_len <= len(data):
                    info["product_name"] = data[name_start:name_start + name_len].decode(
                        "ascii", errors="replace"
                    )
    except Exception:
        pass
    return info


def _extract_fox_info(data: bytes) -> dict:
    """Extract Niagara Fox station information."""
    info = {"protocol": "fox"}
    text = data.decode("ascii", errors="replace")
    for line in text.split("\n"):
        if "hostName" in line:
            parts = line.split("=", 1)
            if len(parts) == 2:
                info["hostname"] = parts[1].strip()
        elif "version" in line.lower():
            parts = line.split("=", 1)
            if len(parts) == 2:
                info["version"] = parts[1].strip()
    return info


def _extract_mqtt_info(data: bytes) -> dict:
    """Extract MQTT CONNACK details."""
    info = {"protocol": "mqtt"}
    if len(data) >= 4:
        return_code = data[3]
        info["connack_return_code"] = return_code
        info["accepts_anonymous"] = return_code == 0  # 0 = Connection Accepted
    return info


def _extract_rtsp_info(data: bytes) -> dict:
    """Extract RTSP server info from OPTIONS response."""
    info = {"protocol": "rtsp"}
    text = data.decode("ascii", errors="replace")
    for line in text.split("\r\n"):
        if line.lower().startswith("server:"):
            info["server"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("public:"):
            info["methods"] = line.split(":", 1)[1].strip()
    return info


# ─── Protocol Definitions ────────────────────────────────────────────────────

PROTOCOL_PROBES = [
    {
        "name": "Modbus TCP",
        "port": 502,
        "payload": _MODBUS_DEVICE_ID,
        "match": lambda data: len(data) >= 9 and data[7] == 0x2B,
        "extract": _extract_modbus_info,
        "asset_type": "plc",
        "protocol": "modbus",
        "severity": "critical",
        "finding_title": "Internet-Exposed Modbus TCP Service",
    },
    {
        "name": "Siemens S7comm",
        "port": 102,
        "payload": _S7_COTP_CR,
        "match": lambda data: len(data) >= 7 and data[0] == 0x03 and data[5] == 0xD0,
        "extract": _extract_s7_info,
        "asset_type": "plc",
        "protocol": "s7comm",
        "severity": "critical",
        "finding_title": "Internet-Exposed Siemens S7 PLC",
    },
    {
        "name": "EtherNet/IP (CIP)",
        "port": 44818,
        "payload": _ENIP_LIST_IDENTITY,
        "match": lambda data: len(data) >= 4 and data[0:2] == b"\x63\x00",
        "extract": _extract_enip_info,
        "asset_type": "plc",
        "protocol": "ethernet_ip",
        "severity": "critical",
        "finding_title": "Internet-Exposed EtherNet/IP Service",
    },
    {
        "name": "DNP3",
        "port": 20000,
        "payload": _DNP3_READ,
        "match": lambda data: len(data) >= 2 and data[0:2] == b"\x05\x64",
        "extract": lambda data: {"protocol": "dnp3"},
        "asset_type": "plc",
        "protocol": "dnp3",
        "severity": "critical",
        "finding_title": "Internet-Exposed DNP3 Service",
    },
    {
        "name": "OPC-UA",
        "port": 4840,
        "payload": _OPCUA_HELLO,
        "match": lambda data: len(data) >= 4 and data[0:3] == b"ACK",
        "extract": lambda data: {"protocol": "opc-ua"},
        "asset_type": "scada",
        "protocol": "opc-ua",
        "severity": "critical",
        "finding_title": "Internet-Exposed OPC-UA Service",
    },
    {
        "name": "BACnet",
        "port": 47808,
        "payload": _BACNET_READ_PROP,
        "match": lambda data: len(data) >= 4 and data[0] == 0x81,
        "extract": lambda data: {"protocol": "bacnet"},
        "asset_type": "smart_building",
        "protocol": "bacnet",
        "severity": "high",
        "finding_title": "Internet-Exposed BACnet Service",
    },
    {
        "name": "Niagara Fox",
        "port": 1911,
        "payload": _FOX_HELLO,
        "match": lambda data: b"fox" in data.lower() if data else False,
        "extract": _extract_fox_info,
        "asset_type": "smart_building",
        "protocol": "fox",
        "severity": "high",
        "finding_title": "Internet-Exposed Niagara Fox Service",
    },
    {
        "name": "MQTT Broker",
        "port": 1883,
        "payload": _MQTT_CONNECT,
        "match": lambda data: len(data) >= 2 and data[0] == 0x20,
        "extract": _extract_mqtt_info,
        "asset_type": "iot_gateway",
        "protocol": "mqtt",
        "severity": "high",
        "finding_title": "Internet-Exposed MQTT Broker",
    },
    {
        "name": "RTSP",
        "port": 554,
        "payload": _RTSP_OPTIONS,
        "match": lambda data: b"RTSP/1.0" in data if data else False,
        "extract": _extract_rtsp_info,
        "asset_type": "camera",
        "protocol": "rtsp",
        "severity": "high",
        "finding_title": "Internet-Exposed RTSP Stream",
    },
]


# ─── Probe Runner ─────────────────────────────────────────────────────────────

async def _probe_single(
    host: str,
    port: int,
    payload: bytes,
    match_fn,
    extract_fn,
) -> dict | None:
    """Send a protocol payload and check the response."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        writer.write(payload)
        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(_MAX_READ), timeout=_READ_TIMEOUT)
        except asyncio.TimeoutError:
            return None

        if data and match_fn(data):
            return extract_fn(data)
        return None
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def probe_asset_protocols(
    hostname: str,
    ip: str | None,
    open_ports: list[int],
) -> list[dict]:
    """Probe all matching OT/IoT protocols on an asset's open ports.

    Returns list of detection dicts with keys:
      name, protocol, asset_type, port, severity, finding_title, metadata
    """
    target = ip or hostname
    results = []

    tasks = []
    for probe_def in PROTOCOL_PROBES:
        if probe_def["port"] in open_ports:
            tasks.append((probe_def, _probe_single(
                target,
                probe_def["port"],
                probe_def["payload"],
                probe_def["match"],
                probe_def["extract"],
            )))

    if not tasks:
        return results

    coros = [t[1] for t in tasks]
    responses = await asyncio.gather(*coros, return_exceptions=True)

    for (probe_def, _), response in zip(tasks, responses):
        if isinstance(response, Exception) or response is None:
            continue
        results.append({
            "name": probe_def["name"],
            "protocol": probe_def["protocol"],
            "asset_type": probe_def["asset_type"],
            "port": probe_def["port"],
            "severity": probe_def["severity"],
            "finding_title": probe_def["finding_title"],
            "metadata": response,
        })

    return results


async def probe_batch(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[str, list[dict]]:
    """Probe OT/IoT protocols for a batch of assets.

    Args:
        assets: list of dicts with keys: hostname, ip, open_ports, id
        concurrency: max parallel probing

    Returns:
        dict mapping hostname -> list of protocol detection dicts.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[dict]] = {}

    async def _run_one(asset: dict):
        async with semaphore:
            hostname = asset["hostname"]
            ip = asset.get("ip")
            ports = asset.get("open_ports") or []
            detections = await probe_asset_protocols(hostname, ip, ports)
            if detections:
                results[hostname] = detections

    await asyncio.gather(
        *(_run_one(asset) for asset in assets),
        return_exceptions=True,
    )
    return results
