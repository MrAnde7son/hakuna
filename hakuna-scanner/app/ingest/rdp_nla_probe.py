"""RDP NLA enforcement probe — X.224 connection request only.

Probes whether an RDP server requires Network Level Authentication. We send
exactly one X.224 Connection Request PDU advertising support for SSL +
HYBRID (NLA) and read the server's negotiation response. We never proceed
to the TLS or CredSSP handshake — that's TLS audit's job, and avoiding the
full handshake means we don't allocate a session on the server.

Server response interpretation (RDP Negotiation Response, type 0x02):
  - selectedProtocol == PROTOCOL_HYBRID (0x02) or PROTOCOL_HYBRID_EX (0x08)
      → NLA enforced (good)
  - selectedProtocol == PROTOCOL_SSL (0x01)
      → TLS but no NLA (CVE-2019-0708 BlueKeep risk class)
  - selectedProtocol == PROTOCOL_RDP (0x00)
      → Standard RDP, no TLS, no NLA (severe)
  - Type 0x03 (Negotiation Failure)
      → Server rejected our offer; record failure code

NLA-disabled is itself a finding (gets `severity` + `finding_title`); the
banner_finding is also written for CVE correlation regardless.
"""

from __future__ import annotations

import asyncio
import logging
import struct

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 5

# X.224 Connection Request with RDP negotiation request advertising
# RDP|SSL|HYBRID. Cookie is a synthetic username string (must be ASCII per
# [MS-RDPBCGR] §2.2.1.1) terminated with \r\n, then the negotiation
# request structure (type=0x01, flags=0, length=8, requested=0x0B).
_COOKIE = b"Cookie: mstshash=hakuna\r\n"
_NEG_REQ = struct.pack("<BBHI", 0x01, 0x00, 0x0008, 0x0000000B)


def _build_x224_cr() -> bytes:
    payload = _COOKIE + _NEG_REQ
    # X.224 CR PDU: length-indicator, code(0xE0), dst-ref, src-ref, class
    x224 = struct.pack(">BBHHB", 6 + len(payload), 0xE0, 0, 0, 0) + payload
    # TPKT header: version=3, reserved=0, total-length(big-endian)
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
    return tpkt


_PROTOCOL_NAMES = {
    0x00: "rdp",
    0x01: "ssl",
    0x02: "hybrid",  # NLA
    0x08: "hybrid_ex",
}


def _parse_response(data: bytes) -> dict | None:
    # TPKT(4) + X.224 CC(7) + RDP_NEG_RSP/FAILURE(8)
    if len(data) < 19 or data[0] != 0x03:
        return None
    rdp_neg = data[11:19]
    neg_type = rdp_neg[0]
    if neg_type == 0x02:  # RDP_NEG_RSP
        selected = struct.unpack("<I", rdp_neg[4:8])[0]
        return {
            "nla_enforced": selected in (0x02, 0x08),
            "selected_protocol": _PROTOCOL_NAMES.get(selected, f"unknown_{selected}"),
            "selected_protocol_code": selected,
        }
    if neg_type == 0x03:  # RDP_NEG_FAILURE
        failure_code = struct.unpack("<I", rdp_neg[4:8])[0]
        return {
            "nla_enforced": None,
            "negotiation_failure_code": failure_code,
        }
    return None


async def _probe_single(host: str, port: int = 3389) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        writer.write(_build_x224_cr())
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=_READ_TIMEOUT)
        except asyncio.TimeoutError:
            return None
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    parsed = _parse_response(data)
    if parsed is None:
        return None

    result: dict = {
        "protocol": "rdp",
        "port": port,
        "version": {"selected_protocol": parsed.get("selected_protocol")},
        "metadata": parsed,
    }

    # NLA disabled → emit finding.
    if parsed.get("nla_enforced") is False:
        result["severity"] = "high"
        result["finding_title"] = "RDP without Network Level Authentication"
    return result


async def probe_batch(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[str, list[dict]]:
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[dict]] = {}

    async def _run_one(asset: dict):
        if 3389 not in (asset.get("open_ports") or []):
            return
        target = asset.get("ip") or asset.get("hostname")
        if not target:
            return
        async with semaphore:
            hit = await _probe_single(target, 3389)
        if hit:
            results[asset["hostname"]] = [hit]

    await asyncio.gather(
        *(_run_one(a) for a in assets),
        return_exceptions=True,
    )
    return results
