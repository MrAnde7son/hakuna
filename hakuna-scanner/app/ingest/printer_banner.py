"""IPP printer fingerprint via Get-Printer-Attributes (RFC 8011).

Skips LPD 515 — it has no standard query operation that returns model info,
and the protocol is functionally dead outside legacy AS/400 fleets.

IPP wire format on 631 (HTTP transport):

    POST /ipp HTTP/1.1
    Content-Type: application/ipp
    <ipp version (2 bytes)> <operation-id (2 bytes)> <request-id (4 bytes)>
    <operation-attributes-tag 0x01>
      attributes-charset = "utf-8"
      attributes-natural-language = "en"
      printer-uri = "ipp://host:631/"
      requested-attributes = "printer-name", "printer-make-and-model",
                             "printer-info", "printer-state",
                             "printer-uri-supported", "printer-firmware-name"
    <end-of-attributes-tag 0x03>

The response is a parallel binary structure. We extract by linear scan
over (tag, name-len, name, value-len, value) tuples — pulling in pyipp
would be overkill for the four attributes we care about.
"""

from __future__ import annotations

import asyncio
import logging
import struct

logger = logging.getLogger(__name__)

_TIMEOUT = 8.0

# IPP tag bytes
_TAG_OPERATION_ATTRS = 0x01
_TAG_PRINTER_ATTRS = 0x04
_TAG_END = 0x03
_TAG_CHARSET = 0x47
_TAG_LANG = 0x48
_TAG_URI = 0x45
_TAG_KEYWORD = 0x44
_TAG_TEXT = 0x41
_TAG_TEXT_WLANG = 0x35
_TAG_NAME = 0x42

_REQUESTED_ATTRS = [
    b"printer-name",
    b"printer-make-and-model",
    b"printer-info",
    b"printer-state",
    b"printer-uri-supported",
    b"printer-firmware-name",
]


def _ipp_string(tag: int, name: bytes, value: bytes) -> bytes:
    return (
        struct.pack(">B", tag)
        + struct.pack(">H", len(name)) + name
        + struct.pack(">H", len(value)) + value
    )


def _build_get_printer_attributes(printer_uri: str) -> bytes:
    body = struct.pack(">HHI", 0x0200, 0x000B, 1)  # version 2.0, op 0x000B, req-id 1
    body += struct.pack(">B", _TAG_OPERATION_ATTRS)
    body += _ipp_string(_TAG_CHARSET, b"attributes-charset", b"utf-8")
    body += _ipp_string(_TAG_LANG, b"attributes-natural-language", b"en")
    body += _ipp_string(_TAG_URI, b"printer-uri", printer_uri.encode())

    # requested-attributes is a 1setOf keyword: first entry has name, rest empty name.
    first = True
    for attr in _REQUESTED_ATTRS:
        name = b"requested-attributes" if first else b""
        body += _ipp_string(_TAG_KEYWORD, name, attr)
        first = False

    body += struct.pack(">B", _TAG_END)
    return body


def _parse_attributes(payload: bytes) -> dict:
    """Extract a few text attributes from an IPP response. Best-effort."""
    out: dict = {}
    i = 0
    n = len(payload)
    if n < 8:
        return out
    # Skip 8-byte header (version, status, req-id).
    i = 8
    current_attr: bytes | None = None
    while i < n:
        tag = payload[i]
        i += 1
        if tag in (_TAG_OPERATION_ATTRS, _TAG_PRINTER_ATTRS):
            continue
        if tag == _TAG_END:
            break
        if i + 2 > n:
            break
        name_len = struct.unpack(">H", payload[i:i+2])[0]
        i += 2
        if i + name_len > n:
            break
        name = payload[i:i+name_len]
        i += name_len
        if i + 2 > n:
            break
        value_len = struct.unpack(">H", payload[i:i+2])[0]
        i += 2
        if i + value_len > n:
            break
        value = payload[i:i+value_len]
        i += value_len

        if name:
            current_attr = name
        if current_attr and tag in (_TAG_TEXT, _TAG_TEXT_WLANG, _TAG_NAME, _TAG_KEYWORD, _TAG_URI):
            try:
                decoded = value.decode("utf-8", errors="replace")
            except Exception:
                continue
            key = current_attr.decode("ascii", errors="replace")
            out.setdefault(key, decoded)
    return out


async def _probe_single(
    session,  # aiohttp.ClientSession — typed loosely so module imports without aiohttp
    host: str,
    port: int = 631,
    *,
    use_tls: bool = False,
) -> dict | None:
    import aiohttp  # lazy: keeps parser code testable without the transport dep
    # PR #2: scheme selection driven by the caller (which knows the
    # service_type — "https" for IPP-over-TLS, "ipp"/None for plain).
    # The previous ``port == 443`` shortcut hard-coded that mapping.
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/ipp"
    body = _build_get_printer_attributes(f"ipp://{host}:{port}/")

    try:
        async with session.post(
            url,
            data=body,
            headers={"Content-Type": "application/ipp"},
            timeout=aiohttp.ClientTimeout(total=_TIMEOUT),
            ssl=False,
        ) as resp:
            if resp.status != 200:
                return None
            payload = await resp.read()
    except Exception:
        return None

    attrs = _parse_attributes(payload)
    if not attrs:
        return None

    return {
        "protocol": "ipp",
        "port": port,
        "version": {
            "make_and_model": attrs.get("printer-make-and-model"),
            "firmware": attrs.get("printer-firmware-name"),
        },
        "metadata": {
            "printer_name": attrs.get("printer-name"),
            "info": attrs.get("printer-info"),
            "state": attrs.get("printer-state"),
            "uris": attrs.get("printer-uri-supported"),
        },
    }


_LEGACY_PORTS: set[int] = {631}
_SERVICE_TYPES: set[str] = {"ipp"}
# Service types that imply HTTP transport — when an IPP-typed port
# happens to be ``https``-stamped (e.g. AirPrint over TLS) we POST the
# Get-Printer-Attributes request through TLS instead of plain HTTP.
_TLS_SERVICE_TYPES: set[str] = {"https"}


async def probe_batch(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[str, list[dict]]:
    """IPP printer fingerprint on every IPP-typed port.

    PR #2: gate on ``asset_ports.service_type == 'ipp'`` (preferred)
    OR ``port == 631`` (fallback). Whether to use TLS is driven by
    the per-port stamped service_type — ``'https'`` flags the port as
    IPP-over-TLS (replaces the old ``port == 443`` hard-code).
    """
    from app.ingest.service_lookup import matching_ports_for_asset

    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[dict]] = {}

    # Candidate filter: any port matching the IPP service-type / 631
    # fallback. The IPP-over-TLS case is handled per-port inside the
    # probe loop below by inspecting port_service_types.
    candidates = [
        a for a in assets
        if matching_ports_for_asset(
            a,
            service_types=_SERVICE_TYPES,
            legacy_ports=_LEGACY_PORTS,
        )
        and (a.get("hostname") or a.get("ip"))
    ]
    if not candidates:
        return results

    import aiohttp  # lazy
    connector = aiohttp.TCPConnector(limit=concurrency * 2, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def _run_one(asset: dict):
            target = asset.get("ip") or asset.get("hostname")
            ports = matching_ports_for_asset(
                asset,
                service_types=_SERVICE_TYPES,
                legacy_ports=_LEGACY_PORTS,
            )
            st_map = asset.get("port_service_types") or {}
            hits: list[dict] = []
            for port in ports:
                # Per-port TLS detection: if the port also happens to
                # be stamped as https (rare — most print servers expose
                # IPP and IPPS on different ports), use TLS transport.
                use_tls = st_map.get(port) in _TLS_SERVICE_TYPES
                async with semaphore:
                    hit = await _probe_single(session, target, port, use_tls=use_tls)
                if hit:
                    hits.append(hit)
            if hits:
                results[asset["hostname"]] = hits

        await asyncio.gather(
            *(_run_one(a) for a in candidates),
            return_exceptions=True,
        )
    return results
