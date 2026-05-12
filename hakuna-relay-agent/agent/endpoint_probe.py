"""Endpoint discovery probes for the Hakuna relay agent.

Single relay method (``endpoint_probe``) covering three anonymous endpoint
discovery protocols not handled elsewhere:

  - ``op="sip_options"``   — SIP OPTIONS (UDP/TCP 5060/5061): reveals the
                             IP phone vendor + firmware via the User-Agent
                             header, and the realm/auth scheme via any
                             401 challenge
  - ``op="rtsp_describe"`` — RTSP DESCRIBE (TCP 554): reveals the camera
                             vendor via the Server header and stream
                             metadata via SDP in the response body
  - ``op="ws_discovery"``  — WS-Discovery Probe (UDP 3702 multicast SOAP,
                             ONVIF Section 7): elicits XAddrs URLs from
                             every ONVIF camera on the local broadcast
                             domain. Returns vendor / model URLs the
                             follow-up GetDeviceInformation call would use.

All three are anonymous read-only probes. SIP and RTSP send a single
no-auth request and parse the response; WS-Discovery sends one multicast
SOAP envelope and collects unicast replies for a bounded time window.

The WS-Discovery probe is only meaningful when the relay is on the same
broadcast domain as the cameras — the auto-trigger rule predicate
enforces that.

Result shape per op
-------------------
- sip_options:
    {status_code, reason, server, user_agent, allow, auth_scheme,
     auth_realm, headers, body_excerpt, _errors?}
- rtsp_describe:
    {status_code, reason, server, content_base, sdp_excerpt,
     content_type, auth_scheme, auth_realm, headers, _errors?}
- ws_discovery:
    {total, devices: [{xaddrs, types, scopes, endpoint_reference}], _errors?}
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import time
import uuid
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 8
_SIP_DEFAULT_PORT = 5060
_RTSP_DEFAULT_PORT = 554
_WS_DISCOVERY_PORT = 3702
_WS_DISCOVERY_MCAST = "239.255.255.250"


class EndpointProbeError(Exception):
    """Any endpoint probe failure surfaced back to the backend."""


# ── Handler ──────────────────────────────────────────────────────────


@register_method("endpoint_probe")
async def endpoint_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    target = (transport_config or {}).get("target")
    port = int((transport_config or {}).get("port") or 0)
    op = (params or {}).get("op") or ""
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    handler = _OP_HANDLERS.get(op)
    if handler is None:
        raise EndpointProbeError(
            f"unknown endpoint probe op {op!r}; allowed: {sorted(_OP_HANDLERS.keys())}"
        )

    # ws_discovery doesn't take a unicast target — it multicasts. SIP and
    # RTSP need a target.
    if op != "ws_discovery" and not target:
        raise EndpointProbeError(f"transport_config.target is required for op {op!r}")

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(handler, target, port, op_params, timeout_s),
            timeout=timeout_s + 4,
        )
    except asyncio.TimeoutError:
        return {"_errors": {op: f"probe timed out after {timeout_s}s"}}


# ── SIP OPTIONS ──────────────────────────────────────────────────────


_SIP_HEADER_RE = re.compile(r"^([A-Za-z0-9\-]+)\s*:\s*(.*)$")
_SIP_AUTH_PARAM_RE = re.compile(r'(\w+)\s*=\s*"?([^",]+)"?')


def _build_sip_options(target: str, port: int) -> bytes:
    """Build a minimal SIP OPTIONS request.

    RFC 3261 §11 — OPTIONS is a request for capabilities, no auth required
    by the spec. Devices respond with 200/486/etc. plus a User-Agent and
    Allow header. Some phones challenge with 401; we record the realm.
    """
    call_id = uuid.uuid4().hex
    tag = uuid.uuid4().hex[:10]
    branch = f"z9hG4bK{uuid.uuid4().hex[:16]}"
    lines = [
        f"OPTIONS sip:{target} SIP/2.0",
        f"Via: SIP/2.0/UDP {target}:{port};branch={branch}",
        f"From: <sip:hakuna@{target}>;tag={tag}",
        f"To: <sip:{target}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 OPTIONS",
        "Max-Forwards: 70",
        "User-Agent: Hakuna-Probe/1.0",
        "Accept: application/sdp",
        "Content-Length: 0",
        "", "",  # CRLF CRLF
    ]
    return "\r\n".join(lines).encode("ascii", errors="replace")


def _probe_sip_options(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    port = port or _SIP_DEFAULT_PORT
    transport = (op_params.get("transport") or "udp").lower()
    if transport not in ("udp", "tcp"):
        return {"_errors": {"sip_options": f"transport must be udp or tcp, got {transport!r}"}}

    pdu = _build_sip_options(target, port)

    if transport == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
        try:
            sock.sendto(pdu, (target, port))
            data, _ = sock.recvfrom(8192)
        except (socket.timeout, OSError) as e:
            return {"_errors": {"sip_options": f"{type(e).__name__}: {e}"}}
        finally:
            sock.close()
    else:
        try:
            sock = socket.create_connection((target, port), timeout=timeout_s)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {"_errors": {"sip_options": f"connect failed: {type(e).__name__}: {e}"}}
        try:
            sock.settimeout(timeout_s)
            sock.sendall(pdu)
            chunks = []
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if len(b"".join(chunks)) > 16384:
                    break
            data = b"".join(chunks)
        except OSError as e:
            return {"_errors": {"sip_options": f"{type(e).__name__}: {e}"}}
        finally:
            sock.close()

    return _parse_sip_response(data)


def _parse_sip_response(data: bytes) -> dict:
    text = data.decode("utf-8", errors="replace")
    out: dict[str, Any] = {
        "status_code": None,
        "reason": "",
        "server": "",
        "user_agent": "",
        "allow": "",
        "auth_scheme": "",
        "auth_realm": "",
        "headers": {},
        "body_excerpt": "",
    }

    head, _, body = text.partition("\r\n\r\n")
    lines = head.splitlines()
    if not lines:
        return {"_errors": {"sip_options": "empty response"}}

    # Status line: SIP/2.0 <code> <reason>
    status_match = re.match(r"^SIP/2\.0\s+(\d{3})\s*(.*)$", lines[0])
    if status_match:
        out["status_code"] = int(status_match.group(1))
        out["reason"] = status_match.group(2).strip()

    for line in lines[1:]:
        m = _SIP_HEADER_RE.match(line)
        if not m:
            continue
        name = m.group(1).lower()
        value = m.group(2).strip()
        out["headers"][name] = value
        if name == "server":
            out["server"] = value
        elif name == "user-agent":
            out["user_agent"] = value
        elif name == "allow":
            out["allow"] = value
        elif name == "www-authenticate":
            scheme, _, rest = value.partition(" ")
            out["auth_scheme"] = scheme.lower()
            realm_match = _SIP_AUTH_PARAM_RE.search(rest)
            if realm_match and realm_match.group(1).lower() == "realm":
                out["auth_realm"] = realm_match.group(2)

    if body:
        out["body_excerpt"] = body[:1024]
    return out


# ── RTSP DESCRIBE ────────────────────────────────────────────────────


def _build_rtsp_describe(target: str, port: int, path: str) -> bytes:
    """Build a minimal RTSP DESCRIBE request (RFC 7826 §13.2)."""
    url = f"rtsp://{target}:{port}{path}"
    lines = [
        f"DESCRIBE {url} RTSP/1.0",
        "CSeq: 1",
        "Accept: application/sdp",
        "User-Agent: Hakuna-Probe/1.0",
        "", "",
    ]
    return "\r\n".join(lines).encode("ascii", errors="replace")


def _probe_rtsp_describe(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    port = port or _RTSP_DEFAULT_PORT
    path = op_params.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path

    pdu = _build_rtsp_describe(target, port, path)
    try:
        sock = socket.create_connection((target, port), timeout=timeout_s)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"_errors": {"rtsp_describe": f"connect failed: {type(e).__name__}: {e}"}}

    try:
        sock.settimeout(timeout_s)
        sock.sendall(pdu)
        chunks: list[bytes] = []
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if len(b"".join(chunks)) > 16384:
                break
        data = b"".join(chunks)
    except OSError as e:
        return {"_errors": {"rtsp_describe": f"{type(e).__name__}: {e}"}}
    finally:
        sock.close()

    return _parse_rtsp_response(data, path=path)


def _parse_rtsp_response(data: bytes, *, path: str) -> dict:
    text = data.decode("utf-8", errors="replace")
    out: dict[str, Any] = {
        "path": path,
        "status_code": None,
        "reason": "",
        "server": "",
        "content_type": "",
        "content_base": "",
        "auth_scheme": "",
        "auth_realm": "",
        "headers": {},
        "sdp_excerpt": "",
    }

    head, _, body = text.partition("\r\n\r\n")
    lines = head.splitlines()
    if not lines:
        return {"_errors": {"rtsp_describe": "empty response"}}

    status_match = re.match(r"^RTSP/1\.0\s+(\d{3})\s*(.*)$", lines[0])
    if status_match:
        out["status_code"] = int(status_match.group(1))
        out["reason"] = status_match.group(2).strip()

    for line in lines[1:]:
        m = _SIP_HEADER_RE.match(line)  # same header syntax as SIP/HTTP
        if not m:
            continue
        name = m.group(1).lower()
        value = m.group(2).strip()
        out["headers"][name] = value
        if name == "server":
            out["server"] = value
        elif name == "content-type":
            out["content_type"] = value
        elif name == "content-base":
            out["content_base"] = value
        elif name == "www-authenticate":
            scheme, _, rest = value.partition(" ")
            out["auth_scheme"] = scheme.lower()
            realm_match = _SIP_AUTH_PARAM_RE.search(rest)
            if realm_match and realm_match.group(1).lower() == "realm":
                out["auth_realm"] = realm_match.group(2)

    if body:
        out["sdp_excerpt"] = body[:2048]
    return out


# ── WS-Discovery (ONVIF) ─────────────────────────────────────────────


# ONVIF / WS-Discovery probe envelope (Section 7 of ONVIF Core Spec).
# We send the multicast probe and collect unicast replies for the timeout
# window. NetworkVideoTransmitter is the ONVIF profile served by every
# ONVIF-conformant camera.
def _build_ws_discovery_probe() -> bytes:
    message_id = uuid.uuid4()
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
        ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<e:Header>'
        '<w:MessageID>uuid:{mid}</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header>'
        '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>'
        '</e:Envelope>'
    ).format(mid=message_id)
    return envelope.encode("utf-8")


def _probe_ws_discovery(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Multicast WS-Discovery Probe; collect unicast replies until timeout.

    `target` is ignored — discovery is multicast. `op_params.iface_ip` lets
    callers pin the source interface when the relay host is multi-homed.
    """
    iface_ip = op_params.get("iface_ip") or ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if iface_ip:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                socket.inet_aton(iface_ip))
            except OSError:
                pass
        sock.bind(("", 0))
        sock.settimeout(min(timeout_s, 2))

        pdu = _build_ws_discovery_probe()
        try:
            sock.sendto(pdu, (_WS_DISCOVERY_MCAST, _WS_DISCOVERY_PORT))
        except OSError as e:
            return {"_errors": {"ws_discovery": f"sendto failed: {type(e).__name__}: {e}"}}

        replies: list[bytes] = []
        sources: list[tuple[str, int]] = []
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(16384)
            except socket.timeout:
                continue
            except OSError:
                break
            replies.append(data)
            sources.append(addr)
            if len(replies) >= 32:
                break
    finally:
        sock.close()

    devices = []
    for reply, addr in zip(replies, sources):
        try:
            device = _parse_ws_discovery_match(reply, source=addr)
        except Exception as e:
            logger.debug("ws_discovery: parse failed: %s", e)
            continue
        if device:
            devices.append(device)

    return {"total": len(devices), "devices": devices}


def _parse_ws_discovery_match(data: bytes, *, source: tuple[str, int]) -> dict | None:
    """Extract XAddrs / Types / Scopes from a WS-Discovery ProbeMatch reply.

    Real-world ONVIF replies vary in namespace prefixes (wsdd:, d:, ns0:, …)
    so we don't rely on XML namespace machinery. The fields we need are
    delimited by well-known element names regardless of prefix.
    """
    text = data.decode("utf-8", errors="replace")
    out: dict[str, Any] = {"source_ip": source[0]}

    xaddrs_match = re.search(r"<(?:[\w-]+:)?XAddrs>([^<]+)</(?:[\w-]+:)?XAddrs>", text)
    if not xaddrs_match:
        # No XAddrs means this isn't a useful ONVIF match — drop it rather
        # than return a half-empty entry.
        return None
    out["xaddrs"] = [u.strip() for u in xaddrs_match.group(1).split() if u.strip()]

    types_match = re.search(r"<(?:[\w-]+:)?Types>([^<]+)</(?:[\w-]+:)?Types>", text)
    if types_match:
        out["types"] = types_match.group(1).strip()

    scopes_match = re.search(r"<(?:[\w-]+:)?Scopes[^>]*>([^<]+)</(?:[\w-]+:)?Scopes>", text)
    if scopes_match:
        scopes = [s.strip() for s in scopes_match.group(1).split() if s.strip()]
        out["scopes"] = scopes
        # Common ONVIF scope hints: onvif://www.onvif.org/name/<model>,
        # onvif://www.onvif.org/hardware/<model>, …
        for scope in scopes:
            if "/name/" in scope:
                out["name"] = scope.rsplit("/name/", 1)[-1]
            elif "/hardware/" in scope:
                out["hardware"] = scope.rsplit("/hardware/", 1)[-1]

    epr_match = re.search(
        r"<(?:[\w-]+:)?Address>([^<]+)</(?:[\w-]+:)?Address>", text)
    if epr_match:
        out["endpoint_reference"] = epr_match.group(1).strip()

    return out


# ── Dispatch table ───────────────────────────────────────────────────


_OP_HANDLERS = {
    "sip_options": _probe_sip_options,
    "rtsp_describe": _probe_rtsp_describe,
    "ws_discovery": _probe_ws_discovery,
}


__all__ = [
    "EndpointProbeError",
    "endpoint_probe_handler",
    "_OP_HANDLERS",
]
