"""OT/ICS passive-only listener for the Hakuna relay agent (Phase 5).

This handler **never sends a packet**. It binds a UDP socket to a
well-known fingerprint port, listens for ≤10 seconds for vendor-
signature traffic, and reports presence + peer IPs. The signature DB is
a closed dict in this file — the LLM cannot supply regexes or byte
patterns. Profile names are an allowlist on both sides (tool layer +
this handler).

## Profiles

| profile             | port  | signature                                              |
|---------------------|-------|--------------------------------------------------------|
| ``yokogawa_vnetip`` | 12289 | bytes ``b"VNET"`` anywhere in payload, OR EtherType-shaped Vnet/IP header |
| ``cclink_ie``       | 61450 | CC-Link IE Field cyclic header magic ``b"\\xD0\\x00"``   |

The Vnet/IP signature is opportunistic — Yokogawa's protocol stack uses
the high-port range 12289–12298 for Vnet/IP control plane. Real
deployments tunnel over those ports continuously, so a ≤10s listen on
12289 alone gives a useful presence signal without needing to bind a
range. CC-Link IE Field is normally L2; the UDP path catches the few
implementations that bridge cyclic frames over IP.

## Why no listen on multiple ports

Binding multiple UDP sockets in one handler invites resource leaks and
makes timeouts harder to reason about. If a future profile needs a port
range, factor it then — for now, one port per profile.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 15
_MAX_LISTEN_S = 10


class OtPassiveError(Exception):
    """Any passive-listener failure surfaced back to the backend."""


_PROFILES: dict[str, dict[str, Any]] = {
    "yokogawa_vnetip": {
        "port": 12289,
        "signatures": [b"VNET", b"YOKOGAWA"],
    },
    "cclink_ie": {
        "port": 61450,
        # Cyclic-frame cookie + a handful of CC-Link IE Field signatures.
        "signatures": [b"\xD0\x00\xD0", b"CCLink", b"CC-Link"],
    },
}


@register_method("ot_passive_probe")
async def ot_passive_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    op = (params or {}).get("op") or ""
    if op != "passive_listen":
        raise OtPassiveError(f"unknown ot_passive op {op!r}; allowed: ['passive_listen']")
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_passive_listen, op_params, timeout_s),
            timeout=timeout_s + 5,
        )
    except asyncio.TimeoutError:
        return {"_errors": {"passive_listen": f"listener timed out after {timeout_s}s"}}


def _run_passive_listen(op_params: dict, timeout_s: int) -> dict:
    profile_name = (op_params or {}).get("profile") or ""
    profile = _PROFILES.get(profile_name)
    if profile is None:
        return {"_errors": {"passive_listen": f"unknown profile {profile_name!r}; allowed: {sorted(_PROFILES.keys())}"}}
    duration_s = max(1, min(int(op_params.get("duration_s") or 5), _MAX_LISTEN_S))

    out: dict[str, Any] = {
        "profile": profile_name,
        "presence": False,
        "frames_observed": 0,
        "peers": [],
        "duration_s": duration_s,
    }

    port = profile["port"]
    sigs: list[bytes] = profile["signatures"]
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # SO_REUSEADDR so we don't fight with another bind on the same port
        # if multiple relay processes ever share a host.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as e:
            return {**out, "_errors": {"passive_listen": f"bind {port}: {e}"}}
    except OSError as e:
        return {**out, "_errors": {"passive_listen": f"socket: {e}"}}

    peers: set[str] = set()
    deadline = time.monotonic() + duration_s
    try:
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            sock.settimeout(min(remaining, 1.0))
            try:
                data, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                continue
            if any(sig in data for sig in sigs):
                out["frames_observed"] += 1
                if peer and peer[0]:
                    peers.add(peer[0])
    finally:
        try:
            sock.close()
        except OSError:
            pass

    out["peers"] = sorted(peers)
    out["presence"] = out["frames_observed"] > 0
    return out
