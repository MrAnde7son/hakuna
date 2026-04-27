"""Enumerate the relay's directly-connected IPv4 subnets as CIDR strings.

Used by the registration handshake so the backend's ``_lan_local_predicate``
(in ``backend/services/audit_auto_trigger.py``) can decide whether the relay
shares a broadcast domain with a target asset before firing a LAN-local
audit (NetBIOS / LLMNR / mDNS).

Strategy:
  1. Try ``psutil`` if installed — covers Linux/macOS/Windows uniformly.
  2. Fall back to stdlib ``socket`` + ``fcntl`` (Linux only). Returns an
     empty list elsewhere if psutil is unavailable; the predicate handles
     missing labels by defensively rejecting events, so the LAN-local
     audits will simply only fire via manual dispatch.

Loopback (127/8) and link-local (169.254/16) ranges are excluded so the
predicate doesn't accidentally green-light probes against assets that
share those reserved ranges.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import List

logger = logging.getLogger(__name__)

_EXCLUDED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def _is_excluded(net: ipaddress.IPv4Network) -> bool:
    return any(net.subnet_of(excluded) for excluded in _EXCLUDED_NETWORKS)


def _from_psutil() -> List[str]:
    try:
        import psutil  # type: ignore
    except ImportError:
        return []

    cidrs: list[str] = []
    seen: set[str] = set()
    try:
        addrs_by_iface = psutil.net_if_addrs()
    except Exception as exc:
        logger.debug("psutil.net_if_addrs() failed: %s", exc)
        return []

    for addrs in addrs_by_iface.values():
        for snic in addrs:
            if snic.family != socket.AF_INET:
                continue
            address = snic.address
            netmask = snic.netmask
            if not address or not netmask:
                continue
            try:
                net = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
            except (TypeError, ValueError):
                continue
            if not isinstance(net, ipaddress.IPv4Network):
                continue
            if _is_excluded(net):
                continue
            cidr = str(net)
            if cidr in seen:
                continue
            seen.add(cidr)
            cidrs.append(cidr)
    return cidrs


def _from_proc_net_route() -> List[str]:
    """Linux fallback: parse /proc/net/route for directly-connected nets."""
    cidrs: list[str] = []
    seen: set[str] = set()
    try:
        with open("/proc/net/route", "r") as f:
            lines = f.readlines()
    except OSError:
        return []

    for raw in lines[1:]:
        parts = raw.split()
        if len(parts) < 8:
            continue
        # Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        try:
            dest = int(parts[1], 16)
            gateway = int(parts[2], 16)
            mask = int(parts[3], 16)
        except ValueError:
            continue
        if gateway != 0:
            # Not a directly-connected route.
            continue
        if dest == 0:
            # Default route, skip.
            continue
        try:
            net_addr = ipaddress.IPv4Address(socket.htonl(dest) & 0xFFFFFFFF)
            mask_addr = ipaddress.IPv4Address(socket.htonl(mask) & 0xFFFFFFFF)
            net = ipaddress.IPv4Network(f"{net_addr}/{mask_addr}", strict=False)
        except (TypeError, ValueError):
            continue
        if _is_excluded(net):
            continue
        cidr = str(net)
        if cidr in seen:
            continue
        seen.add(cidr)
        cidrs.append(cidr)
    return cidrs


def enumerate_local_cidrs() -> List[str]:
    """Return the set of directly-connected IPv4 networks as CIDR strings."""
    cidrs = _from_psutil()
    if cidrs:
        return cidrs
    return _from_proc_net_route()
