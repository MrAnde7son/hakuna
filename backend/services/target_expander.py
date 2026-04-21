"""Expand CIDR subnets in a free-form target list to individual host IPs.

Used by the VM scan entrypoints so users can type `192.168.1.0/24` and have
the scanner dispatch a job per host. URLs, hostnames, and single IPs pass
through untouched — only plain-IP CIDR notation is expanded.
"""
from __future__ import annotations

import ipaddress

DEFAULT_MAX_EXPANDED_HOSTS = 1024


def _looks_like_cidr(token: str) -> bool:
    if "/" not in token:
        return False
    if token.startswith(("http://", "https://")):
        return False
    return True


def expand_cidr_targets(
    targets: list[str],
    max_hosts: int = DEFAULT_MAX_EXPANDED_HOSTS,
) -> list[str]:
    """Return a flat list of targets with CIDR subnets expanded to host IPs.

    Raises ValueError if the combined expansion would exceed ``max_hosts`` —
    the cap exists so a typo like ``10.0.0.0/8`` can't queue 16M tasks.
    """
    expanded: list[str] = []
    total_from_cidrs = 0
    for raw in targets:
        token = raw.strip()
        if not token:
            continue
        if not _looks_like_cidr(token):
            expanded.append(token)
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except (ValueError, TypeError):
            expanded.append(token)
            continue
        # /32 or /128 — the host list is empty; fall back to the network address.
        if net.num_addresses == 1:
            expanded.append(str(net.network_address))
            continue
        hosts = [str(h) for h in net.hosts()]
        total_from_cidrs += len(hosts)
        if total_from_cidrs > max_hosts:
            raise ValueError(
                f"CIDR expansion exceeds {max_hosts}-host cap "
                f"({token} = {len(hosts)} hosts). Use a smaller prefix."
            )
        expanded.extend(hosts)
    return expanded
