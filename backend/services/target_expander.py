"""Target hygiene for the VM scan entry points.

Two concerns, both applied to the free-form target list before dispatch:

1. **CIDR expansion** — `192.168.1.0/24` becomes a job per host. URLs,
   hostnames, and single IPs pass through untouched.

2. **Routability classification** — the VM scanner reaches targets from its
   own network location, so whether a private target works depends entirely
   on where the scanner is deployed. A cloud-hosted scanner (the default GCP
   shape: Cloud Run -> scanner VM) cannot reach RFC1918 space, and every
   expanded host fails preflight with `timeout` / `connect_refused`. That
   used to happen silently: the caller typed a /24, got 254 queued jobs, and
   254 "unreachable" results with nothing explaining why.

   `find_unroutable_targets` flags those targets so the entry points can warn
   or refuse. The policy is deployment-specific — an on-prem scanner sitting
   inside the corp network is *supposed* to scan 10/8 — so it is read from
   the `VM_SCANNER_PRIVATE_TARGETS` env var rather than hardcoded. Default is
   `warn`, which keeps every existing deployment working while making the
   failure mode visible.
"""
from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlsplit

DEFAULT_MAX_EXPANDED_HOSTS = 1024

# Policy for targets that are not globally routable. Read at call time (not
# import time) so tests and runtime config changes take effect without a
# module reload.
PRIVATE_TARGET_POLICY_ENV = "VM_SCANNER_PRIVATE_TARGETS"
DEFAULT_PRIVATE_TARGET_POLICY = "warn"
PRIVATE_TARGET_POLICIES = ("allow", "warn", "block")

# `1.2.3.4:8080` — a bare host:port. Restricted to IPv4 so we never mistake
# an IPv6 address's own colons for a port separator.
_IPV4_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$")


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


# ---------------------------------------------------------------------------
# Routability classification
# ---------------------------------------------------------------------------

def private_target_policy() -> str:
    """Resolve the deployment's policy for non-routable targets.

    Unrecognised values fall back to the default rather than raising — a typo
    in an env var should not take the scan endpoint down.
    """
    raw = (os.getenv(PRIVATE_TARGET_POLICY_ENV) or "").strip().lower()
    return raw if raw in PRIVATE_TARGET_POLICIES else DEFAULT_PRIVATE_TARGET_POLICY


def _extract_host(token: str) -> str:
    """Pull the host portion out of a target token.

    Handles the shapes the scan panel accepts: bare IP, CIDR, `host:port`,
    and full URLs. Returns the token unchanged when none of those match, so
    hostnames fall through to `_is_unroutable` and are ignored there.
    """
    token = token.strip()
    if not token:
        return ""
    if "://" in token:
        try:
            # .hostname strips credentials, port, and IPv6 brackets.
            return urlsplit(token).hostname or ""
        except ValueError:
            return ""
    port_match = _IPV4_PORT_RE.match(token)
    if port_match:
        return port_match.group(1)
    if token.startswith("["):  # [::1] or [::1]:8080
        closing = token.find("]")
        if closing != -1:
            return token[1:closing]
    return token


def _is_unroutable(host: str) -> bool:
    """True when `host` is a literal IP/CIDR outside globally routable space.

    Covers RFC1918, loopback, link-local, CGNAT, and IPv6 unique-local in one
    check. Hostnames return False: classifying them would require a DNS
    lookup, and resolving user-supplied names here would both slow the
    request down and turn the endpoint into a DNS side-channel.
    """
    if not host:
        return False
    try:
        if "/" in host:
            return not ipaddress.ip_network(host, strict=False).is_global
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def find_unroutable_targets(targets: list[str]) -> list[str]:
    """Return the input tokens that are not internet-routable, in order.

    Call this *before* `expand_cidr_targets` so messages quote what the user
    typed (`192.168.1.0/24`) instead of 254 expanded hosts. Duplicates are
    collapsed to keep the message short.
    """
    flagged = [
        token
        for raw in targets
        if (token := raw.strip()) and _is_unroutable(_extract_host(token))
    ]
    return list(dict.fromkeys(flagged))


def unroutable_target_message(tokens: list[str], blocked: bool = False, limit: int = 5) -> str:
    """Build the operator-facing explanation for flagged targets."""
    shown = ", ".join(tokens[:limit])
    remaining = len(tokens) - limit
    if remaining > 0:
        shown += f" (+{remaining} more)"
    lead = "Refusing" if blocked else "Warning"
    tail = (
        f"Set {PRIVATE_TARGET_POLICY_ENV}=warn to dispatch anyway."
        if blocked
        else f"Set {PRIVATE_TARGET_POLICY_ENV}=allow to silence this, or =block to refuse."
    )
    return (
        f"{lead}: {len(tokens)} target(s) are not internet-routable ({shown}). "
        "The VM scanner reaches targets from its own network location, so a "
        "cloud-hosted scanner cannot reach these and every host will fail "
        f"preflight as unreachable. Scan internal ranges from an on-prem "
        f"scanner deployment. {tail}"
    )
