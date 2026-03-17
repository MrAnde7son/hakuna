"""Extension 1: Wildcard DNS detection and safe brute force filtering.

Detects wildcard-enabled domains by querying random canary labels.
When wildcard is detected, records the wildcard fingerprint (IP + response hash)
and filters brute-force results that match the fingerprint.
"""

import hashlib
import logging
import secrets
import socket
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class WildcardFingerprint:
    """Fingerprint of a wildcard DNS response."""
    domain: str
    is_wildcard: bool
    wildcard_ips: set[str]
    response_hash: str | None = None


def detect_wildcard(domain: str, num_probes: int = 3) -> WildcardFingerprint:
    """Probe random subdomains to detect wildcard DNS.

    Queries multiple random labels (e.g., a1b2c3d4.example.com).
    If they all resolve to the same IP(s), wildcard is likely active.
    """
    canary_ips: list[set[str]] = []

    for _ in range(num_probes):
        canary = secrets.token_hex(12)
        test_host = f"{canary}.{domain}"
        try:
            results = socket.getaddrinfo(test_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = {r[4][0] for r in results}
            canary_ips.append(ips)
        except (socket.gaierror, OSError):
            canary_ips.append(set())

    # If all probes resolved AND share at least one common IP → wildcard
    resolved = [ips for ips in canary_ips if ips]
    if len(resolved) < num_probes:
        # Some didn't resolve — not a wildcard
        return WildcardFingerprint(domain=domain, is_wildcard=False, wildcard_ips=set())

    common_ips = resolved[0]
    for ips in resolved[1:]:
        common_ips = common_ips & ips

    if not common_ips:
        return WildcardFingerprint(domain=domain, is_wildcard=False, wildcard_ips=set())

    # Build a fingerprint hash from the sorted common IPs
    ip_str = ",".join(sorted(common_ips))
    response_hash = hashlib.sha256(ip_str.encode()).hexdigest()[:16]

    logger.info(
        "domain=%s wildcard_detected=true wildcard_ips=%s hash=%s",
        domain, ip_str, response_hash,
    )

    return WildcardFingerprint(
        domain=domain,
        is_wildcard=True,
        wildcard_ips=common_ips,
        response_hash=response_hash,
    )


def filter_wildcard_results(
    hosts: list[dict],
    fingerprint: WildcardFingerprint,
) -> tuple[list[dict], int]:
    """Filter brute-force results that match the wildcard fingerprint.

    Returns (filtered_hosts, removed_count).
    Each remaining host that belongs to a wildcard domain gets tagged.
    """
    if not fingerprint.is_wildcard:
        return hosts, 0

    filtered = []
    removed = 0

    for host_entry in hosts:
        hostname = host_entry.get("host", "")
        ip = host_entry.get("ip") or host_entry.get("a") or ""

        # Check if this result's IP matches the wildcard fingerprint
        if ip and ip in fingerprint.wildcard_ips:
            removed += 1
            continue

        # If no IP in the entry, try resolving to check
        if not ip and hostname:
            try:
                results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                resolved_ips = {r[4][0] for r in results}
                if resolved_ips & fingerprint.wildcard_ips:
                    removed += 1
                    continue
            except (socket.gaierror, OSError):
                pass

        filtered.append(host_entry)

    logger.info(
        "domain=%s wildcard_filter: kept=%d removed=%d",
        fingerprint.domain, len(filtered), removed,
    )
    return filtered, removed
