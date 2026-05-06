"""ProjectDiscovery Chaos subdomain discovery.

Queries the Chaos dataset (chaos.projectdiscovery.io) for subdomains of a
seed domain. Chaos aggregates years of bug-bounty recon into a single
curated dataset, often surfacing subdomains that crt.sh and passive DNS
miss because they were never publicly certified or resolved during OTX's
collection window.

Free with a signup key. Endpoint returns subdomain *prefixes* relative to
the queried apex (e.g. ["api", "dev"] for example.com), which we expand
into FQDNs before returning.
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

logger = logging.getLogger(__name__)

_CHAOS_URL = "https://dns.projectdiscovery.io/dns/{domain}/subdomains"
_TIMEOUT = aiohttp.ClientTimeout(total=30)


async def query_chaos(domain: str, api_key: str) -> list[str]:
    """Query Chaos for subdomains of a domain.

    Returns deduplicated, in-scope FQDNs. Never raises — returns empty list
    on error. Retries once on HTTP 429 with a brief backoff.
    """
    if not api_key:
        return []

    url = _CHAOS_URL.format(domain=domain)
    headers = {"Authorization": api_key}

    data: dict | None = None
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=headers) as session:
            for attempt in range(2):
                async with session.get(url) as resp:
                    if resp.status == 429 and attempt == 0:
                        await asyncio.sleep(2)
                        continue
                    if resp.status == 401:
                        logger.warning("chaos: 401 unauthorized — check CHAOS_API_KEY")
                        return []
                    if resp.status != 200:
                        logger.warning("chaos: HTTP %d for %s", resp.status, domain)
                        return []
                    data = await resp.json(content_type=None)
                    break
    except Exception as exc:
        logger.warning("chaos: failed for %s: %s (%s)", domain, exc, type(exc).__name__)
        return []

    if not data:
        return []

    hostnames: set[str] = set()
    for prefix in data.get("subdomains", []) or []:
        prefix = (prefix or "").strip().lower().lstrip("*.")
        if not prefix:
            continue
        # Chaos returns relative prefixes; reconstruct the FQDN. Apex is
        # signaled by an empty / "@" prefix in some payloads.
        if prefix in ("@", domain):
            hostnames.add(domain)
            continue
        fqdn = f"{prefix}.{domain}" if not prefix.endswith(f".{domain}") else prefix
        if "." in fqdn:
            hostnames.add(fqdn)

    logger.info("chaos: domain=%s found %d unique hostnames", domain, len(hostnames))
    return sorted(hostnames)
