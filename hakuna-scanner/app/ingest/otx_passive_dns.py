"""AlienVault OTX passive DNS subdomain discovery.

Queries OTX's free passive DNS API for hostnames that have historically
resolved to a target domain. Complements crt.sh — CT logs only show names
that ever appeared in a public certificate, while passive DNS captures any
name that resolved (HTTP-only services, dev subdomains, etc.).
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

logger = logging.getLogger(__name__)

_OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
_TIMEOUT = aiohttp.ClientTimeout(total=30)


async def query_otx_passive_dns(domain: str, api_key: str) -> list[str]:
    """Query OTX passive DNS for subdomains of a domain.

    Returns deduplicated, in-scope hostnames (only names ending in `.{domain}`
    or equal to `domain`). Never raises — returns empty list on error.
    Retries once on HTTP 429 with a brief backoff.
    """
    if not api_key:
        return []

    url = _OTX_URL.format(domain=domain)
    headers = {"X-OTX-API-KEY": api_key}

    data: dict | None = None
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=headers) as session:
            for attempt in range(2):
                async with session.get(url) as resp:
                    if resp.status == 429 and attempt == 0:
                        await asyncio.sleep(2)
                        continue
                    if resp.status != 200:
                        logger.warning("otx: HTTP %d for %s", resp.status, domain)
                        return []
                    data = await resp.json(content_type=None)
                    break
    except Exception as exc:
        logger.warning("otx: failed for %s: %s", domain, exc)
        return []

    if not data:
        return []

    hostnames: set[str] = set()
    for entry in data.get("passive_dns", []) or []:
        name = (entry.get("hostname") or "").strip().lower().lstrip("*.")
        if not name or "." not in name:
            continue
        if name == domain or name.endswith(f".{domain}"):
            hostnames.add(name)

    logger.info("otx: domain=%s found %d unique hostnames", domain, len(hostnames))
    return sorted(hostnames)
