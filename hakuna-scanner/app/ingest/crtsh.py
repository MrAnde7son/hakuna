"""Certificate Transparency log monitoring via crt.sh.

Queries crt.sh's public API to discover subdomains from CT logs.
This is a passive, free source that finds subdomains that may not
appear in DNS — e.g. internal names in SAN fields of public certs.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import quote

import aiohttp

logger = logging.getLogger(__name__)

_CRTSH_URL = "https://crt.sh/?q={query}&output=json"
_TIMEOUT = aiohttp.ClientTimeout(total=30)


async def query_crtsh(domain: str) -> list[str]:
    """Query crt.sh for subdomains of a domain.

    Returns deduplicated list of hostnames (wildcards stripped).
    Never raises — returns empty list on error.
    """
    query = quote(f"%.{domain}")
    url = _CRTSH_URL.format(query=query)

    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    logger.warning("crtsh: HTTP %d for %s", resp.status, domain)
                    return []
                data = await resp.json(content_type=None)
    except Exception as exc:
        logger.warning("crtsh: failed for %s: %s", domain, exc)
        return []

    hostnames: set[str] = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and "." in name and name.endswith(f".{domain}") or name == domain:
                hostnames.add(name)

    logger.info("crtsh: domain=%s found %d unique hostnames", domain, len(hostnames))
    return sorted(hostnames)
