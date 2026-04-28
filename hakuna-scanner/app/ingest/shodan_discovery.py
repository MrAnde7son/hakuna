"""Shodan host search for EASM discovery.

Direct Shodan API client, complementing `uncover` (which only returns
hosts via a CLI wrapper). This module returns the full Shodan record
per host so downstream classification can flag orphan/shadow assets
and surface known service banners + CVEs.

Free-tier note: /shodan/host/search returns up to 100 results per
query and 1 page (no scrolling). Higher tiers paginate via the `page`
parameter, which we honor up to `max_pages`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator
from urllib.parse import urlencode

import aiohttp

logger = logging.getLogger(__name__)

_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
_TIMEOUT = aiohttp.ClientTimeout(total=30)
_RATE_LIMIT_DELAY = 1.1  # Shodan: 1 req/sec on most plans


def _build_queries(domain: str) -> list[str]:
    """Queries that pivot on a seed domain.

    `ssl:` catches hosts serving a cert mentioning the domain — the
    strongest signal for shadow IT (forgotten dev boxes, M&A leftovers).
    `hostname:` catches anything Shodan resolved into *.domain.
    """
    return [
        f"ssl:{domain}",
        f"hostname:{domain}",
    ]


async def _search_page(
    session: aiohttp.ClientSession,
    api_key: str,
    query: str,
    page: int,
) -> dict | None:
    params = {"key": api_key, "query": query, "page": page}
    url = f"{_SEARCH_URL}?{urlencode(params)}"
    try:
        async with session.get(url) as resp:
            if resp.status == 401:
                logger.warning("shodan: 401 unauthorized — check SHODAN_API_KEY")
                return None
            if resp.status == 403:
                logger.warning("shodan: 403 forbidden — query '%s' requires a paid plan", query)
                return None
            if resp.status == 429:
                logger.warning("shodan: 429 rate-limited on '%s'", query)
                return None
            if resp.status != 200:
                logger.warning("shodan: HTTP %d for '%s'", resp.status, query)
                return None
            return await resp.json(content_type=None)
    except Exception as exc:
        logger.warning("shodan: request failed for '%s': %s", query, exc)
        return None


def _matches_to_hosts(matches: list[dict]) -> list[dict]:
    """Flatten Shodan matches into host records the upsert path expects.

    A single Shodan match describes one IP+port observation. We emit
    one host record per (hostname, ip) pair, plus a bare IP record
    when no hostnames are present — that's the "orphan IP" case.
    """
    hosts: list[dict] = []
    for m in matches:
        ip = m.get("ip_str")
        if not ip:
            continue

        port = m.get("port")
        product = (m.get("product") or "").strip()
        version = (m.get("version") or "").strip()
        org = (m.get("org") or "").strip()
        asn_raw = m.get("asn") or ""
        asn = asn_raw.lstrip("AS") or None
        vulns = sorted((m.get("vulns") or {}).keys()) if isinstance(m.get("vulns"), dict) else None

        shodan_meta = {
            "shodan_port": port,
            "shodan_product": product or None,
            "shodan_version": version or None,
            "shodan_vulns": vulns,
        }

        hostnames = [h.strip().lower() for h in (m.get("hostnames") or []) if h]
        if hostnames:
            for h in hostnames:
                hosts.append({
                    "host": h,
                    "ip": ip,
                    "asn": asn,
                    "asn_org": org or None,
                    **shodan_meta,
                })
        else:
            hosts.append({
                "host": ip,
                "ip": ip,
                "asn": asn,
                "asn_org": org or None,
                **shodan_meta,
            })
    return hosts


async def query_shodan(
    api_key: str,
    domain: str,
    max_pages: int = 1,
) -> list[dict]:
    """Discover hosts for a seed domain via Shodan host search.

    Returns a list of host dicts shaped for `upsert_discovered_hosts`.
    Never raises — returns [] on auth/network/quota failure.
    """
    if not api_key:
        return []

    all_hosts: list[dict] = []
    seen: set[tuple[str, str]] = set()

    async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
        for query in _build_queries(domain):
            for page in range(1, max_pages + 1):
                data = await _search_page(session, api_key, query, page)
                if data is None:
                    break
                matches = data.get("matches") or []
                if not matches:
                    break

                for h in _matches_to_hosts(matches):
                    key = (h["host"], h.get("ip") or "")
                    if key in seen:
                        continue
                    seen.add(key)
                    all_hosts.append(h)

                # Free tier returns total but only the first page is usable.
                # Stop early if the page came back short.
                if len(matches) < 100:
                    break
                await asyncio.sleep(_RATE_LIMIT_DELAY)

            await asyncio.sleep(_RATE_LIMIT_DELAY)

    logger.info("shodan: domain=%s hosts=%d", domain, len(all_hosts))
    return all_hosts
