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
_DNS_DOMAIN_URL = "https://api.shodan.io/dns/domain/{domain}"
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
) -> tuple[dict | None, bool]:
    """Run one Shodan host/search page.

    Returns ``(payload_or_None, paid_only)`` — ``paid_only`` is True only when
    the API responded 403, signalling the search filters require a paid plan
    and the caller should fall back to the free /dns/domain endpoint. All
    other failure modes (401 auth, 429 rate-limit, network) come back as
    ``(None, False)`` so the caller doesn't paper over a real misconfig with
    fallback data.
    """
    params = {"key": api_key, "query": query, "page": page}
    url = f"{_SEARCH_URL}?{urlencode(params)}"
    try:
        async with session.get(url) as resp:
            if resp.status == 401:
                logger.warning("shodan: 401 unauthorized — check SHODAN_API_KEY")
                return None, False
            if resp.status == 403:
                logger.warning("shodan: 403 forbidden — query '%s' requires a paid plan", query)
                return None, True
            if resp.status == 429:
                logger.warning("shodan: 429 rate-limited on '%s'", query)
                return None, False
            if resp.status != 200:
                logger.warning("shodan: HTTP %d for '%s'", resp.status, query)
                return None, False
            return await resp.json(content_type=None), False
    except Exception as exc:
        logger.warning(
            "shodan: request failed for '%s': %s (%s)",
            query, exc, type(exc).__name__,
        )
        return None, False


async def _query_dns_domain(
    session: aiohttp.ClientSession,
    api_key: str,
    domain: str,
) -> list[dict]:
    """Free-tier subdomain enumeration via /dns/domain/{domain}.

    Unlike the host/search endpoint, this is available on every Shodan plan
    including the free dev key. It returns subdomain prefixes plus the DNS
    records Shodan has observed for them (A/AAAA/CNAME/...). We flatten
    those into the same host-dict shape the host/search path produces, but
    without paid-tier metadata (port/product/vulns) since the DNS endpoint
    doesn't include service banners.
    """
    url = _DNS_DOMAIN_URL.format(domain=domain) + f"?{urlencode({'key': api_key})}"
    try:
        async with session.get(url) as resp:
            if resp.status == 401:
                logger.warning("shodan dns: 401 unauthorized — check SHODAN_API_KEY")
                return []
            if resp.status == 404:
                # Free endpoint returns 404 when Shodan has no records for the
                # domain — common for fresh/parked domains. Not an error.
                return []
            if resp.status != 200:
                logger.warning("shodan dns: HTTP %d for %s", resp.status, domain)
                return []
            data = await resp.json(content_type=None)
    except Exception as exc:
        logger.warning(
            "shodan dns: request failed for %s: %s (%s)",
            domain, exc, type(exc).__name__,
        )
        return []

    hosts: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for entry in data.get("data") or []:
        subdomain = (entry.get("subdomain") or "").strip().lower()
        record_type = (entry.get("type") or "").upper()
        value = (entry.get("value") or "").strip()
        if not value:
            continue
        # Empty subdomain means apex.
        fqdn = domain if not subdomain else f"{subdomain}.{domain}"
        ip = value if record_type in ("A", "AAAA") else None
        key = (fqdn, ip or "")
        if key in seen:
            continue
        seen.add(key)
        hosts.append({
            "host": fqdn,
            "ip": ip,
            "asn": None,
            "asn_org": None,
            "shodan_port": None,
            "shodan_product": None,
            "shodan_version": None,
            "shodan_vulns": None,
        })

    logger.info("shodan dns: domain=%s hosts=%d", domain, len(hosts))
    return hosts


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
    saw_paid_only = False

    async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
        for query in _build_queries(domain):
            for page in range(1, max_pages + 1):
                data, paid_only = await _search_page(session, api_key, query, page)
                if paid_only:
                    saw_paid_only = True
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

        # Free-tier fallback: the host/search filters above are paid-only.
        # When the API key can't run them but is otherwise valid, hit the
        # free /dns/domain endpoint so free-tier deployments still
        # contribute subdomain coverage to discovery. We only fall back
        # when the search yielded nothing — paid users keep their richer
        # banner/CVE-bearing matches and skip the redundant DNS call.
        if saw_paid_only and not all_hosts:
            for h in await _query_dns_domain(session, api_key, domain):
                key = (h["host"], h.get("ip") or "")
                if key in seen:
                    continue
                seen.add(key)
                all_hosts.append(h)

    logger.info("shodan: domain=%s hosts=%d", domain, len(all_hosts))
    return all_hosts
