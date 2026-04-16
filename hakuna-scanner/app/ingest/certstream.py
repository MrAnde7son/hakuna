"""Continuous CT monitoring via CertStream.

Extends crtsh.py's daily polling into a real-time websocket consumer.
When a new TLS certificate is logged to any CT log, CertStream pushes
a JSON message containing the cert's subject/SAN hostnames. We filter
to hostnames matching any active target_domain, dedup within the current
session, and upsert them as new assets (which emits new_asset events
that feed into the event bridge workflow triggers).

Implementation notes:
- Uses the public certstream.calidog.io websocket.
- Reconnects with exponential backoff on disconnect.
- In-process TTL dedup cache (5 min) avoids re-upserting on duplicate
  messages from the same cert chain.
- Opt-in via settings.certstream_enabled. Default False so we don't
  open outbound websocket connections unless explicitly turned on.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Iterable

import aiohttp
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.ingest.assets import upsert_discovered_hosts
from app.ingest.delta import emit_new_asset_events

logger = logging.getLogger(__name__)


# In-process dedup cache: hostname → expiry timestamp
# Prevents re-processing the same hostname within a short window when
# CertStream sends overlapping cert chains.
_DEDUP_TTL_SECONDS = 300
_seen_cache: dict[str, float] = {}


async def _load_org_domain_map(sf) -> dict[str, uuid.UUID]:
    """Return {suffix: org_id} for all active target domains.

    Example: {'example.com': UUID('...'), 'corp.io': UUID('...')}.
    Matching is suffix-based — a hostname is claimed by an org if it
    ends in `.{domain}` or equals `domain`.
    """
    async with sf() as db:
        rows = await db.execute(
            text("""
                SELECT td.domain, td.org_id
                FROM target_domains td
                WHERE td.active = true
            """)
        )
        return {r.domain.lower(): r.org_id for r in rows.fetchall()}


def _match_domain(hostname: str, domain_map: dict[str, uuid.UUID]) -> uuid.UUID | None:
    """Find the org_id whose target domain suffixes the given hostname."""
    hostname = hostname.strip().lower().lstrip("*.")
    if not hostname or "." not in hostname:
        return None
    # Try exact match first, then progressively longer suffixes
    for domain, org_id in domain_map.items():
        if hostname == domain or hostname.endswith(f".{domain}"):
            return org_id
    return None


def _iter_cert_hostnames(msg: dict) -> Iterable[str]:
    """Extract hostnames from a CertStream message.

    CertStream message shape:
        {"message_type": "certificate_update",
         "data": {
            "leaf_cert": {
                "subject": {"CN": "example.com", ...},
                "all_domains": ["example.com", "www.example.com", ...]
            },
            ...
         }}
    """
    if msg.get("message_type") != "certificate_update":
        return
    data = msg.get("data") or {}
    leaf = data.get("leaf_cert") or {}

    # all_domains is the authoritative list (SAN + CN)
    for d in leaf.get("all_domains") or []:
        if d:
            yield d

    # Fall back to CN if all_domains was empty
    cn = (leaf.get("subject") or {}).get("CN")
    if cn:
        yield cn


async def _process_message(sf, msg: dict, domain_map: dict[str, uuid.UUID]) -> int:
    """Handle one CertStream message. Returns number of new assets upserted."""
    now_ts = time.time()
    # Purge stale dedup entries once per message (cheap — dict scan)
    if len(_seen_cache) > 10_000:
        for k, exp in list(_seen_cache.items()):
            if exp < now_ts:
                _seen_cache.pop(k, None)

    # Group candidate hostnames by org
    by_org: dict[uuid.UUID, list[dict]] = {}
    for hostname in _iter_cert_hostnames(msg):
        hostname = hostname.strip().lower().lstrip("*.")
        if not hostname:
            continue
        if _seen_cache.get(hostname, 0) > now_ts:
            continue
        org_id = _match_domain(hostname, domain_map)
        if not org_id:
            continue
        _seen_cache[hostname] = now_ts + _DEDUP_TTL_SECONDS
        by_org.setdefault(org_id, []).append({"host": hostname})

    if not by_org:
        return 0

    new_total = 0
    for org_id, hosts in by_org.items():
        async with sf() as db:
            try:
                _, new_ids = await upsert_discovered_hosts(db, org_id, hosts, source="certstream")
                if new_ids:
                    await emit_new_asset_events(db, org_id, new_ids)
                    new_total += len(new_ids)
            except Exception as e:
                logger.warning("certstream: upsert failed for org %s: %s", org_id, e)
    return new_total


async def run_certstream_consumer(sf) -> None:
    """Main consumer loop. Connects to CertStream, processes messages,
    reconnects on failure. Runs forever — should be launched as a long-lived
    celery task or standalone worker.
    """
    if not settings.certstream_enabled:
        logger.info("certstream: disabled in config, not starting consumer")
        return

    url = settings.certstream_url
    backoff = settings.certstream_reconnect_delay
    max_backoff = 600
    refresh_domain_map_every = 300  # seconds
    last_domain_map_refresh = 0.0
    domain_map: dict[str, uuid.UUID] = {}

    while True:
        try:
            logger.info("certstream: connecting to %s", url)
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(url, heartbeat=30) as ws:
                    logger.info("certstream: connected")
                    backoff = settings.certstream_reconnect_delay  # reset
                    msg_count = 0

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            # Refresh domain map periodically
                            now = time.time()
                            if now - last_domain_map_refresh > refresh_domain_map_every:
                                domain_map = await _load_org_domain_map(sf)
                                last_domain_map_refresh = now
                                logger.info(
                                    "certstream: refreshed domain map (%d active domains)",
                                    len(domain_map),
                                )

                            if not domain_map:
                                continue  # no orgs to match against

                            try:
                                data = json.loads(msg.data)
                                new = await _process_message(sf, data, domain_map)
                                if new:
                                    logger.info("certstream: +%d new assets (msg=%d)", new, msg_count)
                            except json.JSONDecodeError:
                                pass
                            except Exception as e:
                                logger.warning("certstream: message handler error: %s", e)
                            msg_count += 1

                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            logger.warning("certstream: websocket closed (type=%s)", msg.type)
                            break
        except asyncio.CancelledError:
            logger.info("certstream: consumer cancelled")
            return
        except Exception as e:
            logger.warning("certstream: connection failed: %s", e)

        await asyncio.sleep(backoff)
        backoff = min(max_backoff, backoff * 2)
