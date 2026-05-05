"""SSH banner grab — RFC 4253 version exchange.

On TCP connect, an SSH server sends a single line of the form::

    SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n

That line is the protocol/software version pair the CVE correlator needs to
map to OpenSSH/Dropbear/libssh CVEs. We do NOT continue the key-exchange —
the version line alone is what we want, and stopping early avoids touching
host-key state on the server side.

Output shape matches ``protocol_probe.probe_batch``: dict keyed by hostname,
each value a list of banner_finding dicts written to
``assets.easm_data.banner_findings``.
"""

from __future__ import annotations

import asyncio
import logging
import re

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 5
_MAX_BANNER_BYTES = 255  # RFC 4253 §4.2

# SSH-protoversion-softwareversion[ comments]
# protoversion is "1.99", "2.0", etc; softwareversion has no spaces.
_BANNER_RE = re.compile(
    r"^SSH-(?P<proto>\d+\.\d+)-(?P<software>\S+)(?:\s+(?P<comments>.+))?$"
)


async def _probe_single(host: str, port: int = 22) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        try:
            line = await asyncio.wait_for(
                reader.readline(), timeout=_READ_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return None

        banner = line.decode("ascii", errors="replace").rstrip("\r\n")
        if not banner.startswith("SSH-") or len(banner) > _MAX_BANNER_BYTES:
            return None

        m = _BANNER_RE.match(banner)
        if not m:
            return None

        return {
            "protocol": "ssh",
            "port": port,
            "banner": banner,
            "version": {
                "proto": m.group("proto"),
                "software": m.group("software"),
                "comments": m.group("comments"),
            },
        }
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


_LEGACY_PORTS: set[int] = {22}
_SERVICE_TYPES: set[str] = {"ssh"}


async def probe_batch(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[str, list[dict]]:
    """Banner-grab SSH on every asset with an SSH-typed port open.

    PR #2: gate on ``asset_ports.service_type == 'ssh'`` (preferred)
    OR ``port == 22`` (fallback). The fallback covers ports not yet
    re-fingerprinted since PR #1; without it, every existing port-22
    record drops out of coverage on the first scan after the migration.

    ``assets`` items: ``{hostname, ip, open_ports, port_service_types?}``.
    ``port_service_types`` is a ``dict[int, str]`` of stamped service
    types per port (populated by ``service_lookup.attach_port_service_types``
    when the orchestrator pre-loads the asset list).
    """
    from app.ingest.service_lookup import matching_ports_for_asset

    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[dict]] = {}

    async def _run_one(asset: dict):
        ports = matching_ports_for_asset(
            asset,
            service_types=_SERVICE_TYPES,
            legacy_ports=_LEGACY_PORTS,
        )
        if not ports:
            return
        target = asset.get("ip") or asset.get("hostname")
        if not target:
            return
        hits: list[dict] = []
        for port in ports:
            async with semaphore:
                hit = await _probe_single(target, port)
            if hit:
                hits.append(hit)
        if hits:
            results[asset["hostname"]] = hits

    await asyncio.gather(
        *(_run_one(a) for a in assets),
        return_exceptions=True,
    )
    return results
