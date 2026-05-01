"""AJP13 CPing/CPong probe — Apache JServ Protocol fingerprinter.

AJP (Apache JServ Protocol) is the binary protocol used by Tomcat to
forward requests from a fronting reverse proxy (e.g. mod_jk on Apache,
mod_proxy_ajp). Default port is 8009 but operators occasionally bind it
elsewhere. AJP exposed to the internet is high-risk: CVE-2020-1938
("Ghostcat") allows arbitrary file disclosure and, with a writable
upload directory, RCE via servlet forwarding.

We don't speak full AJP — just the connector-level health check:

* **CPing** (client → server): magic ``0x12 0x34``, length ``0x00 0x01``,
  prefix code ``0x0A``. Five bytes total.
* **CPong** (server → client): magic ``0x41 0x42`` ("AB"), length
  ``0x00 0x01``, prefix code ``0x09``. Five bytes total.

A correct CPong from an open TCP socket is sufficient identification.
We do NOT issue a Forward Request — that would attempt to forward a
request to a backend servlet, which is exactly the Ghostcat attack
shape we're trying to detect, not perform.

Output shape matches ``ssh_banner.probe_batch``: dict keyed by hostname,
each value a list of banner_finding dicts the orchestrator merges into
``assets.easm_data.banner_findings`` and re-stamps onto
``asset_ports.service_type``.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 5

# Client → server magic: 0x12 0x34. Length 1, body = CPing prefix 0x0A.
_AJP_CPING = b"\x12\x34\x00\x01\x0a"

# Server → client magic: 0x41 0x42 ("AB"). Length 1, body = CPong prefix 0x09.
_AJP_CPONG_MAGIC = b"\x41\x42"
_AJP_CPONG_PREFIX = 0x09
_AJP_CPONG_FRAME = b"\x41\x42\x00\x01\x09"


async def _probe_single(host: str, port: int = 8009) -> dict | None:
    """Send AJP13 CPing, validate CPong reply.

    Returns a banner_finding dict on success, None on failure (timeout,
    connection refused, wrong magic, short read).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        try:
            writer.write(_AJP_CPING)
            await writer.drain()
        except (OSError, asyncio.TimeoutError):
            return None

        # CPong is exactly 5 bytes. readexactly(5) with a timeout: short
        # reads from non-AJP services (which often hang or close) bail
        # without leaving us blocked.
        try:
            frame = await asyncio.wait_for(
                reader.readexactly(5), timeout=_READ_TIMEOUT,
            )
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None

        if len(frame) != 5:
            return None
        if frame[0:2] != _AJP_CPONG_MAGIC:
            return None
        # bytes 2-3 = body length, bytes[4] = prefix code (CPong = 0x09).
        if frame[4] != _AJP_CPONG_PREFIX:
            return None

        return {
            "protocol": "ajp",
            "port": port,
            "banner": "AJP13 CPong",
            "version": {
                "product": "Tomcat-AJP",
            },
            "metadata": {
                "cping_sent": _AJP_CPING.hex(),
                "cpong_received": frame.hex(),
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


_LEGACY_PORTS: set[int] = {8009}
_SERVICE_TYPES: set[str] = {"ajp"}


async def probe_batch(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[str, list[dict]]:
    """Banner-grab AJP on every asset with an AJP-typed port open.

    Mirrors ``ssh_banner.probe_batch``: gates on
    ``asset_ports.service_type == 'ajp'`` (preferred) OR ``port == 8009``
    (fallback). The fallback covers ports not yet re-fingerprinted since
    PR #1; without it, every existing port-8009 record drops out of
    coverage on the first scan after the migration.

    Each asset dict carries ``hostname``, ``ip``, ``open_ports`` and an
    optional ``port_service_types: dict[int, str]`` populated by
    :func:`service_lookup.attach_port_service_types`.
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
            try:
                async with semaphore:
                    hit = await _probe_single(target, port)
            except Exception as exc:  # noqa: BLE001 — best-effort probe
                logger.debug(
                    "ajp_probe error host=%s port=%s: %s",
                    asset.get("hostname"), port, exc,
                )
                continue
            if hit:
                hits.append(hit)
        if hits:
            results[asset["hostname"]] = hits

    await asyncio.gather(
        *(_run_one(a) for a in assets),
        return_exceptions=True,
    )
    return results
