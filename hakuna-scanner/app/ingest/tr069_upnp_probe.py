"""TR-069 (CWMP) and UPnP/SSDP fingerprint.

Two protocols, one module — they live on adjacent CPE/IoT ports and the
output shape is identical.

* **TR-069 7547** — ACS endpoint on a CPE device. The device speaks SOAP
  back to the ACS, but the listener on 7547 is also a SOAP endpoint that
  responds to a `GetRPCMethods` request from the ACS-side. We fetch the
  WSDL/server header to identify the CPE vendor; the SOAP body is
  deliberately empty to avoid CWMP session creation.

* **UPnP/SSDP 1900 + descriptor URLs** — sending an M-SEARCH multicast
  doesn't make sense in an asset-scoped probe. Instead we look for a
  description.xml fetched over HTTP on the discovered descriptor port
  (commonly 1900, 49152, 8080). The discovery URL is on
  ``easm_data.upnp_descriptor_url`` if a prior stage found it; otherwise
  we try `/description.xml` and `/rootDesc.xml` on port 1900.

UPnP exposed on the public internet is itself a finding (`severity=high`);
TR-069 exposed without TLS is informational.
"""

from __future__ import annotations

import asyncio
import logging
import re

logger = logging.getLogger(__name__)

_TIMEOUT = 6.0

_TR069_PROBE_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    '<soap:Body/></soap:Envelope>'
)

_UPNP_DESCRIPTOR_PATHS = ("/description.xml", "/rootDesc.xml", "/upnp/desc.xml")

_UPNP_FIELD_RE = {
    "manufacturer": re.compile(r"<manufacturer>([^<]+)</manufacturer>", re.I),
    "model_name": re.compile(r"<modelName>([^<]+)</modelName>", re.I),
    "model_number": re.compile(r"<modelNumber>([^<]+)</modelNumber>", re.I),
    "friendly_name": re.compile(r"<friendlyName>([^<]+)</friendlyName>", re.I),
    "udn": re.compile(r"<UDN>([^<]+)</UDN>", re.I),
}


async def _probe_tr069(
    session,  # aiohttp.ClientSession — typed loosely; lazy import below
    host: str,
    port: int = 7547,
) -> dict | None:
    import aiohttp
    # Try HTTPS first (TR-069 over TLS is the spec default), fall back HTTP.
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}:{port}/"
        try:
            async with session.post(
                url,
                data=_TR069_PROBE_BODY,
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": '""',
                },
                timeout=aiohttp.ClientTimeout(total=_TIMEOUT),
                ssl=False,
                allow_redirects=False,
            ) as resp:
                server = resp.headers.get("Server")
                www_auth = resp.headers.get("WWW-Authenticate")
                if not server and resp.status not in (200, 401, 405, 500):
                    continue
                result: dict = {
                    "protocol": "tr069",
                    "port": port,
                    "banner": server,
                    "version": {"server": server},
                    "metadata": {
                        "transport": scheme,
                        "http_status": resp.status,
                        "auth_required": bool(www_auth),
                    },
                }
                if scheme == "http":
                    result["severity"] = "low"
                    result["finding_title"] = "TR-069 ACS endpoint over cleartext HTTP"
                return result
        except Exception:
            continue
    return None


async def _probe_upnp(
    session,  # aiohttp.ClientSession
    host: str,
    port: int,
    descriptor_url: str | None,
) -> dict | None:
    import aiohttp
    candidates: list[str] = []
    if descriptor_url:
        candidates.append(descriptor_url)
    for path in _UPNP_DESCRIPTOR_PATHS:
        candidates.append(f"http://{host}:{port}{path}")

    for url in candidates:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=_TIMEOUT),
                ssl=False,
                allow_redirects=False,
            ) as resp:
                if resp.status != 200:
                    continue
                body = await resp.text(errors="replace")
        except Exception:
            continue

        if "<root" not in body and "<device" not in body:
            continue

        fields = {
            key: m.group(1).strip()
            for key, regex in _UPNP_FIELD_RE.items()
            if (m := regex.search(body))
        }
        if not fields:
            continue

        return {
            "protocol": "upnp",
            "port": port,
            "banner": fields.get("friendly_name"),
            "version": {
                "manufacturer": fields.get("manufacturer"),
                "model": fields.get("model_name"),
                "model_number": fields.get("model_number"),
            },
            "metadata": {
                "udn": fields.get("udn"),
                "descriptor_url": url,
            },
            "severity": "high",
            "finding_title": "UPnP descriptor exposed on public network",
        }
    return None


async def probe_batch(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[str, list[dict]]:
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[dict]] = {}

    candidates = [
        a for a in assets
        if (a.get("hostname") or a.get("ip"))
        and ({7547, 1900} & set(a.get("open_ports") or []))
    ]
    if not candidates:
        return results

    import aiohttp  # lazy
    connector = aiohttp.TCPConnector(limit=concurrency * 2, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def _run_one(asset: dict):
            target = asset.get("ip") or asset.get("hostname")
            ports = set(asset.get("open_ports") or [])
            descriptor_url = (asset.get("easm_data") or {}).get("upnp_descriptor_url")
            hits: list[dict] = []
            if 7547 in ports:
                async with semaphore:
                    hit = await _probe_tr069(session, target, 7547)
                if hit:
                    hits.append(hit)
            if 1900 in ports:
                async with semaphore:
                    hit = await _probe_upnp(session, target, 1900, descriptor_url)
                if hit:
                    hits.append(hit)
            if hits:
                results[asset["hostname"]] = hits

        await asyncio.gather(
            *(_run_one(a) for a in candidates),
            return_exceptions=True,
        )
    return results
