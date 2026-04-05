"""Normalize tool output → Asset ORM rows via upsert."""

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset

logger = logging.getLogger(__name__)


async def upsert_discovered_hosts(
    db: AsyncSession,
    org_id: uuid.UUID,
    hosts: list[dict],
    source: str,
) -> tuple[int, list[uuid.UUID]]:
    """Upsert discovered hostnames into assets table.

    Returns (total_upserted, list_of_new_asset_ids).
    """
    if not hosts:
        return 0, []

    now = datetime.now(timezone.utc)
    new_ids: list[uuid.UUID] = []
    upserted = 0

    for entry in hosts:
        hostname = entry.get("host") or entry.get("hostname") or ""
        hostname = hostname.strip().lower()
        if not hostname:
            continue

        ip = entry.get("ip") or entry.get("a") or entry.get("address")
        asn = entry.get("asn")
        asn_org = entry.get("asn_org") or entry.get("org")

        result = await db.execute(
            text("""
                INSERT INTO assets (id, org_id, hostname, ip, asn, asn_org, source, first_seen, last_seen, tags)
                VALUES (:id, :org_id, :hostname, :ip, :asn, :asn_org, :source, :now, :now, '{}')
                ON CONFLICT (org_id, hostname) DO UPDATE SET
                    ip = COALESCE(EXCLUDED.ip, assets.ip),
                    asn = COALESCE(EXCLUDED.asn, assets.asn),
                    asn_org = COALESCE(EXCLUDED.asn_org, assets.asn_org),
                    last_seen = EXCLUDED.last_seen
                RETURNING id, (xmax = 0) AS is_new
            """),
            {
                "id": uuid.uuid4(),
                "org_id": org_id,
                "hostname": hostname,
                "ip": ip,
                "asn": asn,
                "asn_org": asn_org,
                "source": source,
                "now": now,
            },
        )
        row = result.fetchone()
        if row:
            upserted += 1
            if row.is_new:
                new_ids.append(row.id)

    await db.commit()
    logger.info("org=%s source=%s upserted=%d new=%d", org_id, source, upserted, len(new_ids))
    return upserted, new_ids


async def update_dns_records(
    db: AsyncSession,
    org_id: uuid.UUID,
    dns_results: list[dict],
) -> int:
    """Update DNS records on existing assets from dnsx output."""
    updated = 0
    for entry in dns_results:
        hostname = (entry.get("host") or "").strip().lower()
        if not hostname:
            continue

        dns_data = {}
        if entry.get("a"):
            dns_data["A"] = entry["a"] if isinstance(entry["a"], list) else [entry["a"]]
        if entry.get("cname"):
            dns_data["CNAME"] = entry["cname"] if isinstance(entry["cname"], list) else [entry["cname"]]
        if entry.get("mx"):
            dns_data["MX"] = entry["mx"] if isinstance(entry["mx"], list) else [entry["mx"]]
        if entry.get("txt"):
            dns_data["TXT"] = entry["txt"] if isinstance(entry["txt"], list) else [entry["txt"]]

        ip = None
        a_records = dns_data.get("A", [])
        if a_records:
            ip = a_records[0]

        await db.execute(
            text("""
                UPDATE assets SET
                    dns_records = cast(:dns as jsonb),
                    ip = COALESCE(:ip, ip),
                    last_seen = :now
                WHERE org_id = :org_id AND hostname = :hostname
            """),
            {
                "dns": json.dumps(dns_data),
                "ip": ip,
                "org_id": org_id,
                "hostname": hostname,
                "now": datetime.now(timezone.utc),
            },
        )
        updated += 1

    await db.commit()
    return updated


async def update_ports(
    db: AsyncSession,
    org_id: uuid.UUID,
    port_results: list[dict],
) -> int:
    """Update open_ports and services on assets from naabu -sV output."""
    host_ports: dict[str, list[int]] = {}
    host_services: dict[str, dict[int, dict]] = {}

    for entry in port_results:
        host = (entry.get("host") or entry.get("ip") or "").strip().lower()
        port = entry.get("port")
        if not host or not port:
            continue

        port = int(port)
        host_ports.setdefault(host, []).append(port)

        # Extract service version info from naabu -sV
        svc = entry.get("service") or {}
        if svc:
            host_services.setdefault(host, {})[port] = {
                "name": svc.get("name", ""),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
            }

    updated = 0
    now = datetime.now(timezone.utc)
    for host, ports in host_ports.items():
        ports = sorted(set(ports))
        services = host_services.get(host, {})
        # Build services as {port: {name, product, version}}
        services_json = json.dumps({str(p): services[p] for p in sorted(services)}) if services else None

        await db.execute(
            text("""
                UPDATE assets SET
                    open_ports = :ports,
                    services = COALESCE(cast(:services as json), services),
                    last_seen = :now
                WHERE org_id = :org_id AND (hostname = :host OR host(ip) = :host)
            """),
            {"ports": ports, "services": services_json, "org_id": org_id, "host": host, "now": now},
        )
        updated += 1

    await db.commit()
    return updated


async def update_enrichment(
    db: AsyncSession,
    org_id: uuid.UUID,
    httpx_results: list[dict],
) -> int:
    """Update HTTP enrichment data on assets from httpx output."""
    updated = 0
    now = datetime.now(timezone.utc)

    for entry in httpx_results:
        host = (entry.get("input") or entry.get("host") or "").strip().lower()
        if not host:
            continue

        tech = entry.get("tech") or entry.get("technologies")
        cdn_name = entry.get("cdn_name") or entry.get("cdn")
        waf = entry.get("waf_name") or entry.get("waf")

        # Build services dict from httpx probe results
        url = entry.get("url") or ""
        webserver = entry.get("webserver") or entry.get("web_server") or ""
        port = entry.get("port")
        scheme = url.split("://")[0].lower() if "://" in url else ""
        if not port:
            port = 443 if scheme == "https" else 80 if scheme == "http" else None
        services_dict = {}
        if port and scheme:
            services_dict[str(port)] = {
                "name": scheme,
                "product": webserver,
                "version": "",
            }
        services_json = json.dumps(services_dict) if services_dict else None

        await db.execute(
            text("""
                UPDATE assets SET
                    http_status = :status,
                    http_title = :title,
                    http_url = :url,
                    tech_stack = cast(:tech as jsonb),
                    cdn_provider = :cdn,
                    waf = :waf,
                    services = COALESCE(services, '{}'::jsonb) || COALESCE(cast(:services as jsonb), '{}'::jsonb),
                    last_enriched = :now,
                    last_seen = :now
                WHERE org_id = :org_id AND hostname = :host
            """),
            {
                "status": entry.get("status_code") or entry.get("status-code"),
                "title": entry.get("title"),
                "url": url,
                "tech": json.dumps(tech) if tech else None,
                "cdn": cdn_name if isinstance(cdn_name, str) else (cdn_name[0] if cdn_name else None),
                "waf": waf if isinstance(waf, str) else (waf[0] if waf else None),
                "services": services_json,
                "org_id": org_id,
                "host": host,
                "now": now,
            },
        )
        updated += 1

    await db.commit()
    return updated


async def update_tls(
    db: AsyncSession,
    org_id: uuid.UUID,
    tls_results: list[dict],
) -> int:
    """Update TLS cert data on assets from tlsx output."""
    updated = 0
    now = datetime.now(timezone.utc)

    for entry in tls_results:
        host = (entry.get("host") or entry.get("input") or "").strip().lower()
        # strip port if present
        if ":" in host:
            host = host.split(":")[0]
        if not host:
            continue

        tls_cert = {
            "issuer": entry.get("issuer_dn") or entry.get("issuer"),
            "subject": entry.get("subject_dn") or entry.get("subject"),
            "sans": entry.get("san") or entry.get("subject_an"),
            "expiry": entry.get("not_after") or entry.get("expired"),
            "cipher": entry.get("cipher"),
            "version": entry.get("tls_version") or entry.get("version"),
        }

        await db.execute(
            text("""
                UPDATE assets SET
                    tls_cert = cast(:tls as jsonb),
                    last_enriched = :now,
                    last_seen = :now
                WHERE org_id = :org_id AND hostname = :host
            """),
            {"tls": json.dumps(tls_cert), "org_id": org_id, "host": host, "now": now},
        )
        updated += 1

    await db.commit()
    return updated


async def update_cdn(
    db: AsyncSession,
    org_id: uuid.UUID,
    cdn_results: list[dict],
) -> int:
    """Update CDN/WAF info from cdncheck output."""
    updated = 0
    now = datetime.now(timezone.utc)

    for entry in cdn_results:
        host = (entry.get("input") or entry.get("host") or "").strip().lower()
        if not host:
            continue

        cdn = entry.get("cdn_name") or entry.get("cdn")
        waf = entry.get("waf_name") or entry.get("waf")

        await db.execute(
            text("""
                UPDATE assets SET
                    cdn_provider = COALESCE(:cdn, cdn_provider),
                    waf = COALESCE(:waf, waf),
                    last_enriched = :now,
                    last_seen = :now
                WHERE org_id = :org_id AND (hostname = :host OR host(ip) = :host)
            """),
            {
                "cdn": cdn if isinstance(cdn, str) else None,
                "waf": waf if isinstance(waf, str) else None,
                "org_id": org_id,
                "host": host,
                "now": now,
            },
        )
        updated += 1

    await db.commit()
    return updated
