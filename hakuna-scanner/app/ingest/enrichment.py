"""Extension 3 & 4: Ingest functions for deep enrichment and nmap results.

Handles: tlsx per-port cert storage, httpx full JSON enrichment records,
katana endpoint discovery, and nmap fingerprinting results.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Patterns that suggest an authentication page
AUTH_INDICATORS = re.compile(
    r"(login|signin|sign[_-]in|auth|password|passwd|credential|sso|oauth|"
    r"register|signup|sign[_-]up|forgot|reset[_-]password|mfa|2fa|otp)",
    re.IGNORECASE,
)


async def upsert_asset_port(
    db: AsyncSession,
    asset_id: uuid.UUID,
    port: int,
    protocol: str = "tcp",
    service_name: str | None = None,
    service_version: str | None = None,
    banner: str | None = None,
    cpe_list: list | None = None,
    tls_cert: dict | None = None,
    nmap_scripts: dict | None = None,
) -> uuid.UUID:
    """Upsert a port record for an asset."""
    now = datetime.now(timezone.utc)
    port_id = uuid.uuid4()

    result = await db.execute(
        text("""
            INSERT INTO asset_ports (id, asset_id, port, protocol, service_name, service_version,
                                     banner, cpe_list, tls_cert, nmap_scripts, updated_at)
            VALUES (:id, :asset_id, :port, :proto, :svc_name, :svc_ver, :banner,
                    cast(:cpe as jsonb), cast(:tls as jsonb), cast(:nmap as jsonb), :now)
            ON CONFLICT (asset_id, port, protocol) DO UPDATE SET
                service_name = COALESCE(EXCLUDED.service_name, asset_ports.service_name),
                service_version = COALESCE(EXCLUDED.service_version, asset_ports.service_version),
                banner = COALESCE(EXCLUDED.banner, asset_ports.banner),
                cpe_list = COALESCE(EXCLUDED.cpe_list, asset_ports.cpe_list),
                tls_cert = COALESCE(EXCLUDED.tls_cert, asset_ports.tls_cert),
                nmap_scripts = COALESCE(EXCLUDED.nmap_scripts, asset_ports.nmap_scripts),
                updated_at = EXCLUDED.updated_at
            RETURNING id
        """),
        {
            "id": port_id,
            "asset_id": asset_id,
            "port": port,
            "proto": protocol,
            "svc_name": service_name,
            "svc_ver": service_version,
            "banner": banner,
            "cpe": json.dumps(cpe_list) if cpe_list else None,
            "tls": json.dumps(tls_cert) if tls_cert else None,
            "nmap": json.dumps(nmap_scripts) if nmap_scripts else None,
            "now": now,
        },
    )
    row = result.fetchone()
    return row.id if row else port_id


async def store_tlsx_per_port(
    db: AsyncSession,
    org_id: uuid.UUID,
    tls_results: list[dict],
) -> dict:
    """Store tlsx results per-port in asset_ports, and extract SANs for discovery feedback.

    Returns {"updated": int, "new_sans": list[str]} where new_sans are hostnames
    discovered from certificate SANs that don't yet exist in the asset DB.
    """
    updated = 0
    all_sans: set[str] = set()

    for entry in tls_results:
        host_raw = (entry.get("host") or entry.get("input") or "").strip().lower()
        if not host_raw:
            continue

        # Parse host:port
        if ":" in host_raw:
            hostname, port_str = host_raw.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                hostname = host_raw
                port = 443
        else:
            hostname = host_raw
            port = 443

        # Get asset_id
        row = await db.execute(
            text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
            {"org_id": org_id, "host": hostname},
        )
        asset_row = row.fetchone()
        if not asset_row:
            continue

        tls_cert = {
            "issuer": entry.get("issuer_dn") or entry.get("issuer"),
            "subject": entry.get("subject_dn") or entry.get("subject"),
            "sans": entry.get("san") or entry.get("subject_an") or [],
            "expiry": entry.get("not_after") or entry.get("expired"),
            "cipher": entry.get("cipher"),
            "version": entry.get("tls_version") or entry.get("version"),
        }

        await upsert_asset_port(
            db, asset_row.id, port, tls_cert=tls_cert,
        )

        # Collect SANs
        sans = tls_cert.get("sans") or []
        if isinstance(sans, list):
            for san in sans:
                san = san.strip().lower().lstrip("*.")
                if san and "." in san:
                    all_sans.add(san)

        updated += 1

    # Find SANs that are not yet known assets
    new_sans = []
    if all_sans:
        existing = await db.execute(
            text("SELECT hostname FROM assets WHERE org_id = :org_id AND hostname = ANY(:hosts)"),
            {"org_id": org_id, "hosts": list(all_sans)},
        )
        existing_hosts = {row.hostname for row in existing.fetchall()}
        new_sans = [s for s in all_sans if s not in existing_hosts]

    await db.commit()
    logger.info("org=%s tlsx_per_port updated=%d new_sans=%d", org_id, updated, len(new_sans))
    return {"updated": updated, "new_sans": new_sans}


async def store_httpx_enrichment(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    httpx_entry: dict,
) -> uuid.UUID:
    """Store full httpx JSON output as an AssetEnrichment record."""
    enrichment_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    tech = httpx_entry.get("tech") or httpx_entry.get("technologies")
    cdn_name = httpx_entry.get("cdn_name") or httpx_entry.get("cdn")
    is_cdn = bool(cdn_name)
    final_url = httpx_entry.get("final_url") or httpx_entry.get("location") or httpx_entry.get("url")

    await db.execute(
        text("""
            INSERT INTO asset_enrichments (id, asset_id, httpx_full, final_url, page_title, tech_stack, is_cdn, created_at)
            VALUES (:id, :asset_id, cast(:httpx as jsonb), :final_url, :title, cast(:tech as jsonb), :is_cdn, :now)
        """),
        {
            "id": enrichment_id,
            "asset_id": asset_id,
            "httpx": json.dumps(httpx_entry),
            "final_url": final_url,
            "title": httpx_entry.get("title"),
            "tech": json.dumps(tech) if tech else None,
            "is_cdn": is_cdn,
            "now": now,
        },
    )
    return enrichment_id


async def store_katana_endpoints(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    katana_results: list[dict],
) -> dict:
    """Parse katana output and store discovered endpoints.

    Returns {"endpoints_stored": int, "new_hostnames": list[str], "auth_pages": int}.
    """
    now = datetime.now(timezone.utc)
    stored = 0
    auth_pages = 0
    discovered_hostnames: set[str] = set()

    for entry in katana_results:
        url = entry.get("request", {}).get("endpoint") or entry.get("endpoint") or entry.get("url") or ""
        if not url:
            continue

        method = entry.get("request", {}).get("method") or "GET"

        # Parse URL for path and hostname
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
            endpoint_host = parsed.hostname
        except Exception:
            path = url
            endpoint_host = None

        # Collect new hostnames
        if endpoint_host:
            endpoint_host = endpoint_host.lower()
            discovered_hostnames.add(endpoint_host)

        # Detect auth pages from URL path and form fields
        is_auth = bool(AUTH_INDICATORS.search(url))
        if not is_auth:
            # Check form field names in response body hints
            body = entry.get("response", {}).get("body") or ""
            if AUTH_INDICATORS.search(body):
                is_auth = True

        endpoint_id = uuid.uuid4()
        await db.execute(
            text("""
                INSERT INTO asset_endpoints (id, asset_id, url, path, method, discovered_at, is_auth_page)
                VALUES (:id, :asset_id, :url, :path, :method, :now, :is_auth)
                ON CONFLICT DO NOTHING
            """),
            {
                "id": endpoint_id,
                "asset_id": asset_id,
                "url": url,
                "path": path,
                "method": method,
                "now": now,
                "is_auth": is_auth,
            },
        )
        stored += 1
        if is_auth:
            auth_pages += 1

    # Find new hostnames not in asset DB
    new_hostnames = []
    if discovered_hostnames:
        existing = await db.execute(
            text("SELECT hostname FROM assets WHERE org_id = :org_id AND hostname = ANY(:hosts)"),
            {"org_id": org_id, "hosts": list(discovered_hostnames)},
        )
        existing_hosts = {row.hostname for row in existing.fetchall()}
        new_hostnames = [h for h in discovered_hostnames if h not in existing_hosts]

    await db.commit()
    logger.info(
        "org=%s asset=%s katana: endpoints=%d auth_pages=%d new_hosts=%d",
        org_id, asset_id, stored, auth_pages, len(new_hostnames),
    )
    return {"endpoints_stored": stored, "new_hostnames": new_hostnames, "auth_pages": auth_pages}


async def store_nmap_results(
    db: AsyncSession,
    asset_id: uuid.UUID,
    nmap_host: "NmapHost",
    duration: float,
    timed_out: bool = False,
) -> dict:
    """Store nmap scan results: per-port CPE/service/banner + OS fingerprint.

    nmap_host is a libnmap NmapHost object.
    Returns summary dict.
    """
    now = datetime.now(timezone.utc)
    ports_updated = 0

    # OS fingerprint
    os_fp = None
    if hasattr(nmap_host, "os_fingerprinted") and nmap_host.os_fingerprinted:
        os_matches = nmap_host.os_match_probabilities()
        if os_matches:
            os_fp = os_matches[0].name

    nmap_status = "timeout" if timed_out else "complete"

    await db.execute(
        text("""
            UPDATE assets SET
                os_fingerprint = COALESCE(:os_fp, os_fingerprint),
                nmap_status = :status,
                nmap_last_run = :now
            WHERE id = :id
        """),
        {"os_fp": os_fp, "status": nmap_status, "now": now, "id": asset_id},
    )

    # Per-port results
    for svc in nmap_host.services:
        port = svc.port
        protocol = svc.protocol or "tcp"
        service_name = svc.service or None
        service_version = None
        if svc.service_dict:
            parts = [svc.service_dict.get("product", ""), svc.service_dict.get("version", "")]
            service_version = " ".join(p for p in parts if p).strip() or None

        banner = svc.banner or None
        cpe_list = list(svc.cpelist) if hasattr(svc, "cpelist") and svc.cpelist else None

        # Extract nmap script output
        scripts = {}
        if hasattr(svc, "scripts_results") and svc.scripts_results:
            for script in svc.scripts_results:
                scripts[script.get("id", "unknown")] = script.get("output", "")

        # Extract TLS cert from ssl-cert script
        tls_cert = None
        ssl_cert_output = scripts.get("ssl-cert")
        if ssl_cert_output:
            tls_cert = {"raw": ssl_cert_output}

        await upsert_asset_port(
            db, asset_id, port, protocol,
            service_name=service_name,
            service_version=service_version,
            banner=banner,
            cpe_list=cpe_list,
            tls_cert=tls_cert,
            nmap_scripts=scripts if scripts else None,
        )
        ports_updated += 1

    await db.commit()
    logger.info(
        "asset=%s nmap: status=%s os=%s ports=%d duration=%.1fs",
        asset_id, nmap_status, os_fp, ports_updated, duration,
    )
    return {
        "nmap_status": nmap_status,
        "os_fingerprint": os_fp,
        "ports_updated": ports_updated,
        "duration": duration,
    }
