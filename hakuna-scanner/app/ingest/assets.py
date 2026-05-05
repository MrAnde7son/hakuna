"""Normalize tool output → Asset ORM rows via upsert."""

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset

logger = logging.getLogger(__name__)


_UPSERT_BATCH_SIZE = 500


async def upsert_discovered_hosts(
    db: AsyncSession,
    org_id: uuid.UUID,
    hosts: list[dict],
    source: str,
) -> tuple[int, list[uuid.UUID]]:
    """Upsert discovered hostnames into assets table.

    Returns (total_upserted, list_of_new_asset_ids).

    Group 1 of the discovery chain runs subfinder/crtsh/uncover/shodan/
    wildcard_bruteforce concurrently. A per-row UPSERT loop produced
    DeadlockDetectedError when two tasks acquired locks on the same
    (org_id, hostname) rows in opposite order. We collapse each batch
    into one statement (Postgres orders conflict targets internally,
    so a single statement cannot deadlock with itself) and sort the
    rows so two concurrent batches with overlapping hosts also acquire
    locks in the same order.
    """
    if not hosts:
        return 0, []

    now = datetime.now(timezone.utc)

    # Dedupe within the input — Postgres rejects two rows with the same
    # ON CONFLICT target in a single statement. Merge non-null fields
    # so we don't lose data when the same hostname appears twice.
    by_hostname: dict[str, dict] = {}
    for entry in hosts:
        hostname = (entry.get("host") or entry.get("hostname") or "").strip().lower()
        if not hostname:
            continue
        ip = entry.get("ip") or entry.get("a") or entry.get("address") or None
        asn = entry.get("asn") or None
        asn_org = entry.get("asn_org") or entry.get("org") or None
        prev = by_hostname.get(hostname)
        if prev:
            ip = ip or prev["ip"]
            asn = asn or prev["asn"]
            asn_org = asn_org or prev["asn_org"]
        by_hostname[hostname] = {"hostname": hostname, "ip": ip, "asn": asn, "asn_org": asn_org}

    if not by_hostname:
        return 0, []

    # Canonical lock order across concurrent writers.
    records = [by_hostname[h] for h in sorted(by_hostname)]

    new_ids: list[uuid.UUID] = []
    upserted = 0

    for chunk_start in range(0, len(records), _UPSERT_BATCH_SIZE):
        chunk = records[chunk_start : chunk_start + _UPSERT_BATCH_SIZE]
        values_parts: list[str] = []
        params: dict = {"org_id": org_id, "source": source, "now": now}
        for i, rec in enumerate(chunk):
            values_parts.append(
                f"(:id_{i}, :org_id, :h_{i}, CAST(:ip_{i} AS inet), "
                f":asn_{i}, :asn_org_{i}, :source, :now, :now, '{{}}')"
            )
            params[f"id_{i}"] = uuid.uuid4()
            params[f"h_{i}"] = rec["hostname"]
            params[f"ip_{i}"] = rec["ip"]
            params[f"asn_{i}"] = rec["asn"]
            params[f"asn_org_{i}"] = rec["asn_org"]

        sql = (
            "INSERT INTO assets "
            "(id, org_id, hostname, ip, asn, asn_org, source, first_seen, last_seen, tags) "
            f"VALUES {', '.join(values_parts)} "
            "ON CONFLICT (org_id, hostname) DO UPDATE SET "
            "ip = COALESCE(EXCLUDED.ip, assets.ip), "
            "asn = COALESCE(EXCLUDED.asn, assets.asn), "
            "asn_org = COALESCE(EXCLUDED.asn_org, assets.asn_org), "
            "last_seen = EXCLUDED.last_seen "
            "RETURNING id, (xmax = 0) AS is_new"
        )
        result = await db.execute(text(sql), params)
        for row in result.fetchall():
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
    *,
    scanned_hosts: list[str] | None = None,
    failed_hosts: list[str] | None = None,
) -> int:
    """Update open_ports + services + port_scan_state from naabu output.

    ``scanned_hosts`` are the hostnames that were submitted to a
    successful naabu batch — those without entries in ``port_results``
    are marked as scanned-with-zero-ports (open_ports='{}'). ``failed_hosts``
    are hostnames in batches that errored or timed out — they get
    port_scan_state='failed' but their existing open_ports is preserved
    (stale data beats no data while debugging).

    When both lists are None the legacy behavior is preserved (only hosts
    with results are touched). Existing callers that haven't migrated
    keep working.
    """
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
        services_json = json.dumps({str(p): services[p] for p in sorted(services)}) if services else None

        await db.execute(
            text("""
                UPDATE assets SET
                    open_ports = :ports,
                    services = COALESCE(cast(:services as json), services),
                    last_seen = :now,
                    port_scan_state = 'scanned',
                    port_scan_last_at = :now
                WHERE org_id = :org_id AND (hostname = :host OR host(ip) = :host)
            """),
            {"ports": ports, "services": services_json, "org_id": org_id, "host": host, "now": now},
        )
        updated += 1

    # Hosts that were scanned successfully but produced zero results: mark
    # as scanned with an empty port array so callers can distinguish them
    # from never-scanned (NULL) and failed assets.
    if scanned_hosts:
        result_hosts = {h.lower() for h in host_ports.keys()}
        empty_hosts = [h.lower() for h in scanned_hosts if h.lower() not in result_hosts]
        if empty_hosts:
            await db.execute(
                text("""
                    UPDATE assets SET
                        open_ports = ARRAY[]::int[],
                        port_scan_state = 'scanned',
                        port_scan_last_at = :now
                    WHERE org_id = :org_id
                      AND (hostname = ANY(:hosts) OR host(ip) = ANY(:hosts))
                """),
                {"hosts": empty_hosts, "org_id": org_id, "now": now},
            )

    if failed_hosts:
        await db.execute(
            text("""
                UPDATE assets SET
                    port_scan_state = 'failed',
                    port_scan_last_at = :now
                WHERE org_id = :org_id
                  AND (hostname = ANY(:hosts) OR host(ip) = ANY(:hosts))
            """),
            {"hosts": [h.lower() for h in failed_hosts], "org_id": org_id, "now": now},
        )

    await db.commit()
    return updated


async def update_enrichment(
    db: AsyncSession,
    org_id: uuid.UUID,
    httpx_results: list[dict],
) -> int:
    """Update HTTP enrichment data on assets from httpx output.

    Persists per-port fingerprint to asset_ports (so the VM scanner can
    target every web service on a host) and keeps assets.http_url /
    http_status / tech_stack as a "primary" rollup for the asset list UI.
    The primary is the first probed port we see for the asset, with 443
    and 80 preferred over alternates.
    """
    updated = 0
    now = datetime.now(timezone.utc)

    from app.ingest.http_header_audit import audit_response

    # Group entries per asset so we can pick a sensible primary URL
    # (443 > 80 > everything else) without overwriting it with the last-
    # seen entry, which is order-dependent.
    by_host: dict[str, list[dict]] = {}
    for entry in httpx_results:
        host_raw = (entry.get("input") or entry.get("host") or "").strip().lower()
        if not host_raw:
            continue
        # input is "hostname:port" when fan-out is enabled; strip to host.
        host = host_raw.rsplit(":", 1)[0] if ":" in host_raw else host_raw
        by_host.setdefault(host, []).append(entry)

    def _primary_rank(entry: dict) -> tuple[int, int]:
        url = entry.get("url") or ""
        scheme = url.split("://", 1)[0].lower() if "://" in url else ""
        port = entry.get("port")
        if not port:
            port = 443 if scheme == "https" else 80 if scheme == "http" else 0
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = 0
        # Lower rank wins. Preferred order: 443, 80, then ascending port.
        if port == 443:
            return (0, port)
        if port == 80:
            return (1, port)
        return (2, port)

    from app.ingest.enrichment import upsert_asset_port_http

    for host, entries in by_host.items():
        entries_sorted = sorted(entries, key=_primary_rank)

        # Resolve asset_id once per host instead of N times in the per-port
        # write loop below.
        asset_row = await db.execute(
            text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
            {"org_id": org_id, "host": host},
        )
        asset_id_row = asset_row.fetchone()
        if asset_id_row is None:
            # Asset got pruned between scope-build and now — skip.
            continue
        asset_id = asset_id_row.id

        # Per-port writes to asset_ports for every probed entry.
        services_dict: dict[str, dict] = {}
        for entry in entries_sorted:
            url = entry.get("url") or ""
            scheme = url.split("://", 1)[0].lower() if "://" in url else ""
            webserver = entry.get("webserver") or entry.get("web_server") or ""
            port = entry.get("port")
            if not port:
                port = 443 if scheme == "https" else 80 if scheme == "http" else None
            try:
                port = int(port) if port is not None else None
            except (TypeError, ValueError):
                port = None
            if not port:
                continue

            tech_entry = entry.get("tech") or entry.get("technologies")
            status = entry.get("status_code") or entry.get("status-code")

            services_dict[str(port)] = {
                "name": scheme or "http",
                "product": webserver,
                "version": "",
            }

            # Stamp normalized service identity (migration 017) from the
            # URL scheme so PR #2 gates can target every fingerprinted HTTP
            # service, not just 80/443. Confidence 70 — strong enough to
            # win over a stale row but a banner-grab probe (90) wins on
            # the next enrichment pass if there's a richer signal.
            http_svc_type = "https" if scheme == "https" else "http" if scheme == "http" else None

            await upsert_asset_port_http(
                db,
                asset_id,
                port,
                http_status=status,
                http_title=entry.get("title"),
                http_url=url or None,
                http_webserver=webserver or None,
                http_tech_stack=tech_entry,
                service_type=http_svc_type,
                service_product=webserver or None,
                service_confidence=70 if http_svc_type else None,
            )

        # Asset-level rollup uses the first (highest-ranked) entry as the
        # primary URL. Keeps the existing asset list / dashboards pointing
        # at 443/80 when they exist, while the per-port detail lives on
        # asset_ports.
        primary = entries_sorted[0]
        primary_url = primary.get("url") or ""
        primary_tech = primary.get("tech") or primary.get("technologies")
        cdn_name = primary.get("cdn_name") or primary.get("cdn")
        waf = primary.get("waf_name") or primary.get("waf")
        try:
            security_audit = audit_response(primary)
        except Exception:  # noqa: BLE001
            security_audit = None
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
                    services = COALESCE(services::jsonb, '{}'::jsonb) || COALESCE(cast(:services as jsonb), '{}'::jsonb),
                    security_audit = cast(:security as jsonb),
                    last_enriched = :now,
                    last_seen = :now
                WHERE org_id = :org_id AND hostname = :host
            """),
            {
                "status": primary.get("status_code") or primary.get("status-code"),
                "title": primary.get("title"),
                "url": primary_url,
                "tech": json.dumps(primary_tech) if primary_tech else None,
                "cdn": cdn_name if isinstance(cdn_name, str) else (cdn_name[0] if cdn_name else None),
                "waf": waf if isinstance(waf, str) else (waf[0] if waf else None),
                "services": services_json,
                "security": json.dumps(security_audit) if security_audit else None,
                "org_id": org_id,
                "host": host,
                "now": now,
            },
        )
        updated += len(entries_sorted)

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
