"""Extension 3 & 4: Ingest functions for deep enrichment and nmap results.

Handles: tlsx per-port cert storage, httpx full JSON enrichment records,
katana endpoint discovery, and nmap fingerprinting results.
"""

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.ingest._jsonb import jsonb_dumps as _jsonb_dumps
from app.ingest.cpe_infer import infer_cpes
from app.ingest.http_header_audit import audit_response

logger = logging.getLogger(__name__)

# Stage 5 of the EASM pipeline: derive CPEs from httpx fingerprints so the
# Nuclei router can target templates. Default-on; flip off via env to bisect.
CPE_INFER_ENABLED = os.environ.get("CPE_INFER_ENABLED", "1").lower() not in {"0", "false", "no"}

# Patterns that suggest an authentication page
AUTH_INDICATORS = re.compile(
    r"(login|signin|sign[_-]in|auth|password|passwd|credential|sso|oauth|"
    r"register|signup|sign[_-]up|forgot|reset[_-]password|mfa|2fa|otp)",
    re.IGNORECASE,
)


# Map from legacy nmap-flavoured ``service_name`` strings to the normalized
# ``service_type`` identifier introduced in migration 017. Kept in sync with
# the backfill mapping in alembic 017_add_service_type so an existing row's
# computed service_type matches what a fresh nmap pass would write.
NMAP_SERVICE_TYPE_MAP: dict[str, str] = {
    "ssh": "ssh",
    "mysql": "mysql",
    "postgresql": "postgres",
    "postgres": "postgres",
    "http": "http",
    "https": "https",
    "ms-wbt-server": "rdp",
    "rdp": "rdp",
    "ipp": "ipp",
    "ajp13": "ajp",
    "ajp": "ajp",
}


def normalize_nmap_service_type(service_name: str | None) -> str | None:
    """Return the normalized service_type for an nmap service_name, or None."""
    if not service_name:
        return None
    return NMAP_SERVICE_TYPE_MAP.get(service_name.strip().lower())


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
    service_type: str | None = None,
    service_product: str | None = None,
    service_confidence: int | None = None,
) -> uuid.UUID:
    """Upsert a port record for an asset.

    ``service_type`` / ``service_product`` / ``service_confidence`` are the
    normalized service-identity columns introduced in migration 017. They
    use higher-confidence-wins semantics (vs. the COALESCE-on-conflict used
    by the rest of the columns): if the existing row already has a
    confidence >= the incoming value, the existing identity is preserved.
    This is what lets a banner-grab probe (confidence 90) overwrite an
    httpx scheme guess (confidence 70) but not vice versa.
    """
    now = datetime.now(timezone.utc)
    port_id = uuid.uuid4()

    result = await db.execute(
        text("""
            INSERT INTO asset_ports (id, asset_id, port, protocol, service_name, service_version,
                                     banner, cpe_list, tls_cert, nmap_scripts,
                                     service_type, service_product, service_confidence,
                                     updated_at)
            VALUES (:id, :asset_id, :port, :proto, :svc_name, :svc_ver, :banner,
                    cast(:cpe as jsonb), cast(:tls as jsonb), cast(:nmap as jsonb),
                    :svc_type, :svc_product, :svc_conf,
                    :now)
            ON CONFLICT (asset_id, port, protocol) DO UPDATE SET
                service_name = COALESCE(EXCLUDED.service_name, asset_ports.service_name),
                service_version = COALESCE(EXCLUDED.service_version, asset_ports.service_version),
                banner = COALESCE(EXCLUDED.banner, asset_ports.banner),
                cpe_list = COALESCE(EXCLUDED.cpe_list, asset_ports.cpe_list),
                tls_cert = COALESCE(EXCLUDED.tls_cert, asset_ports.tls_cert),
                nmap_scripts = COALESCE(EXCLUDED.nmap_scripts, asset_ports.nmap_scripts),
                service_type = CASE
                    WHEN EXCLUDED.service_type IS NULL THEN asset_ports.service_type
                    WHEN asset_ports.service_confidence IS NULL
                         OR EXCLUDED.service_confidence IS NULL THEN
                        COALESCE(EXCLUDED.service_type, asset_ports.service_type)
                    WHEN EXCLUDED.service_confidence >= asset_ports.service_confidence
                        THEN EXCLUDED.service_type
                    ELSE asset_ports.service_type
                END,
                service_product = CASE
                    WHEN EXCLUDED.service_type IS NULL THEN asset_ports.service_product
                    WHEN asset_ports.service_confidence IS NULL
                         OR EXCLUDED.service_confidence IS NULL THEN
                        COALESCE(EXCLUDED.service_product, asset_ports.service_product)
                    WHEN EXCLUDED.service_confidence >= asset_ports.service_confidence
                        THEN COALESCE(EXCLUDED.service_product, asset_ports.service_product)
                    ELSE asset_ports.service_product
                END,
                service_confidence = CASE
                    WHEN EXCLUDED.service_type IS NULL THEN asset_ports.service_confidence
                    WHEN asset_ports.service_confidence IS NULL THEN EXCLUDED.service_confidence
                    WHEN EXCLUDED.service_confidence IS NULL THEN asset_ports.service_confidence
                    ELSE GREATEST(asset_ports.service_confidence, EXCLUDED.service_confidence)
                END,
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
            "cpe": _jsonb_dumps(cpe_list) if cpe_list else None,
            "tls": _jsonb_dumps(tls_cert) if tls_cert else None,
            "nmap": _jsonb_dumps(nmap_scripts) if nmap_scripts else None,
            "svc_type": service_type,
            "svc_product": service_product,
            "svc_conf": service_confidence,
            "now": now,
        },
    )
    row = result.fetchone()
    return row.id if row else port_id


async def upsert_asset_port_http(
    db: AsyncSession,
    asset_id: uuid.UUID,
    port: int,
    *,
    http_status: int | None = None,
    http_title: str | None = None,
    http_url: str | None = None,
    http_webserver: str | None = None,
    http_tech_stack: list | dict | None = None,
    protocol: str = "tcp",
    service_type: str | None = None,
    service_product: str | None = None,
    service_confidence: int | None = None,
) -> None:
    """Write the per-port httpx fingerprint to asset_ports.

    UPSERT (not UPDATE) because tlsx and httpx run in the same parallel
    enrichment group — the port row may not yet exist when httpx finishes
    on a non-TLS port (e.g. an admin UI on 8088). Uses COALESCE-on-conflict
    so a follow-up tlsx write doesn't blow away the HTTP fingerprint and
    vice versa.

    ``service_type`` / ``service_product`` / ``service_confidence`` use the
    same higher-confidence-wins semantics as :func:`upsert_asset_port`: a
    banner-grab probe (confidence 90) writing later won't be clobbered by
    a stale httpx scheme guess (confidence 70) on the next enrichment run.
    """
    now = datetime.now(timezone.utc)
    tech_json = (
        _jsonb_dumps(http_tech_stack)
        if http_tech_stack not in (None, "", [], {})
        else None
    )
    await db.execute(
        text("""
            INSERT INTO asset_ports (
                id, asset_id, port, protocol,
                http_status, http_title, http_url, http_webserver,
                http_tech_stack, last_http_probed_at,
                service_type, service_product, service_confidence,
                updated_at
            )
            VALUES (
                :id, :asset_id, :port, :proto,
                :status, :title, :url, :webserver,
                cast(:tech as jsonb), :now,
                :svc_type, :svc_product, :svc_conf,
                :now
            )
            ON CONFLICT (asset_id, port, protocol) DO UPDATE SET
                http_status = COALESCE(EXCLUDED.http_status, asset_ports.http_status),
                http_title = COALESCE(EXCLUDED.http_title, asset_ports.http_title),
                http_url = COALESCE(EXCLUDED.http_url, asset_ports.http_url),
                http_webserver = COALESCE(EXCLUDED.http_webserver, asset_ports.http_webserver),
                http_tech_stack = COALESCE(EXCLUDED.http_tech_stack, asset_ports.http_tech_stack),
                last_http_probed_at = EXCLUDED.last_http_probed_at,
                service_type = CASE
                    WHEN EXCLUDED.service_type IS NULL THEN asset_ports.service_type
                    WHEN asset_ports.service_confidence IS NULL
                         OR EXCLUDED.service_confidence IS NULL THEN
                        COALESCE(EXCLUDED.service_type, asset_ports.service_type)
                    WHEN EXCLUDED.service_confidence >= asset_ports.service_confidence
                        THEN EXCLUDED.service_type
                    ELSE asset_ports.service_type
                END,
                service_product = CASE
                    WHEN EXCLUDED.service_type IS NULL THEN asset_ports.service_product
                    WHEN asset_ports.service_confidence IS NULL
                         OR EXCLUDED.service_confidence IS NULL THEN
                        COALESCE(EXCLUDED.service_product, asset_ports.service_product)
                    WHEN EXCLUDED.service_confidence >= asset_ports.service_confidence
                        THEN COALESCE(EXCLUDED.service_product, asset_ports.service_product)
                    ELSE asset_ports.service_product
                END,
                service_confidence = CASE
                    WHEN EXCLUDED.service_type IS NULL THEN asset_ports.service_confidence
                    WHEN asset_ports.service_confidence IS NULL THEN EXCLUDED.service_confidence
                    WHEN EXCLUDED.service_confidence IS NULL THEN asset_ports.service_confidence
                    ELSE GREATEST(asset_ports.service_confidence, EXCLUDED.service_confidence)
                END,
                updated_at = EXCLUDED.updated_at
        """),
        {
            "id": uuid.uuid4(),
            "asset_id": asset_id,
            "port": port,
            "proto": protocol,
            "status": http_status,
            "title": http_title,
            "url": http_url,
            "webserver": http_webserver,
            "tech": tech_json,
            "svc_type": service_type,
            "svc_product": service_product,
            "svc_conf": service_confidence,
            "now": now,
        },
    )


async def upsert_asset_port_cpes(
    db: AsyncSession,
    asset_id: uuid.UUID,
    port: int,
    cpe_list: list[str],
    protocol: str = "tcp",
) -> None:
    """Overwrite the cpe_list for a port. Used by the inference layer.

    Distinct from ``upsert_asset_port`` (which uses COALESCE semantics so nmap's
    authoritative CPEs survive subsequent partial updates). Inference is the
    opposite: a rescan that loses a tech fingerprint should drop the stale CPE,
    not preserve it. So this helper writes ``cpe_list = EXCLUDED.cpe_list``
    directly. Inserts a new row if the (asset, port, protocol) tuple is missing.
    """
    if not cpe_list:
        return
    now = datetime.now(timezone.utc)
    await db.execute(
        text("""
            INSERT INTO asset_ports (id, asset_id, port, protocol, cpe_list, updated_at)
            VALUES (:id, :asset_id, :port, :proto, cast(:cpe as jsonb), :now)
            ON CONFLICT (asset_id, port, protocol) DO UPDATE SET
                cpe_list = EXCLUDED.cpe_list,
                updated_at = EXCLUDED.updated_at
        """),
        {
            "id": uuid.uuid4(),
            "asset_id": asset_id,
            "port": port,
            "proto": protocol,
            "cpe": _jsonb_dumps(cpe_list),
            "now": now,
        },
    )


def _httpx_port_for_entry(httpx_entry: dict) -> int | None:
    """Derive the port for a httpx entry. Mirrors assets.py update_enrichment."""
    port = httpx_entry.get("port")
    if port:
        try:
            return int(port)
        except (TypeError, ValueError):
            pass
    url = httpx_entry.get("url") or ""
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


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
    tls_cert: dict | None = None,
    jarm_hash: str | None = None,
) -> uuid.UUID:
    """Store full httpx JSON output as an AssetEnrichment record.

    When ``CPE_INFER_ENABLED`` (default on), also runs the CPE inference layer
    over the httpx entry + optional ``tls_cert`` (looked up by the caller from
    the asset's port records, since tlsx runs before httpx in the chain) +
    optional ``jarm_hash`` (from tlsx -jarm) and writes the resulting CPE list
    onto the matching ``asset_ports`` row.
    """
    enrichment_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    tech = httpx_entry.get("tech") or httpx_entry.get("technologies")
    cdn_name = httpx_entry.get("cdn_name") or httpx_entry.get("cdn")
    is_cdn = bool(cdn_name)
    final_url = httpx_entry.get("final_url") or httpx_entry.get("location") or httpx_entry.get("url")

    # httpx stores screenshot path in the JSON output when -screenshot is used
    screenshot_path = httpx_entry.get("screenshot_path") or httpx_entry.get("screenshot")

    # Header / cookie audit — embedded in httpx_full under `security_audit` so
    # the backend can read posture without a schema change. Never raise:
    # enrichment must not fail on a malformed header dict.
    try:
        httpx_entry = {**httpx_entry, "security_audit": audit_response(httpx_entry)}
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "header_audit failed for asset=%s url=%s: %s",
            asset_id, httpx_entry.get("url"), exc,
        )

    await db.execute(
        text("""
            INSERT INTO asset_enrichments (id, asset_id, httpx_full, final_url, page_title, tech_stack, is_cdn, screenshot_path, created_at)
            VALUES (:id, :asset_id, cast(:httpx as jsonb), :final_url, :title, cast(:tech as jsonb), :is_cdn, :ss_path, :now)
        """),
        {
            "id": enrichment_id,
            "asset_id": asset_id,
            "httpx": _jsonb_dumps(httpx_entry),
            "final_url": final_url,
            "title": httpx_entry.get("title"),
            "tech": _jsonb_dumps(tech) if tech else None,
            "is_cdn": is_cdn,
            "ss_path": screenshot_path,
            "now": now,
        },
    )

    # CPE inference (Stage 5). Hard rule: enrichment must never fail because
    # of inference — every error path swallows and logs.
    if CPE_INFER_ENABLED:
        try:
            result = infer_cpes(httpx_entry, tls_cert, jarm_hash=jarm_hash)
            port = _httpx_port_for_entry(httpx_entry)
            if result.cpe_list and port is not None:
                await upsert_asset_port_cpes(db, asset_id, port, result.cpe_list)
            # Store the full technology profile (including non-software like
            # CDNs, WAFs, analytics) on the enrichment record for UI display.
            if result.detected_technologies:
                await db.execute(
                    text("""
                        UPDATE asset_enrichments
                        SET tech_stack = cast(:tech as jsonb)
                        WHERE id = :eid
                    """),
                    {
                        "eid": enrichment_id,
                        "tech": _jsonb_dumps(result.detected_technologies),
                    },
                )
        except Exception as exc:  # noqa: BLE001 — never block enrichment on inference
            logger.warning(
                "cpe_infer failed for asset=%s url=%s: %s",
                asset_id, httpx_entry.get("url"), exc,
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

        # Promote katana fields into the typed columns added by alembic 010
        # so the planner can rank these endpoints (status 200 + has-body
        # endpoints are higher-signal scan targets than 401/302 surfaces).
        response = entry.get("response") or {}
        headers = response.get("headers") or {}
        status_code = response.get("status_code") or response.get("status")
        content_type = None
        if isinstance(headers, dict):
            for key in ("content-type", "Content-Type", "content_type"):
                if key in headers:
                    content_type = str(headers[key])[:128]
                    break

        endpoint_id = uuid.uuid4()
        await db.execute(
            text("""
                INSERT INTO asset_endpoints (
                    id, asset_id, url, path, method,
                    source, content_type, status_code,
                    discovered_at, is_auth_page
                )
                VALUES (
                    :id, :asset_id, :url, :path, :method,
                    'katana', :content_type, :status_code,
                    :now, :is_auth
                )
                ON CONFLICT (asset_id, url, method, source) DO NOTHING
            """),
            {
                "id": endpoint_id,
                "asset_id": asset_id,
                "url": url,
                "path": path,
                "method": method,
                "content_type": content_type,
                "status_code": int(status_code) if isinstance(status_code, (int, str)) and str(status_code).isdigit() else None,
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

    # Collect UDP open ports for the assets.open_udp_ports denormalization.
    # Populated only when the nmap run included UDP services — a TCP-only
    # run leaves the column untouched (NULL or whatever it was before).
    udp_open: set[int] = set()
    has_udp_results = False
    for svc in nmap_host.services:
        if (svc.protocol or "tcp") == "udp":
            has_udp_results = True
            # nmap UDP marks ports "open|filtered" for the closed default —
            # only count actually-open ones.
            if (svc.state or "").startswith("open") and not svc.state.startswith("open|filtered"):
                udp_open.add(svc.port)

    if has_udp_results:
        await db.execute(
            text("""
                UPDATE assets SET
                    os_fingerprint = COALESCE(:os_fp, os_fingerprint),
                    nmap_status = :status,
                    nmap_last_run = :now,
                    open_udp_ports = :udp_ports
                WHERE id = :id
            """),
            {
                "os_fp": os_fp, "status": nmap_status, "now": now, "id": asset_id,
                "udp_ports": sorted(udp_open),
            },
        )
    else:
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

        # Normalize the nmap service_name into the new service_type column
        # so PR #2 gates can match on identity (e.g. "ssh") rather than port
        # number. Confidence 80 — nmap's service detection is more
        # authoritative than an httpx scheme guess (70) but less than a
        # hand-rolled banner parser (85-90).
        svc_type = normalize_nmap_service_type(service_name)
        await upsert_asset_port(
            db, asset_id, port, protocol,
            service_name=service_name,
            service_version=service_version,
            banner=banner,
            cpe_list=cpe_list,
            tls_cert=tls_cert,
            nmap_scripts=scripts if scripts else None,
            service_type=svc_type,
            service_product=service_version if svc_type else None,
            service_confidence=80 if svc_type else None,
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


# Stage 6: JS library fingerprinting. Default-on; flip off via env to bisect.
JS_FINGERPRINT_ENABLED = os.environ.get("JS_FINGERPRINT_ENABLED", "1").lower() not in {"0", "false", "no"}

# Stage 7: Favicon hash fingerprinting. Default-on.
FAVICON_FINGERPRINT_ENABLED = os.environ.get("FAVICON_FINGERPRINT_ENABLED", "1").lower() not in {"0", "false", "no"}

# Stage 8: Default endpoint probing. Default-on.
ENDPOINT_PROBE_ENABLED = os.environ.get("ENDPOINT_PROBE_ENABLED", "1").lower() not in {"0", "false", "no"}


async def store_js_fingerprints(
    db: AsyncSession,
    org_id: uuid.UUID,
    js_results: dict[str, list[dict]],
) -> dict:
    """Merge JS fingerprint detections into asset_ports.cpe_list.

    js_results: hostname → list of detection dicts from js_fingerprint.fingerprint_assets.
    Each detection has: name, version, cpe_vendor, cpe_product, cpe.

    Merges with existing CPEs (from httpx inference / nmap) rather than
    overwriting, so all sources contribute to the final cpe_list.

    Returns {"assets_updated": int, "cpes_added": int}.
    """
    assets_updated = 0
    cpes_added = 0

    for hostname, detections in js_results.items():
        if not detections:
            continue

        # Find asset.
        row = await db.execute(
            text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
            {"org_id": org_id, "host": hostname},
        )
        asset_row = row.fetchone()
        if not asset_row:
            continue

        asset_id = asset_row.id

        # Determine the port to write CPEs to (prefer 443, then 80).
        port_row = await db.execute(
            text("""
                SELECT port, cpe_list FROM asset_ports
                WHERE asset_id = :aid AND port IN (443, 80, 8443, 8080)
                ORDER BY CASE port WHEN 443 THEN 1 WHEN 80 THEN 2 WHEN 8443 THEN 3 ELSE 4 END
                LIMIT 1
            """),
            {"aid": asset_id},
        )
        existing_port = port_row.fetchone()

        # Merge existing CPEs with new JS detections.
        existing_cpes: list[str] = []
        target_port = 443
        if existing_port:
            target_port = existing_port.port
            existing_cpes = existing_port.cpe_list or []

        # Build set of existing vendor:product for dedup.
        existing_keys: set[str] = set()
        for cpe_str in existing_cpes:
            parts = cpe_str.split(":")
            if len(parts) >= 5:
                existing_keys.add(f"{parts[3]}:{parts[4]}")

        new_cpes = list(existing_cpes)
        added = 0
        for det in detections:
            key = f"{det['cpe_vendor']}:{det['cpe_product']}"
            if key not in existing_keys:
                existing_keys.add(key)
                new_cpes.append(det["cpe"])
                added += 1

        if added > 0:
            await upsert_asset_port_cpes(db, asset_id, target_port, new_cpes)
            assets_updated += 1
            cpes_added += added

    await db.commit()
    logger.info(
        "org=%s js_fingerprint: assets_updated=%d cpes_added=%d",
        org_id, assets_updated, cpes_added,
    )
    return {"assets_updated": assets_updated, "cpes_added": cpes_added}


async def store_favicon_fingerprints(
    db: AsyncSession,
    org_id: uuid.UUID,
    favicon_results: dict[str, list[dict]],
) -> dict:
    """Merge favicon hash detections into asset_ports.cpe_list.

    Same merge strategy as store_js_fingerprints: appends new CPEs without
    overwriting existing ones from other sources.

    Returns {"assets_updated": int, "cpes_added": int}.
    """
    assets_updated = 0
    cpes_added = 0

    for hostname, detections in favicon_results.items():
        if not detections:
            continue

        row = await db.execute(
            text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
            {"org_id": org_id, "host": hostname},
        )
        asset_row = row.fetchone()
        if not asset_row:
            continue

        asset_id = asset_row.id

        port_row = await db.execute(
            text("""
                SELECT port, cpe_list FROM asset_ports
                WHERE asset_id = :aid AND port IN (443, 80, 8443, 8080)
                ORDER BY CASE port WHEN 443 THEN 1 WHEN 80 THEN 2 WHEN 8443 THEN 3 ELSE 4 END
                LIMIT 1
            """),
            {"aid": asset_id},
        )
        existing_port = port_row.fetchone()

        existing_cpes: list[str] = []
        target_port = 443
        if existing_port:
            target_port = existing_port.port
            existing_cpes = existing_port.cpe_list or []

        existing_keys: set[str] = set()
        for cpe_str in existing_cpes:
            parts = cpe_str.split(":")
            if len(parts) >= 5:
                existing_keys.add(f"{parts[3]}:{parts[4]}")

        new_cpes = list(existing_cpes)
        added = 0
        for det in detections:
            key = f"{det['cpe_vendor']}:{det['cpe_product']}"
            if key not in existing_keys:
                existing_keys.add(key)
                new_cpes.append(det["cpe"])
                added += 1

        if added > 0:
            await upsert_asset_port_cpes(db, asset_id, target_port, new_cpes)
            assets_updated += 1
            cpes_added += added

    await db.commit()
    logger.info(
        "org=%s favicon_fingerprint: assets_updated=%d cpes_added=%d",
        org_id, assets_updated, cpes_added,
    )
    return {"assets_updated": assets_updated, "cpes_added": cpes_added}


async def store_endpoint_probe_results(
    db: AsyncSession,
    org_id: uuid.UUID,
    probe_results: dict[str, list[dict]],
) -> dict:
    """Merge endpoint probe detections into asset_ports.cpe_list.

    Same merge strategy as store_js_fingerprints.

    Returns {"assets_updated": int, "cpes_added": int}.
    """
    assets_updated = 0
    cpes_added = 0

    for hostname, detections in probe_results.items():
        if not detections:
            continue

        row = await db.execute(
            text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
            {"org_id": org_id, "host": hostname},
        )
        asset_row = row.fetchone()
        if not asset_row:
            continue

        asset_id = asset_row.id

        port_row = await db.execute(
            text("""
                SELECT port, cpe_list FROM asset_ports
                WHERE asset_id = :aid AND port IN (443, 80, 8443, 8080)
                ORDER BY CASE port WHEN 443 THEN 1 WHEN 80 THEN 2 WHEN 8443 THEN 3 ELSE 4 END
                LIMIT 1
            """),
            {"aid": asset_id},
        )
        existing_port = port_row.fetchone()

        existing_cpes: list[str] = []
        target_port = 443
        if existing_port:
            target_port = existing_port.port
            existing_cpes = existing_port.cpe_list or []

        existing_keys: set[str] = set()
        for cpe_str in existing_cpes:
            parts = cpe_str.split(":")
            if len(parts) >= 5:
                existing_keys.add(f"{parts[3]}:{parts[4]}")

        new_cpes = list(existing_cpes)
        added = 0
        for det in detections:
            key = f"{det['cpe_vendor']}:{det['cpe_product']}"
            if key not in existing_keys:
                existing_keys.add(key)
                new_cpes.append(det["cpe"])
                added += 1

        if added > 0:
            await upsert_asset_port_cpes(db, asset_id, target_port, new_cpes)
            assets_updated += 1
            cpes_added += added

    await db.commit()
    logger.info(
        "org=%s endpoint_probe: assets_updated=%d cpes_added=%d",
        org_id, assets_updated, cpes_added,
    )
    return {"assets_updated": assets_updated, "cpes_added": cpes_added}


async def store_jarm_fingerprints(
    db: AsyncSession,
    org_id: uuid.UUID,
    tls_results: list[dict],
) -> dict:
    """Store JARM hashes from tlsx output onto asset_ports and run CPE inference.

    tlsx -jarm adds a "jarm_hash" field to each JSON line. This function:
    1. Writes the JARM hash into asset_ports.tls_cert (merged with existing cert data).
    2. Runs the JARM → CPE inference layer and merges into cpe_list.

    Returns {"jarm_matched": int, "c2_detected": int}.
    """
    from app.ingest.cpe_infer import _from_jarm, _emit

    jarm_matched = 0
    c2_detected = 0

    for entry in tls_results:
        jarm_hash = entry.get("jarm_hash") or entry.get("jarm") or ""
        if not jarm_hash or jarm_hash.replace("0", "") == "":
            continue

        host_raw = (entry.get("host") or entry.get("input") or "").strip().lower()
        if not host_raw:
            continue

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

        row = await db.execute(
            text("SELECT id FROM assets WHERE org_id = :org_id AND hostname = :host"),
            {"org_id": org_id, "host": hostname},
        )
        asset_row = row.fetchone()
        if not asset_row:
            continue

        # Merge JARM hash into tls_cert JSONB.
        await db.execute(
            text("""
                UPDATE asset_ports SET
                    tls_cert = COALESCE(tls_cert, '{}'::jsonb) || jsonb_build_object('jarm_hash', cast(:jarm AS text)),
                    updated_at = :now
                WHERE asset_id = :aid AND port = :port AND protocol = 'tcp'
            """),
            {
                "aid": asset_row.id,
                "port": port,
                "jarm": jarm_hash,
                "now": datetime.now(timezone.utc),
            },
        )

        # Run JARM CPE inference.
        cpes: list[str] = []
        seen: set[str] = set()
        tags = _from_jarm(jarm_hash, cpes, seen)

        if cpes:
            # Merge with existing CPEs on this port.
            port_row = await db.execute(
                text("SELECT cpe_list FROM asset_ports WHERE asset_id = :aid AND port = :port AND protocol = 'tcp'"),
                {"aid": asset_row.id, "port": port},
            )
            existing = port_row.fetchone()
            existing_cpes = (existing.cpe_list or []) if existing else []

            existing_keys: set[str] = set()
            for cpe_str in existing_cpes:
                parts = cpe_str.split(":")
                if len(parts) >= 5:
                    existing_keys.add(f"{parts[3]}:{parts[4]}")

            merged = list(existing_cpes)
            for cpe in cpes:
                parts = cpe.split(":")
                if len(parts) >= 5:
                    key = f"{parts[3]}:{parts[4]}"
                    if key not in existing_keys:
                        existing_keys.add(key)
                        merged.append(cpe)

            if len(merged) > len(existing_cpes):
                await upsert_asset_port_cpes(db, asset_row.id, port, merged)
                jarm_matched += 1

        if "c2" in tags:
            c2_detected += 1
            # Tag the asset as potential C2.
            await db.execute(
                text("""
                    UPDATE assets SET tags = array_append(
                        array_remove(tags, 'potential_c2'), 'potential_c2'
                    )
                    WHERE id = :aid AND org_id = :org_id
                """),
                {"aid": asset_row.id, "org_id": org_id},
            )

    await db.commit()
    logger.info(
        "org=%s jarm: matched=%d c2_detected=%d",
        org_id, jarm_matched, c2_detected,
    )
    return {"jarm_matched": jarm_matched, "c2_detected": c2_detected}
