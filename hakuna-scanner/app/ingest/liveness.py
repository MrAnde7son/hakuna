"""Extension 2: Asset liveness validation gate.

Checks DNS resolution, port response, and HTTP probe to determine
whether assets are alive, unconfirmed, or likely dead.
"""

import json
import logging
import os
import socket
import uuid
from datetime import datetime, timezone

import aiohttp
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Path to the takeover fingerprint database. Loaded lazily so tests can
# reload it (see `reload_takeover_db`).
_TAKEOVER_DB_PATH = os.path.join(os.path.dirname(__file__), "takeover_fingerprints.json")

# Cap the body read to avoid pulling large pages; the fingerprint strings
# we care about always appear in the first few KB.
_TAKEOVER_MAX_BODY_BYTES = 16_000

# Per-probe HTTP timeout. Short enough that a hundred dangling hosts don't
# stall discovery; long enough to catch slow cloud error pages.
_TAKEOVER_HTTP_TIMEOUT = 5.0

# Known cloud provider IP ranges (CIDR prefixes) for dangling DNS detection.
# This is a simplified check — production should use published IP range files.
#
# Order matters: providers with highly specific prefixes (Cloudflare, GCP)
# are checked before providers with broad prefixes (Azure, AWS) to avoid
# false-positive matches. For example, 104.16.0.0/13 is Cloudflare, but
# Azure also publishes a "104." prefix; we want Cloudflare to win.
CLOUD_PROVIDER_PREFIXES = {
    "cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
                   "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
                   "172.64.", "172.65.", "172.66.", "172.67.", "173.245.",
                   "188.114.", "190.93.", "197.234.", "198.41."],
    "gcp": ["34.64.", "34.80.", "34.96.", "34.104.", "34.120.", "34.128.", "35."],
    "aws": [
        "3.", "13.", "15.", "18.", "34.", "35.", "44.", "46.51.", "50.", "52.",
        "54.", "63.", "72.44.", "75.2.", "76.223.", "99.", "100.", "107.",
        "108.", "142.", "143.", "150.", "157.", "160.", "161.", "162.",
        "168.", "170.", "174.", "175.", "176.", "177.", "178.", "184.",
        "185.", "192.0.2.",
    ],
    "azure": [
        "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.",
        "13.70.", "13.71.", "13.72.", "13.73.", "13.74.", "13.75.",
        "13.76.", "13.77.", "13.78.", "13.79.", "13.80.", "13.81.",
        "13.82.", "13.83.", "13.84.", "13.85.", "13.86.", "13.87.",
        "13.88.", "13.89.", "13.90.", "13.91.", "13.92.", "13.93.",
        "20.", "23.", "40.", "51.", "52.", "65.", "70.", "102.", "104.",
        "137.", "138.", "157.", "168.", "191.",
    ],
}


def identify_cloud_provider(ip: str) -> str | None:
    """Return cloud provider name if IP matches a known range, else None."""
    if not ip:
        return None
    for provider, prefixes in CLOUD_PROVIDER_PREFIXES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                return provider
    return None


def _load_takeover_db() -> list[dict]:
    """Load the takeover fingerprint database from disk."""
    try:
        with open(_TAKEOVER_DB_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("takeover fingerprints: failed to load %s: %s", _TAKEOVER_DB_PATH, exc)
        return []
    return data.get("services", [])


_TAKEOVER_DB: list[dict] = _load_takeover_db()


def reload_takeover_db() -> None:
    """Force-reload the takeover fingerprint DB. For tests."""
    global _TAKEOVER_DB
    _TAKEOVER_DB = _load_takeover_db()


# Severity labels in the JSON are the same strings the Finding table stores,
# but we normalize defensively in case the DB is ever edited.
_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "info": "info",
}


def _match_cname_service(cname_targets: list[str]) -> dict | None:
    """Return the first service entry whose cname_patterns match any target."""
    if not cname_targets or not _TAKEOVER_DB:
        return None
    lowered = [c.lower().rstrip(".") for c in cname_targets if c]
    for service in _TAKEOVER_DB:
        for pattern in service.get("cname_patterns", []):
            pat = pattern.lower()
            for target in lowered:
                if pat in target:
                    return service
    return None


def _match_body_service(status: int, body: str) -> dict | None:
    """Return the first service entry whose http_fingerprints match."""
    if not body or not _TAKEOVER_DB:
        return None
    for service in _TAKEOVER_DB:
        allowed_codes = service.get("status_codes") or []
        if allowed_codes and status not in allowed_codes:
            continue
        for fp in service.get("http_fingerprints", []):
            if fp and fp in body:
                return service
    return None


async def _fetch_probe(url: str, session: aiohttp.ClientSession) -> tuple[int, str] | None:
    """Lightweight GET used only for takeover fingerprinting. Never raises."""
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=_TAKEOVER_HTTP_TIMEOUT),
            allow_redirects=False,
            ssl=False,
        ) as resp:
            raw = await resp.content.read(_TAKEOVER_MAX_BODY_BYTES)
            body = raw.decode("utf-8", errors="replace")
            return resp.status, body
    except Exception:
        return None


async def check_takeover_fingerprint(
    hostname: str,
    cname_targets: list[str] | None = None,
    session: aiohttp.ClientSession | None = None,
) -> dict | None:
    """Probe a dangling hostname for a known takeover fingerprint.

    Strategy:
      1. If the CNAME target matches a known service, that's a strong pre-filter
         — try HTTP and confirm with a body fingerprint. If the body matches,
         return the service entry with the HTTP evidence attached. If the
         body doesn't match (or HTTP fails), fall back to the CNAME-only
         match so we still flag the dangling record.
      2. If no CNAME match, try both http:// and https:// and match body
         fingerprints against any service in the DB.

    Returns a dict augmenting the matched service entry with probe evidence,
    or None if nothing matched. Never raises.
    """
    if not _TAKEOVER_DB:
        return None

    owns_session = session is None
    try:
        if owns_session:
            connector = aiohttp.TCPConnector(limit=5, ssl=False)
            session = aiohttp.ClientSession(
                connector=connector,
                headers={"User-Agent": "Mozilla/5.0 (compatible; HakunaScanner/1.0 takeover-probe)"},
            )

        cname_match = _match_cname_service(cname_targets or [])

        # Always try HTTP + HTTPS to grab a body fingerprint.
        http_result = None
        for scheme in ("https", "http"):
            probe = await _fetch_probe(f"{scheme}://{hostname}", session)
            if probe is not None:
                http_result = (scheme, probe[0], probe[1])
                break

        body_match = None
        if http_result is not None:
            _, status, body = http_result
            body_match = _match_body_service(status, body)

        # Prefer body-fingerprint match (strongest evidence); fall back to
        # CNAME-only match which is still actionable but weaker.
        matched = body_match or cname_match
        if matched is None:
            return None

        severity = _SEVERITY_ALIASES.get(
            str(matched.get("severity", "")).lower(), "high",
        )
        evidence = {
            "service": matched.get("name"),
            "severity": severity,
            "description": matched.get("description", ""),
            "matched_by": "http_fingerprint" if body_match else "cname_pattern",
        }
        if cname_match and cname_match is matched:
            evidence["cname_pattern_matched"] = True
        if http_result is not None:
            scheme, status, body = http_result
            evidence["http_status"] = status
            evidence["http_scheme"] = scheme
            if body_match:
                # Record which fingerprint triggered for downstream triage.
                for fp in body_match.get("http_fingerprints", []):
                    if fp in body:
                        evidence["matched_fingerprint"] = fp
                        break
        return evidence
    finally:
        if owns_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass


def check_dns_resolution(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses. Returns list of IPs or empty list."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list({r[4][0] for r in results})
        return ips
    except (socket.gaierror, OSError):
        return []


async def validate_and_update_assets(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_ids: list[uuid.UUID],
    port_check_results: dict[str, bool],
    http_check_results: dict[str, bool],
) -> dict:
    """Run liveness checks and update asset state.

    DNS resolution is done inline (Python socket). Port and HTTP checks
    are passed in from the caller (Naabu recheck + httpx probe).

    Returns summary dict with counts per state.
    """
    now = datetime.now(timezone.utc)
    summary = {"confirmed_alive": 0, "unconfirmed": 0, "likely_dead": 0, "dangling_dns": 0}

    for asset_id in asset_ids:
        row = await db.execute(
            text("""
                SELECT id, hostname, host(ip) as ip, open_ports, consecutive_failures,
                       liveness_state, tags, cdn_provider
                FROM assets WHERE id = :id AND org_id = :org_id
            """),
            {"id": asset_id, "org_id": org_id},
        )
        asset = row.fetchone()
        if not asset:
            continue

        hostname = asset.hostname
        checks_passed = 0

        # Check 1: DNS resolution
        resolved_ips = check_dns_resolution(hostname)
        dns_ok = len(resolved_ips) > 0
        if dns_ok:
            checks_passed += 1

        # Check 2: Port response (from naabu recheck)
        port_ok = port_check_results.get(hostname, False)
        if port_ok:
            checks_passed += 1

        # Check 3: HTTP probe (from httpx probe)
        http_ok = http_check_results.get(hostname, False)
        if http_ok:
            checks_passed += 1

        # Determine state
        old_failures = asset.consecutive_failures or 0
        tags = list(asset.tags or [])

        # CDN-fronted assets often block raw SYN probes (naabu), so
        # DNS + HTTP is sufficient to confirm liveness.
        is_cdn = bool(asset.cdn_provider) or "cdn" in tags
        threshold = 1 if (is_cdn and dns_ok and http_ok) else 2

        if checks_passed >= threshold:
            new_state = "confirmed_alive"
            new_failures = 0
            summary["confirmed_alive"] += 1
        elif checks_passed == 1:
            new_state = "unconfirmed"
            new_failures = old_failures + 1
            summary["unconfirmed"] += 1
        else:
            new_failures = old_failures + 1
            if new_failures >= 3:
                new_state = "likely_dead"
            else:
                new_state = "unconfirmed"
            summary["likely_dead" if new_state == "likely_dead" else "unconfirmed"] += 1

        # Dangling DNS detection: DNS resolves but no port responds
        is_dangling = dns_ok and not port_ok
        if is_dangling:
            if "dangling_dns" not in tags:
                tags.append("dangling_dns")
            summary["dangling_dns"] += 1

            # Check for cloud provider → potential subdomain takeover
            cloud_provider = None
            for ip in resolved_ips:
                cloud_provider = identify_cloud_provider(ip)
                if cloud_provider:
                    break

            if cloud_provider and "potential_takeover" not in tags:
                tags.append("potential_takeover")
        else:
            # Remove dangling tags if asset is now responding
            tags = [t for t in tags if t not in ("dangling_dns", "potential_takeover")]

        await db.execute(
            text("""
                UPDATE assets SET
                    liveness_state = :state,
                    consecutive_failures = :failures,
                    last_validated_at = :now,
                    tags = :tags
                WHERE id = :id
            """),
            {
                "state": new_state,
                "failures": new_failures,
                "now": now,
                "tags": tags,
                "id": asset_id,
            },
        )

    await db.commit()
    logger.info("org=%s liveness validation: %s", org_id, summary)
    return summary


async def create_dangling_dns_finding(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    hostname: str,
    resolved_ips: list[str],
    cloud_provider: str | None,
    cname_targets: list[str] | None = None,
    session: aiohttp.ClientSession | None = None,
) -> uuid.UUID:
    """Create a finding record for dangling DNS / potential subdomain takeover.

    When CNAME targets are known, attempts a lightweight HTTP probe against
    the hostname and cross-references the response with
    ``takeover_fingerprints.json`` to confirm a specific vulnerable service
    (S3, GitHub Pages, Heroku, etc.). A confirmed fingerprint promotes the
    finding to ``subdomain_takeover`` with severity taken from the fingerprint
    entry. Falls back to the legacy cloud-provider IP-prefix heuristic when
    no fingerprint matches.
    """
    finding_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    # Try fingerprint-based detection first — strongest signal available.
    takeover_evidence: dict | None = None
    try:
        takeover_evidence = await check_takeover_fingerprint(
            hostname, cname_targets=cname_targets, session=session,
        )
    except Exception as exc:
        # Never let probe errors break finding creation.
        logger.debug("takeover fingerprint probe failed for %s: %s", hostname, exc)
        takeover_evidence = None

    if takeover_evidence is not None:
        service_name = takeover_evidence.get("service") or "unknown-service"
        severity = takeover_evidence.get("severity") or "high"
        finding_type = "subdomain_takeover"
        title = f"Subdomain takeover ({service_name}): {hostname}"
        description = (
            f"Hostname {hostname} is vulnerable to subdomain takeover via {service_name}.\n\n"
            f"{takeover_evidence.get('description', '')}"
        ).strip()
        matched_by = takeover_evidence.get("matched_by")
        if matched_by == "http_fingerprint":
            description += (
                f"\n\nConfirmed by HTTP response fingerprint "
                f"(status {takeover_evidence.get('http_status')}): "
                f"'{takeover_evidence.get('matched_fingerprint', '')}'."
            )
        elif matched_by == "cname_pattern":
            description += (
                "\n\nMatched by CNAME target pattern; HTTP body fingerprint was "
                "not conclusive but the CNAME points at an unclaimed provider "
                "endpoint."
            )
        meta = {
            "resolved_ips": resolved_ips,
            "cloud_provider": cloud_provider,
            "hostname": hostname,
            "cname_targets": cname_targets or [],
            "takeover": takeover_evidence,
        }
    else:
        severity = "high" if cloud_provider else "medium"
        finding_type = "dangling_dns"
        title = f"Dangling DNS: {hostname}"
        if cloud_provider:
            title = f"Potential subdomain takeover ({cloud_provider}): {hostname}"

        description = (
            f"Hostname {hostname} resolves to {', '.join(resolved_ips)} but no ports respond. "
            f"This may indicate a dangling DNS record pointing to a decommissioned resource."
        )
        if cloud_provider:
            description += (
                f" The resolved IP belongs to {cloud_provider}, suggesting the underlying "
                f"cloud resource may have been released. An attacker could claim this resource "
                f"and serve content on {hostname}."
            )
        meta = {
            "resolved_ips": resolved_ips,
            "cloud_provider": cloud_provider,
            "hostname": hostname,
            "cname_targets": cname_targets or [],
        }

    await db.execute(
        text("""
            INSERT INTO findings (id, org_id, asset_id, finding_type, severity, title, description, metadata, status, created_at, updated_at)
            VALUES (:id, :org_id, :asset_id, :finding_type, :severity, :title, :desc, cast(:meta as jsonb), 'open', :now, :now)
            ON CONFLICT DO NOTHING
        """),
        {
            "id": finding_id,
            "org_id": org_id,
            "asset_id": asset_id,
            "finding_type": finding_type,
            "severity": severity,
            "title": title,
            "desc": description,
            "meta": json.dumps(meta),
            "now": now,
        },
    )
    return finding_id


async def quarantine_asset(db: AsyncSession, asset_id: uuid.UUID):
    """Move a likely_dead asset to archived/quarantine state."""
    await db.execute(
        text("UPDATE assets SET liveness_state = 'archived' WHERE id = :id AND liveness_state = 'likely_dead'"),
        {"id": asset_id},
    )
