"""Extension 2: Asset liveness validation gate.

Checks DNS resolution, port response, and HTTP probe to determine
whether assets are alive, unconfirmed, or likely dead.
"""

import json
import logging
import socket
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Known cloud provider IP ranges (CIDR prefixes) for dangling DNS detection.
# This is a simplified check — production should use published IP range files.
CLOUD_PROVIDER_PREFIXES = {
    "aws": [
        "3.", "13.", "15.", "18.", "34.", "35.", "44.", "46.51.", "50.", "52.",
        "54.", "63.", "72.44.", "75.2.", "76.223.", "99.", "100.", "107.",
        "108.", "142.", "143.", "150.", "157.", "160.", "161.", "162.",
        "168.", "170.", "174.", "175.", "176.", "177.", "178.", "184.",
        "185.", "192.0.2.",
    ],
    "gcp": ["34.64.", "34.80.", "34.96.", "34.104.", "34.120.", "34.128.", "35."],
    "azure": [
        "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.",
        "13.70.", "13.71.", "13.72.", "13.73.", "13.74.", "13.75.",
        "13.76.", "13.77.", "13.78.", "13.79.", "13.80.", "13.81.",
        "13.82.", "13.83.", "13.84.", "13.85.", "13.86.", "13.87.",
        "13.88.", "13.89.", "13.90.", "13.91.", "13.92.", "13.93.",
        "20.", "23.", "40.", "51.", "52.", "65.", "70.", "102.", "104.",
        "137.", "138.", "157.", "168.", "191.",
    ],
    "cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
                   "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
                   "172.64.", "172.65.", "172.66.", "172.67.", "173.245.",
                   "188.114.", "190.93.", "197.234.", "198.41."],
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
                       liveness_state, tags
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

        if checks_passed >= 2:
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
) -> uuid.UUID:
    """Create a finding record for dangling DNS / potential subdomain takeover."""
    finding_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    severity = "high" if cloud_provider else "medium"
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
            "finding_type": "dangling_dns",
            "severity": severity,
            "title": title,
            "desc": description,
            "meta": json.dumps({
                "resolved_ips": resolved_ips,
                "cloud_provider": cloud_provider,
                "hostname": hostname,
            }),
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
