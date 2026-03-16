"""
EASM integration service — talks to hakuna-scanner (standalone EASM service).

Responsibilities:
1. On registration: create org + domain in hakuna, trigger discovery scan
2. On demand: import discovered assets into the main platform as a synthetic scan
3. Enrich Nessus-uploaded assets with EASM metadata (ports, tech, certs, CDN/WAF)
"""
import os
import logging
from datetime import datetime
from typing import Optional

import httpx

from sqlalchemy.orm import Session
from models.models import Organization, Scan, Asset

logger = logging.getLogger(__name__)

HAKUNA_BASE_URL = os.getenv("HAKUNA_SCANNER_URL", "http://localhost:8001")
HAKUNA_API = f"{HAKUNA_BASE_URL}/api/v1"

# ── Free email domains (skip EASM for these) ────────────────────────

FREE_EMAIL_DOMAINS = frozenset({
    # Google
    "gmail.com", "googlemail.com",
    # Microsoft
    "outlook.com", "hotmail.com", "live.com", "msn.com", "outlook.co.il",
    # Yahoo
    "yahoo.com", "yahoo.co.uk", "yahoo.co.il", "yahoo.fr", "yahoo.de",
    "yahoo.ca", "yahoo.com.au", "yahoo.co.in", "yahoo.co.jp",
    "ymail.com", "rocketmail.com",
    # Apple
    "icloud.com", "me.com", "mac.com",
    # AOL / Verizon
    "aol.com", "aim.com",
    # ProtonMail
    "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
    # Zoho
    "zoho.com", "zohomail.com",
    # Tutanota
    "tutanota.com", "tutanota.de", "tutamail.com", "tuta.io",
    # GMX / Web.de
    "gmx.com", "gmx.net", "gmx.de", "web.de",
    # Mail.com / Mail.ru
    "mail.com", "email.com", "mail.ru", "inbox.ru", "list.ru", "bk.ru",
    # ISP / Telecom
    "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "cox.net",
    "charter.net", "earthlink.net", "optonline.net", "frontier.com",
    # Regional
    "walla.co.il", "walla.com", "bezeqint.net", "013.net", "netvision.net.il",
    "orange.fr", "free.fr", "laposte.net", "wanadoo.fr",
    "btinternet.com", "virginmedia.com", "sky.com",
    "t-online.de", "arcor.de", "freenet.de",
    # Other
    "fastmail.com", "hushmail.com", "mailfence.com",
    "yandex.com", "yandex.ru",
    "qq.com", "163.com", "126.com", "sina.com",
    "rediffmail.com", "rediff.com",
    "zoho.com",
})


def extract_corporate_domain(email: str) -> Optional[str]:
    """Extract the domain from an email address, returning None if it's a free provider."""
    if not email or "@" not in email:
        return None
    domain = email.rsplit("@", 1)[1].lower().strip()
    if domain in FREE_EMAIL_DOMAINS:
        return None
    return domain


# ── Hakuna-scanner HTTP client ──────────────────────────────────────

async def _hakuna_request(method: str, path: str, **kwargs) -> Optional[dict]:
    """Make a request to hakuna-scanner API. Returns None on failure."""
    url = f"{HAKUNA_API}{path}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as e:
        logger.warning(f"Hakuna API {method} {path} returned {e.response.status_code}: {e.response.text}")
        return None
    except httpx.RequestError as e:
        logger.warning(f"Hakuna API unreachable ({method} {path}): {e}")
        return None


async def create_easm_org(org_name: str) -> Optional[str]:
    """Create an org in hakuna-scanner. Returns the hakuna org UUID or None."""
    data = await _hakuna_request("POST", "/orgs", json={"name": org_name})
    if data:
        return data.get("id")
    return None


async def add_easm_domain(hakuna_org_id: str, domain: str) -> bool:
    """Add a target domain to a hakuna org."""
    data = await _hakuna_request("POST", f"/orgs/{hakuna_org_id}/domains", json={"domain": domain})
    return data is not None


async def trigger_easm_scan(hakuna_org_id: str, scan_type: str = "full") -> Optional[str]:
    """Trigger a scan in hakuna-scanner. Returns scan run ID or None."""
    data = await _hakuna_request("POST", f"/orgs/{hakuna_org_id}/scans", json={"scan_type": scan_type})
    if data:
        return data.get("id")
    return None


async def get_easm_scan_status(hakuna_org_id: str, scan_id: str) -> Optional[dict]:
    """Get the status of an EASM scan run."""
    return await _hakuna_request("GET", f"/orgs/{hakuna_org_id}/scans/{scan_id}")


async def get_easm_assets(hakuna_org_id: str, limit: int = 1000, offset: int = 0) -> Optional[list]:
    """Fetch discovered assets from hakuna-scanner."""
    data = await _hakuna_request("GET", f"/orgs/{hakuna_org_id}/assets", params={"limit": limit, "offset": offset})
    return data if isinstance(data, list) else None


async def get_easm_asset_stats(hakuna_org_id: str) -> Optional[dict]:
    """Get aggregate stats for EASM assets."""
    return await _hakuna_request("GET", f"/orgs/{hakuna_org_id}/assets/stats")


async def get_easm_events(hakuna_org_id: str, since: Optional[str] = None, limit: int = 100) -> Optional[list]:
    """Get recent change events from hakuna-scanner."""
    params = {"limit": limit}
    if since:
        params["since"] = since
    data = await _hakuna_request("GET", f"/orgs/{hakuna_org_id}/events", params=params)
    return data if isinstance(data, list) else None


# ── Registration hook ───────────────────────────────────────────────

async def trigger_easm_for_new_org(db: Session, org: Organization, email: str):
    """
    Called after registration. Extracts corporate domain from email,
    creates hakuna org + domain, triggers full scan.
    Non-blocking — failures are logged but don't break registration.
    """
    domain = extract_corporate_domain(email)
    if not domain:
        logger.info(f"Skipping EASM for org '{org.name}': free/personal email domain")
        return

    logger.info(f"Triggering EASM discovery for org '{org.name}' domain '{domain}'")

    hakuna_org_id = await create_easm_org(org.name)
    if not hakuna_org_id:
        logger.warning(f"Failed to create EASM org for '{org.name}'")
        return

    if not await add_easm_domain(hakuna_org_id, domain):
        logger.warning(f"Failed to add domain '{domain}' to EASM org {hakuna_org_id}")
        return

    scan_id = await trigger_easm_scan(hakuna_org_id)
    if scan_id:
        logger.info(f"EASM scan triggered: org={hakuna_org_id}, scan={scan_id}")
    else:
        logger.warning(f"Failed to trigger EASM scan for org {hakuna_org_id}")

    # Persist hakuna references on the org
    org.easm_org_id = hakuna_org_id
    org.easm_domain = domain
    db.commit()


# ── Asset import (EASM → main platform) ────────────────────────────

async def import_easm_assets(db: Session, org: Organization) -> Optional[dict]:
    """
    Pull EASM-discovered assets from hakuna-scanner and create them as a
    synthetic scan (source_type='easm') in the main platform.

    Returns summary dict or None on failure.
    """
    if not org.easm_org_id:
        return None

    easm_assets = await get_easm_assets(org.easm_org_id)
    if not easm_assets:
        logger.info(f"No EASM assets to import for org '{org.name}'")
        return {"imported": 0}

    # Create synthetic scan record
    scan = Scan(
        org_id=org.id,
        filename=f"easm-discovery-{org.easm_domain}",
        scan_name=f"EASM Discovery — {org.easm_domain}",
        scan_date=datetime.utcnow().isoformat(),
        scan_type="easm_discovery",
        source_type="easm",
        raw_metadata={
            "hakuna_org_id": org.easm_org_id,
            "domain": org.easm_domain,
            "asset_count": len(easm_assets),
        },
    )
    db.add(scan)
    db.flush()

    imported = 0
    for ea in easm_assets:
        hostname = ea.get("hostname", "")
        ip = ea.get("ip", "")
        if not hostname and not ip:
            continue

        # Build FQDN from hostname
        fqdn = hostname if "." in hostname else None

        # Build OS hint from tech_stack if available
        tech = ea.get("tech_stack") or []
        os_hint = None
        if isinstance(tech, list):
            for t in tech:
                tl = t.lower() if isinstance(t, str) else ""
                if any(k in tl for k in ("windows", "linux", "ubuntu", "debian", "centos", "freebsd")):
                    os_hint = t
                    break

        # Map open ports to a summary string
        ports = ea.get("open_ports") or []
        services_data = ea.get("services") or {}

        asset = Asset(
            scan_id=scan.id,
            ip=ip or None,
            hostname=hostname.split(".")[0] if hostname else None,
            fqdn=fqdn,
            os=os_hint,
            is_internet_facing=True,  # EASM assets are external by definition
            environment_tag="external",
            criticality=5,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.add(asset)
        imported += 1

    db.commit()
    logger.info(f"Imported {imported} EASM assets for org '{org.name}' (scan_id={scan.id})")

    return {
        "scan_id": scan.id,
        "imported": imported,
        "domain": org.easm_domain,
    }


# ── EASM enrichment for Nessus assets ──────────────────────────────

async def enrich_assets_from_easm(db: Session, org: Organization, scan_id: int):
    """
    After a Nessus scan is uploaded, match its assets against EASM-discovered
    assets by IP or hostname/FQDN. Enrich matched assets with EASM metadata
    and link them in hakuna-scanner.

    This runs as a post-upload enrichment step.
    """
    if not org.easm_org_id:
        return

    easm_assets = await get_easm_assets(org.easm_org_id)
    if not easm_assets:
        return

    # Build lookup maps from EASM assets
    easm_by_ip = {}
    easm_by_hostname = {}
    for ea in easm_assets:
        if ea.get("ip"):
            easm_by_ip[ea["ip"]] = ea
        if ea.get("hostname"):
            easm_by_hostname[ea["hostname"].lower()] = ea
            # Also index by short hostname
            short = ea["hostname"].split(".")[0].lower()
            if short not in easm_by_hostname:
                easm_by_hostname[short] = ea

    # Match Nessus assets against EASM data
    nessus_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    enriched = 0

    for asset in nessus_assets:
        ea = None

        # Try IP match first
        if asset.ip and asset.ip in easm_by_ip:
            ea = easm_by_ip[asset.ip]

        # Try FQDN match
        if not ea and asset.fqdn:
            ea = easm_by_hostname.get(asset.fqdn.lower())

        # Try hostname match
        if not ea and asset.hostname:
            ea = easm_by_hostname.get(asset.hostname.lower())

        if not ea:
            continue

        # Enrich the Nessus asset with EASM data
        if not asset.fqdn and ea.get("hostname") and "." in ea["hostname"]:
            asset.fqdn = ea["hostname"]

        if not asset.ip and ea.get("ip"):
            asset.ip = ea["ip"]

        # Mark as internet-facing if EASM found it externally
        asset.is_internet_facing = True

        # Store EASM metadata in environment_tag if not already set
        if asset.environment_tag in (None, "internal"):
            asset.environment_tag = "internet-facing"

        enriched += 1

        # Link in hakuna-scanner (fire-and-forget)
        hakuna_asset_id = ea.get("id")
        if hakuna_asset_id:
            await _hakuna_request(
                "POST",
                f"/orgs/{org.easm_org_id}/assets/{hakuna_asset_id}/nessus",
                json={"nessus_asset_id": str(asset.id)},
            )

    if enriched:
        db.commit()
        logger.info(f"EASM-enriched {enriched}/{len(nessus_assets)} assets in scan {scan_id}")
