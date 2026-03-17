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
from typing import Optional, Tuple

import httpx

from sqlalchemy.orm import Session
from models.models import Organization, Scan, Asset, Finding

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


async def get_easm_domains(hakuna_org_id: str) -> Optional[list]:
    """List target domains for a hakuna org."""
    data = await _hakuna_request("GET", f"/orgs/{hakuna_org_id}/domains")
    return data if isinstance(data, list) else None


async def get_easm_scan_runs(hakuna_org_id: str, limit: int = 20) -> Optional[list]:
    """List recent scan runs for a hakuna org."""
    data = await _hakuna_request("GET", f"/orgs/{hakuna_org_id}/scans", params={"limit": limit})
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

def _build_easm_data(ea: dict) -> dict:
    """Build the easm_data blob from a hakuna-scanner asset."""
    return {
        "easm_asset_id": ea.get("id"),
        "tech_stack": ea.get("tech_stack") or [],
        "open_ports": ea.get("open_ports") or [],
        "services": ea.get("services") or {},
        "tls_cert": ea.get("tls_cert") or {},
        "cdn_provider": ea.get("cdn_provider"),
        "waf": ea.get("waf"),
        "dns_records": ea.get("dns_records") or {},
        "http_status": ea.get("http_status"),
        "http_title": ea.get("http_title"),
        "http_url": ea.get("http_url"),
        "easm_tags": ea.get("tags") or [],
        "easm_source": ea.get("source"),
        "first_seen_easm": ea.get("first_seen"),
        "last_seen_easm": ea.get("last_seen"),
        "last_enriched_easm": ea.get("last_enriched"),
    }


# ── EASM finding definitions ───────────────────────────────────────

SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _generate_easm_findings(db: Session, scan_id: int, asset: Asset, ea: dict) -> int:
    """Generate one finding per EASM observation. Idempotent: skips existing plugin_id+asset combos."""
    now = datetime.utcnow()
    hostname = ea.get("hostname", "")

    # Collect existing plugin_ids for this asset to skip duplicates
    existing_plugins = set()
    for f in db.query(Finding.plugin_id).filter(
        Finding.scan_id == scan_id,
        Finding.asset_id == asset.id,
        Finding.source_type == "easm",
    ).all():
        existing_plugins.add(f.plugin_id)

    findings_to_add = []

    # ── Tech stack: one finding per technology ─────────────────────
    for tech_name in (ea.get("tech_stack") or []):
        pid = f"EASM-TECH-{tech_name.upper().replace(' ', '-')}"
        if pid in existing_plugins:
            continue
        # Check for versioned tech — old versions get higher priority
        tech_priority = 1.0
        effort = "quick_win"
        if ":" in tech_name:
            tech_priority = 2.5  # versioned tech = worth reviewing
            effort = "medium"
        findings_to_add.append(Finding(
            scan_id=scan_id, asset_id=asset.id,
            source_type="easm", source_vuln_id=pid,
            plugin_id=pid,
            plugin_name=f"{tech_name} Detected",
            plugin_family="EASM: Web Technology",
            severity=0, severity_label="Info", risk_factor="None",
            priority_score=tech_priority, effort_level=effort,
            owner_suggestion="SecOps",
            synopsis=f"The web technology '{tech_name}' was detected on {hostname}.",
            description=f"External attack surface scanning identified that {hostname} is running {tech_name}. "
                        f"This information was gathered via HTTP response analysis.",
            solution="No action required. Review if this technology should be publicly exposed.",
            plugin_output=f"Detected technology: {tech_name}\nHost: {hostname}",
            first_seen=now, last_seen=now,
        ))

    # ── Open ports: one finding per port ──────────────────────────
    services = ea.get("services") or {}
    for port in (ea.get("open_ports") or []):
        pid = f"EASM-PORT-{port}"
        if pid in existing_plugins:
            # Update last_seen on existing port finding
            db.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.asset_id == asset.id,
                Finding.plugin_id == pid,
            ).update({"last_seen": now})
            continue
        svc = services.get(str(port), {})
        svc_name = svc.get("name", "unknown") if svc else "unknown"
        svc_detail = f"{svc.get('product', '')} {svc.get('version', '')}".strip() if svc else ""
        output_lines = [f"Port: {port}/tcp", f"State: open", f"Service: {svc_name}"]
        if svc_detail:
            output_lines.append(f"Product: {svc_detail}")
        # Non-standard ports get higher priority
        standard_ports = {80, 443, 22, 25, 53}
        port_int = int(port) if isinstance(port, str) else port
        port_priority = 2.0 if port_int not in standard_ports else 1.0
        findings_to_add.append(Finding(
            scan_id=scan_id, asset_id=asset.id,
            source_type="easm", source_vuln_id=pid,
            plugin_id=pid,
            plugin_name=f"Open Port: {port}/tcp ({svc_name})",
            plugin_family="EASM: Port Scan",
            severity=0, severity_label="Info", risk_factor="None",
            priority_score=port_priority, effort_level="quick_win",
            owner_suggestion="IT",
            port=str(port), protocol="tcp",
            synopsis=f"Port {port}/tcp is open on {hostname}.",
            description=f"External port scanning identified that {hostname} has port {port}/tcp open "
                        f"with service '{svc_name}'. This port is reachable from the internet.",
            solution="Review if this port needs to be publicly accessible. Close unnecessary ports.",
            plugin_output="\n".join(output_lines),
            first_seen=now, last_seen=now,
        ))

    # ── TLS certificate ───────────────────────────────────────────
    cert = ea.get("tls_cert") or {}
    if cert.get("expiry"):
        pid = "EASM-TLS-CERT"
        expiry_str = cert["expiry"]
        try:
            expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            days_left = (expiry.replace(tzinfo=None) - datetime.utcnow()).days
        except (ValueError, AttributeError):
            expiry = None
            days_left = None

        # Severity based on expiry
        if days_left is not None and days_left < 0:
            sev, sev_label, risk = 4, "Critical", "Critical"
        elif days_left is not None and days_left < 30:
            sev, sev_label, risk = 3, "High", "High"
        elif days_left is not None and days_left < 90:
            sev, sev_label, risk = 2, "Medium", "Medium"
        else:
            sev, sev_label, risk = 0, "Info", "None"

        # Priority based on cert urgency
        if days_left is not None and days_left < 0:
            tls_priority = 9.0
            tls_effort = "medium"
        elif days_left is not None and days_left < 30:
            tls_priority = 7.0
            tls_effort = "medium"
        elif days_left is not None and days_left < 90:
            tls_priority = 4.0
            tls_effort = "quick_win"
        else:
            tls_priority = 1.0
            tls_effort = "quick_win"

        if pid in existing_plugins:
            # Update severity — cert may have moved from info to expiring
            db.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.asset_id == asset.id,
                Finding.plugin_id == pid,
            ).update({
                "severity": sev, "severity_label": sev_label, "risk_factor": risk,
                "priority_score": tls_priority, "effort_level": tls_effort,
                "last_seen": now,
                "plugin_output": _build_tls_output(hostname, cert, days_left),
            })
        else:
            findings_to_add.append(Finding(
                scan_id=scan_id, asset_id=asset.id,
                source_type="easm", source_vuln_id=pid,
                plugin_id=pid,
                plugin_name="TLS Certificate" if sev == 0 else (
                    "TLS Certificate Expired" if days_left < 0 else "TLS Certificate Expiring Soon"
                ),
                plugin_family="EASM: TLS/SSL",
                severity=sev, severity_label=sev_label, risk_factor=risk,
                priority_score=tls_priority, effort_level=tls_effort,
                owner_suggestion="IT",
                synopsis=f"TLS certificate for {hostname} — {'expired' if days_left is not None and days_left < 0 else f'{days_left} days remaining' if days_left is not None else 'unknown expiry'}.",
                description=f"External TLS inspection of {hostname} revealed certificate details. "
                            f"Issuer: {cert.get('issuer', 'unknown')}. "
                            f"Subject: {cert.get('subject', 'unknown')}.",
                solution="Renew the certificate before expiry." if sev > 0 else "No action required.",
                plugin_output=_build_tls_output(hostname, cert, days_left),
                first_seen=now, last_seen=now,
            ))

    # ── CDN detection ─────────────────────────────────────────────
    cdn = ea.get("cdn_provider")
    if cdn:
        pid = f"EASM-CDN-{cdn.upper().replace(' ', '-')}"
        if pid not in existing_plugins:
            findings_to_add.append(Finding(
                scan_id=scan_id, asset_id=asset.id,
                source_type="easm", source_vuln_id=pid,
                plugin_id=pid,
                plugin_name=f"CDN Detected: {cdn}",
                plugin_family="EASM: Infrastructure",
                severity=0, severity_label="Info", risk_factor="None",
                priority_score=0.5, effort_level="quick_win", owner_suggestion="IT",
                synopsis=f"{hostname} is behind CDN provider '{cdn}'.",
                description=f"External scanning detected that {hostname} routes traffic through {cdn} CDN. "
                            f"This means the origin server IP may be hidden behind CDN infrastructure.",
                solution="No action required. Ensure CDN configuration is properly secured.",
                plugin_output=f"CDN Provider: {cdn}\nHost: {hostname}",
                first_seen=now, last_seen=now,
            ))

    # ── WAF detection ─────────────────────────────────────────────
    waf = ea.get("waf")
    if waf:
        pid = f"EASM-WAF-{waf.upper().replace(' ', '-')}"
        if pid not in existing_plugins:
            findings_to_add.append(Finding(
                scan_id=scan_id, asset_id=asset.id,
                source_type="easm", source_vuln_id=pid,
                plugin_id=pid,
                plugin_name=f"WAF Detected: {waf}",
                plugin_family="EASM: Infrastructure",
                severity=0, severity_label="Info", risk_factor="None",
                priority_score=0.5, effort_level="quick_win", owner_suggestion="SecOps",
                synopsis=f"{hostname} is protected by WAF '{waf}'.",
                description=f"External scanning detected that {hostname} is protected by the {waf} web application firewall.",
                solution="No action required. Ensure WAF rules are kept up to date.",
                plugin_output=f"WAF: {waf}\nHost: {hostname}",
                first_seen=now, last_seen=now,
            ))

    # ── HTTP service ──────────────────────────────────────────────
    http_status = ea.get("http_status")
    if http_status is not None:
        pid = "EASM-HTTP-SERVICE"
        http_title = ea.get("http_title") or ""
        http_url = ea.get("http_url") or ""
        if pid not in existing_plugins:
            findings_to_add.append(Finding(
                scan_id=scan_id, asset_id=asset.id,
                source_type="easm", source_vuln_id=pid,
                plugin_id=pid,
                plugin_name=f"HTTP Service Detected ({http_status})",
                plugin_family="EASM: Web Service",
                severity=0, severity_label="Info", risk_factor="None",
                priority_score=1.0, effort_level="quick_win", owner_suggestion="IT",
                port="443" if http_url.startswith("https") else "80", protocol="tcp",
                synopsis=f"HTTP service detected on {hostname}.",
                description=f"External HTTP probing of {hostname} returned status {http_status}.",
                solution="No action required. Verify the service should be publicly accessible.",
                plugin_output=f"URL: {http_url}\nStatus: {http_status}\nTitle: {http_title}",
                first_seen=now, last_seen=now,
            ))
        else:
            db.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.asset_id == asset.id,
                Finding.plugin_id == pid,
            ).update({
                "last_seen": now,
                "plugin_output": f"URL: {http_url}\nStatus: {http_status}\nTitle: {http_title}",
            })

    # ── DNS records ───────────────────────────────────────────────
    dns = ea.get("dns_records") or {}
    if dns:
        pid = "EASM-DNS-RECORDS"
        if pid not in existing_plugins:
            output_lines = [f"Host: {hostname}"]
            for rtype, values in dns.items():
                if isinstance(values, list):
                    for v in values:
                        output_lines.append(f"  {rtype}: {v}")
                else:
                    output_lines.append(f"  {rtype}: {values}")
            findings_to_add.append(Finding(
                scan_id=scan_id, asset_id=asset.id,
                source_type="easm", source_vuln_id=pid,
                plugin_id=pid,
                plugin_name="DNS Records",
                plugin_family="EASM: DNS",
                severity=0, severity_label="Info", risk_factor="None",
                priority_score=0.5, effort_level="quick_win", owner_suggestion="IT",
                synopsis=f"DNS records for {hostname}.",
                description=f"External DNS resolution for {hostname} returned the following records.",
                solution="No action required. Review DNS records for accuracy.",
                plugin_output="\n".join(output_lines),
                first_seen=now, last_seen=now,
            ))

    db.add_all(findings_to_add)
    return len(findings_to_add)


def _build_tls_output(hostname: str, cert: dict, days_left: Optional[int]) -> str:
    lines = [f"Host: {hostname}"]
    if cert.get("subject"):
        lines.append(f"Subject: {cert['subject']}")
    if cert.get("issuer"):
        lines.append(f"Issuer: {cert['issuer']}")
    if cert.get("sans"):
        sans = cert["sans"] if isinstance(cert["sans"], list) else [cert["sans"]]
        lines.append(f"SANs: {', '.join(sans)}")
    if cert.get("expiry"):
        lines.append(f"Expiry: {cert['expiry']}")
    if days_left is not None:
        lines.append(f"Days remaining: {days_left}")
    if cert.get("version"):
        lines.append(f"TLS Version: {cert['version']}")
    if cert.get("cipher"):
        lines.append(f"Cipher: {cert['cipher']}")
    return "\n".join(lines)


def _find_existing_easm_scan(db: Session, org: Organization, domain: str) -> Optional[Scan]:
    """Find an existing EASM scan for this org+domain to reuse on rescan."""
    scans = db.query(Scan).filter(
        Scan.org_id == org.id,
        Scan.source_type == "easm",
    ).all()
    for s in scans:
        meta = s.raw_metadata or {}
        if meta.get("domain") == domain:
            return s
    return None


def _create_easm_scan(db: Session, org: Organization, domain: str, scan_type: str = "full") -> Scan:
    """Create a new EASM scan record for a specific domain."""
    now = datetime.utcnow()
    label = scan_type.replace("_", " ").title()
    scan = Scan(
        org_id=org.id,
        filename=f"easm-{scan_type}-{domain}-{now.strftime('%Y%m%d-%H%M%S')}",
        scan_name=f"EASM {label} — {domain}",
        scan_date=now.isoformat(),
        scan_type=f"easm_{scan_type}",
        source_type="easm",
        raw_metadata={
            "hakuna_org_id": org.easm_org_id,
            "domain": domain,
            "scan_type": scan_type,
        },
    )
    db.add(scan)
    db.flush()
    return scan


def _import_assets_for_domain(
    db: Session, scan: Scan, easm_assets: list, domain: str,
) -> Tuple[int, int]:
    """Import assets belonging to a specific domain into a scan. Returns (created, findings_created)."""
    created = 0
    findings_created = 0
    now = datetime.utcnow()

    for ea in easm_assets:
        hostname = ea.get("hostname", "")
        ip = ea.get("ip", "")
        if not hostname and not ip:
            continue

        # Filter: only assets whose hostname ends with this domain
        if hostname and not hostname.lower().endswith(domain.lower()):
            continue

        fqdn = hostname if "." in hostname else None
        easm_data = _build_easm_data(ea)

        # Try OS detection from tech stack
        tech = ea.get("tech_stack") or []
        os_hint = None
        if isinstance(tech, list):
            for t in tech:
                tl = t.lower() if isinstance(t, str) else ""
                if any(k in tl for k in ("windows", "linux", "ubuntu", "debian", "centos", "freebsd")):
                    os_hint = t
                    break

        asset = Asset(
            scan_id=scan.id,
            ip=ip or None,
            hostname=hostname.split(".")[0] if hostname else None,
            fqdn=fqdn,
            os=os_hint,
            is_internet_facing=True,
            environment_tag="external",
            criticality=5,
            first_seen=now,
            last_seen=now,
            easm_data=easm_data,
        )
        db.add(asset)
        db.flush()
        created += 1

        findings_created += _generate_easm_findings(db, scan.id, asset, ea)

    return created, findings_created


async def import_easm_assets_for_domain(
    db: Session, org: Organization, domain: str, scan_type: str = "full",
) -> Optional[dict]:
    """
    Import EASM-discovered assets for a single domain into a new scan record.
    Each domain scan is its own row in the scan list.
    """
    if not org.easm_org_id:
        return None

    easm_assets = await get_easm_assets(org.easm_org_id) or []

    scan = _create_easm_scan(db, org, domain, scan_type)
    created, findings_created = _import_assets_for_domain(db, scan, easm_assets, domain)

    # Update scan metadata
    now = datetime.utcnow()
    scan.raw_metadata = {
        "hakuna_org_id": org.easm_org_id,
        "domain": domain,
        "scan_type": scan_type,
        "asset_count": created,
        "last_sync": now.isoformat(),
    }

    # Update asset severity counts
    for a in db.query(Asset).filter(Asset.scan_id == scan.id).all():
        counts = {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
        for f in db.query(Finding.severity).filter(Finding.asset_id == a.id).all():
            key = {4: "critical_count", 3: "high_count", 2: "medium_count", 1: "low_count", 0: "info_count"}.get(f.severity, "info_count")
            counts[key] += 1
        for k, v in counts.items():
            setattr(a, k, v)

    db.commit()
    logger.info(f"EASM scan for '{domain}': assets={created}, findings={findings_created} (scan_id={scan.id})")

    return {
        "scan_id": scan.id,
        "created": created,
        "findings_created": findings_created,
        "domain": domain,
    }


async def scan_domain(
    db: Session, org: Organization, domain: str, scan_type: str = "full",
) -> Optional[dict]:
    """
    Full flow: add domain to hakuna (idempotent), trigger scan,
    reuse existing scan record or create one marked as 'running'.
    Assets are imported later when the scan completes (via refresh_easm_scan).
    """
    if not org.easm_org_id:
        return None

    # Ensure domain is registered in hakuna (idempotent)
    await add_easm_domain(org.easm_org_id, domain)

    # Trigger scan in hakuna
    run_id = await trigger_easm_scan(org.easm_org_id, scan_type)

    # Reuse existing EASM scan for this domain, or create a new one
    scan = _find_existing_easm_scan(db, org, domain)
    if scan:
        # Keep old assets/findings visible until the new scan completes
        now = datetime.utcnow()
        scan.scan_date = now.isoformat()
        scan.created_at = now
        scan.raw_metadata = {
            "hakuna_org_id": org.easm_org_id,
            "domain": domain,
            "scan_type": scan_type,
            "run_id": run_id,
            "status": "running" if run_id else "failed",
        }
    else:
        scan = _create_easm_scan(db, org, domain, scan_type)
        scan.raw_metadata = {
            **scan.raw_metadata,
            "run_id": run_id,
            "status": "running" if run_id else "failed",
        }
    db.commit()

    return {
        "scan_id": scan.id,
        "run_id": run_id,
        "domain": domain,
        "status": "running" if run_id else "failed",
    }


async def refresh_easm_scan(db: Session, org: Organization, scan_id: int) -> Optional[dict]:
    """
    Check hakuna scan status. If completed, import assets into the scan record.
    Returns updated status.
    """
    if not org.easm_org_id:
        return None

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.source_type == "easm").first()
    if not scan:
        return None

    meta = scan.raw_metadata or {}
    run_id = meta.get("run_id")
    domain = meta.get("domain")
    current_status = meta.get("status")

    # Already completed — nothing to do
    if current_status == "completed":
        return {"scan_id": scan.id, "status": "completed", "domain": domain}

    # Check status in hakuna
    if run_id:
        run_status = await get_easm_scan_status(org.easm_org_id, run_id)
        hakuna_status = (run_status or {}).get("status", "unknown")
    else:
        hakuna_status = "failed"

    # Map hakuna statuses
    if hakuna_status in ("completed", "done"):
        # Clear old assets/findings before importing fresh results
        db.query(Finding).filter(Finding.asset_id.in_(
            db.query(Asset.id).filter(Asset.scan_id == scan.id)
        )).delete(synchronize_session=False)
        db.query(Asset).filter(Asset.scan_id == scan.id).delete(synchronize_session=False)

        # Import assets now that scan is done
        easm_assets = await get_easm_assets(org.easm_org_id) or []
        created, findings_created = _import_assets_for_domain(db, scan, easm_assets, domain)

        now = datetime.utcnow()
        scan.raw_metadata = {
            **meta,
            "status": "completed",
            "asset_count": created,
            "last_sync": now.isoformat(),
        }

        # Update asset severity counts
        for a in db.query(Asset).filter(Asset.scan_id == scan.id).all():
            counts = {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
            for f in db.query(Finding.severity).filter(Finding.asset_id == a.id).all():
                key = {4: "critical_count", 3: "high_count", 2: "medium_count", 1: "low_count", 0: "info_count"}.get(f.severity, "info_count")
                counts[key] += 1
            for k, v in counts.items():
                setattr(a, k, v)

        db.commit()
        logger.info(f"EASM scan completed for '{domain}': assets={created}, findings={findings_created} (scan_id={scan.id})")

        return {"scan_id": scan.id, "status": "completed", "created": created, "findings_created": findings_created, "domain": domain}

    elif hakuna_status in ("failed", "error"):
        scan.raw_metadata = {**meta, "status": "failed"}
        db.commit()
        return {"scan_id": scan.id, "status": "failed", "domain": domain}

    else:
        # Still running/queued
        status = "running" if hakuna_status == "running" else hakuna_status
        scan.raw_metadata = {**meta, "status": status}
        db.commit()
        return {"scan_id": scan.id, "status": status, "domain": domain}


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

        # Store full EASM enrichment data
        asset.easm_data = _build_easm_data(ea)

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
