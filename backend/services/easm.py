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

from sqlalchemy import func as sqlfunc, text as sa_text
from sqlalchemy.orm import Session
from models.models import (
    Organization, Scan, Asset, Finding,
    AutomateClick, FindingOwnership, CampaignFinding, SBOMVulnerability,
)

from apscheduler.triggers.cron import CronTrigger
from services.asset_observations import record_observation

logger = logging.getLogger(__name__)

HAKUNA_BASE_URL = os.getenv("HAKUNA_SCANNER_URL", "http://localhost:8001")


# ── Shared HTTP client for scanner calls ────────────────────────────
#
# Historical behavior (before 2026-04): every call to the scanner instantiated
# a fresh `httpx.AsyncClient`, which paid a TCP handshake + new connection
# pool setup per request. On orgs with active UI polling (scan-runs, status,
# domains refreshed every few seconds) this added ~100-300ms per call and
# made the backend brittle to scanner restarts — any in-flight connection
# would surface as `httpx.ReadError('')` because the per-call client had no
# retry policy and nothing to reuse.
#
# Now: a single module-level `AsyncClient` is created lazily on first use
# (you can't construct one at import time because httpx wants an event loop),
# and every call reuses its connection pool. Transient errors get one retry
# via `_hakuna_request_detailed` below.
_hakuna_client: Optional[httpx.AsyncClient] = None


def _get_hakuna_client() -> httpx.AsyncClient:
    """Return the module-level shared AsyncClient, constructing it lazily.

    Safe to call from any async context; the first call creates it and
    subsequent calls reuse the same instance (and connection pool).
    """
    global _hakuna_client
    if _hakuna_client is None:
        _hakuna_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=5.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
    return _hakuna_client


async def close_hakuna_client() -> None:
    """Close the shared client. Call from FastAPI's shutdown hook.

    Not strictly required — AsyncClient cleans up its transport when
    garbage-collected — but pairing an explicit close with the app lifecycle
    keeps logs quiet on graceful shutdown.
    """
    global _hakuna_client
    if _hakuna_client is not None:
        try:
            await _hakuna_client.aclose()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass
        _hakuna_client = None


def _extract_core_name(name: str) -> list[str]:
    """Extract candidate domain names from a company name.

    Returns multiple candidates: full name and stripped name.
    'Vulcan Cyber Ltd' → ['vulcancyber', 'vulcan']
    'Bit Discovery, Inc.' → ['bitdiscovery']
    """
    import re
    core = name.lower()
    # Remove legal suffixes
    for suffix in (", inc.", ", inc", " inc.", " inc", " ltd.", " ltd", " llc",
                   " sas", " gmbh", " ag", " plc", " limited", " corp.", " corp"):
        core = core.replace(suffix, "")
    core = re.sub(r"[^a-z0-9\s]", "", core).strip()

    full = core.replace(" ", "")
    # Also try without generic words
    stripped = core
    for word in ("security", "cyber", "networks", "network", "technologies",
                 "technology", "solutions", "systems", "software", "labs"):
        stripped = stripped.replace(word, "")
    stripped = stripped.strip().replace(" ", "")

    candidates = [full]
    if stripped and stripped != full and len(stripped) >= 3:
        candidates.append(stripped)
    return candidates


def _associate_subsidiary_domains(db: Session, org_id: int):
    """Match subsidiary names to domains via DNS probing.

    For each subsidiary without domains, tries {name}.com and {name}.io
    via DNS resolution. Also matches against EASM-discovered hostnames.
    """
    import socket
    from models.threat_intel_models import CorporateEntity

    subs = db.query(CorporateEntity).filter(
        CorporateEntity.org_id == org_id,
        CorporateEntity.direct_parent_lei.isnot(None),
    ).all()

    if not subs:
        return

    # Get EASM hostnames for cross-matching
    easm_scans = db.query(Scan).filter(Scan.source_type == "easm").all()
    easm_domains = set()
    for scan in easm_scans:
        d = (scan.raw_metadata or {}).get("domain")
        if d:
            easm_domains.add(d.lower())
    easm_assets = db.query(Asset.fqdn).filter(
        Asset.scan_id.in_([s.id for s in easm_scans]),
        Asset.fqdn.isnot(None),
    ).all()
    all_hostnames = {a[0].lower() for a in easm_assets if a[0]}

    updated = 0
    for sub in subs:
        if sub.associated_domains:
            continue

        candidates = _extract_core_name(sub.legal_name or "")
        if not candidates:
            continue

        matched = []

        # 1. Match against EASM-discovered domains/hostnames
        for core in candidates:
            for d in easm_domains:
                if core in d.split(".")[0] or d.split(".")[0] in core:
                    if d not in matched:
                        matched.append(d)
            for h in all_hostnames:
                root = ".".join(h.split(".")[-2:])
                if core in root.split(".")[0]:
                    if root not in matched:
                        matched.append(root)

        # 2. DNS probe: try {name}.com and {name}.io for each candidate
        if not matched:
            for core in candidates:
                for tld in (".com", ".io"):
                    candidate = core + tld
                    try:
                        socket.getaddrinfo(candidate, None, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
                        matched.append(candidate)
                        break  # one hit per candidate is enough
                    except socket.gaierror:
                        continue
                if matched:
                    break

        if matched:
            sub.associated_domains = list(set(matched))
            updated += 1

    # Also associate EASM domains with root (parent) entities
    roots = db.query(CorporateEntity).filter(
        CorporateEntity.org_id == org_id,
        CorporateEntity.direct_parent_lei.is_(None),
    ).all()
    for root in roots:
        if root.associated_domains:
            continue
        core_candidates = _extract_core_name(root.legal_name or "")
        for core in core_candidates:
            for d in easm_domains:
                if core in d.split(".")[0] or d.split(".")[0] in core:
                    root.associated_domains = [d]
                    updated += 1
                    break
            if root.associated_domains:
                break

    if updated:
        db.commit()
        logger.info("Associated domains for %d entities", updated)


def _emit_easm_scan_failed_notification(
    db: Session,
    org_id: int,
    scan: Scan,
    domain: Optional[str],
    error_msg: str,
    phase: str,
) -> None:
    """Fire-and-forget scan_failed notification for an EASM scan.

    Kept separate from the main flow so notification failures never mask the
    underlying scan failure. `phase` is either "import" (failure while we were
    ingesting assets into the platform) or "scanner" (failure reported by the
    remote hakuna-scanner worker).
    """
    try:
        from services.notifications import create_notification
        scan_label = scan.scan_name or domain or f"scan #{scan.id}"
        title_suffix = " during import" if phase == "import" else ""
        create_notification(
            db, org_id, "scan_failed",
            f"EASM scan '{scan_label}' failed{title_suffix}",
            body=(error_msg or "")[:200],
            link="/settings?tab=upload",
            entity_type="scan", entity_id=scan.id,
            metadata={
                "scan_name": scan_label,
                "domain": domain,
                "source_type": "easm",
                "phase": phase,
                "error": (error_msg or "")[:500],
            },
        )
        db.commit()
    except Exception:
        logger.exception(
            f"Failed to emit EASM scan_failed notification for scan_id={scan.id} (non-fatal)"
        )


def _clear_scan_data(db: Session, scan_id: int):
    """Delete all findings, dependents, and non-shared assets for a scan.

    Deletes dependent rows first to avoid FK constraint violations.

    Preserves any asset with non-EASM provenance — either referenced by
    findings from another scan, or carrying source_systems/observations
    from a non-EASM source (e.g. a Cloudflare connector contributed facts
    without creating findings). Without this guard, re-running an EASM
    scan cascade-deletes AssetObservation rows and wipes source_systems
    entries that other integrations accumulated onto the asset.
    """
    from models.models import AssetObservation

    is_sqlite = db.bind.dialect.name == "sqlite"
    if is_sqlite:
        db.execute(sa_text("PRAGMA foreign_keys=OFF"))
    try:
        # Delete finding dependents + findings
        finding_ids = [r[0] for r in db.query(Finding.id).filter(Finding.scan_id == scan_id).all()]
        if finding_ids:
            for model in (AutomateClick, FindingOwnership, CampaignFinding, SBOMVulnerability):
                db.query(model).filter(model.finding_id.in_(finding_ids)).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.scan_id == scan_id).delete(synchronize_session=False)

        # Collect asset IDs to preserve (any non-EASM provenance)
        scan_asset_ids = {r[0] for r in db.query(Asset.id).filter(Asset.scan_id == scan_id).all()}
        if not scan_asset_ids:
            db.flush()
            return

        preserve_ids = set()

        # 1. Referenced by findings from another scan
        preserve_ids.update(
            r[0] for r in db.query(Finding.asset_id).filter(
                Finding.asset_id.in_(scan_asset_ids),
                Finding.scan_id != scan_id,
            ).all()
        )

        # 2. Carries source_systems from a source other than "easm"
        for asset in db.query(Asset).filter(Asset.id.in_(scan_asset_ids)).all():
            sources = asset.source_systems or []
            if any(s and s != "easm" for s in sources):
                preserve_ids.add(asset.id)

        # 3. Has an observation row from a non-EASM source
        preserve_ids.update(
            r[0] for r in db.query(AssetObservation.asset_id).filter(
                AssetObservation.asset_id.in_(scan_asset_ids),
                AssetObservation.source_system != "easm",
            ).all()
        )

        q_del = db.query(Asset).filter(Asset.scan_id == scan_id)
        if preserve_ids:
            q_del = q_del.filter(~Asset.id.in_(preserve_ids))
        q_del.delete(synchronize_session=False)

        # For preserved assets, drop their EASM observation row so the
        # re-import records a fresh one. Other sources' observations
        # stay put. source_systems stays intact.
        if preserve_ids:
            db.query(AssetObservation).filter(
                AssetObservation.asset_id.in_(preserve_ids),
                AssetObservation.source_system == "easm",
            ).delete(synchronize_session=False)

        db.flush()
    finally:
        if is_sqlite:
            db.execute(sa_text("PRAGMA foreign_keys=ON"))


_SEVERITY_KEY = {4: "critical_count", 3: "high_count", 2: "medium_count", 1: "low_count", 0: "info_count"}


def _update_asset_severity_counts(db: Session, scan_id: int) -> None:
    """Update critical/high/medium/low/info counts for all assets in a scan.

    Uses a single GROUP BY query instead of N+1 per-asset queries.
    """
    rows = (
        db.query(Finding.asset_id, Finding.severity, sqlfunc.count())
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.scan_id == scan_id)
        .group_by(Finding.asset_id, Finding.severity)
        .all()
    )
    counts_by_asset: dict = {}
    for asset_id, severity, cnt in rows:
        bucket = counts_by_asset.setdefault(
            asset_id,
            {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
        )
        bucket[_SEVERITY_KEY.get(severity, "info_count")] = cnt

    for a in db.query(Asset).filter(Asset.scan_id == scan_id).all():
        for k, v in counts_by_asset.get(a.id, {}).items():
            setattr(a, k, v)


def _compute_next_run(cron_expr: str) -> Optional[datetime]:
    """Compute the next run time from a cron expression."""
    try:
        trigger = CronTrigger.from_crontab(cron_expr)
        return trigger.get_next_fire_time(None, datetime.utcnow())
    except Exception:
        return None
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
    data, _status, _err = await _hakuna_request_detailed(method, path, **kwargs)
    return data


# Transient httpx errors that warrant exactly one retry. These correspond
# to mid-request failures where the connection pool handed us a dead socket
# (typically after the scanner restarts) — a second attempt with a fresh
# connection almost always succeeds. ConnectError is a first-attempt failure
# with the same remedy (retry once after brief delay).
_RETRYABLE_HTTPX_ERRORS: tuple[type[Exception], ...] = (
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
    httpx.ConnectError,
    httpx.PoolTimeout,
)


async def _hakuna_request_detailed(
    method: str, path: str, **kwargs,
) -> tuple[Optional[dict], Optional[int], Optional[str]]:
    """Make a request to hakuna-scanner API and return ``(data, status_code, error_str)``.

    On HTTP errors: ``(None, status, message)``.
    On network errors (after 1 retry): ``(None, None, message)``.
    On success: ``(data, status, None)``.

    Uses the module-level shared `AsyncClient` for connection reuse, and
    retries exactly once on transient network errors (dead-pooled-socket,
    mid-read, protocol reset) since those are overwhelmingly caused by the
    scanner restarting and they resolve on the next attempt. HTTP status
    errors are NOT retried — if the scanner returned 4xx/5xx, the request
    made it and the response is authoritative.

    Use this when the caller needs to react to specific status codes (e.g.
    self-healing on a stale org UUID 404 from /orgs/{id}/scans).
    """
    url = f"{HAKUNA_API}{path}"
    client = _get_hakuna_client()

    last_transient: Optional[Exception] = None
    for attempt in range(2):  # 0 = initial, 1 = retry
        try:
            resp = await client.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp.json(), resp.status_code, None
        except httpx.HTTPStatusError as e:
            # Real server response — don't retry, let caller decide.
            msg = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
            logger.warning(f"Hakuna API {method} {path} returned {msg}")
            return None, e.response.status_code, msg
        except _RETRYABLE_HTTPX_ERRORS as e:
            last_transient = e
            if attempt == 0:
                detail = str(e) or repr(e) or type(e).__name__
                logger.info(
                    f"Hakuna API transient {type(e).__name__} on {method} {path}: "
                    f"{detail} — retrying once"
                )
                continue
            # Fall through to generic handler below on second failure.
            break
        except httpx.RequestError as e:
            # Non-retryable network error (e.g. InvalidURL, UnsupportedProtocol).
            detail = str(e) or repr(e) or type(e).__name__
            msg = f"Network error: {detail}"
            logger.warning(f"Hakuna API unreachable ({method} {path}): {detail}")
            return None, None, msg

    # Both attempts on a retryable error exhausted.
    detail = str(last_transient) or repr(last_transient) or type(last_transient).__name__
    msg = f"Network error: {detail}"
    logger.warning(
        f"Hakuna API unreachable ({method} {path}) after retry: {detail}"
    )
    return None, None, msg


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


async def trigger_easm_scan(hakuna_org_id: str, scan_type: str = "full", target_domain: str = None) -> Optional[str]:
    """Trigger a scan in hakuna-scanner. Returns scan run ID or None."""
    payload = {"scan_type": scan_type}
    if target_domain:
        payload["target_domain"] = target_domain
    data = await _hakuna_request("POST", f"/orgs/{hakuna_org_id}/scans", json=payload)
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


async def get_easm_scan_runs(hakuna_org_id: str, limit: int = 20, domain: str = None) -> Optional[list]:
    """List recent scan runs for a hakuna org, optionally filtered by domain."""
    params = {"limit": limit}
    if domain:
        params["domain"] = domain
    data = await _hakuna_request("GET", f"/orgs/{hakuna_org_id}/scans", params=params)
    return data if isinstance(data, list) else None


# ── Registration hook ───────────────────────────────────────────────

async def trigger_easm_for_new_org(db: Session, org: Organization, email: str):
    """
    Called after registration. Extracts corporate domain from email,
    creates hakuna org + domain, triggers full scan with weekly schedule.
    Non-blocking — failures are logged but don't break registration.
    """
    domain = extract_corporate_domain(email)
    if not domain:
        logger.info(f"Skipping EASM for org '{org.name}': free/personal email domain")
        return

    # Persist the domain immediately so the frontend can show it even if the scanner is unreachable
    org.easm_domain = domain
    db.commit()

    logger.info(f"Triggering EASM discovery for org '{org.name}' domain '{domain}'")

    hakuna_org_id = await create_easm_org(org.name)
    if not hakuna_org_id:
        logger.warning(f"Failed to create EASM org for '{org.name}'")
        return

    if not await add_easm_domain(hakuna_org_id, domain):
        logger.warning(f"Failed to add domain '{domain}' to EASM org {hakuna_org_id}")
        return

    # Persist hakuna org reference now that scanner confirmed it
    org.easm_org_id = hakuna_org_id
    db.commit()

    # Create local Scan record, trigger scan, and set weekly schedule
    result = await scan_domain(db, org, domain, scan_type="full")
    if not result:
        logger.warning(f"Failed to trigger EASM scan for org {hakuna_org_id}")
        return

    logger.info(f"EASM scan triggered: org={hakuna_org_id}, scan={result.get('scan_id')}, run={result.get('run_id')}")

    # Apply weekly schedule (every Monday at 02:00 UTC)
    scan = db.query(Scan).filter(Scan.id == result["scan_id"]).first()
    if scan:
        schedule = "0 2 * * 1"
        scan.schedule = schedule
        db.commit()
        from services.easm_scheduler import register_scan
        register_scan(scan.id, schedule)
        logger.info(f"Weekly EASM schedule registered for scan {scan.id}")


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
        "liveness_state": ea.get("liveness_state", "unconfirmed"),
        # CPE list aggregated from asset_ports by the scanner API. Populated
        # by the CPE inference layer (hakuna-scanner/app/ingest/cpe_infer.py).
        # Used downstream by services/cpe_matcher.py for CPE → CVE correlation.
        "cpe_list": ea.get("cpe_list") or [],
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

    # ── CVEs via CPE → CVE correlation ────────────────────────────
    # Matches CPEs (populated by hakuna-scanner's CPE inference layer) against
    # the ThreatCVE table. Version-less CPEs ("cpe:2.3:a:nginx:nginx:*:...")
    # are skipped by the matcher — they produce no finding but still route
    # Nuclei templates via the VM scanner. See services/cpe_matcher.py.
    cpe_list = ea.get("cpe_list") or []
    if cpe_list:
        from services.cpe_matcher import match_cves_for_cpes
        try:
            matched_cves = match_cves_for_cpes(db, cpe_list)
        except Exception:
            logger.exception(f"CPE→CVE matching failed for {hostname} (non-fatal)")
            matched_cves = []

        for cve in matched_cves:
            cve_id = cve.get("cve_id")
            if not cve_id:
                continue
            pid = f"EASM-CVE-{cve_id}"
            if pid in existing_plugins:
                # Refresh last_seen on existing CVE finding
                db.query(Finding).filter(
                    Finding.scan_id == scan_id,
                    Finding.asset_id == asset.id,
                    Finding.plugin_id == pid,
                ).update({"last_seen": now})
                continue

            # Map CVSS score → severity band matching the existing taxonomy
            cvss = cve.get("cvss3_score") or 0.0
            if cvss >= 9.0:
                sev, sev_label, risk = 4, "Critical", "Critical"
            elif cvss >= 7.0:
                sev, sev_label, risk = 3, "High", "High"
            elif cvss >= 4.0:
                sev, sev_label, risk = 2, "Medium", "Medium"
            elif cvss > 0.0:
                sev, sev_label, risk = 1, "Low", "Low"
            else:
                sev, sev_label, risk = 0, "Info", "None"

            # Priority: CVSS baseline, big bump for KEV (known exploited), smaller for public exploit
            priority = float(cvss)
            if cve.get("in_kev"):
                priority = max(priority, 9.0)
            elif cve.get("has_public_exploit"):
                priority = max(priority, priority + 1.5)

            matched_cpe = cve.get("matched_cpe", "")
            badges = []
            if cve.get("in_kev"):
                badges.append("CISA KEV")
            if cve.get("has_public_exploit"):
                badges.append("Public exploit")
            badge_str = f" [{', '.join(badges)}]" if badges else ""

            findings_to_add.append(Finding(
                scan_id=scan_id, asset_id=asset.id,
                source_type="easm", source_vuln_id=cve_id,
                plugin_id=pid,
                plugin_name=f"{cve_id}: Known vulnerability{badge_str}",
                plugin_family="EASM: CVE",
                severity=sev, severity_label=sev_label, risk_factor=risk,
                priority_score=round(priority, 1),
                effort_level="medium",
                owner_suggestion="SecOps",
                cvss3_base_score=cvss or None,
                synopsis=f"{cve_id} affects technology detected on {hostname}.",
                description=(cve.get("description") or "")[:1000]
                    or f"CVE {cve_id} matches the CPE fingerprint observed on {hostname}.",
                solution=(
                    "Update or patch the affected software to a version not listed "
                    "in the CVE's affected range."
                ),
                plugin_output=(
                    f"Host: {hostname}\n"
                    f"Matched CPE: {matched_cpe}\n"
                    f"CVE: {cve_id}\n"
                    f"CVSS3: {cvss}\n"
                    f"KEV: {cve.get('in_kev', False)}\n"
                    f"Public exploit: {cve.get('has_public_exploit', False)}"
                ),
                first_seen=now, last_seen=now,
            ))

    for f in findings_to_add:
        f.source_systems = ["easm"]
    db.add_all(findings_to_add)
    db.flush()

    # Record per-source finding observations
    from services.asset_observations import record_finding_observation
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    _org_id = scan.org_id if scan else None
    for f in findings_to_add:
        record_finding_observation(
            db, finding_id=f.id, source_system="easm",
            raw_fields={"plugin_id": f.plugin_id, "plugin_name": f.plugin_name,
                         "severity": f.severity, "plugin_output": f.plugin_output},
            scan_id=scan_id, org_id=_org_id,
        )

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
    """Upsert assets belonging to a specific domain into a scan. Returns (upserted_count, findings_created).

    Uses upsert logic (update existing asset by IP/hostname if it already exists in this scan)
    to preserve stable asset IDs. This is critical for cross-source dedup: VM scan findings
    may reference EASM asset IDs, and deleting/recreating those assets would orphan the findings.
    """
    created = 0
    findings_created = 0
    now = datetime.utcnow()

    # Build lookup of existing assets in this scan by IP and by hostname
    existing_by_ip: dict[str, Asset] = {}
    existing_by_hostname: dict[str, Asset] = {}
    for a in db.query(Asset).filter(Asset.scan_id == scan.id).all():
        if a.ip:
            existing_by_ip[a.ip] = a
        if a.fqdn:
            existing_by_hostname[a.fqdn] = a
        elif a.hostname:
            existing_by_hostname[a.hostname] = a

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

        # Upsert: reuse existing asset if IP or hostname matches — keeps IDs stable
        asset = (
            (ip and existing_by_ip.get(ip))
            or (fqdn and existing_by_hostname.get(fqdn))
            or (hostname and existing_by_hostname.get(hostname.split(".")[0]))
        )
        if asset:
            # Update in-place to preserve asset.id (cross-scan findings may reference it)
            asset.ip = ip or asset.ip
            asset.hostname = hostname.split(".")[0] if hostname else asset.hostname
            asset.fqdn = fqdn or asset.fqdn
            asset.os = os_hint or asset.os
            asset.easm_data = easm_data
            asset.last_seen = now
            # Accumulate EASM as a source without clobbering other integrations'
            # contributions (e.g. cloudflare_api) to source_systems.
            current_sources = asset.source_systems or []
            if "easm" not in current_sources:
                asset.source_systems = current_sources + ["easm"]
        else:
            # Evaluate asset-type rules for EASM assets
            # Pass all EASM enrichment data — normalize_asset_data() will
            # flatten easm_data and compute derived fingerprint fields.
            type_kwargs = {}
            try:
                import services.asset_type_rules as asset_type_rule_engine
                rule_data = {
                    "hostname": hostname,
                    "ip": ip,
                    "fqdn": fqdn,
                    "os": os_hint or "",
                    "source_type": "easm",
                    "easm_data": easm_data,
                    # Also pass top-level EASM fields for direct access
                    "open_ports": ea.get("open_ports") or [],
                    "services": ea.get("services") or {},
                    "tech_stack": ea.get("tech_stack") or [],
                    "cpe": ea.get("cpe") or [],
                    "http_url": ea.get("http_url") or "",
                    "http_status": ea.get("http_status"),
                    "http_title": ea.get("http_title") or "",
                    "cdn_provider": ea.get("cdn_provider") or "",
                    "waf": ea.get("waf") or "",
                }
                type_result = asset_type_rule_engine.evaluate_asset_type_rules(
                    rule_data, db,
                    org_id=scan.org_id if hasattr(scan, "org_id") else None,
                    source_type="easm",
                )
                if type_result:
                    type_kwargs = {
                        "asset_type": type_result["asset_type"],
                        "asset_identity": type_result["asset_identity"],
                        "asset_attributes": type_result["asset_attributes"],
                    }
            except Exception:
                pass  # graceful fallback

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
                source_systems=["easm"],
                **type_kwargs,
            )
            db.add(asset)
            db.flush()
        created += 1

        # Record per-source observation for EASM
        record_observation(
            db, asset_id=asset.id, source_system="easm",
            raw_fields={"ip": ip, "hostname": hostname, "fqdn": fqdn,
                         "os": os_hint, "easm_data": easm_data},
            scan_id=scan.id, org_id=scan.org_id,
        )

        findings_created += _generate_easm_findings(db, scan.id, asset, ea)

    return created, findings_created


async def import_easm_assets_for_domain(
    db: Session, org: Organization, domain: str, scan_type: str = "full",
) -> Optional[dict]:
    """
    Import EASM-discovered assets for a domain.
    Reuses the existing scan record for this org+domain instead of creating a new one.
    """
    if not org.easm_org_id:
        return None

    easm_assets = await get_easm_assets(org.easm_org_id) or []

    # Reuse existing scan for this domain, or create one if first time
    scan = _find_existing_easm_scan(db, org, domain)
    if scan:
        # Clear EASM's own findings before reimporting.
        _clear_scan_data(db, scan.id)
    else:
        scan = _create_easm_scan(db, org, domain, scan_type)

    created, findings_created = _import_assets_for_domain(db, scan, easm_assets, domain)

    # Update scan metadata
    now = datetime.utcnow()
    scan.scan_date = now.isoformat()
    scan.status = "completed"
    scan.last_run_at = now
    scan.run_count = (scan.run_count or 0) + 1
    scan.raw_metadata = {
        "hakuna_org_id": org.easm_org_id,
        "domain": domain,
        "scan_type": scan_type,
        "asset_count": created,
        "last_sync": now.isoformat(),
        "status": "completed",
    }

    # Update asset severity counts (single GROUP BY query, not N+1)
    _update_asset_severity_counts(db, scan.id)

    db.commit()

    # Run full post-ingest pipeline (auto-tag, ownership, SLA, dedup, etc.)
    from services.post_ingest import finalize_scan
    finalize_scan(db, scan_id=scan.id, org_id=org.id)

    logger.info(f"EASM scan for '{domain}': assets={created}, findings={findings_created} (scan_id={scan.id})")

    return {
        "scan_id": scan.id,
        "created": created,
        "findings_created": findings_created,
        "domain": domain,
    }


async def _trigger_easm_scan_with_error(
    hakuna_org_id: str, scan_type: str, target_domain: str,
) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Like ``trigger_easm_scan`` but returns ``(run_id, status_code, error)``.
    Lets ``scan_domain`` distinguish a 404 (stale org UUID) from other failures."""
    payload = {"scan_type": scan_type, "target_domain": target_domain}
    data, status, err = await _hakuna_request_detailed(
        "POST", f"/orgs/{hakuna_org_id}/scans", json=payload,
    )
    return (data.get("id") if data else None), status, err


async def scan_domain(
    db: Session, org: Organization, domain: str, scan_type: str = "full",
) -> Optional[dict]:
    """
    Full flow: add domain to hakuna (idempotent), trigger scan,
    reuse existing scan record or create one marked as 'running'.
    Assets are imported later when the scan completes (via refresh_easm_scan).

    Self-heals when ``org.easm_org_id`` references an org that no longer
    exists in the scanner DB (404 on the trigger call) — this happens when
    the scanner Postgres is wiped (``docker compose down -v``) but the
    backend SQLite still has the stale UUID. On 404 we clear the cached
    UUID, re-create the org via ``create_easm_org``, and retry once.
    """
    if not org.easm_org_id:
        return None

    # Ensure domain is registered in hakuna (idempotent)
    await add_easm_domain(org.easm_org_id, domain)

    # Trigger scan — capture status so we can self-heal on a stale org UUID
    run_id, status, error = await _trigger_easm_scan_with_error(
        org.easm_org_id, scan_type, domain,
    )

    # Self-heal: stale easm_org_id (scanner DB was wiped). Clear and recreate.
    if run_id is None and status == 404:
        logger.warning(
            f"EASM trigger 404 for org '{org.name}' (easm_org_id={org.easm_org_id}) "
            f"— scanner does not know this org. Re-registering and retrying once."
        )
        new_hakuna_org_id = await create_easm_org(org.name)
        if new_hakuna_org_id:
            org.easm_org_id = new_hakuna_org_id
            db.commit()
            await add_easm_domain(new_hakuna_org_id, domain)
            run_id, status, error = await _trigger_easm_scan_with_error(
                new_hakuna_org_id, scan_type, domain,
            )
            logger.info(
                f"EASM org '{org.name}' re-registered as {new_hakuna_org_id}; "
                f"retry trigger run_id={run_id}"
            )
        else:
            error = "Self-heal failed: could not re-register org on scanner"

    # Build the metadata blob — when run_id is None, persist *why* it failed
    # so the UI can show it instead of an empty error field.
    failed = run_id is None
    failure_reason = None
    if failed:
        failure_reason = error or f"Scanner trigger returned no run_id (status={status})"

    scan = _find_existing_easm_scan(db, org, domain)
    now = datetime.utcnow()
    base_meta = {
        "hakuna_org_id": org.easm_org_id,
        "domain": domain,
        "scan_type": scan_type,
        "run_id": run_id,
        "status": "failed" if failed else "running",
    }
    if failure_reason:
        base_meta["error"] = failure_reason

    if scan:
        # Keep old assets/findings visible until the new scan completes
        scan.scan_date = now.isoformat()
        scan.raw_metadata = base_meta
    else:
        scan = _create_easm_scan(db, org, domain, scan_type)
        scan.raw_metadata = {**scan.raw_metadata, **base_meta}
    scan.status = "failed" if failed else "running"
    db.commit()

    return {
        "scan_id": scan.id,
        "run_id": run_id,
        "domain": domain,
        "status": scan.status,
        "error": failure_reason,
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

    # Check status in hakuna. Distinguish between three outcomes:
    #   1. Scanner reachable + returned a known status → use it
    #   2. Scanner reachable but returned 404 → run was wiped, mark failed
    #   3. Scanner unreachable (transient network error) → DO NOT change status,
    #      keep polling on the next refresh. This is critical: a 1-second
    #      Docker network blip should not permanently fail an in-progress scan.
    run_status: Optional[dict] = None
    fetch_status: Optional[int] = None
    fetch_error: Optional[str] = None
    if run_id:
        run_status, fetch_status, fetch_error = await _hakuna_request_detailed(
            "GET", f"/orgs/{org.easm_org_id}/scans/{run_id}",
        )
    else:
        # No run_id at all — the original trigger never produced one. Terminal failure.
        fetch_error = "No run_id stored on scan record"

    # Transient unreachability (no HTTP response at all): keep current state.
    if run_id and run_status is None and fetch_status is None:
        logger.info(
            f"EASM refresh skipped for scan_id={scan.id} domain='{domain}' — "
            f"scanner temporarily unreachable ({fetch_error}). Will retry next poll."
        )
        return {
            "scan_id": scan.id,
            "status": current_status or "running",
            "domain": domain,
            "transient_error": fetch_error,
        }

    # Got an HTTP response (or had no run_id). Map to a status string.
    if run_status is not None:
        hakuna_status = run_status.get("status", "unknown")
    elif fetch_status == 404:
        # Scan run literally doesn't exist on the scanner side. Terminal.
        hakuna_status = "failed"
    else:
        # Other HTTP errors (5xx, etc.) — treat as transient too, don't fail the scan.
        logger.info(
            f"EASM refresh got HTTP {fetch_status} for scan_id={scan.id} — treating as transient, "
            f"will retry next poll. Detail: {fetch_error}"
        )
        return {
            "scan_id": scan.id,
            "status": current_status or "running",
            "domain": domain,
            "transient_error": fetch_error,
        }

    # Map hakuna statuses
    if hakuna_status in ("completed", "done"):
        try:
            # Snapshot existing asset identities BEFORE clearing so we can
            # compute "how many are new this run" for the notification.
            # _clear_scan_data deletes EASM-only assets, so without this
            # snapshot every re-imported asset would look brand new.
            prior_identities: set[tuple[str, str]] = {
                (a.ip or "", (a.fqdn or a.hostname or "").lower())
                for a in db.query(Asset).filter(Asset.scan_id == scan.id).all()
            }

            _clear_scan_data(db, scan.id)

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
            scan.status = "completed"
            scan.last_run_at = now
            scan.run_count = (scan.run_count or 0) + 1

            # Compute next_run_at if scan has a schedule
            if scan.schedule:
                scan.next_run_at = _compute_next_run(scan.schedule)

            # Update asset severity counts (single GROUP BY query, not N+1)
            _update_asset_severity_counts(db, scan.id)

            db.commit()

            # Run full post-ingest pipeline (auto-tag, ownership, SLA, dedup, etc.)
            from services.post_ingest import finalize_scan
            finalize_scan(db, scan_id=scan.id, org_id=org.id)

            # Threat intel enrichment: HIBP breach check + GLEIF corporate structure
            try:
                from threat_intel.hibp_sync import sync_hibp_breaches_to_db, check_domain_breaches
                sync_hibp_breaches_to_db(db)
                breach_result = check_domain_breaches(db, org.id, domain)
                logger.info(f"EASM breach check for '{domain}': {breach_result}")
            except Exception:
                logger.exception(f"HIBP sync failed for '{domain}' (non-fatal)")

            try:
                from threat_intel.wikidata_sync import sync_corporate_tree_to_db
                # Derive company name from domain (e.g., "tenable.com" → "Tenable")
                company_name = domain.split(".")[0].capitalize() if domain else org.name
                wiki_result = sync_corporate_tree_to_db(db, company_name, org_id=org.id)
                logger.info(f"EASM Wikidata corporate sync for '{company_name}': {wiki_result}")

                # Fallback: SEC EDGAR for US public companies when Wikidata has no subsidiaries
                if wiki_result.get("subsidiaries", 0) == 0:
                    from threat_intel.edgar_sync import sync_subsidiaries_to_db
                    edgar_result = sync_subsidiaries_to_db(db, company_name, org_id=org.id)
                    logger.info(f"EASM EDGAR subsidiary sync for '{company_name}': {edgar_result}")

                # Associate domains with subsidiaries by matching names against EASM scan domains
                _associate_subsidiary_domains(db, org.id)
            except Exception:
                logger.exception(f"Corporate structure sync failed for domain '{domain}' (non-fatal)")

            # ── Notifications ──
            # Mirror the Nessus ingest pattern in app.py:_run_scan_ingest so
            # users get notified on EASM completion the same way they do for
            # uploaded scans. Fire scan_complete unconditionally, plus
            # new_assets/critical_findings when those counts are non-zero.
            try:
                from services.notifications import create_notification

                scan_label = scan.scan_name or domain or f"scan #{scan.id}"

                # Count newly-discovered assets (not present in prior_identities)
                new_asset_count = 0
                for a in db.query(Asset).filter(Asset.scan_id == scan.id).all():
                    key = (a.ip or "", (a.fqdn or a.hostname or "").lower())
                    if key not in prior_identities:
                        new_asset_count += 1

                # Count critical/high findings from this scan
                crit_high = (
                    db.query(Finding)
                    .filter(Finding.scan_id == scan.id, Finding.severity >= 3)
                    .count()
                )

                create_notification(
                    db, org.id, "scan_complete",
                    f"EASM scan '{scan_label}' completed",
                    body=f"{created} assets, {findings_created} findings processed",
                    link=f"/findings?scan_id={scan.id}",
                    entity_type="scan", entity_id=scan.id,
                    metadata={
                        "assets": created,
                        "findings": findings_created,
                        "scan_name": scan_label,
                        "domain": domain,
                        "source_type": "easm",
                    },
                )
                if crit_high > 0:
                    create_notification(
                        db, org.id, "critical_findings",
                        f"{crit_high} critical/high findings in EASM scan '{scan_label}'",
                        link=f"/findings?scan_id={scan.id}&severity=3,4",
                        entity_type="scan", entity_id=scan.id,
                        metadata={
                            "count": crit_high,
                            "scan_name": scan_label,
                            "domain": domain,
                            "source_type": "easm",
                        },
                    )
                if new_asset_count > 0:
                    create_notification(
                        db, org.id, "new_assets",
                        f"{new_asset_count} new assets discovered in EASM scan '{scan_label}'",
                        link=f"/assets?scan_id={scan.id}",
                        entity_type="scan", entity_id=scan.id,
                        metadata={
                            "count": new_asset_count,
                            "scan_name": scan_label,
                            "domain": domain,
                            "source_type": "easm",
                        },
                    )
                db.commit()
            except Exception:
                logger.exception(f"EASM completion notification failed for '{domain}' (non-fatal)")

            logger.info(f"EASM scan completed for '{domain}': assets={created}, findings={findings_created} (scan_id={scan.id})")

            return {"scan_id": scan.id, "status": "completed", "created": created, "findings_created": findings_created, "domain": domain}
        except Exception as exc:
            db.rollback()
            logger.exception(f"EASM import failed for '{domain}' (scan_id={scan.id}), marking as failed")
            import traceback
            error_tail = traceback.format_exc()[-500:]
            scan.raw_metadata = {**meta, "status": "failed", "error": error_tail}
            scan.status = "failed"
            db.commit()
            _emit_easm_scan_failed_notification(
                db, org.id, scan, domain,
                error_msg=str(exc) or "Import failed",
                phase="import",
            )
            return {"scan_id": scan.id, "status": "failed", "domain": domain}

    elif hakuna_status in ("failed", "error", "unknown"):
        # Prefer the scanner's own error string when present (it includes the
        # actual exception from the celery task) over the generic status label.
        scanner_error = (run_status or {}).get("error") if run_status else None
        if scanner_error:
            error_msg = f"Scanner: {scanner_error}"
        elif fetch_status == 404:
            error_msg = "Scanner does not have this scan run (404) — likely wiped"
        else:
            error_msg = f"Scanner returned status: {hakuna_status}"
        scan.raw_metadata = {**meta, "status": "failed", "error": error_msg}
        scan.status = "failed"
        db.commit()
        _emit_easm_scan_failed_notification(
            db, org.id, scan, domain, error_msg=error_msg, phase="scanner",
        )
        return {"scan_id": scan.id, "status": "failed", "domain": domain, "error": error_msg}

    else:
        # Still running/queued — relay progress info
        status = "running" if hakuna_status == "running" else hakuna_status
        progress = {}
        if run_status:
            progress = {
                "current_stage": run_status.get("current_stage"),
                "stage_index": run_status.get("stage_index", 0),
                "total_stages": run_status.get("total_stages", 0),
                "stage_started_at": run_status.get("stage_started_at"),
                "stage_log": run_status.get("stage_log"),
            }
        scan.raw_metadata = {**meta, "status": status, **progress}
        scan.status = status
        db.commit()
        return {"scan_id": scan.id, "status": status, "domain": domain, **progress}


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
