"""
EASM integration service — talks to hakuna-scanner (standalone EASM service).

Responsibilities:
1. On registration: create org + domain in hakuna, trigger discovery scan
2. On demand: import discovered assets into the main platform as a synthetic scan
3. Enrich Nessus-uploaded assets with EASM metadata (ports, tech, certs, CDN/WAF)
"""
import os
import re
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime
from typing import Optional, Tuple

import httpx

from sqlalchemy import func as sqlfunc, text as sa_text
from sqlalchemy.orm import Session
from models.models import (
    Organization, Scan, Asset, Finding,
    AutomateClick, FindingOwnership, CampaignFinding, SBOMVulnerability,
    SBOMComponent, InventorySoftware,
)

from apscheduler.triggers.cron import CronTrigger
from services.asset_observations import record_observation
from services.easm_taxonomy import (
    cwe_ids_for_subissues,
    metadata_for as easm_metadata_for,
    references_dict as easm_references_dict,
    seed_easm_context,
)

logger = logging.getLogger(__name__)

HAKUNA_BASE_URL = os.getenv("HAKUNA_SCANNER_URL", "http://localhost:8001")

# Non-software vendor:product pairs that should be excluded from cpe_list
# (used for CVE correlation) but kept in detected_technologies (UI display).
# Mirrors skip_cpe entries in hakuna-scanner/app/ingest/cpe_map.json.
_NON_SOFTWARE_CPE_PAIRS = frozenset({
    "cloudflare:cloudflare", "akamai:akamai", "fastly:fastly",
    "amazon:cloudfront", "hsts:hsts", "google:recaptcha",
    "google:analytics", "google:tag_manager", "google:font_api",
    "google:maps", "facebook:pixel", "hotjar:hotjar",
    "intercom:intercom", "hubspot:hubspot", "segment:segment",
    "mixpanel:mixpanel", "heap:heap", "zendesk:zendesk",
    "drift:drift", "crisp:crisp", "tawk:tawk.to",
    "automattic:gravatar", "fontawesome:font_awesome",
    "unpkg:unpkg", "cdnjs:cdnjs", "jsdelivr:jsdelivr",
    "sucuri:sucuri", "imperva:incapsula",
})


# Module-level executor for best-effort reverse DNS. Submitting the lookup to
# a thread pool lets us abandon the future after a short timeout so a slow
# resolver can't stall EASM ingest across dozens of IPs.
_RDNS_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="easm-rdns")

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_ipv4(val: str) -> bool:
    if not val or not _IPV4_RE.match(val):
        return False
    return all(0 <= int(o) <= 255 for o in val.split("."))


def _reverse_dns_best_effort(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Return the PTR hostname for `ip`, or None on failure/timeout."""
    try:
        fut = _RDNS_EXECUTOR.submit(socket.gethostbyaddr, ip)
        name, _, _ = fut.result(timeout=timeout)
        return name or None
    except (FuturesTimeout, socket.herror, socket.gaierror, OSError):
        return None
    except Exception:
        return None


def _resolve_host_fields(
    raw_hostname: str,
    raw_ip: str,
    try_reverse_dns: bool = True,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Normalize EASM-provided host/ip into (ip, hostname_short, fqdn).

    EASM records sometimes carry an IP in the `hostname` field (no separate
    `ip`). Naively splitting on '.' then turns "20.83.163.0" into "20" — the
    bug that displayed the asset as just "20" in the UI.

    Rules:
    - If `raw_hostname` parses as an IPv4 and `raw_ip` is empty, move it into ip.
    - If only an IP is known and reverse DNS succeeds, adopt the PTR as hostname/fqdn.
    - `hostname` stores the short label (first dot-segment) of a real hostname;
      `fqdn` stores the full dotted name. Neither is ever populated from an IP.
    """
    raw_hostname = (raw_hostname or "").strip()
    raw_ip = (raw_ip or "").strip()

    if raw_hostname and _is_ipv4(raw_hostname) and not raw_ip:
        raw_ip = raw_hostname
        raw_hostname = ""

    if raw_ip and not raw_hostname and try_reverse_dns:
        rdns = _reverse_dns_best_effort(raw_ip)
        if rdns:
            raw_hostname = rdns

    ip_val = raw_ip or None
    fqdn_val = raw_hostname if raw_hostname and "." in raw_hostname else None
    hostname_val = raw_hostname.split(".")[0] if raw_hostname else None
    return ip_val, hostname_val, fqdn_val


def _filter_cpe_list(cpe_list: list) -> list:
    """Remove non-software CPEs from a cpe_list at read time.

    Filters out:
    1. Known non-software pairs (CDNs, WAFs, analytics, etc.)
    2. Versionless open-ended tokens where vendor == product and version is *
    """
    result = []
    for cpe_str in cpe_list:
        if not isinstance(cpe_str, str):
            continue
        parts = cpe_str.split(":")
        if len(parts) < 6:
            continue
        vendor, product, version = parts[3], parts[4], parts[5]
        vp = f"{vendor}:{product}"
        if vp in _NON_SOFTWARE_CPE_PAIRS:
            continue
        if vendor == product and version == "*":
            continue
        result.append(cpe_str)
    return result


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


# Sources eligible for automatic subsidiary fan-out scans. Anything outside
# this set (e.g. "dns_probe") is low-confidence — surfaced in the UI but
# never auto-scanned, since DNS probes of {name}.com frequently hit squatters
# or unrelated companies we're not authorized to scan.
HIGH_CONFIDENCE_DOMAIN_SOURCES = frozenset({
    "wikidata_official",
    "edgar_official",
    "gleif_official",
    "easm_name_match",
})


def _record_domain_source(entity, domain: str, source: str) -> None:
    """Set the provenance for `domain` on `entity` without clobbering prior values.

    First writer wins — a later DNS probe must not downgrade a Wikidata claim.
    """
    sources = dict(entity.domain_sources or {})
    sources.setdefault(domain, source)
    entity.domain_sources = sources


def _associate_subsidiary_domains(db: Session, org_id: int):
    """Match subsidiary names to domains via DNS probing.

    For each subsidiary without domains, tries {name}.com and {name}.io
    via DNS resolution. Also matches against EASM-discovered hostnames.
    Tracks per-domain provenance in `domain_sources` so the fan-out only
    auto-scans high-confidence matches.
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

        matched: list[tuple[str, str]] = []  # (domain, source)

        # 1. Match against EASM-discovered domains/hostnames (high confidence —
        #    the match anchors to a domain the org already scans).
        for core in candidates:
            for d in easm_domains:
                if core in d.split(".")[0] or d.split(".")[0] in core:
                    if d not in [m[0] for m in matched]:
                        matched.append((d, "easm_name_match"))
            for h in all_hostnames:
                root = ".".join(h.split(".")[-2:])
                if core in root.split(".")[0]:
                    if root not in [m[0] for m in matched]:
                        matched.append((root, "easm_name_match"))

        # 2. DNS probe: try {name}.com and {name}.io for each candidate (low
        #    confidence — may hit squatters / unrelated companies).
        if not matched:
            for core in candidates:
                for tld in (".com", ".io"):
                    candidate = core + tld
                    try:
                        socket.getaddrinfo(candidate, None, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
                        matched.append((candidate, "dns_probe"))
                        break  # one hit per candidate is enough
                    except socket.gaierror:
                        continue
                if matched:
                    break

        if matched:
            sub.associated_domains = list({m[0] for m in matched})
            for d, src in matched:
                _record_domain_source(sub, d, src)
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
                    _record_domain_source(root, d, "easm_name_match")
                    updated += 1
                    break
            if root.associated_domains:
                break

    if updated:
        db.commit()
        logger.info("Associated domains for %d entities", updated)


# Hard cap on how many subsidiary domains we'll auto-scan per parent scan
# completion. Prevents a parent with hundreds of subsidiaries from flooding
# the scanner queue and inflating the org's EASM footprint unexpectedly.
DEFAULT_SUBSIDIARY_FANOUT_CAP = 20


async def fan_out_subsidiary_scans(
    db: Session,
    org: Organization,
    scan_type: str = "discovery",
    include_low_confidence: bool = False,
    max_subsidiaries: int = DEFAULT_SUBSIDIARY_FANOUT_CAP,
    parent_scan_id: Optional[int] = None,
) -> dict:
    """Trigger EASM scans for subsidiary domains discovered by the corporate sync.

    Only auto-scans domains whose provenance is in
    ``HIGH_CONFIDENCE_DOMAIN_SOURCES`` unless ``include_low_confidence`` is set.
    Idempotent: domains that already have an EASM scan for this org are skipped
    via ``_find_existing_easm_scan``.

    Returns a summary: {"triggered": [...], "skipped_existing": [...],
    "skipped_low_confidence": [...], "skipped_cap": N}.
    """
    from models.threat_intel_models import CorporateEntity

    if not org.easm_org_id:
        return {"triggered": [], "skipped_existing": [], "skipped_low_confidence": [], "skipped_cap": 0}

    subs = db.query(CorporateEntity).filter(
        CorporateEntity.org_id == org.id,
        CorporateEntity.direct_parent_lei.isnot(None),
    ).all()

    triggered: list[dict] = []
    skipped_existing: list[str] = []
    skipped_low_conf: list[dict] = []
    skipped_cap = 0
    seen_domains: set[str] = set()

    for sub in subs:
        # Skip inactive / merged entities — scanning their legacy domains is
        # rarely authorized and usually produces noise.
        if sub.entity_status and sub.entity_status.upper() not in ("ACTIVE", ""):
            continue

        sources = sub.domain_sources or {}
        for domain in (sub.associated_domains or []):
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)

            source = sources.get(domain, "unknown")
            is_high_conf = source in HIGH_CONFIDENCE_DOMAIN_SOURCES
            if not is_high_conf and not include_low_confidence:
                skipped_low_conf.append({"domain": domain, "source": source, "lei": sub.lei})
                continue

            # Dedup: reuse existing scan record instead of re-triggering.
            if _find_existing_easm_scan(db, org, domain) is not None:
                skipped_existing.append(domain)
                continue

            if len(triggered) >= max_subsidiaries:
                skipped_cap += 1
                continue

            try:
                result = await scan_domain(db, org, domain, scan_type=scan_type)
            except Exception:
                logger.exception(
                    "Subsidiary fan-out scan failed for domain=%s (lei=%s)",
                    domain, sub.lei,
                )
                continue

            if result and result.get("scan_id"):
                scan = db.query(Scan).filter(Scan.id == result["scan_id"]).first()
                if scan is not None:
                    meta = dict(scan.raw_metadata or {})
                    meta["discovery_source"] = "subsidiary_fanout"
                    meta["parent_lei"] = sub.lei
                    meta["parent_legal_name"] = sub.legal_name
                    meta["domain_source"] = source
                    if parent_scan_id is not None:
                        meta["parent_scan_id"] = parent_scan_id
                    scan.raw_metadata = meta
                    db.commit()
                triggered.append({
                    "domain": domain,
                    "lei": sub.lei,
                    "legal_name": sub.legal_name,
                    "scan_id": result.get("scan_id"),
                    "source": source,
                })

    if triggered or skipped_existing or skipped_low_conf:
        logger.info(
            "Subsidiary fan-out for org_id=%s: triggered=%d existing=%d low_conf=%d cap=%d",
            org.id, len(triggered), len(skipped_existing), len(skipped_low_conf), skipped_cap,
        )

    return {
        "triggered": triggered,
        "skipped_existing": skipped_existing,
        "skipped_low_confidence": skipped_low_conf,
        "skipped_cap": skipped_cap,
    }


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

    # Delete finding dependents + findings
    finding_ids = [r[0] for r in db.query(Finding.id).filter(Finding.scan_id == scan_id).all()]
    if finding_ids:
        for model in (AutomateClick, FindingOwnership, CampaignFinding, SBOMVulnerability):
            db.query(model).filter(model.finding_id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(Finding).filter(Finding.scan_id == scan_id).delete(synchronize_session=False)

    # Drop SBOM rows before InventorySoftware: SBOMComponent.software_id FKs
    # InventorySoftware, and SBOMVulnerability.component_id FKs SBOMComponent.
    # The earlier SBOMVulnerability sweep above only catches rows with
    # finding_id in this scan — vulns with NULL/cross-scan finding_id are still
    # anchored here via component_id.
    sbom_component_ids = [
        r[0] for r in db.query(SBOMComponent.id).filter(SBOMComponent.scan_id == scan_id).all()
    ]
    if sbom_component_ids:
        db.query(SBOMVulnerability).filter(
            SBOMVulnerability.component_id.in_(sbom_component_ids)
        ).delete(synchronize_session=False)
        db.query(SBOMComponent).filter(SBOMComponent.scan_id == scan_id).delete(
            synchronize_session=False,
        )

    db.query(InventorySoftware).filter(InventorySoftware.scan_id == scan_id).delete(
        synchronize_session=False,
    )

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
        # Reset enrichment timestamps so the next scan re-enriches these assets.
        db.query(Asset).filter(Asset.id.in_(preserve_ids)).update(
            {"last_enriched": None, "last_js_fingerprinted": None},
            synchronize_session=False,
        )

    db.flush()


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
    RuntimeError,  # uvloop "handler is closed" on stale TCP transport
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


async def cancel_easm_scan(hakuna_org_id: str, scan_id: str) -> tuple[bool, Optional[str]]:
    """Ask hakuna-scanner to cancel a queued/running scan run.

    Returns ``(ok, error_message)``. ``ok=True`` means the scanner flipped
    the run to cancelled; ``ok=False`` means it was unreachable or already
    in a terminal state (the caller can still update local metadata so the
    UI stops polling).
    """
    data, status, err = await _hakuna_request_detailed(
        "POST", f"/orgs/{hakuna_org_id}/scans/{scan_id}/cancel"
    )
    if data is not None:
        return True, None
    return False, err or (f"HTTP {status}" if status else "Scanner unreachable")


async def trigger_github_npm_scan(
    hakuna_org_id: str,
    target_domain: str,
    *,
    mode: str = "discovery",
    enable_keyword_search: bool = True,
    confidence_threshold: float = 0.3,
) -> Optional[dict]:
    """Run GitHub/npm attribution for a domain on hakuna-scanner.

    Synchronous: the scanner runs the engine inline and returns the unified
    DiscoveryResult. We override the default 30s client timeout because
    discovery hits dozens of GitHub/npm endpoints and can legitimately take
    several minutes when the rate limit kicks in.
    """
    payload = {
        "target_domain": target_domain,
        "mode": mode,
        "confidence_threshold": confidence_threshold,
        "enable_keyword_search": enable_keyword_search,
    }
    return await _hakuna_request(
        "POST",
        f"/orgs/{hakuna_org_id}/github-attribution",
        json=payload,
        timeout=httpx.Timeout(600.0, connect=5.0),
    )


async def get_easm_assets(
    hakuna_org_id: str,
    limit: int = 1000,
    offset: int = 0,
    updated_since: Optional[str] = None,
) -> Optional[list]:
    """Fetch discovered assets from hakuna-scanner.

    updated_since: ISO-8601 timestamp. When provided, only assets whose
    last_seen is at or after this point are returned — used to drive
    incremental mid-scan imports without re-upserting the full asset set
    on every poll.
    """
    params: dict = {"limit": limit, "offset": offset}
    if updated_since:
        params["updated_since"] = updated_since
    data = await _hakuna_request("GET", f"/orgs/{hakuna_org_id}/assets", params=params)
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


async def get_easm_endpoints(
    hakuna_org_id: str,
    easm_asset_id: Optional[str] = None,
    source: Optional[str] = None,
    method: Optional[str] = None,
    auth_required: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "discovered_at",
    order: str = "desc",
    limit: int = 100,
    offset: int = 0,
) -> Optional[dict]:
    """Fetch discovered endpoints (katana / kiterunner / openapi / graphql / llm_js)
    from hakuna-scanner.

    Returns the raw {total, limit, offset, endpoints: [...]} envelope on success,
    None on network error. Caller is responsible for translating scanner asset
    UUIDs back to backend asset IDs when needed.
    """
    params: dict = {"limit": limit, "offset": offset, "sort_by": sort_by, "order": order}
    if easm_asset_id:
        params["asset_id"] = easm_asset_id
    if source:
        params["source"] = source
    if method:
        params["method"] = method
    if auth_required is not None:
        params["auth_required"] = str(auth_required).lower()
    if search:
        params["search"] = search
    data = await _hakuna_request(
        "GET", f"/orgs/{hakuna_org_id}/assets/endpoints", params=params,
    )
    return data if isinstance(data, dict) else None


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
    services = ea.get("services") or {}
    # Banner findings live on the scanner under either a top-level
    # ``banner_findings`` key or nested in the scanner's own ``easm_data``
    # JSON column. Carry whichever is populated through to the backend so
    # cve_correlator._banner_components can consume them.
    scanner_easm = ea.get("easm_data") or {}
    banner_findings = (
        ea.get("banner_findings")
        or (scanner_easm.get("banner_findings") if isinstance(scanner_easm, dict) else None)
        or []
    )
    # Aggregate Shodan-reported CVEs across all ports into a single list.
    # Per-port CVEs land in services[port].shodan_vulns when the scanner's
    # Shodan ingest path runs (see hakuna-scanner/app/ingest/delta.py
    # apply_shodan_observations). The flat list is what the VM auto-trigger
    # and prioritizer read — they don't care which port surfaced the CVE.
    shodan_vulns: set[str] = set()
    if isinstance(services, dict):
        for svc in services.values():
            if not isinstance(svc, dict):
                continue
            for cve in svc.get("shodan_vulns") or []:
                if isinstance(cve, str):
                    shodan_vulns.add(cve)
    return {
        "easm_asset_id": ea.get("id"),
        "tech_stack": ea.get("tech_stack") or [],
        "open_ports": ea.get("open_ports") or [],
        "services": services,
        "shodan_vulns": sorted(shodan_vulns),
        "tls_cert": ea.get("tls_cert") or {},
        "security_audit": ea.get("security_audit") or {},
        "tls_deep_audit": ea.get("tls_deep_audit") or {},
        "cdn_provider": ea.get("cdn_provider"),
        "cloud_provider": ea.get("cloud_provider"),
        "attribution": ea.get("attribution") or {},
        "liveness_score": ea.get("liveness_score", 100),
        "liveness_state": ea.get("liveness_state"),
        "waf": ea.get("waf"),
        "dns_records": ea.get("dns_records") or {},
        "banner_findings": banner_findings,
        "http_status": ea.get("http_status"),
        "http_title": ea.get("http_title"),
        "http_url": ea.get("http_url"),
        "easm_tags": ea.get("tags") or [],
        "easm_source": ea.get("source"),
        "first_seen_easm": ea.get("first_seen"),
        "last_seen_easm": ea.get("last_seen"),
        "last_enriched_easm": ea.get("last_enriched"),
        "liveness_state": ea.get("liveness_state", "unconfirmed"),
        # CPE list (CVE-matchable only — excludes CDNs, WAFs, analytics, policies).
        # Filtered by hakuna-scanner's CPE inference layer; also filtered here
        # at read time via _filter_cpe_list to clean up stale data.
        "cpe_list": _filter_cpe_list(ea.get("cpe_list") or []),
        # All detected technologies including non-software (for UI display).
        "detected_technologies": ea.get("detected_technologies") or ea.get("cpe_list") or [],
    }


# ── EASM finding definitions ───────────────────────────────────────

SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _easm_metadata_kwargs(
    plugin_id: str,
    *,
    extra_cwes: Optional[list[str]] = None,
    is_kev: bool = False,
    exploit_available: bool = False,
) -> dict:
    """Resolve plugin_family / cwe_ids / references / ctx_* for an EASM finding.

    Pulled out so every Finding constructor in _generate_easm_findings sets
    these consistently. extra_cwes is unioned with the registry value (used
    by HEADER/COOKIE bundles where CWEs come from sub-issue ids).
    """
    meta = easm_metadata_for(plugin_id)
    cwes = list(meta.get("cwe_ids", []))
    for c in (extra_cwes or []):
        if c and c not in cwes:
            cwes.append(c)
    ctx = seed_easm_context(is_kev=is_kev, exploit_available=exploit_available)
    kwargs = {
        "plugin_family": meta.get("family", "EASM: Other"),
        "cwe_ids": cwes,
        "references": easm_references_dict(meta.get("references", [])),
        "ctx_reachability": ctx["ctx_reachability"],
        "ctx_accessibility": ctx["ctx_accessibility"],
    }
    if ctx["ctx_exploitability"] is not None:
        kwargs["ctx_exploitability"] = ctx["ctx_exploitability"]
    return kwargs


def _upsert_inventory_software_from_cpes(
    db: Session, scan_id: int, asset_id: int, cpe_list: list[str],
) -> None:
    """Persist EASM-inferred software as InventorySoftware rows.

    Feeds services/sbom_pipeline.build_sbom_from_inventory so externally
    discovered software shows up in the SBOM view alongside agent-reported
    inventory. Versionless CPEs are still recorded — the SBOM pipeline
    tolerates null versions and lists the component without EOL/CVE matches.
    """
    from services.cpe_matcher import parse_cpe

    seen: set[Tuple[str, str, str]] = set()
    for cpe_str in cpe_list:
        parsed = parse_cpe(cpe_str)
        if parsed is None:
            continue
        version = parsed.version if parsed.has_version else None
        key = (parsed.vendor, parsed.product, version or "")
        if key in seen:
            continue
        seen.add(key)

        db.add(InventorySoftware(
            scan_id=scan_id,
            asset_id=asset_id,
            name=parsed.product,
            version=version,
            vendor=parsed.vendor,
            source_plugin="easm-cpe-inference",
        ))


_LIVENESS_SUPPRESS_THRESHOLD = 30


def _generate_easm_findings(db: Session, scan_id: int, asset: Asset, ea: dict) -> Tuple[int, list]:
    """Generate one finding per EASM observation. Idempotent: skips existing plugin_id+asset combos.

    Returns ``(count, new_finding_ids)`` so callers can drive finalize_batch
    over the exact rows that were inserted this call.
    """
    # Suppress finding generation for stale assets (liveness_score below
    # threshold). The asset record is still imported and visible in the
    # inventory with its current state — we just stop emitting *new*
    # exposure findings for hosts that haven't been confirmed alive in
    # several scan cycles. Existing findings remain open so historical
    # exposure isn't lost.
    score = ea.get("liveness_score")
    if score is not None and score < _LIVENESS_SUPPRESS_THRESHOLD:
        return 0, []

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
    services = ea.get("services") or {}

    # ── Exposed database ports ────────────────────────────────────
    # Flag the classic "internet-facing database" anti-pattern. open_ports is
    # already populated from naabu; services holds banner/product info when
    # available. Critical when the banner confirms the expected DB service,
    # High when only the port is open (could be a firewalled proxy, so one
    # step lower confidence).
    DB_PORTS = {
        3306: ("MySQL", "mysql"),
        5432: ("PostgreSQL", "postgres"),
        27017: ("MongoDB", "mongo"),
        6379: ("Redis", "redis"),
        9200: ("Elasticsearch", "elastic"),
        11211: ("Memcached", "memcache"),
        1433: ("MSSQL", "mssql"),
        1521: ("Oracle", "oracle"),
        5984: ("CouchDB", "couch"),
        7474: ("Neo4j", "neo4j"),
        9042: ("Cassandra", "cassandra"),
        2379: ("etcd", "etcd"),
    }
    for port in (ea.get("open_ports") or []):
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            continue
        if port_int not in DB_PORTS:
            continue
        db_name, banner_key = DB_PORTS[port_int]
        pid = f"EASM-EXPOSED-DB-{port_int}"
        svc = (services.get(str(port_int)) or services.get(port) or {}) if isinstance(services, dict) else {}
        banner_blob = " ".join(
            str(svc.get(k, "")) for k in ("name", "product", "version")
        ).lower()
        confirmed = banner_key in banner_blob
        if confirmed:
            db_sev, db_sev_label, db_risk = 4, "Critical", "Critical"
            db_priority = 9.0
        else:
            db_sev, db_sev_label, db_risk = 3, "High", "High"
            db_priority = 7.5
        output_lines = [
            f"Host: {hostname}",
            f"Port: {port_int}/tcp",
            f"Expected service: {db_name}",
            f"Banner: {banner_blob.strip() or 'none'}",
            f"Confirmed by banner: {'yes' if confirmed else 'no'}",
        ]
        if pid in existing_plugins:
            db.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.asset_id == asset.id,
                Finding.plugin_id == pid,
            ).update({
                "severity": db_sev,
                "severity_label": db_sev_label,
                "risk_factor": db_risk,
                "priority_score": db_priority,
                "last_seen": now,
                "plugin_output": "\n".join(output_lines),
            })
        else:
            findings_to_add.append(Finding(
                scan_id=scan_id, asset_id=asset.id,
                source_type="easm", source_vuln_id=pid,
                plugin_id=pid,
                plugin_name=f"Exposed {db_name} Database ({port_int}/tcp)",
                severity=db_sev, severity_label=db_sev_label, risk_factor=db_risk,
                priority_score=db_priority, effort_level="medium",
                owner_suggestion="IT",
                port=str(port_int), protocol="tcp",
                **_easm_metadata_kwargs(pid),
                synopsis=f"{db_name} database port {port_int}/tcp is reachable from the internet on {hostname}.",
                description=(
                    f"External port scanning found {db_name} port {port_int}/tcp open on {hostname}. "
                    f"Database services should not be directly reachable from the public internet — "
                    f"they should live behind a VPN, bastion host, or private network segment. "
                    f"{'Service banner confirms an active ' + db_name + ' instance.' if confirmed else 'Service banner does not confirm the expected service, but the port is commonly used by ' + db_name + '.'}"
                ),
                solution=(
                    f"Close port {port_int}/tcp at the firewall or move the {db_name} instance behind a "
                    f"VPN/bastion. If this port must remain open, restrict source IPs to trusted ranges "
                    f"and require strong authentication and TLS."
                ),
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
                **_easm_metadata_kwargs(pid),
            ))

    # ── Weak TLS protocols / ciphers ──────────────────────────────
    # Grades the TLS version + cipher suite captured by tlsx. One finding
    # per asset; all detected issues are bundled into plugin_output and the
    # overall severity is the worst of the issues. Re-ingest updates
    # severity in place (mirrors EASM-TLS-CERT).
    if cert and (cert.get("version") or cert.get("cipher")):
        tls_issues = []  # list[(severity_int, label, output_line)]
        tls_version_raw = str(cert.get("version") or "").strip()
        tls_version_norm = tls_version_raw.upper().replace("V", " ")
        # Accept both "TLS 1.0" and "TLSv1" / "TLSv1.0" forms
        if "TLS 1.0" in tls_version_norm or tls_version_raw.upper() in {"TLSV1", "TLSV1.0"}:
            tls_issues.append((3, "High", f"Protocol {tls_version_raw} is deprecated (no longer permitted by PCI-DSS and most browsers)"))
        elif "TLS 1.1" in tls_version_norm or tls_version_raw.upper() == "TLSV1.1":
            tls_issues.append((2, "Medium", f"Protocol {tls_version_raw} is deprecated"))
        elif tls_version_raw.upper() in {"SSLV3", "SSL 3.0", "SSLV2"}:
            tls_issues.append((4, "Critical", f"Protocol {tls_version_raw} is broken and must not be used"))

        cipher_raw = str(cert.get("cipher") or "").strip()
        # Match common weak cipher names. "DES" alone is safe to match because
        # AES/ChaCha20 don't contain the substring; this catches both legacy DES
        # and triple-DES variants (DES-CBC3-SHA, DES-EDE3-CBC, 3DES-…).
        if cipher_raw and re.search(r"RC4|DES|NULL|EXPORT|MD5|anon", cipher_raw, re.I):
            tls_issues.append((3, "High", f"Weak cipher suite: {cipher_raw}"))

        if tls_issues:
            pid = "EASM-TLS-WEAK"
            # Severity = worst issue (highest int)
            weak_sev = max(i[0] for i in tls_issues)
            weak_sev_label = next(lbl for s, lbl, _ in tls_issues if s == weak_sev)
            weak_risk = weak_sev_label
            if weak_sev >= 4:
                weak_priority, weak_effort = 9.0, "medium"
            elif weak_sev == 3:
                weak_priority, weak_effort = 7.0, "medium"
            else:
                weak_priority, weak_effort = 5.0, "medium"
            output_lines = [f"Host: {hostname}"]
            if tls_version_raw:
                output_lines.append(f"Protocol: {tls_version_raw}")
            if cipher_raw:
                output_lines.append(f"Cipher: {cipher_raw}")
            output_lines.append("Issues:")
            output_lines.extend(f"  - {line}" for _, _, line in tls_issues)

            if pid in existing_plugins:
                db.query(Finding).filter(
                    Finding.scan_id == scan_id,
                    Finding.asset_id == asset.id,
                    Finding.plugin_id == pid,
                ).update({
                    "severity": weak_sev,
                    "severity_label": weak_sev_label,
                    "risk_factor": weak_risk,
                    "priority_score": weak_priority,
                    "effort_level": weak_effort,
                    "last_seen": now,
                    "plugin_output": "\n".join(output_lines),
                })
            else:
                findings_to_add.append(Finding(
                    scan_id=scan_id, asset_id=asset.id,
                    source_type="easm", source_vuln_id=pid,
                    plugin_id=pid,
                    plugin_name="Weak TLS Configuration",
                    severity=weak_sev, severity_label=weak_sev_label, risk_factor=weak_risk,
                    priority_score=weak_priority, effort_level=weak_effort,
                    owner_suggestion="IT",
                    synopsis=f"{hostname} is using a weak TLS protocol or cipher suite.",
                    description=(
                        f"External TLS inspection of {hostname} detected a weak configuration. "
                        f"Modern browsers and compliance regimes (PCI-DSS 4.0, NIST SP 800-52 Rev. 2) "
                        f"require TLS 1.2+ with strong cipher suites. Continuing to support deprecated "
                        f"protocols or weak ciphers leaves clients vulnerable to downgrade, BEAST, "
                        f"POODLE, SWEET32, and related attacks."
                    ),
                    solution=(
                        "Disable TLS 1.0, TLS 1.1, SSLv2, and SSLv3 on the server. Remove cipher "
                        "suites containing RC4, 3DES, DES, NULL, EXPORT, MD5, or anonymous key exchange. "
                        "Prefer TLS 1.2 and TLS 1.3 with AEAD cipher suites (e.g., "
                        "ECDHE-RSA-AES128-GCM-SHA256)."
                    ),
                    plugin_output="\n".join(output_lines),
                    first_seen=now, last_seen=now,
                    **_easm_metadata_kwargs(pid),
                ))

    # ── HTTP security headers / cookies ───────────────────────────
    # The hakuna-scanner runs app.ingest.http_header_audit.audit_response()
    # over every httpx hit and stores the result on assets.security_audit.
    # Issues are bundled into two findings per asset (one headers, one
    # cookies) with severity = worst sub-issue, mirroring EASM-TLS-WEAK.
    security_audit = ea.get("security_audit") or {}
    audit_issues = security_audit.get("issues") or []
    if audit_issues:
        header_ids = {
            "hsts-missing", "hsts-weak",
            "csp-missing", "clickjacking-protection-missing",
            "content-type-sniffing", "referrer-policy-missing",
            "permissions-policy-missing",
        }
        cookie_ids = {
            "cookie-insecure", "cookie-not-httponly",
            "cookie-samesite-missing", "cookie-samesite-none-insecure",
        }

        def _emit_audit_finding(pid, title, owner, synopsis, description, solution, matching_ids):
            matches = [i for i in audit_issues if i.get("id") in matching_ids]
            if not matches:
                return
            sev = max(int(i.get("severity", 0)) for i in matches)
            sev_label = SEVERITY_LABELS.get(sev, "Info")
            priority = 5.5 if sev >= 2 else (3.0 if sev == 1 else 1.0)
            effort = "quick_win"  # header/cookie fixes are config changes

            output_lines = [f"Host: {hostname}"]
            if security_audit.get("url"):
                output_lines.append(f"URL: {security_audit['url']}")
            output_lines.append("Issues:")
            output_lines.extend(f"  - {i.get('detail', i.get('id'))}" for i in matches)

            # CWE union for the bundled finding — pulled from the per-issue
            # map so adding a new sub-issue requires editing easm_taxonomy
            # only, not this code path.
            subissue_cwes = cwe_ids_for_subissues(i.get("id", "") for i in matches)

            if pid in existing_plugins:
                db.query(Finding).filter(
                    Finding.scan_id == scan_id,
                    Finding.asset_id == asset.id,
                    Finding.plugin_id == pid,
                ).update({
                    "severity": sev,
                    "severity_label": sev_label,
                    "risk_factor": sev_label,
                    "priority_score": priority,
                    "last_seen": now,
                    "plugin_output": "\n".join(output_lines),
                    "cwe_ids": subissue_cwes,
                })
            else:
                findings_to_add.append(Finding(
                    scan_id=scan_id, asset_id=asset.id,
                    source_type="easm", source_vuln_id=pid,
                    plugin_id=pid,
                    plugin_name=title,
                    severity=sev, severity_label=sev_label, risk_factor=sev_label,
                    priority_score=priority, effort_level=effort,
                    owner_suggestion=owner,
                    synopsis=synopsis,
                    description=description,
                    solution=solution,
                    plugin_output="\n".join(output_lines),
                    first_seen=now, last_seen=now,
                    **_easm_metadata_kwargs(pid, extra_cwes=subissue_cwes),
                ))

        _emit_audit_finding(
            pid="EASM-HTTP-HEADER-WEAK",
            title="Weak HTTP Security Headers",
            owner="IT",
            synopsis=f"{hostname} is missing or weakly configuring one or more HTTP security headers.",
            description=(
                "The OWASP Secure Headers Project recommends setting "
                "Strict-Transport-Security, Content-Security-Policy, "
                "X-Frame-Options (or CSP frame-ancestors), X-Content-Type-Options, "
                "Referrer-Policy, and Permissions-Policy on every HTTP response. "
                "Missing headers expose the application to clickjacking, MIME "
                "sniffing, referrer leakage, and protocol-downgrade attacks."
            ),
            solution=(
                "Add the missing response headers at the web server, reverse "
                "proxy, or CDN layer. Prefer HSTS max-age of 1 year or longer "
                "with includeSubDomains; set X-Content-Type-Options: nosniff; "
                "define an explicit Content-Security-Policy."
            ),
            matching_ids=header_ids,
        )

        _emit_audit_finding(
            pid="EASM-COOKIE-WEAK",
            title="Insecure Cookie Attributes",
            owner="IT",
            synopsis=f"{hostname} emits cookies without Secure, HttpOnly, or SameSite flags.",
            description=(
                "Cookies set without Secure can be exfiltrated over cleartext "
                "HTTP; cookies without HttpOnly are readable by JavaScript and "
                "enable session hijacking via XSS; cookies without SameSite are "
                "sent on cross-site requests and enable CSRF. "
                "SameSite=None without Secure is rejected by modern browsers."
            ),
            solution=(
                "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all "
                "session and CSRF-protection cookies. Use SameSite=None only "
                "when cross-site cookie delivery is required, and always "
                "combine it with Secure."
            ),
            matching_ids=cookie_ids,
        )

    # ── Deep TLS audit (sslyze cipher enum + chain + OCSP + CAA) ──
    # Source: hakuna-scanner app.ingest.tls_deep_audit. One finding per
    # concern, bundling all related issues and taking worst severity.
    deep_audit = ea.get("tls_deep_audit") or {}
    deep_issues = deep_audit.get("issues") or []
    if deep_issues:
        def _emit_deep_finding(pid, title, owner, synopsis, description, solution, matching_ids, effort="medium"):
            matches = [i for i in deep_issues if i.get("id") in matching_ids]
            if not matches:
                return
            sev = max(int(i.get("severity", 0)) for i in matches)
            sev_label = SEVERITY_LABELS.get(sev, "Info")
            priority = {4: 9.0, 3: 7.0, 2: 5.5, 1: 3.0, 0: 1.0}.get(sev, 1.0)

            output_lines = [f"Host: {hostname}"]
            port = deep_audit.get("port")
            if port:
                output_lines.append(f"Port: {port}")
            output_lines.append("Issues:")
            output_lines.extend(f"  - {i.get('detail', i.get('id'))}" for i in matches)

            if pid in existing_plugins:
                db.query(Finding).filter(
                    Finding.scan_id == scan_id,
                    Finding.asset_id == asset.id,
                    Finding.plugin_id == pid,
                ).update({
                    "severity": sev,
                    "severity_label": sev_label,
                    "risk_factor": sev_label,
                    "priority_score": priority,
                    "last_seen": now,
                    "plugin_output": "\n".join(output_lines),
                })
            else:
                findings_to_add.append(Finding(
                    scan_id=scan_id, asset_id=asset.id,
                    source_type="easm", source_vuln_id=pid,
                    plugin_id=pid,
                    plugin_name=title,
                    severity=sev, severity_label=sev_label, risk_factor=sev_label,
                    priority_score=priority, effort_level=effort,
                    owner_suggestion=owner,
                    synopsis=synopsis,
                    description=description,
                    solution=solution,
                    plugin_output="\n".join(output_lines),
                    first_seen=now, last_seen=now,
                    **_easm_metadata_kwargs(pid),
                ))

        _emit_deep_finding(
            pid="EASM-TLS-CIPHER-ACCEPTED",
            title="Server Accepts Weak TLS Ciphers or Deprecated Versions",
            owner="IT",
            synopsis=f"{hostname} accepts weak cipher suites or deprecated TLS versions during negotiation.",
            description=(
                "Distinct from the negotiated-cipher check (EASM-TLS-WEAK): even "
                "when a modern client negotiates TLS 1.3 with a strong AEAD "
                "cipher, the server may still accept SSLv3, TLS 1.0/1.1, or "
                "weak ciphers (RC4, 3DES, NULL, EXPORT, anon, MD5) for clients "
                "that offer them. Attackers use downgrade and legacy-client "
                "paths (POODLE, BEAST, SWEET32, FREAK) against exactly this."
            ),
            solution=(
                "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 entirely. Remove "
                "cipher suites containing RC4, 3DES, DES, NULL, EXPORT, MD5, "
                "or anonymous key exchange from the server configuration. "
                "Prefer TLS 1.2 + TLS 1.3 with AEAD suites only."
            ),
            matching_ids={"tls-broken-version-accepted", "tls-deprecated-version-accepted", "tls-weak-cipher-accepted"},
        )

        _emit_deep_finding(
            pid="EASM-CERT-CHAIN-UNTRUSTED",
            title="Certificate Chain Does Not Validate to a Trusted Root",
            owner="IT",
            synopsis=f"{hostname} presents a certificate chain that fails trust store validation.",
            description=(
                "The certificate chain presented by the server did not validate "
                "against one or more standard trust stores (Mozilla, Apple, "
                "Microsoft, Java, Android). Clients will show certificate "
                "warnings; automated clients may refuse to connect entirely."
            ),
            solution=(
                "Rebuild the certificate chain with all required intermediate "
                "certificates. Verify the server serves the full chain (leaf "
                "+ intermediates) in the correct order. Confirm the root CA "
                "is present in major trust stores."
            ),
            matching_ids={"cert-chain-untrusted"},
        )

        _emit_deep_finding(
            pid="EASM-CERT-OCSP",
            title="OCSP Reports Certificate as Revoked",
            owner="IT",
            synopsis=f"{hostname} is serving a revoked certificate according to OCSP.",
            description=(
                "The Online Certificate Status Protocol (OCSP) responder "
                "returned a 'revoked' status for this certificate. Continuing "
                "to serve a revoked certificate is a security incident — it "
                "indicates either key compromise or a configuration that was "
                "not rotated after revocation."
            ),
            solution=(
                "Identify why the certificate was revoked, rotate any "
                "potentially compromised keys, and deploy a new certificate "
                "immediately. Check ACME / CA dashboards for the revocation "
                "reason code."
            ),
            matching_ids={"cert-revoked"},
            effort="high",
        )

        _emit_deep_finding(
            pid="EASM-CERT-CAA-MISMATCH",
            title="CAA Records Do Not Authorize Certificate Issuer",
            owner="IT",
            synopsis=f"{hostname} has CAA DNS records that do not include the issuing CA.",
            description=(
                "RFC 8659 Certification Authority Authorization (CAA) DNS "
                "records constrain which CAs may issue certificates for a "
                "domain. The CAA records for this host do not authorize the "
                "CA that issued the current certificate. Either the CAA "
                "record is stale, or a certificate was issued in violation "
                "of the published policy — which in turn suggests the CAA "
                "check is not being enforced at issuance time, or the "
                "domain's DNS was manipulated."
            ),
            solution=(
                "Reconcile the CAA records with the CA you intend to use. "
                "Either update the CAA record (DNS) to include the current "
                "issuer, or reissue the certificate with a CA that the CAA "
                "record already authorizes."
            ),
            matching_ids={"cert-caa-mismatch"},
        )

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
                severity=0, severity_label="Info", risk_factor="None",
                priority_score=0.5, effort_level="quick_win", owner_suggestion="IT",
                synopsis=f"{hostname} is behind CDN provider '{cdn}'.",
                description=f"External scanning detected that {hostname} routes traffic through {cdn} CDN. "
                            f"This means the origin server IP may be hidden behind CDN infrastructure.",
                solution="No action required. Ensure CDN configuration is properly secured.",
                plugin_output=f"CDN Provider: {cdn}\nHost: {hostname}",
                first_seen=now, last_seen=now,
                **_easm_metadata_kwargs(pid),
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
                severity=0, severity_label="Info", risk_factor="None",
                priority_score=0.5, effort_level="quick_win", owner_suggestion="SecOps",
                synopsis=f"{hostname} is protected by WAF '{waf}'.",
                description=f"External scanning detected that {hostname} is protected by the {waf} web application firewall.",
                solution="No action required. Ensure WAF rules are kept up to date.",
                plugin_output=f"WAF: {waf}\nHost: {hostname}",
                first_seen=now, last_seen=now,
                **_easm_metadata_kwargs(pid),
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
                severity=0, severity_label="Info", risk_factor="None",
                priority_score=1.0, effort_level="quick_win", owner_suggestion="IT",
                port="443" if http_url.startswith("https") else "80", protocol="tcp",
                synopsis=f"HTTP service detected on {hostname}.",
                description=f"External HTTP probing of {hostname} returned status {http_status}.",
                solution="No action required. Verify the service should be publicly accessible.",
                plugin_output=f"URL: {http_url}\nStatus: {http_status}\nTitle: {http_title}",
                first_seen=now, last_seen=now,
                **_easm_metadata_kwargs(pid),
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

    # ── Pending upstream detections ───────────────────────────────
    # These plugin_ids are registered in services.easm_taxonomy so compliance
    # rules referencing CWE-1385 / CWE-284 / CWE-548 / CWE-798 validate at
    # mapping load time. They emit only when hakuna-scanner populates the
    # corresponding signal field on ea — until then the loops are no-ops.
    for tk in (ea.get("subdomain_takeovers") or []):
        target = (tk.get("target") or "").strip()
        cname = (tk.get("cname") or "").strip()
        fingerprint = (tk.get("fingerprint") or "").strip()
        if not target:
            continue
        pid = "EASM-SUBDOMAIN-TAKEOVER"
        if pid in existing_plugins:
            continue
        findings_to_add.append(Finding(
            scan_id=scan_id, asset_id=asset.id,
            source_type="easm", source_vuln_id=pid,
            plugin_id=pid,
            plugin_name=f"Subdomain Takeover: {target}",
            severity=4, severity_label="Critical", risk_factor="Critical",
            priority_score=9.0, effort_level="medium", owner_suggestion="SecOps",
            synopsis=f"{target} resolves to a dangling CNAME ({cname}) on a takeover-prone provider.",
            description=(
                f"External DNS resolution shows {target} CNAME → {cname}. The target "
                f"resource appears unclaimed on its hosting provider, allowing an "
                f"attacker to register the resource and serve arbitrary content under "
                f"your domain. Fingerprint: {fingerprint or 'unknown'}."
            ),
            solution=(
                "Either reclaim the resource on the upstream provider or remove the "
                "DNS record. Audit all CNAMEs pointing at third-party infrastructure "
                "for similar dangling references."
            ),
            plugin_output=f"Target: {target}\nCNAME: {cname}\nFingerprint: {fingerprint}",
            first_seen=now, last_seen=now,
            **_easm_metadata_kwargs(pid, exploit_available=True),
        ))

    for panel in (ea.get("exposed_admin_panels") or []):
        url = (panel.get("url") or "").strip()
        panel_type = (panel.get("panel_type") or "Admin Panel").strip()
        if not url:
            continue
        pid = "EASM-EXPOSED-ADMIN-PANEL"
        if pid in existing_plugins:
            continue
        findings_to_add.append(Finding(
            scan_id=scan_id, asset_id=asset.id,
            source_type="easm", source_vuln_id=pid,
            plugin_id=pid,
            plugin_name=f"Exposed Admin Panel: {panel_type}",
            severity=3, severity_label="High", risk_factor="High",
            priority_score=7.5, effort_level="medium", owner_suggestion="SecOps",
            synopsis=f"Administrative interface for {panel_type} is reachable from the internet at {url}.",
            description=(
                f"External probing identified a {panel_type} login at {url} reachable "
                f"from the public internet. Admin interfaces should sit behind a VPN, "
                f"IP allowlist, or zero-trust proxy."
            ),
            solution=(
                "Restrict the admin interface to internal networks or a VPN. If public "
                "exposure is required, enforce SSO/MFA, rate limit logins, and monitor "
                "for credential stuffing."
            ),
            plugin_output=f"URL: {url}\nPanel: {panel_type}",
            first_seen=now, last_seen=now,
            **_easm_metadata_kwargs(pid),
        ))

    for listing in (ea.get("directory_listings") or []):
        url = (listing.get("url") or "").strip()
        files_count = listing.get("files_count")
        if not url:
            continue
        pid = "EASM-DIRECTORY-LISTING"
        if pid in existing_plugins:
            continue
        findings_to_add.append(Finding(
            scan_id=scan_id, asset_id=asset.id,
            source_type="easm", source_vuln_id=pid,
            plugin_id=pid,
            plugin_name="Directory Listing Enabled",
            severity=2, severity_label="Medium", risk_factor="Medium",
            priority_score=5.5, effort_level="quick_win", owner_suggestion="IT",
            synopsis=f"Directory listing is enabled at {url}.",
            description=(
                f"External probing of {url} returned a directory index. Auto-generated "
                f"directory listings expose filenames, sizes, and timestamps to anyone "
                f"who can reach the URL — useful reconnaissance for attackers and a "
                f"common path to leaked backups, configs, or source archives."
            ),
            solution=(
                "Disable autoindex / directory listing at the web server (e.g. nginx "
                "`autoindex off`, Apache `Options -Indexes`). Audit the directory for "
                "files that should not be web-accessible."
            ),
            plugin_output=f"URL: {url}\nFiles: {files_count if files_count is not None else 'unknown'}",
            first_seen=now, last_seen=now,
            **_easm_metadata_kwargs(pid),
        ))

    for leak in (ea.get("leaked_credentials") or []):
        source = (leak.get("source") or "external").strip()
        snippet = (leak.get("snippet") or "").strip()
        pid = "EASM-LEAKED-CREDENTIAL"
        if pid in existing_plugins:
            continue
        findings_to_add.append(Finding(
            scan_id=scan_id, asset_id=asset.id,
            source_type="easm", source_vuln_id=pid,
            plugin_id=pid,
            plugin_name=f"Leaked Credential ({source})",
            severity=4, severity_label="Critical", risk_factor="Critical",
            priority_score=9.0, effort_level="medium", owner_suggestion="SecOps",
            synopsis=f"A credential associated with {hostname} was found exposed in {source}.",
            description=(
                f"External monitoring detected a credential matching {hostname} in "
                f"{source}. Leaked credentials enable account takeover and lateral "
                f"movement; they require immediate rotation and an investigation into "
                f"whether they have been used."
            ),
            solution=(
                "Rotate the credential immediately. Audit recent authentication logs "
                "for use of the leaked value. If the credential was hardcoded in "
                "source, scrub git history and add a secret-scanning policy."
            ),
            plugin_output=f"Host: {hostname}\nSource: {source}\nSnippet: {snippet[:200]}",
            first_seen=now, last_seen=now,
            **_easm_metadata_kwargs(pid, exploit_available=True),
        ))

    # ── CVEs via CPE → CVE correlation ────────────────────────────
    # Matches CPEs (populated by hakuna-scanner's CPE inference layer) against
    # the ThreatCVE table. Version-less CPEs ("cpe:2.3:a:nginx:nginx:*:...")
    # are skipped by the matcher — they produce no finding but still route
    # Nuclei templates via the VM scanner. See services/cpe_matcher.py.
    cpe_list = _filter_cpe_list(ea.get("cpe_list") or [])
    if cpe_list:
        # Persist software inventory before findings so SBOMComponent rows
        # are rebuilt against fresh inventory at finalize time.
        try:
            _upsert_inventory_software_from_cpes(db, scan_id, asset.id, cpe_list)
        except Exception:
            logger.exception(
                f"Inventory upsert from CPEs failed for {hostname} (non-fatal)"
            )

        from services.cpe_matcher import match_cves_for_cpes, parse_cpe
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

            # Embed the matched product (and version when known) in plugin_name
            # so sbom_pipeline.build_sbom_from_inventory can link this CVE
            # finding to its SBOMComponent via substring match.
            parsed_cpe = parse_cpe(matched_cpe) if matched_cpe else None
            if parsed_cpe:
                product_label = parsed_cpe.product
                if parsed_cpe.has_version:
                    product_label = f"{parsed_cpe.product} {parsed_cpe.version}"
                plugin_name = f"{cve_id}: {product_label} — Known vulnerability{badge_str}"
            else:
                plugin_name = f"{cve_id}: Known vulnerability{badge_str}"

            findings_to_add.append(Finding(
                scan_id=scan_id, asset_id=asset.id,
                source_type="easm", source_vuln_id=cve_id,
                plugin_id=pid,
                plugin_name=plugin_name,
                severity=sev, severity_label=sev_label, risk_factor=risk,
                priority_score=round(priority, 1),
                effort_level="medium",
                owner_suggestion="SecOps",
                cves=[cve_id],
                cvss2_score=cve.get("cvss2_score"),
                cvss3_score=cvss or None,
                cvss3_vector=cve.get("cvss3_vector"),
                cvss4_score=cve.get("cvss4_score"),
                cvss4_vector=cve.get("cvss4_vector"),
                is_kev=cve.get("in_kev", False),
                exploit_available=cve.get("has_public_exploit", False),
                exploit_count=cve.get("exploit_count") or 0,
                exploit_maturity_level=cve.get("exploit_maturity_level"),
                epss_score=cve.get("epss_score"),
                epss_percentile=cve.get("epss_percentile"),
                ransomware_linked=cve.get("ransomware_linked", False),
                trending_in_news=cve.get("trending_in_news", False),
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
                    f"Public exploit: {cve.get('has_public_exploit', False)}\n"
                    f"EPSS: {cve.get('epss_score', 'N/A')}\n"
                    f"Exploit maturity: {cve.get('exploit_maturity_level', 'N/A')}"
                ),
                first_seen=now, last_seen=now,
                **_easm_metadata_kwargs(
                    pid,
                    is_kev=bool(cve.get("in_kev")),
                    exploit_available=bool(cve.get("has_public_exploit")),
                ),
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

    new_finding_ids = [f.id for f in findings_to_add if f.id is not None]
    return len(findings_to_add), new_finding_ids


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
) -> Tuple[int, int, list, list]:
    """Upsert assets belonging to a specific domain into a scan.

    Returns ``(upserted_count, findings_created, new_asset_ids, new_finding_ids)``.
    The ID lists cover only rows that were newly inserted (not updated in place)
    so callers can feed them into finalize_batch for streaming post-ingest.

    Uses upsert logic (update existing asset by IP/hostname if it already exists in this scan)
    to preserve stable asset IDs. This is critical for cross-source dedup: VM scan findings
    may reference EASM asset IDs, and deleting/recreating those assets would orphan the findings.
    """
    created = 0
    findings_created = 0
    new_asset_ids: list[int] = []
    new_finding_ids: list[int] = []
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

    # Pre-build the (kind, identity) lookup used by _promote_easm_subassets so
    # the per-host promotion stays idempotent within a scan without an extra
    # query per asset. asset_identity is a JSON column (not JSONB) so we
    # filter in Python rather than via SQL JSON path.
    existing_subassets = _build_subasset_lookup(scan.id, db)

    for ea in easm_assets:
        raw_hostname = ea.get("hostname", "") or ""
        raw_ip = ea.get("ip", "") or ""
        if not raw_hostname and not raw_ip:
            continue

        # Filter: only assets whose hostname ends with this domain.
        # Skip the filter when the "hostname" value is actually an IP (it can't
        # match any domain suffix) — _resolve_host_fields will reclassify it.
        if raw_hostname and not _is_ipv4(raw_hostname) and not raw_hostname.lower().endswith(domain.lower()):
            continue

        ip, hostname_short, fqdn = _resolve_host_fields(raw_hostname, raw_ip)
        # Domain-scope filter for reverse-DNS-derived hostnames: if we synthesized
        # a hostname from rDNS that doesn't match the domain scope, discard it
        # but keep the IP-only asset.
        if fqdn and not fqdn.lower().endswith(domain.lower()) and not raw_hostname:
            hostname_short = None
            fqdn = None
        hostname = hostname_short  # UI/query references below expect `hostname`
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
            or (hostname and existing_by_hostname.get(hostname))
        )
        if asset:
            # Update in-place to preserve asset.id (cross-scan findings may reference it)
            asset.ip = ip or asset.ip
            asset.hostname = hostname or asset.hostname
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

            # Fingerprint fallback: if user-defined rules didn't classify this
            # asset and EASM detected an HTTP service on it, treat it as a
            # web_app so it can dedup against Nessus WAS / VM scanner rows that
            # target the same URL. Without this, EASM defaults to `host` and
            # cross-source dedup silently splits a single logical asset into
            # three (host + web_app + web_app).
            if not type_kwargs:
                http_url = (ea.get("http_url") or "").strip()
                if http_url:
                    from services.dedup import normalize_web_app_url
                    type_kwargs = {
                        "asset_type": "web_app",
                        "asset_identity": {"url": normalize_web_app_url(http_url) or http_url},
                        "asset_attributes": {},
                    }

            asset = Asset(
                scan_id=scan.id,
                ip=ip,
                hostname=hostname,
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
            new_asset_ids.append(asset.id)
        created += 1

        # Record per-source observation for EASM
        record_observation(
            db, asset_id=asset.id, source_system="easm",
            raw_fields={"ip": ip, "hostname": hostname, "fqdn": fqdn,
                         "os": os_hint, "easm_data": easm_data},
            scan_id=scan.id, org_id=scan.org_id,
        )

        # Write internet_to_asset edges into the unified graph (Phase 1
        # of the chain coordinator). Non-fatal — edge emission must not
        # break asset ingest.
        try:
            from services.asset_edges import write_easm_internet_edges
            write_easm_internet_edges(
                db,
                org_id=scan.org_id,
                asset_id=asset.id,
                open_ports=ea.get("open_ports"),
                confidence="high",
            )
        except Exception:
            logger.exception("internet_to_asset edge write failed for asset %s", asset.id)
            db.rollback()

        fcount, fids = _generate_easm_findings(db, scan.id, asset, ea)
        findings_created += fcount
        new_finding_ids.extend(fids)

        # Promote scanner classifications into first-class child assets
        # (ai_agent / mcp_server / cloud_storage_bucket). Non-fatal: a
        # failure here must not break asset ingest for the parent host.
        try:
            child_ids = _promote_easm_subassets(
                db, scan, asset, ea, now, existing_subassets,
            )
            if child_ids:
                new_asset_ids.extend(child_ids)
                created += len(child_ids)
        except Exception:
            logger.exception("subasset promotion failed for asset %s", asset.id)
            db.rollback()

    return created, findings_created, new_asset_ids, new_finding_ids


# ── First-class child-asset promotion (ai_agent / mcp_server / bucket) ──

# Asset kinds the EASM ingest promotes from scanner classifier output.
# These sit "on top of" the host (one host can serve multiple AI apps),
# linked back via ``asset_attributes.parent_asset_id``.
_PROMOTE_AS_CHILD = {"ai_agent", "mcp_server"}

# CNAME suffixes that identify cloud storage buckets. We match on
# substring rather than exact suffix because providers expose multiple
# variants (regional endpoints, website endpoints, dualstack hostnames)
# whose only stable signal is the suffix family.
_BUCKET_CNAME_PATTERNS: list[tuple[str, str]] = [
    (".s3.amazonaws.com", "aws_s3"),
    (".s3-website", "aws_s3"),
    (".s3-accelerate.amazonaws.com", "aws_s3"),
    (".s3.dualstack.", "aws_s3"),
    (".s3.", "aws_s3"),
    (".storage.googleapis.com", "gcs"),
    (".blob.core.windows.net", "azure_blob"),
    (".web.core.windows.net", "azure_blob"),
    (".r2.cloudflarestorage.com", "cloudflare_r2"),
    (".digitaloceanspaces.com", "do_spaces"),
]


def _detect_bucket_from_cname(cname: str) -> Optional[tuple[str, str]]:
    """Return (provider, bucket_name) if cname matches a bucket pattern.

    The bucket name is the leftmost label of the CNAME — the only
    component that's stable across provider URL formats.
    """
    if not cname:
        return None
    cname_lower = str(cname).lower().rstrip(".")
    for suffix, provider in _BUCKET_CNAME_PATTERNS:
        if suffix in cname_lower:
            bucket_name = cname_lower.split(".", 1)[0]
            if bucket_name and bucket_name != cname_lower:
                return provider, bucket_name
    return None


def _build_subasset_lookup(scan_id: int, db: Session) -> dict[tuple, Asset]:
    """Build a (asset_type, identity-tuple) → Asset lookup for this scan.

    Mirrors the pattern in ``_import_github_npm_assets``. Lets the
    promotion path stay idempotent within a scan without a per-asset
    JSON-column query (assets.asset_identity is JSON, not JSONB, so
    SQL-side path filtering is unreliable).
    """
    out: dict[tuple, Asset] = {}
    rows = db.query(Asset).filter(
        Asset.scan_id == scan_id,
        Asset.asset_type.in_(("ai_agent", "mcp_server", "cloud_storage_bucket")),
    ).all()
    for a in rows:
        ident = a.asset_identity or {}
        if a.asset_type in _PROMOTE_AS_CHILD:
            out[(a.asset_type, ident.get("url"))] = a
        elif a.asset_type == "cloud_storage_bucket":
            out[(a.asset_type, ident.get("provider"), ident.get("bucket_name"))] = a
    return out


def _promote_easm_subassets(
    db: Session,
    scan: Scan,
    host_asset: Asset,
    ea: dict,
    now: datetime,
    existing: dict[tuple, Asset],
) -> list[int]:
    """Create first-class child Assets from scanner classifier output.

    Two promotion paths today:

    * ``asset_type`` in {ai_agent, mcp_server} — child sits on the host,
      keyed by URL, parent_asset_id back-references the host.
    * ``dns_records.CNAME`` matches a known bucket suffix —
      cloud_storage_bucket asset keyed by (provider, bucket_name).

    Idempotent within a scan via the pre-built ``existing`` lookup.
    Returns IDs of newly created rows only.
    """
    new_ids: list[int] = []
    asset_type = (ea.get("asset_type") or "").lower()
    hostname = host_asset.hostname or host_asset.fqdn

    # ── ai_agent / mcp_server ─────────────────────────────────────
    if asset_type in _PROMOTE_AS_CHILD and hostname:
        url = (ea.get("http_url") or f"https://{hostname}").strip()
        identity = {"url": url, "host": hostname}
        attributes = {
            "parent_asset_id": host_asset.id,
            "service": asset_type,
            "tech_stack": ea.get("tech_stack") or [],
        }
        key = (asset_type, url)
        a = existing.get(key)
        if a:
            a.asset_attributes = {**(a.asset_attributes or {}), **attributes}
            a.last_seen = now
            sources = a.source_systems or []
            if "easm" not in sources:
                a.source_systems = sources + ["easm"]
        else:
            a = Asset(
                scan_id=scan.id,
                hostname=hostname,
                ip=host_asset.ip,
                asset_type=asset_type,
                asset_identity=identity,
                asset_attributes=attributes,
                is_internet_facing=host_asset.is_internet_facing,
                environment_tag=host_asset.environment_tag or "external",
                criticality=host_asset.criticality or 5,
                first_seen=now,
                last_seen=now,
                source_systems=["easm"],
            )
            db.add(a)
            db.flush()
            existing[key] = a
            new_ids.append(a.id)

    # ── cloud_storage_bucket ──────────────────────────────────────
    dns_records = ea.get("dns_records") or {}
    cnames = dns_records.get("CNAME") or dns_records.get("cname") or []
    if isinstance(cnames, str):
        cnames = [cnames]
    for cname in cnames:
        match = _detect_bucket_from_cname(cname)
        if not match:
            continue
        provider, bucket_name = match
        bucket_fqdn = str(cname).lower().rstrip(".")
        identity = {"provider": provider, "bucket_name": bucket_name}
        attributes = {
            "parent_asset_id": host_asset.id,
            "fronting_host": hostname,
            "cname": bucket_fqdn,
        }
        key = ("cloud_storage_bucket", provider, bucket_name)
        a = existing.get(key)
        if a:
            a.asset_attributes = {**(a.asset_attributes or {}), **attributes}
            a.last_seen = now
            sources = a.source_systems or []
            if "easm" not in sources:
                a.source_systems = sources + ["easm"]
        else:
            a = Asset(
                scan_id=scan.id,
                hostname=bucket_fqdn,
                fqdn=bucket_fqdn,
                asset_type="cloud_storage_bucket",
                asset_identity=identity,
                asset_attributes=attributes,
                is_internet_facing=True,
                environment_tag="external",
                criticality=5,
                first_seen=now,
                last_seen=now,
                source_systems=["easm"],
            )
            db.add(a)
            db.flush()
            existing[key] = a
            new_ids.append(a.id)
        # First matching CNAME wins — a host typically fronts at most one bucket.
        break

    return new_ids


# ── GitHub/npm attribution ingest ───────────────────────────────────

# severity strings emitted by hakuna-scanner ExposedFile/WorkflowRisk records
# → numeric levels matching Finding.severity (4=Critical … 0=Info).
_GH_SEVERITY_MAP: dict[str, tuple[int, str, str, float]] = {
    "critical": (4, "Critical", "Critical", 9.0),
    "high":     (3, "High",     "High",     7.5),
    "medium":   (2, "Medium",   "Medium",   5.0),
    "low":      (1, "Low",      "Low",      3.0),
    "info":     (0, "Info",     "None",     1.0),
}


def _split_repo_full_name(full_name: str) -> tuple[str, str]:
    """Split "owner/repo" into ("owner", "repo"); empty strings on malformed input."""
    if not full_name or "/" not in full_name:
        return "", full_name or ""
    owner, _, repo = full_name.partition("/")
    return owner, repo


def _import_github_npm_assets(
    db: Session, scan: Scan, result: dict, domain: str,
) -> Tuple[int, int, list, list]:
    """Upsert code_repo / github_org / github_user / npm_package assets from a
    DiscoveryResult, plus exposed-file findings on the matching repo assets.

    Returns ``(asset_count, finding_count, new_asset_ids, new_finding_ids)``.
    Idempotent within a scan: existing assets matched by (asset_type, identity)
    are updated in place; existing findings keyed by (plugin_id, asset_id) are
    refreshed. Cross-scan dedup runs later via the standard dedup_config.
    """
    attributed = (result or {}).get("attributed_assets") or {}
    vulns = (result or {}).get("vulnerabilities") or {}
    now = datetime.utcnow()

    new_asset_ids: list[int] = []
    new_finding_ids: list[int] = []
    asset_count = 0

    # Build lookup of existing assets in this scan by (asset_type, identity-tuple)
    existing: dict[tuple[str, tuple], Asset] = {}
    for a in db.query(Asset).filter(Asset.scan_id == scan.id).all():
        if not a.asset_type or not a.asset_identity:
            continue
        ident = a.asset_identity or {}
        if a.asset_type == "code_repo":
            key = (a.asset_type, (ident.get("provider"), ident.get("org"), ident.get("repo")))
        elif a.asset_type in ("github_org", "github_user"):
            key = (a.asset_type, (ident.get("provider"), ident.get("login")))
        elif a.asset_type == "npm_package":
            key = (a.asset_type, (ident.get("registry"), ident.get("name")))
        else:
            continue
        existing[key] = a

    def _upsert(asset_type: str, identity: dict, attributes: dict) -> Asset:
        nonlocal asset_count
        if asset_type == "code_repo":
            key = (asset_type, (identity.get("provider"), identity.get("org"), identity.get("repo")))
        elif asset_type in ("github_org", "github_user"):
            key = (asset_type, (identity.get("provider"), identity.get("login")))
        else:  # npm_package
            key = (asset_type, (identity.get("registry"), identity.get("name")))

        a = existing.get(key)
        if a:
            a.asset_attributes = {**(a.asset_attributes or {}), **attributes}
            a.last_seen = now
            sources = a.source_systems or []
            if "easm" not in sources:
                a.source_systems = sources + ["easm"]
        else:
            a = Asset(
                scan_id=scan.id,
                asset_type=asset_type,
                asset_identity=identity,
                asset_attributes=attributes,
                is_internet_facing=True,
                environment_tag="external",
                criticality=5,
                first_seen=now,
                last_seen=now,
                source_systems=["easm"],
            )
            db.add(a)
            db.flush()
            existing[key] = a
            new_asset_ids.append(a.id)
        record_observation(
            db, asset_id=a.id, source_system="easm",
            raw_fields={"asset_type": asset_type, "identity": identity, "attributes": attributes},
            scan_id=scan.id, org_id=scan.org_id,
        )
        asset_count += 1
        return a

    # ── github_org assets ─────────────────────────────────────────
    for org in attributed.get("github_orgs") or []:
        login = org.get("login")
        if not login:
            continue
        _upsert(
            "github_org",
            {"provider": "github", "login": login},
            {
                "url": org.get("url"),
                "blog": org.get("blog"),
                "email": org.get("email"),
                "is_verified_domain": bool(org.get("is_verified_domain")),
                "domain_match": org.get("domain_match"),
                "confidence_score": org.get("confidence_score"),
                "reasons": org.get("reasons") or [],
                "discovered_for_domain": domain,
            },
        )

    # ── github_user assets ────────────────────────────────────────
    for user in attributed.get("github_users") or []:
        login = user.get("login")
        if not login:
            continue
        _upsert(
            "github_user",
            {"provider": "github", "login": login},
            {
                "url": user.get("url"),
                "email": user.get("email"),
                "confidence_score": user.get("confidence_score"),
                "reasons": user.get("reasons") or [],
                "discovered_for_domain": domain,
            },
        )

    # ── code_repo assets ──────────────────────────────────────────
    repo_assets_by_full_name: dict[str, Asset] = {}
    for repo in attributed.get("github_repos") or []:
        full_name = repo.get("full_name") or ""
        owner, name = _split_repo_full_name(full_name)
        if not owner or not name:
            continue
        a = _upsert(
            "code_repo",
            {"provider": "github", "org": owner, "repo": name},
            {
                "full_name": full_name,
                "url": repo.get("url"),
                "clone_url": repo.get("clone_url"),
                "default_branch": repo.get("default_branch") or "main",
                "owner_login": repo.get("owner_login"),
                "owner_type": repo.get("owner_type"),
                "is_fork": bool(repo.get("is_fork")),
                "archived": bool(repo.get("archived")),
                "stars": repo.get("stars") or 0,
                "language": repo.get("language"),
                "pushed_at": repo.get("pushed_at"),
                "confidence_score": repo.get("confidence_score"),
                "reasons": repo.get("reasons") or [],
                "discovered_for_domain": domain,
            },
        )
        repo_assets_by_full_name[full_name] = a

    # ── npm_package assets ────────────────────────────────────────
    for pkg in attributed.get("npm_packages") or []:
        name = pkg.get("name")
        if not name:
            continue
        _upsert(
            "npm_package",
            {"registry": "npm", "name": name},
            {
                "version": pkg.get("version"),
                "maintainers": pkg.get("maintainers") or [],
                "repository_url": pkg.get("repository_url"),
                "homepage": pkg.get("homepage"),
                "last_published": pkg.get("last_published"),
                "confidence_score": pkg.get("confidence_score"),
                "reasons": pkg.get("reasons") or [],
                "discovered_for_domain": domain,
            },
        )

    # ── exposed_files findings on code_repo assets ────────────────
    # Each ExposedFile becomes one Finding on the parent code_repo asset.
    # We use a stable plugin_id per rule_id so multiple files of the same
    # type on one repo dedup, but different rule types coexist.
    findings_to_add: list[Finding] = []
    # Pre-fetch existing easm-source findings on repo assets in this scan to
    # detect duplicates and refresh in place rather than re-inserting.
    repo_asset_ids = [a.id for a in repo_assets_by_full_name.values()]
    existing_findings: dict[tuple[int, str], Finding] = {}
    if repo_asset_ids:
        for f in db.query(Finding).filter(
            Finding.scan_id == scan.id,
            Finding.asset_id.in_(repo_asset_ids),
            Finding.source_type == "easm",
        ).all():
            existing_findings[(f.asset_id, f.plugin_id)] = f

    finding_count = 0
    for ef in vulns.get("exposed_files") or []:
        repo_full_name = ef.get("repo") or ""
        asset = repo_assets_by_full_name.get(repo_full_name)
        if not asset:
            continue
        rule_id = (ef.get("rule_id") or "unknown").upper()
        pid = f"EASM-EXPOSED-FILE-{rule_id}"
        sev_key = (ef.get("severity") or "medium").lower()
        sev, sev_label, risk, priority = _GH_SEVERITY_MAP.get(
            sev_key, _GH_SEVERITY_MAP["medium"],
        )
        path = ef.get("path") or ""
        url = ef.get("url") or ""
        detail = ef.get("detail") or ""
        plugin_output = "\n".join(filter(None, [
            f"Repository: {repo_full_name}",
            f"Path: {path}",
            f"URL: {url}",
            f"Detail: {detail}" if detail else "",
        ]))
        existing = existing_findings.get((asset.id, pid))
        if existing:
            existing.severity = sev
            existing.severity_label = sev_label
            existing.risk_factor = risk
            existing.priority_score = priority
            existing.last_seen = now
            existing.plugin_output = plugin_output
            finding_count += 1
            continue

        findings_to_add.append(Finding(
            scan_id=scan.id, asset_id=asset.id,
            source_type="easm", source_vuln_id=pid,
            plugin_id=pid,
            plugin_name=f"Exposed {rule_id} file in public repository",
            plugin_family="EASM: Other",
            severity=sev, severity_label=sev_label, risk_factor=risk,
            priority_score=priority, effort_level="medium",
            owner_suggestion="AppSec",
            synopsis=(
                f"A well-known sensitive file ({path}) is publicly accessible in "
                f"GitHub repository {repo_full_name}."
            ),
            description=(
                f"The file path '{path}' was found in the public repository "
                f"{repo_full_name}. Files matching the rule '{rule_id}' commonly "
                f"contain credentials, infrastructure secrets, or other sensitive "
                f"data that should not be published. Only the file's presence at a "
                f"known path was recorded — content was not retrieved."
            ),
            solution=(
                "Review the file and rotate any credentials or secrets it contains. "
                "Remove the file from the repository and rewrite history "
                "(e.g. `git filter-repo`) so the leaked content is not retrievable "
                "from the commit log. Add the path to .gitignore and consider "
                "enabling secret scanning / push protection on the repository."
            ),
            plugin_output=plugin_output,
            first_seen=now, last_seen=now,
        ))
        finding_count += 1

    for f in findings_to_add:
        f.source_systems = ["easm"]
    if findings_to_add:
        db.add_all(findings_to_add)
        db.flush()
        from services.asset_observations import record_finding_observation
        for f in findings_to_add:
            record_finding_observation(
                db, finding_id=f.id, source_system="easm",
                raw_fields={"plugin_id": f.plugin_id, "plugin_name": f.plugin_name,
                             "severity": f.severity, "plugin_output": f.plugin_output},
                scan_id=scan.id, org_id=scan.org_id,
            )
            if f.id is not None:
                new_finding_ids.append(f.id)

    return asset_count, finding_count, new_asset_ids, new_finding_ids


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

    created, findings_created, _new_asset_ids, _new_finding_ids = _import_assets_for_domain(
        db, scan, easm_assets, domain,
    )

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
    try:
        from services.post_ingest import finalize_scan
        finalize_scan(db, scan_id=scan.id, org_id=org.id)
        db.commit()
    except Exception:
        logger.exception("finalize_scan failed for EASM scan %d", scan.id)
        db.rollback()

    # Build SBOM rows from the InventorySoftware records emitted by
    # _generate_easm_findings. Runs after finalize_scan so any deduped
    # findings are visible to the CVE-matching pass.
    try:
        from services.sbom_pipeline import build_sbom_from_inventory
        build_sbom_from_inventory(db, scan.id)
        db.commit()
    except Exception:
        logger.exception("SBOM pipeline failed for EASM scan %d (non-fatal)", scan.id)
        db.rollback()

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
    suppress_auto_followup: bool = False,
) -> Optional[dict]:
    """
    Full flow: add domain to hakuna (idempotent), trigger scan,
    reuse existing scan record or create one marked as 'running'.
    Assets are imported later when the scan completes (via refresh_easm_scan).

    Self-heals when ``org.easm_org_id`` references an org that no longer
    exists in the scanner DB (404 on the trigger call) — this happens when
    the scanner Postgres is wiped (``docker compose down -v``) but the
    backend DB still has the stale UUID. On 404 we clear the cached
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
    # Per-scan opt-out for ALL automated follow-ups: anonymous audits
    # (SMB/SNMP, datastore, AI, anon-protocol, IPMI, NetBIOS) AND the post-
    # ingest VM (Nuclei) scan. Read by ``audit_auto_trigger`` when port_change
    # events land, and by ``post_ingest._auto_vm_scan_for_easm`` before the
    # VM-trigger flag is written.
    if suppress_auto_followup:
        base_meta["suppress_auto_followup"] = True

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

            # If we've been doing incremental imports mid-scan, assets are
            # already present with stable IDs (possibly linked to VM findings
            # or other integrations). Wiping them here would orphan those
            # linkages and throw away finalize_batch work. The final
            # _import_assets_for_domain pass is an upsert, so skipping the
            # clear is safe — stale rows get their last_seen bumped; rows
            # the scanner no longer reports simply retain their prior state.
            did_incremental = bool(meta.get("incremental_since"))
            if not did_incremental:
                _clear_scan_data(db, scan.id)

            # Import assets now that scan is done
            easm_assets = await get_easm_assets(org.easm_org_id) or []

            # Pull NVD CVEs for any new CPEs detected during enrichment.
            # This must run BEFORE _import_assets_for_domain so the CPE→CVE
            # correlation in _generate_easm_findings can find matching CVEs.
            try:
                from threat_intel.threat_intel_sync import sync_cves_for_cpes
                all_cpes = []
                for ea in easm_assets:
                    all_cpes.extend(_filter_cpe_list(ea.get("cpe_list") or []))
                if all_cpes:
                    cpe_result = sync_cves_for_cpes(db, cpe_list=all_cpes)
                    logger.info(f"EASM CPE→CVE sync for '{domain}': {cpe_result}")
            except Exception:
                logger.exception(f"CPE→CVE sync failed for '{domain}' (non-fatal)")
                db.rollback()

            created, findings_created, _new_asset_ids, _new_finding_ids = _import_assets_for_domain(
                db, scan, easm_assets, domain,
            )

            # Commit host-asset import before kicking off GitHub/npm attribution.
            # The attribution step is network-dependent and can take minutes;
            # a failure (network blip, scanner restart) should not roll back the
            # host import we just finished.
            db.commit()

            # GitHub/npm attribution: discover and ingest code_repo / github_org /
            # github_user / npm_package assets for the same domain. Non-fatal —
            # if the scanner endpoint is unavailable or rate-limited, the host
            # asset import above still succeeds.
            gh_asset_count = 0
            gh_finding_count = 0
            try:
                gh_result = await trigger_github_npm_scan(org.easm_org_id, domain)
                if gh_result:
                    gh_asset_count, gh_finding_count, _gh_aids, _gh_fids = (
                        _import_github_npm_assets(db, scan, gh_result, domain)
                    )
                    created += gh_asset_count
                    findings_created += gh_finding_count
                    db.commit()
                    logger.info(
                        f"EASM GitHub/npm import for '{domain}': "
                        f"assets={gh_asset_count} findings={gh_finding_count}"
                    )
            except Exception:
                logger.exception(
                    f"GitHub/npm attribution failed for '{domain}' (non-fatal)"
                )
                db.rollback()

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
            try:
                from services.post_ingest import finalize_scan
                finalize_scan(db, scan_id=scan.id, org_id=org.id)
                db.commit()
            except Exception:
                logger.exception("finalize_scan failed for EASM scan %d", scan.id)
                db.rollback()

            # Build SBOM rows from InventorySoftware records emitted during
            # finding generation, mirroring the upload path in app.py.
            try:
                from services.sbom_pipeline import build_sbom_from_inventory
                build_sbom_from_inventory(db, scan.id)
                db.commit()
            except Exception:
                logger.exception(
                    "SBOM pipeline failed for EASM scan %d (non-fatal)", scan.id
                )
                db.rollback()

            # Threat intel enrichment: HIBP breach check + GLEIF corporate structure
            try:
                from threat_intel.hibp_sync import sync_hibp_breaches_to_db, check_domain_breaches
                sync_hibp_breaches_to_db(db)
                breach_result = check_domain_breaches(db, org.id, domain)
                logger.info(f"EASM breach check for '{domain}': {breach_result}")
            except Exception:
                logger.exception(f"HIBP sync failed for '{domain}' (non-fatal)")
                db.rollback()

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
                db.rollback()

            # Fan out EASM scans to high-confidence subsidiary domains. Only
            # domains tagged from official registries (Wikidata/EDGAR/GLEIF) or
            # name-matched against this org's existing EASM scope get
            # auto-scanned; DNS-probe guesses require operator confirmation
            # via POST /easm/corporate/scan-subsidiaries.
            try:
                fanout = await fan_out_subsidiary_scans(
                    db, org,
                    scan_type="discovery",
                    include_low_confidence=False,
                    parent_scan_id=scan.id,
                )
                if fanout.get("triggered"):
                    logger.info(
                        f"EASM subsidiary fan-out from scan_id={scan.id}: "
                        f"triggered {len(fanout['triggered'])} domain(s)"
                    )
            except Exception:
                logger.exception(f"Subsidiary fan-out failed for scan_id={scan.id} (non-fatal)")
                db.rollback()

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
                db.rollback()

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

    elif hakuna_status == "cancelled":
        # User-initiated (via /api/scans/{id}/cancel) or scanner-initiated
        # (timeout, abort). Either way it's terminal — stop polling, but
        # don't emit a failure notification: the local cancel handler
        # already stamped raw_metadata.status, and a "scan failed" alert
        # for a deliberate cancel is noise.
        scan.raw_metadata = {
            **meta,
            "status": "cancelled",
            "error": meta.get("error") or "Scan cancelled",
        }
        scan.status = "cancelled"
        db.commit()
        return {"scan_id": scan.id, "status": "cancelled", "domain": domain}

    else:
        # Still running/queued — relay progress info AND stream any assets
        # the scanner has discovered since the last incremental import.
        # Watermarked by ``incremental_since`` in raw_metadata so we only pull
        # rows whose last_seen moved forward; re-upsert of unchanged rows
        # would be wasteful on large scans.
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

        # Incremental import — only when the scan is actively running. Queued
        # scans have nothing yet; polling them is wasted work.
        incremental_created = 0
        incremental_findings = 0
        new_watermark: Optional[str] = meta.get("incremental_since")
        batch_new_asset_ids: list = []
        batch_new_finding_ids: list = []
        if status == "running":
            try:
                # Pull the watermark *before* the fetch so any assets whose
                # last_seen lands exactly on the next tick aren't missed.
                fetch_started = datetime.utcnow()
                since = meta.get("incremental_since")
                easm_assets = await get_easm_assets(
                    org.easm_org_id, updated_since=since,
                )
                if easm_assets:
                    (
                        incremental_created,
                        incremental_findings,
                        batch_new_asset_ids,
                        batch_new_finding_ids,
                    ) = _import_assets_for_domain(db, scan, easm_assets, domain)
                # Advance watermark to the fetch time regardless of whether
                # rows came back — if nothing changed, we still don't want
                # to re-scan the same range next poll.
                new_watermark = fetch_started.isoformat()
            except Exception:
                logger.exception(
                    "EASM incremental import failed for scan %d (non-fatal; "
                    "finalize_scan will reconcile at completion)",
                    scan.id,
                )
                db.rollback()

        scan.raw_metadata = {
            **meta,
            "status": status,
            **progress,
            "incremental_since": new_watermark,
            "incremental_asset_count": (meta.get("incremental_asset_count", 0) or 0) + incremental_created,
            "incremental_finding_count": (meta.get("incremental_finding_count", 0) or 0) + incremental_findings,
        }
        scan.status = status
        db.commit()

        # Run the incremental post-ingest for *only the newly inserted rows*
        # so they're tagged, prioritized and triggered immediately.
        if batch_new_asset_ids or batch_new_finding_ids:
            try:
                from services.post_ingest import finalize_batch
                finalize_batch(
                    db,
                    scan_id=scan.id,
                    org_id=scan.org_id,
                    new_asset_ids=batch_new_asset_ids,
                    new_finding_ids=batch_new_finding_ids,
                )
                db.commit()
            except Exception:
                logger.exception(
                    "finalize_batch failed for EASM scan %d (non-fatal)",
                    scan.id,
                )
                db.rollback()

        return {
            "scan_id": scan.id,
            "status": status,
            "domain": domain,
            **progress,
            "incremental_asset_count": scan.raw_metadata.get("incremental_asset_count", 0),
            "incremental_finding_count": scan.raw_metadata.get("incremental_finding_count", 0),
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

        # Store full EASM enrichment data
        asset.easm_data = _build_easm_data(ea)

        # Mirror open-port reachability into the unified edge graph.
        try:
            from services.asset_edges import write_easm_internet_edges
            write_easm_internet_edges(
                db,
                org_id=org.id,
                asset_id=asset.id,
                open_ports=ea.get("open_ports"),
                confidence="high",
            )
        except Exception:
            logger.exception(
                "internet_to_asset edge write failed for asset %s during Nessus enrich",
                asset.id,
            )
            db.rollback()

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
