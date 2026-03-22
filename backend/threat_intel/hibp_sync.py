"""
HIBP & XposedOrNot breach monitoring sync.

Data sources (all free, no API key):
  - HIBP breach catalog (haveibeenpwned.com/api/v3/breaches) — list of all known breaches
  - XposedOrNot domain breach check (xposedornot.com/api/v1/domain/) — breaches affecting a domain
"""

import json
import logging
import urllib.request
from datetime import datetime

from models.threat_intel_models import BreachRecord, DomainBreach

logger = logging.getLogger(__name__)

_USER_AGENT = "Hakuna-EASM/1.0 (breach-monitor)"

# HIBP is free for the breach catalog endpoint (no API key needed)
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"


def _get_ssl_context():
    """Reuse SSL context from threat_intel_sync if available."""
    try:
        from threat_intel.threat_intel_sync import _get_ssl_context as _get_ctx
        return _get_ctx()
    except Exception:
        import ssl
        return ssl.create_default_context()


def _fetch_json(url: str, timeout: int = 15) -> dict | list | None:
    """Fetch JSON from a URL with proper headers."""
    req = urllib.request.Request(url, headers={
        "User-Agent": _USER_AGENT,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_get_ssl_context()) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            logger.warning("Rate limited fetching %s", url)
            return None
        if e.code == 404:
            return None
        raise
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


def fetch_hibp_breaches() -> list[dict]:
    """Fetch the full HIBP breach catalog (free, no API key)."""
    data = _fetch_json(HIBP_BREACHES_URL)
    if isinstance(data, list):
        logger.info("Fetched %d breaches from HIBP", len(data))
        return data
    return []


def find_breaches_for_domain(db, domain: str) -> list[dict]:
    """Find breaches in our local catalog that match a domain.

    Matches on the breach's own domain field (e.g., breach from "adobe.com"
    would match if you're monitoring "adobe.com").
    Also matches breaches where the breach domain is a subdomain of the monitored domain.
    """
    # Exact domain match from local breach records
    matches = db.query(BreachRecord).filter(
        BreachRecord.domain.ilike(f"%{domain}%"),
        BreachRecord.is_fabricated == False,
        BreachRecord.is_spam_list == False,
    ).all()

    results = []
    for b in matches:
        results.append({
            "breach": b.name,
            "domain": b.domain,
            "exposed_count": b.pwn_count or 0,
        })

    logger.info("Domain %s: %d matching breaches in catalog", domain, len(results))
    return results


def sync_hibp_breaches_to_db(db) -> dict:
    """Fetch HIBP breach catalog and upsert into breach_records table.

    Returns {"added": int, "updated": int, "total": int}.
    """
    breaches = fetch_hibp_breaches()
    if not breaches:
        return {"added": 0, "updated": 0, "total": 0}

    added = updated = 0

    for b in breaches:
        name = b.get("Name", "")
        if not name:
            continue

        existing = db.query(BreachRecord).filter(BreachRecord.name == name).first()

        if existing:
            existing.title = b.get("Title", existing.title)
            existing.domain = b.get("Domain", existing.domain)
            existing.breach_date = b.get("BreachDate", existing.breach_date)
            existing.modified_date = b.get("ModifiedDate", existing.modified_date)
            existing.pwn_count = b.get("PwnCount", existing.pwn_count)
            existing.description = b.get("Description", existing.description)
            existing.logo_path = b.get("LogoPath", existing.logo_path)
            existing.data_classes = b.get("DataClasses", existing.data_classes)
            existing.is_verified = b.get("IsVerified", existing.is_verified)
            existing.is_fabricated = b.get("IsFabricated", existing.is_fabricated)
            existing.is_sensitive = b.get("IsSensitive", existing.is_sensitive)
            existing.is_spam_list = b.get("IsSpamList", existing.is_spam_list)
            existing.updated_at = datetime.utcnow()
            updated += 1
        else:
            record = BreachRecord(
                name=name,
                title=b.get("Title", name),
                domain=b.get("Domain"),
                breach_date=b.get("BreachDate"),
                added_date=b.get("AddedDate"),
                modified_date=b.get("ModifiedDate"),
                pwn_count=b.get("PwnCount", 0),
                description=b.get("Description"),
                logo_path=b.get("LogoPath"),
                data_classes=b.get("DataClasses", []),
                is_verified=b.get("IsVerified", False),
                is_fabricated=b.get("IsFabricated", False),
                is_sensitive=b.get("IsSensitive", False),
                is_spam_list=b.get("IsSpamList", False),
                source="hibp",
            )
            db.add(record)
            added += 1

    db.commit()
    total = db.query(BreachRecord).count()
    logger.info("HIBP sync: added=%d updated=%d total=%d", added, updated, total)
    return {"added": added, "updated": updated, "total": total}


def check_domain_breaches(db, org_id: int, domain: str) -> dict:
    """Check which breaches in our catalog affect a domain and store results.

    Matches breaches where the breached site's domain matches the monitored domain.
    Requires sync_hibp_breaches_to_db() to have run first to populate the catalog.
    Returns {"breaches_found": int, "total_exposed": int}.
    """
    breaches = find_breaches_for_domain(db, domain)
    if not breaches:
        return {"breaches_found": 0, "total_exposed": 0}

    total_exposed = 0
    found = 0

    for b in breaches:
        breach_name = b.get("breach", "")
        if not breach_name:
            continue

        exposed = int(b.get("exposed_count", 0))
        total_exposed += exposed

        existing = db.query(DomainBreach).filter(
            DomainBreach.org_id == org_id,
            DomainBreach.domain == domain,
            DomainBreach.breach_name == breach_name,
        ).first()

        if existing:
            existing.exposed_count = exposed
            existing.checked_at = datetime.utcnow()
        else:
            db.add(DomainBreach(
                org_id=org_id,
                domain=domain,
                breach_name=breach_name,
                exposed_count=exposed,
                source="xposedornot",
            ))

        found += 1

    db.commit()
    logger.info("Domain breach check: domain=%s org=%d breaches=%d exposed=%d",
                domain, org_id, found, total_exposed)
    return {"breaches_found": found, "total_exposed": total_exposed}
