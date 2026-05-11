"""
Wikidata corporate structure sync — tracks subsidiaries and acquisitions.

Data source (free, no auth):
  - Wikidata SPARQL endpoint (query.wikidata.org) — structured M&A and subsidiary data
"""

import json
import logging
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Optional

from models.threat_intel_models import CorporateEntity

logger = logging.getLogger(__name__)

WIKIDATA_SPARQL = "https://query.wikidata.org/sparql"
_USER_AGENT = "Hakuna-EASM/1.0 (corporate-structure; mailto:support@hakunahq.com)"


def _sparql_query(query: str) -> list[dict]:
    """Execute a SPARQL query against Wikidata and return results."""
    params = urllib.parse.urlencode({"query": query, "format": "json"})
    url = f"{WIKIDATA_SPARQL}?{params}"
    req = urllib.request.Request(url, headers={
        "User-Agent": _USER_AGENT,
        "Accept": "application/sparql-results+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("results", {}).get("bindings", [])
    except Exception as exc:
        logger.warning("Wikidata SPARQL query failed: %s", exc)
        return []


def _extract_qid(uri: str) -> str:
    """Extract QID from Wikidata entity URI."""
    return uri.rsplit("/", 1)[-1] if uri else ""


def _val(binding: dict, key: str) -> str:
    """Extract value from SPARQL binding."""
    return binding.get(key, {}).get("value", "")


def _sparql_escape_literal(value: str) -> str:
    """Escape user-supplied text for safe interpolation into a SPARQL string
    literal (``"..."``).

    The corporate-refresh path feeds organization-controlled ``Organization.name``
    and ``CorporateEntity.legal_name`` through ``find_company``; both can contain
    arbitrary characters. Without escaping, a ``"`` in the input closes the literal
    early and the rest of the query is interpreted as SPARQL syntax. The order
    matters — escape ``\\`` first or the substitution will mangle later escapes.
    """
    if not isinstance(value, str):
        return ""
    return (
        value
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


# Bands match those used in onboarding (settings.onboarding.profile.org_size).
def _band_employee_count(raw: str) -> str | None:
    """Map a raw Wikidata P1128 employee count to a band string."""
    if not raw:
        return None
    try:
        n = int(float(raw))
    except (TypeError, ValueError):
        return None
    if n < 1:
        return None
    if n <= 10:
        return "1-10"
    if n <= 50:
        return "11-50"
    if n <= 200:
        return "51-200"
    if n <= 1000:
        return "201-1000"
    if n <= 10000:
        return "1k-10k"
    return "10k+"


def _year_from_inception(raw: str) -> int | None:
    """Wikidata P571 comes through as an ISO-ish timestamp (e.g. '1995-01-01T00:00:00Z')."""
    if not raw or len(raw) < 4:
        return None
    try:
        return int(raw[:4])
    except ValueError:
        return None


def find_company(company_name: str) -> dict | None:
    """Find a company on Wikidata by name. Returns the best match."""
    safe_name = _sparql_escape_literal(company_name)
    query = f"""
    SELECT ?company ?companyLabel ?country ?countryLabel ?inception ?website
           ?hq ?hqLabel ?industryLabel ?employees WHERE {{
      ?company wdt:P31/wdt:P279* wd:Q4830453 .
      ?company rdfs:label "{safe_name}"@en .
      OPTIONAL {{ ?company wdt:P17 ?country . }}
      OPTIONAL {{ ?company wdt:P571 ?inception . }}
      OPTIONAL {{ ?company wdt:P856 ?website . }}
      OPTIONAL {{ ?company wdt:P159 ?hq . }}
      OPTIONAL {{ ?company wdt:P452 ?industry . }}
      OPTIONAL {{ ?company wdt:P1128 ?employees . }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" . }}
    }}
    LIMIT 5
    """
    results = _sparql_query(query)

    if not results:
        # Fallback: fuzzy search via Wikidata search API
        return _search_company_api(company_name)

    best = results[0]
    qid = _extract_qid(_val(best, "company"))
    return {
        "qid": qid,
        "legal_name": _val(best, "companyLabel"),
        "headquarters_country": _val(best, "countryLabel"),
        "headquarters_city": _val(best, "hqLabel"),
        "inception": _val(best, "inception"),
        "website": _val(best, "website"),
        "industry": _val(best, "industryLabel") or None,
        "employee_count_band": _band_employee_count(_val(best, "employees")),
        "founded_year": _year_from_inception(_val(best, "inception")),
    }


def _search_company_api(company_name: str) -> dict | None:
    """Fallback: search Wikidata API for a company entity."""
    params = urllib.parse.urlencode({
        "action": "wbsearchentities",
        "search": company_name,
        "language": "en",
        "type": "item",
        "limit": "5",
        "format": "json",
    })
    url = f"https://www.wikidata.org/w/api.php?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("Wikidata search API failed: %s", exc)
        return None

    for item in data.get("search", []):
        desc = (item.get("description") or "").lower()
        if any(k in desc for k in ("company", "corporation", "software", "security", "tech")):
            qid = item["id"]
            return _get_entity_details(qid)

    # If no company-like match, try the first result
    if data.get("search"):
        return _get_entity_details(data["search"][0]["id"])

    return None


def _get_entity_details(qid: str) -> dict | None:
    """Fetch basic details for a Wikidata entity by QID."""
    query = f"""
    SELECT ?companyLabel ?countryLabel ?hqLabel ?inception ?website
           ?industryLabel ?employees WHERE {{
      OPTIONAL {{ wd:{qid} wdt:P17 ?country . }}
      OPTIONAL {{ wd:{qid} wdt:P571 ?inception . }}
      OPTIONAL {{ wd:{qid} wdt:P856 ?website . }}
      OPTIONAL {{ wd:{qid} wdt:P159 ?hq . }}
      OPTIONAL {{ wd:{qid} wdt:P452 ?industry . }}
      OPTIONAL {{ wd:{qid} wdt:P1128 ?employees . }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" . }}
      BIND(wd:{qid} AS ?company)
    }}
    LIMIT 1
    """
    results = _sparql_query(query)
    if not results:
        return {"qid": qid, "legal_name": qid}

    r = results[0]
    return {
        "qid": qid,
        "legal_name": _val(r, "companyLabel") or qid,
        "headquarters_country": _val(r, "countryLabel"),
        "headquarters_city": _val(r, "hqLabel"),
        "inception": _val(r, "inception"),
        "website": _val(r, "website"),
        "industry": _val(r, "industryLabel") or None,
        "employee_count_band": _band_employee_count(_val(r, "employees")),
        "founded_year": _year_from_inception(_val(r, "inception")),
    }


def get_subsidiaries(qid: str) -> list[dict]:
    """Get all subsidiaries and acquired companies for a Wikidata entity.

    Queries:
    - P355 (subsidiary) — current subsidiaries
    - P1830 (owner of) — owned entities
    - P749 reverse (parent organization) — entities listing this as parent
    - P127 reverse (owned by) — entities listing this as owner
    - P1365 (replaces) — merged/acquired entities
    Filters to business/organization entities only.
    """
    query = f"""
    SELECT DISTINCT ?sub ?subLabel ?countryLabel ?hqLabel ?inception ?website ?relType WHERE {{
      {{
        wd:{qid} wdt:P355 ?sub .
        BIND("subsidiary" AS ?relType)
      }} UNION {{
        wd:{qid} wdt:P1830 ?sub .
        BIND("owned" AS ?relType)
      }} UNION {{
        ?sub wdt:P749 wd:{qid} .
        BIND("subsidiary" AS ?relType)
      }} UNION {{
        ?sub wdt:P127 wd:{qid} .
        ?sub wdt:P31/wdt:P279* wd:Q4830453 .
        BIND("acquired" AS ?relType)
      }} UNION {{
        wd:{qid} wdt:P1365 ?sub .
        BIND("merged" AS ?relType)
      }}
      OPTIONAL {{ ?sub wdt:P17 ?country . }}
      OPTIONAL {{ ?sub wdt:P571 ?inception . }}
      OPTIONAL {{ ?sub wdt:P856 ?website . }}
      OPTIONAL {{ ?sub wdt:P159 ?hq . }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" . }}
    }}
    ORDER BY ?subLabel
    """
    results = _sparql_query(query)

    subs = []
    seen = set()
    for r in results:
        sub_qid = _extract_qid(_val(r, "sub"))
        if sub_qid in seen:
            continue
        seen.add(sub_qid)

        subs.append({
            "qid": sub_qid,
            "legal_name": _val(r, "subLabel"),
            "headquarters_country": _val(r, "countryLabel"),
            "headquarters_city": _val(r, "hqLabel"),
            "inception": _val(r, "inception"),
            "website": _val(r, "website"),
            "relationship": _val(r, "relType"),
        })

    logger.info("Wikidata subsidiaries of %s: %d found", qid, len(subs))
    return subs


def get_acquisitions(qid: str) -> list[dict]:
    """Get acquisition history for a company."""
    query = f"""
    SELECT ?acquired ?acquiredLabel ?dateLabel ?countryLabel WHERE {{
      wd:{qid} wdt:P1830 ?acquired .
      OPTIONAL {{
        ?acquired p:P127 ?ownerStmt .
        ?ownerStmt ps:P127 wd:{qid} .
        OPTIONAL {{ ?ownerStmt pq:P580 ?date . }}
      }}
      OPTIONAL {{ ?acquired wdt:P17 ?country . }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" . }}
    }}
    ORDER BY DESC(?date)
    """
    results = _sparql_query(query)

    acqs = []
    seen = set()
    for r in results:
        acq_qid = _extract_qid(_val(r, "acquired"))
        if acq_qid in seen:
            continue
        seen.add(acq_qid)
        acqs.append({
            "qid": acq_qid,
            "legal_name": _val(r, "acquiredLabel"),
            "country": _val(r, "countryLabel"),
            "acquisition_date": _val(r, "dateLabel"),
        })

    return acqs


def sync_corporate_tree_to_db(db, company_name: str, org_id: int | None = None) -> dict:
    """Search Wikidata for a company, fetch subsidiaries, and store everything.

    Returns {"root": str, "root_name": str, "subsidiaries": int}.
    """
    # Step 1: Find the company
    root = find_company(company_name)
    if not root:
        return {"root": None, "subsidiaries": 0}

    root_qid = root["qid"]

    # Step 2: Upsert root entity
    _upsert_entity(db, root, org_id=org_id, is_root=True)

    # Step 3: Fetch and store subsidiaries
    subs = get_subsidiaries(root_qid)
    for sub in subs:
        sub["direct_parent_qid"] = root_qid
        sub["direct_parent_name"] = root["legal_name"]
        _upsert_entity(db, sub, parent_org_id=org_id)

    db.commit()
    logger.info(
        "Wikidata tree sync: root=%s (%s) subsidiaries=%d",
        root_qid, root["legal_name"], len(subs),
    )
    return {
        "root": root_qid,
        "root_name": root["legal_name"],
        "subsidiaries": len(subs),
    }


def _upsert_entity(
    db, entity_data: dict,
    org_id: int | None = None,
    parent_org_id: int | None = None,
    is_root: bool = False,
):
    """Upsert a CorporateEntity from Wikidata data.

    Uses QID as the `lei` field (unique entity identifier).
    """
    qid = entity_data.get("qid")
    if not qid:
        return

    existing = db.query(CorporateEntity).filter(CorporateEntity.lei == qid).first()

    # Extract domain from website URL
    website = entity_data.get("website", "")
    domain = None
    if website:
        try:
            from urllib.parse import urlparse
            domain = urlparse(website).hostname
            if domain and domain.startswith("www."):
                domain = domain[4:]
        except Exception:
            pass

    if existing:
        existing.legal_name = entity_data.get("legal_name") or existing.legal_name
        existing.headquarters_country = entity_data.get("headquarters_country") or existing.headquarters_country
        existing.headquarters_city = entity_data.get("headquarters_city") or existing.headquarters_city
        existing.entity_status = "ACTIVE"
        # Profile fields refresh on each sync — Wikidata is our source of
        # truth for the corporate entity. Operator-entered onboarding
        # values are protected at the read layer (effective_company_profile).
        if entity_data.get("industry"):
            existing.industry = entity_data["industry"]
        if entity_data.get("employee_count_band"):
            existing.employee_count_band = entity_data["employee_count_band"]
        if entity_data.get("founded_year"):
            existing.founded_year = entity_data["founded_year"]
        if entity_data.get("website"):
            existing.homepage_url = entity_data["website"]
        if entity_data.get("direct_parent_qid"):
            existing.direct_parent_lei = entity_data["direct_parent_qid"]
            existing.direct_parent_name = entity_data.get("direct_parent_name")
        if domain and domain not in (existing.associated_domains or []):
            existing.associated_domains = list(set((existing.associated_domains or []) + [domain]))
            sources = dict(existing.domain_sources or {})
            sources.setdefault(domain, "wikidata_official")
            existing.domain_sources = sources
        existing.updated_at = datetime.utcnow()
        if org_id and not existing.org_id:
            existing.org_id = org_id
    else:
        entity = CorporateEntity(
            lei=qid,  # Using QID as unique identifier
            legal_name=entity_data.get("legal_name", qid),
            headquarters_country=entity_data.get("headquarters_country"),
            headquarters_city=entity_data.get("headquarters_city"),
            entity_status="ACTIVE",
            category=entity_data.get("relationship", "subsidiary") if not is_root else "parent",
            direct_parent_lei=entity_data.get("direct_parent_qid"),
            direct_parent_name=entity_data.get("direct_parent_name"),
            associated_domains=[domain] if domain else [],
            domain_sources={domain: "wikidata_official"} if domain else {},
            industry=entity_data.get("industry"),
            employee_count_band=entity_data.get("employee_count_band"),
            founded_year=entity_data.get("founded_year"),
            homepage_url=entity_data.get("website"),
            org_id=org_id or parent_org_id,
            raw_data=entity_data,
        )
        db.add(entity)
