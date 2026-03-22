"""
SEC EDGAR subsidiary sync — extracts subsidiary lists from 10-K Exhibit 21 filings.

Data source (free, no auth):
  - SEC EDGAR (data.sec.gov) — public company filings
  - Exhibit 21 of 10-K filings lists all significant subsidiaries

Only works for US publicly traded companies.
"""

import html
import json
import logging
import re
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Optional

from models.threat_intel_models import CorporateEntity

logger = logging.getLogger(__name__)

_USER_AGENT = "Hakuna-EASM support@hakunahq.com"


def _fetch(url: str, timeout: int = 15) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("EDGAR fetch failed for %s: %s", url, exc)
        return None


def _fetch_json(url: str, timeout: int = 15) -> dict | None:
    raw = _fetch(url, timeout)
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    return None


def find_company_cik(company_name: str) -> dict | None:
    """Search EDGAR for a company by name. Returns {cik, name} or None."""
    params = urllib.parse.urlencode({
        "company": company_name,
        "CIK": "",
        "type": "10-K",
        "dateb": "",
        "owner": "include",
        "count": "5",
        "search_text": "",
        "action": "getcompany",
        "output": "atom",
    })

    # Use the company tickers/search endpoint
    url = f"https://efts.sec.gov/LATEST/search-index?q=%22{urllib.parse.quote(company_name)}%22&forms=10-K&dateRange=custom&startdt=2024-01-01"
    data = _fetch_json(url)
    if not data:
        return None

    hits = data.get("hits", {}).get("hits", [])
    if not hits:
        return None

    source = hits[0].get("_source", {})
    ciks = source.get("ciks", [])
    names = source.get("display_names", [])

    if ciks:
        return {
            "cik": ciks[0].lstrip("0"),
            "cik_padded": ciks[0],
            "name": names[0] if names else company_name,
        }
    return None


def get_latest_exhibit21(cik_padded: str) -> list[dict]:
    """Fetch the latest 10-K filing and extract Exhibit 21 (subsidiaries).

    Returns list of {"name": str, "jurisdiction": str}.
    """
    # Step 1: Get filings for this CIK
    url = f"https://data.sec.gov/submissions/CIK{cik_padded}.json"
    data = _fetch_json(url)
    if not data:
        return []

    recent = data.get("filings", {}).get("recent", {})
    forms = recent.get("form", [])
    accessions = recent.get("accessionNumber", [])

    # Find latest 10-K
    ten_k_acc = None
    for i, form in enumerate(forms):
        if form == "10-K":
            ten_k_acc = accessions[i]
            break

    if not ten_k_acc:
        logger.info("No 10-K filing found for CIK %s", cik_padded)
        return []

    # Step 2: Get filing index to find Exhibit 21
    acc_clean = ten_k_acc.replace("-", "")
    cik_num = cik_padded.lstrip("0")
    index_url = f"https://www.sec.gov/Archives/edgar/data/{cik_num}/{acc_clean}/{ten_k_acc}-index.htm"
    index_html = _fetch(index_url)
    if not index_html:
        return []

    # Find exhibit 21 document
    ex21_pattern = re.compile(r'href="(/Archives/edgar/data/[^"]*exhibit\s*21[^"]*\.htm)"', re.IGNORECASE)
    match = ex21_pattern.search(index_html)
    if not match:
        # Try alternate pattern
        ex21_pattern2 = re.compile(r'href="(/Archives/edgar/data/[^"]*ex-?21[^"]*\.htm)"', re.IGNORECASE)
        match = ex21_pattern2.search(index_html)

    if not match:
        logger.info("No Exhibit 21 found in 10-K for CIK %s", cik_padded)
        return []

    # Step 3: Fetch and parse Exhibit 21
    ex21_url = f"https://www.sec.gov{match.group(1)}"
    ex21_html = _fetch(ex21_url)
    if not ex21_html:
        return []

    return _parse_exhibit21(ex21_html)


def _parse_exhibit21(raw_html: str) -> list[dict]:
    """Parse Exhibit 21 HTML to extract subsidiary name + jurisdiction pairs.

    Exhibit 21 is typically a simple table or list of:
      "Subsidiary Name" | "Jurisdiction of Incorporation"
    """
    # Strip HTML tags
    text = re.sub(r"<[^>]+>", "\n", raw_html)
    text = html.unescape(text)

    # Split into lines and clean
    lines = [line.strip() for line in text.split("\n") if line.strip()]

    subsidiaries = []
    skip_words = {
        "exhibit", "subsidiaries", "name", "jurisdiction", "incorporation",
        "organization", "document", "ex-21", "formation", "of", "ex-21.1",
    }

    i = 0
    while i < len(lines):
        line = lines[i]

        # Skip header lines
        if any(w in line.lower() for w in ("exhibit 21", "subsidiaries of", "name of subsidiary", "jurisdiction")):
            i += 1
            continue

        # A subsidiary entry: company name followed by jurisdiction
        # Common pattern: "Company Name    State/Country"
        # Or on separate lines: "Company Name" then "State/Country"
        name = line.strip()
        jurisdiction = None

        # Check if jurisdiction is on the same line (tab/space separated)
        # Common jurisdictions
        known_jurisdictions = {
            "delaware", "california", "texas", "new york", "maryland", "virginia",
            "nevada", "washington", "georgia", "florida", "colorado", "massachusetts",
            "illinois", "pennsylvania", "ohio", "oregon", "minnesota", "michigan",
            "israel", "ireland", "france", "germany", "united kingdom", "uk",
            "canada", "australia", "japan", "singapore", "india", "netherlands",
            "brazil", "china", "hong kong", "south korea", "switzerland", "spain",
            "italy", "sweden", "norway", "denmark", "finland", "austria", "belgium",
        }

        # Check next line for jurisdiction
        if i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            if next_line.lower() in known_jurisdictions or len(next_line) < 30:
                # Likely jurisdiction on next line
                if next_line.lower() not in skip_words and len(next_line) > 1:
                    jurisdiction = next_line
                    i += 1

        # Skip if name looks like a header or is too short
        if len(name) < 3 or name.lower() in skip_words:
            i += 1
            continue

        # Skip lines that are just numbers or dates
        if re.match(r"^[\d\s/.-]+$", name):
            i += 1
            continue

        subsidiaries.append({
            "name": name,
            "jurisdiction": jurisdiction,
        })
        i += 1

    logger.info("Parsed %d subsidiaries from Exhibit 21", len(subsidiaries))
    return subsidiaries


def sync_subsidiaries_to_db(
    db, company_name: str, org_id: int | None = None,
) -> dict:
    """Find a company on EDGAR, extract subsidiaries from Exhibit 21, and store them.

    Returns {"root": str, "subsidiaries": int}.
    """
    # Step 1: Find the company
    company = find_company_cik(company_name)
    if not company:
        logger.info("Company '%s' not found on EDGAR", company_name)
        return {"root": None, "subsidiaries": 0}

    cik = company["cik_padded"]
    root_name = company["name"]

    # Step 2: Extract subsidiaries from Exhibit 21
    subs = get_latest_exhibit21(cik)
    if not subs:
        return {"root": root_name, "subsidiaries": 0}

    # Step 3: Upsert root entity
    root_id = f"SEC-{cik}"
    _upsert_entity(db, root_id, root_name, org_id=org_id, category="parent")

    # Step 4: Store subsidiaries
    stored = 0
    for sub in subs:
        sub_name = sub["name"]
        jurisdiction = sub.get("jurisdiction")
        sub_id = f"SEC-{cik}-{stored}"

        _upsert_entity(
            db, sub_id, sub_name,
            jurisdiction=jurisdiction,
            parent_id=root_id,
            parent_name=root_name,
            parent_org_id=org_id,
        )
        stored += 1

    db.commit()
    logger.info(
        "EDGAR sync: root=%s (%s) subsidiaries=%d",
        cik, root_name, stored,
    )
    return {"root": root_name, "cik": cik, "subsidiaries": stored}


def _upsert_entity(
    db,
    entity_id: str,
    name: str,
    org_id: int | None = None,
    parent_org_id: int | None = None,
    jurisdiction: str | None = None,
    parent_id: str | None = None,
    parent_name: str | None = None,
    category: str | None = None,
):
    """Upsert a CorporateEntity from EDGAR data."""
    existing = db.query(CorporateEntity).filter(CorporateEntity.lei == entity_id).first()

    # Map jurisdiction to country
    us_states = {
        "delaware", "california", "texas", "new york", "maryland", "virginia",
        "nevada", "washington", "georgia", "florida", "colorado", "massachusetts",
        "illinois", "pennsylvania", "ohio", "oregon", "minnesota", "michigan",
    }
    country = None
    if jurisdiction:
        if jurisdiction.lower() in us_states:
            country = "United States"
        else:
            country = jurisdiction

    if existing:
        existing.legal_name = name
        if jurisdiction:
            existing.legal_jurisdiction = jurisdiction
        if country:
            existing.headquarters_country = country
        if parent_id:
            existing.direct_parent_lei = parent_id
            existing.direct_parent_name = parent_name
        existing.entity_status = "ACTIVE"
        existing.updated_at = datetime.utcnow()
        if org_id and not existing.org_id:
            existing.org_id = org_id
    else:
        entity = CorporateEntity(
            lei=entity_id,
            legal_name=name,
            legal_jurisdiction=jurisdiction,
            headquarters_country=country,
            entity_status="ACTIVE",
            category=category or "subsidiary",
            direct_parent_lei=parent_id,
            direct_parent_name=parent_name,
            org_id=org_id or parent_org_id,
        )
        db.add(entity)
