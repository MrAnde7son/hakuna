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


# Headers that appear as column labels in Exhibit 21 tables. If a cell's
# normalized text matches one of these, it is never an entity name.
_EX21_HEADER_TOKENS = frozenset({
    "name", "entity", "subsidiary", "subsidiaries", "subsidiary name",
    "name of subsidiary", "name of entity", "legal entity",
    "jurisdiction", "jurisdiction of incorporation", "jurisdiction of organization",
    "jurisdiction of formation", "state of incorporation", "state of organization",
    "state or country", "state/country", "state or country of incorporation",
    "place of incorporation", "country", "country of incorporation", "state",
    "percent", "percent owned", "percent ownership", "percent of voting power",
    "ownership", "ownership percent", "% ownership", "% owned", "% ",
    "doing business as", "d/b/a", "dba", "parent", "organization",
    "list of subsidiaries", "exhibit", "ex-21", "ex-21.1",
    "incorporation", "formation", "of",
})

# Jurisdictions (states, provinces, countries) that, on their own, are never
# entity names. We use membership here only to filter out bare-jurisdiction
# cells that slipped into the name column; we still accept names that contain
# these words (e.g. "Delaware Holdings LLC").
_EX21_BARE_JURISDICTIONS = frozenset({
    # US states
    "alabama", "alaska", "arizona", "arkansas", "california", "colorado",
    "connecticut", "delaware", "florida", "georgia", "hawaii", "idaho",
    "illinois", "indiana", "iowa", "kansas", "kentucky", "louisiana", "maine",
    "maryland", "massachusetts", "michigan", "minnesota", "mississippi",
    "missouri", "montana", "nebraska", "nevada", "new hampshire", "new jersey",
    "new mexico", "new york", "north carolina", "north dakota", "ohio",
    "oklahoma", "oregon", "pennsylvania", "rhode island", "south carolina",
    "south dakota", "tennessee", "texas", "utah", "vermont", "virginia",
    "washington", "west virginia", "wisconsin", "wyoming",
    "district of columbia", "puerto rico",
    # Countries / regions commonly seen
    "united states", "usa", "u.s.", "u.s.a.", "uk", "u.k.",
    "united kingdom", "england", "scotland", "ireland", "israel", "france",
    "germany", "canada", "australia", "japan", "singapore", "india",
    "netherlands", "the netherlands", "brazil", "china", "hong kong",
    "south korea", "switzerland", "spain", "italy", "sweden", "norway",
    "denmark", "finland", "austria", "belgium", "luxembourg", "portugal",
    "mexico", "argentina", "chile", "colombia", "peru", "new zealand",
    "south africa", "uae", "united arab emirates", "saudi arabia", "turkey",
    "russia", "poland", "czech republic", "hungary", "romania", "greece",
    "thailand", "vietnam", "indonesia", "malaysia", "philippines", "taiwan",
    "cayman islands", "bermuda", "british virgin islands", "bvi",
    "isle of man", "jersey", "guernsey", "gibraltar", "mauritius",
    # Canadian provinces + other sub-national regions occasionally listed bare
    "ontario", "quebec", "british columbia", "alberta",
    # Generic
    "various", "n/a",
})

_PERCENT_RE = re.compile(r"^\s*\d{1,3}(\.\d+)?\s*%\s*$")
_NUMERIC_ONLY_RE = re.compile(r"^[\d\s/.,\-]+$")


def _normalize_cell(text: str) -> str:
    """Collapse whitespace and trim a cell value."""
    return re.sub(r"\s+", " ", (text or "").strip())


def _is_header_cell(text: str) -> bool:
    return text.lower().strip(" .:*") in _EX21_HEADER_TOKENS


def _is_percentage(text: str) -> bool:
    return bool(_PERCENT_RE.match(text))


def _is_bare_jurisdiction(text: str) -> bool:
    low = text.lower().strip(" .,*")
    # Strip a leading "State of " / "Commonwealth of " prefix
    low = re.sub(r"^(state of|commonwealth of|republic of|kingdom of)\s+", "", low)
    return low in _EX21_BARE_JURISDICTIONS


def _is_date_or_footnote(text: str) -> bool:
    low = text.lower()
    if "as of " in low:
        return True
    if re.search(r"\b(december|january|february|march|april|may|june|july|august|september|october|november)\b\s*\d", low):
        return True
    if low.startswith("*") or low.startswith("(") and low.endswith(")"):
        return True
    return False


def _looks_like_entity_name(text: str) -> bool:
    """A string that could plausibly be a subsidiary name.

    Must have letters, not be a bare header / jurisdiction / percentage / date.
    """
    if not text or len(text) < 3:
        return False
    if not any(c.isalpha() for c in text):
        return False
    if _is_percentage(text) or _NUMERIC_ONLY_RE.match(text):
        return False
    if _is_header_cell(text):
        return False
    if _is_bare_jurisdiction(text):
        return False
    if _is_date_or_footnote(text):
        return False
    return True


def _extract_table_rows(raw_html: str) -> list[list[str]]:
    """Extract rows of non-empty cell values from any tables in the HTML.

    Returns a flat list of row-cell lists across all tables. Empty cells and
    cells that are only whitespace/formatting are dropped.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return []

    soup = BeautifulSoup(raw_html, "lxml")
    rows: list[list[str]] = []
    for tr in soup.find_all("tr"):
        cells: list[str] = []
        for td in tr.find_all(["td", "th"]):
            txt = _normalize_cell(td.get_text(" ", strip=True))
            if txt:
                cells.append(txt)
        if cells:
            rows.append(cells)
    return rows


def _parse_table_rows(rows: list[list[str]]) -> list[dict]:
    """Extract (name, jurisdiction) pairs from parsed table rows.

    Uses the header row (if present) to locate the name and jurisdiction
    columns. Falls back to heuristics row-by-row when no header is found
    or a row's layout drifts.
    """
    # Locate header row and infer column indices.
    name_col: Optional[int] = None
    juris_col: Optional[int] = None
    data_start = 0
    for i, row in enumerate(rows[:10]):  # header is always near the top
        header_hits = sum(1 for c in row if _is_header_cell(c))
        if header_hits >= 2 or (len(row) >= 2 and all(_is_header_cell(c) for c in row)):
            for j, c in enumerate(row):
                low = c.lower().strip(" .:*")
                if name_col is None and low in {
                    "name", "entity", "subsidiary", "subsidiaries",
                    "subsidiary name", "name of subsidiary", "name of entity",
                    "legal entity",
                }:
                    name_col = j
                elif juris_col is None and (
                    "jurisdiction" in low
                    or low in {"state", "country", "state/country",
                               "state or country", "place of incorporation"}
                ):
                    juris_col = j
            data_start = i + 1
            break

    subsidiaries: list[dict] = []
    for row in rows[data_start:]:
        if not row:
            continue
        # Drop rows that are entirely non-entity content (all-% or all-header).
        if all(
            _is_percentage(c) or _is_header_cell(c) or _is_date_or_footnote(c)
            for c in row
        ):
            continue

        # Prefer the mapped column, but fall back to the first plausible cell.
        name = row[name_col] if (name_col is not None and name_col < len(row)) else ""
        if not _looks_like_entity_name(name):
            name = ""
            for c in row:
                if _looks_like_entity_name(c):
                    name = c
                    break

        if not name:
            continue

        jurisdiction: Optional[str] = None
        if juris_col is not None and juris_col < len(row):
            candidate = row[juris_col]
            if candidate and candidate != name and not _is_percentage(candidate):
                jurisdiction = candidate
        if not jurisdiction:
            # Fall back to the last cell that looks like a jurisdiction.
            for c in reversed(row):
                if c == name or _is_percentage(c) or _is_header_cell(c):
                    continue
                if _is_bare_jurisdiction(c) or (len(c) < 40 and any(ch.isalpha() for ch in c)):
                    jurisdiction = c
                    break

        subsidiaries.append({"name": name, "jurisdiction": jurisdiction})

    return subsidiaries


def _parse_text_lines(raw_html: str) -> list[dict]:
    """Fallback parser for plain-text / non-tabular Exhibit 21 filings."""
    text = re.sub(r"<[^>]+>", "\n", raw_html)
    text = html.unescape(text)
    lines = [_normalize_cell(line) for line in text.split("\n") if line.strip()]

    subsidiaries: list[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i]

        if any(w in line.lower() for w in (
            "exhibit 21", "subsidiaries of", "name of subsidiary",
            "jurisdiction of", "list of subsidiaries",
        )):
            i += 1
            continue

        if not _looks_like_entity_name(line):
            i += 1
            continue

        jurisdiction: Optional[str] = None
        if i + 1 < len(lines):
            nxt = lines[i + 1]
            if _is_bare_jurisdiction(nxt) or (
                len(nxt) < 40 and any(ch.isalpha() for ch in nxt)
                and not _is_header_cell(nxt)
                and not _is_percentage(nxt)
                and not _looks_like_entity_name(nxt)  # not another entity name
            ):
                jurisdiction = nxt
                i += 1

        subsidiaries.append({"name": line, "jurisdiction": jurisdiction})
        i += 1

    return subsidiaries


def _parse_exhibit21(raw_html: str) -> list[dict]:
    """Parse Exhibit 21 HTML to extract subsidiary name + jurisdiction pairs.

    Exhibit 21 filings vary: modern 10-Ks use HTML tables with 2 or 3
    columns (Name | [% Owned] | Jurisdiction); older or hand-formatted
    filings are plain text with tab/whitespace alignment.

    We first try the table parser (BeautifulSoup over <tr>/<td>) because
    stripping tags and splitting on newlines loses the row boundary and
    causes cells like "100%" or "Delaware" to be read as entity names.
    If no <tr> rows are found we fall back to the line-based heuristic.
    """
    rows = _extract_table_rows(raw_html)
    if rows:
        subsidiaries = _parse_table_rows(rows)
        if subsidiaries:
            logger.info(
                "Parsed %d subsidiaries from Exhibit 21 (table)", len(subsidiaries)
            )
            return subsidiaries

    subsidiaries = _parse_text_lines(raw_html)
    logger.info("Parsed %d subsidiaries from Exhibit 21 (text)", len(subsidiaries))
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
