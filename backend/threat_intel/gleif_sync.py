"""
GLEIF corporate structure sync — tracks parent/subsidiary relationships for M&A.

Data source (free, no auth):
  - GLEIF API v1 (api.gleif.org) — Legal Entity Identifier registry with relationship data
"""

import json
import logging
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Optional

from models.threat_intel_models import CorporateEntity

logger = logging.getLogger(__name__)

GLEIF_API = "https://api.gleif.org/api/v1"
_USER_AGENT = "Hakuna-EASM/1.0 (corporate-structure)"


def _get_ssl_context():
    try:
        from threat_intel.threat_intel_sync import _get_ssl_context as _get_ctx
        return _get_ctx()
    except Exception:
        import ssl
        return ssl.create_default_context()


def _fetch_json(url: str, timeout: int = 15) -> dict | None:
    req = urllib.request.Request(url, headers={
        "User-Agent": _USER_AGENT,
        "Accept": "application/vnd.api+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_get_ssl_context()) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("GLEIF fetch failed for %s: %s", url, exc)
        return None


def search_entities(company_name: str, limit: int = 10) -> list[dict]:
    """Search GLEIF for entities matching a company name.

    Returns list of normalized entity dicts.
    """
    params = urllib.parse.urlencode({
        "filter[entity.legalName]": company_name,
        "page[size]": str(limit),
    })
    url = f"{GLEIF_API}/lei-records?{params}"
    data = _fetch_json(url)
    if not data:
        return []

    results = []
    for item in data.get("data", []):
        entity = _normalize_entity(item)
        if entity:
            results.append(entity)

    logger.info("GLEIF search '%s': %d results", company_name, len(results))
    return results


def get_entity_by_lei(lei: str) -> dict | None:
    """Fetch a specific entity by LEI."""
    url = f"{GLEIF_API}/lei-records/{lei}"
    data = _fetch_json(url)
    if not data or "data" not in data:
        return None
    return _normalize_entity(data["data"])


def get_direct_children(lei: str) -> list[dict]:
    """Get all direct child entities (subsidiaries) of a parent LEI."""
    params = urllib.parse.urlencode({
        "filter[relationship.startNode.id]": lei,
        "filter[relationship.relationshipType]": "IS_DIRECTLY_CONSOLIDATED_BY",
        "page[size]": "100",
    })
    url = f"{GLEIF_API}/lei-records?{params}"

    # GLEIF relationship API uses a different approach:
    # Query relationships, then fetch the child entities
    rel_url = f"{GLEIF_API}/lei-records/{lei}/direct-child-relationships?page[size]=100"
    data = _fetch_json(rel_url)

    if not data:
        # Fallback: search by direct parent LEI
        fallback_params = urllib.parse.urlencode({
            "filter[entity.legalName]": "*",
            "filter[relationship.directParent]": lei,
            "page[size]": "100",
        })
        data = _fetch_json(f"{GLEIF_API}/lei-records?{fallback_params}")

    children = []
    if data:
        for item in data.get("data", []):
            # Relationships endpoint returns relationship objects
            rel = item.get("attributes", {})
            child_lei = rel.get("relationship", {}).get("startNode", {}).get("id")
            if child_lei:
                child = get_entity_by_lei(child_lei)
                if child:
                    children.append(child)

    logger.info("GLEIF children of %s: %d found", lei, len(children))
    return children


def get_parent_chain(lei: str) -> list[dict]:
    """Walk up the parent chain from a given LEI.

    Returns list of entities from direct parent to ultimate parent.
    """
    chain = []
    current_lei = lei
    visited = set()

    for _ in range(10):  # Max depth to avoid infinite loops
        if current_lei in visited:
            break
        visited.add(current_lei)

        entity = get_entity_by_lei(current_lei)
        if not entity:
            break

        parent_lei = entity.get("direct_parent_lei")
        if not parent_lei or parent_lei == current_lei:
            break

        parent = get_entity_by_lei(parent_lei)
        if parent:
            chain.append(parent)
        current_lei = parent_lei

    return chain


def _normalize_entity(item: dict) -> dict | None:
    """Normalize a GLEIF API lei-record into a flat dict."""
    if not item:
        return None

    attrs = item.get("attributes", {})
    entity = attrs.get("entity", {})
    registration = attrs.get("registration", {})

    legal_name_obj = entity.get("legalName", {})
    legal_name = legal_name_obj.get("name") if isinstance(legal_name_obj, dict) else str(legal_name_obj)

    if not legal_name:
        return None

    lei = item.get("id") or attrs.get("lei")

    # Legal address
    legal_addr = entity.get("legalAddress", {})
    hq_addr = entity.get("headquartersAddress", {})

    # Other names
    other_names = entity.get("otherNames", [])
    trading_name = None
    if other_names:
        for n in other_names:
            if isinstance(n, dict) and n.get("type") == "TRADING_OR_OPERATING_NAME":
                trading_name = n.get("name")
                break

    return {
        "lei": lei,
        "legal_name": legal_name,
        "trading_name": trading_name,
        "legal_jurisdiction": entity.get("jurisdiction"),
        "category": entity.get("category"),
        "entity_status": entity.get("status"),
        "registration_status": registration.get("status"),
        "legal_address_country": legal_addr.get("country"),
        "legal_address_city": legal_addr.get("city"),
        "headquarters_country": hq_addr.get("country"),
        "headquarters_city": hq_addr.get("city"),
        "raw_data": item,
    }


def sync_entity_tree_to_db(db, company_name: str, org_id: int | None = None) -> dict:
    """Search for a company, fetch its corporate tree, and store everything.

    Returns {"root": str, "subsidiaries": int, "parents": int}.
    """
    # Step 1: Search for the company
    results = search_entities(company_name, limit=5)
    if not results:
        return {"root": None, "subsidiaries": 0, "parents": 0}

    root = results[0]  # Best match
    root_lei = root["lei"]

    # Step 2: Upsert root entity
    _upsert_entity(db, root, org_id=org_id)

    # Step 3: Fetch and store parent chain
    parents = get_parent_chain(root_lei)
    for parent in parents:
        _upsert_entity(db, parent)

    # Step 4: Fetch and store direct children (subsidiaries)
    children = get_direct_children(root_lei)
    for child in children:
        _upsert_entity(db, child, parent_org_id=org_id)

    db.commit()
    logger.info(
        "GLEIF tree sync: root=%s (%s) parents=%d children=%d",
        root_lei, root["legal_name"], len(parents), len(children),
    )
    return {
        "root": root_lei,
        "root_name": root["legal_name"],
        "subsidiaries": len(children),
        "parents": len(parents),
    }


def _upsert_entity(db, entity_data: dict, org_id: int | None = None, parent_org_id: int | None = None):
    """Upsert a single CorporateEntity record."""
    lei = entity_data.get("lei")
    if not lei:
        return

    existing = db.query(CorporateEntity).filter(CorporateEntity.lei == lei).first()

    if existing:
        for key in ("legal_name", "trading_name", "legal_jurisdiction", "category",
                     "entity_status", "registration_status", "legal_address_country",
                     "legal_address_city", "headquarters_country", "headquarters_city"):
            val = entity_data.get(key)
            if val is not None:
                setattr(existing, key, val)
        existing.raw_data = entity_data.get("raw_data")
        existing.updated_at = datetime.utcnow()
        if org_id and not existing.org_id:
            existing.org_id = org_id
    else:
        entity = CorporateEntity(
            lei=lei,
            legal_name=entity_data["legal_name"],
            trading_name=entity_data.get("trading_name"),
            legal_jurisdiction=entity_data.get("legal_jurisdiction"),
            category=entity_data.get("category"),
            entity_status=entity_data.get("entity_status"),
            registration_status=entity_data.get("registration_status"),
            legal_address_country=entity_data.get("legal_address_country"),
            legal_address_city=entity_data.get("legal_address_city"),
            headquarters_country=entity_data.get("headquarters_country"),
            headquarters_city=entity_data.get("headquarters_city"),
            raw_data=entity_data.get("raw_data"),
            org_id=org_id or parent_org_id,
        )
        db.add(entity)


def get_subsidiaries_for_org(db, org_id: int) -> list[dict]:
    """Get all known subsidiaries for an organization.

    Returns all entities linked to this org that have a parent (i.e., not root entities).
    Includes the parent entity's EASM domain for grouping.
    """
    children = db.query(CorporateEntity).filter(
        CorporateEntity.org_id == org_id,
        CorporateEntity.direct_parent_lei.isnot(None),
    ).all()

    # Build parent LEI → domain lookup
    parent_leis = {c.direct_parent_lei for c in children if c.direct_parent_lei}
    parent_domains = {}
    if parent_leis:
        parents = db.query(CorporateEntity).filter(
            CorporateEntity.lei.in_(parent_leis),
        ).all()
        for p in parents:
            # Use parent's associated domains, or derive from name
            domains = p.associated_domains or []
            parent_domains[p.lei] = domains[0] if domains else (p.legal_name or "")

    return [
        {
            "lei": c.lei,
            "legal_name": c.legal_name,
            "trading_name": c.trading_name,
            "country": c.headquarters_country or c.legal_address_country,
            "city": c.headquarters_city or c.legal_address_city,
            "status": c.entity_status,
            "jurisdiction": c.legal_jurisdiction,
            "associated_domains": c.associated_domains or [],
            "parent_name": c.direct_parent_name,
            "parent_domain": parent_domains.get(c.direct_parent_lei, ""),
        }
        for c in children
    ]
