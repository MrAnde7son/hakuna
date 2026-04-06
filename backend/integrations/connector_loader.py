"""Load OOTB connector templates from JSON files at startup."""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_CONNECTORS = {}
_CONNECTORS_DIR = Path(__file__).parent / "connectors"


def load_connectors():
    """Load all connector JSON files from the connectors directory."""
    global _CONNECTORS
    _CONNECTORS = {}
    for f in sorted(_CONNECTORS_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            cid = data.get("id", f.stem)
            _CONNECTORS[cid] = data
            logger.info("Loaded connector template: %s", cid)
        except Exception as e:
            logger.error("Failed to load connector %s: %s", f.name, e)


def _connector_summary(c):
    return {
        "id": c["id"],
        "name": c["name"],
        "description": c.get("description", ""),
        "logo": c.get("logo", "🔌"),
        "direction": c["direction"],
        "entity": c["entity"],
        "transport_type": c["transport_type"],
        "category": c.get("category", ""),
        "relay_capable": c.get("relay_capable", False),
    }


def get_all_connectors(search: str = None, category: str = None,
                       page: int = 1, page_size: int = 12):
    """Return paginated connector templates (summary view)."""
    if not _CONNECTORS:
        load_connectors()
    items = list(_CONNECTORS.values())

    # Filter by category
    if category and category != "all":
        items = [c for c in items if c.get("category") == category]

    # Filter by search
    if search:
        q = search.lower()
        items = [c for c in items if q in c["name"].lower() or q in c.get("description", "").lower()]

    total = len(items)

    # Paginate
    start = (page - 1) * page_size
    end = start + page_size
    items = items[start:end]

    return {
        "items": [_connector_summary(c) for c in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "page_count": max(1, -(-total // page_size)),
    }


def get_all_connectors_unpaginated():
    """Return all connector templates (summary view) — used for category counts."""
    if not _CONNECTORS:
        load_connectors()
    return [_connector_summary(c) for c in _CONNECTORS.values()]


def get_connector(connector_id):
    """Return full connector template by ID, or None."""
    if not _CONNECTORS:
        load_connectors()
    return _CONNECTORS.get(connector_id)
