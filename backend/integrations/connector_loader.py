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


def get_all_connectors():
    """Return list of all loaded connector templates (summary view)."""
    if not _CONNECTORS:
        load_connectors()
    return [
        {
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
        for c in _CONNECTORS.values()
    ]


def get_connector(connector_id):
    """Return full connector template by ID, or None."""
    if not _CONNECTORS:
        load_connectors()
    return _CONNECTORS.get(connector_id)
