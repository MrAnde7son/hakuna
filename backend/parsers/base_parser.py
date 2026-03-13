"""
Abstract base class for all vulnerability scanner parsers.

Every parser must implement this interface to be registered in the parser registry.
The parse() method returns the standard normalized shape:
    {scan: {...}, assets: [...], findings: [...]}
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class BaseParser(ABC):
    """Base class all scanner parsers must implement."""

    source_type: str = ""                  # e.g. "nessus", "qualys", "rapid7"
    supported_extensions: list[str] = []   # e.g. [".nessus", ".html", ".csv"]

    @abstractmethod
    def can_parse(self, content: bytes, filename: str) -> bool:
        """Return True if this parser can handle the given file.

        Implementations should check file extension and/or content signatures.
        """
        ...

    @abstractmethod
    def parse(self, content: bytes, filename: str) -> dict:
        """Parse file content and return normalized data.

        Returns:
            {
                "scan": {scan-level metadata dict},
                "assets": [list of asset dicts],
                "findings": [list of finding dicts],
            }
        """
        ...

    def get_inventory_dispatch(self) -> dict:
        """Return plugin_id -> (table_key, extract_fn) for inventory extraction.

        Override in subclasses that produce inventory-extractable plugin output.
        Default: empty dict (no inventory extraction for this source).
        """
        return {}

    def get_scanner_detection_plugin(self) -> Optional[str]:
        """Return the plugin ID used for scanner/credential/network detection.

        For Nessus this is "19506". Other scanners may have an equivalent.
        Default: None (no special detection plugin).
        """
        return None
