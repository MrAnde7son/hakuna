"""
Nessus scanner parser — wraps the existing parse functions for HTML, XML, and CSV formats.

This is a thin adapter that delegates to the original parse functions in parser.py,
conforming to the BaseParser interface for the parser registry.
"""
from typing import Optional

from parsers.base_parser import BaseParser
from parsers.parser import parse_nessus_html, parse_nessus_xml, parse_nessus_csv
from parsers.inventory_extractor import PLUGIN_DISPATCH


class NessusParser(BaseParser):
    source_type = "nessus"
    supported_extensions = [".html", ".htm", ".nessus", ".csv"]

    def can_parse(self, content: bytes, filename: str) -> bool:
        fname = filename.lower()
        return any(fname.endswith(ext) for ext in self.supported_extensions)

    def parse(self, content: bytes, filename: str) -> dict:
        fname = filename.lower()

        if fname.endswith(".nessus"):
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                text = content.decode("latin-1")
            return parse_nessus_xml(text, filename)

        if fname.endswith(".csv"):
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                text = content.decode("latin-1")
            return parse_nessus_csv(text, filename)

        # Default: HTML
        try:
            text = content.decode("latin-1")
        except Exception:
            text = content.decode("utf-8", errors="replace")
        return parse_nessus_html(text, filename)

    def get_inventory_dispatch(self) -> dict:
        return PLUGIN_DISPATCH

    def get_scanner_detection_plugin(self) -> Optional[str]:
        return "19506"
