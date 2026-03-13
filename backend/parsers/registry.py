"""
Parser registry — manages pluggable scanner parsers.

Call init_parsers() at app startup to register all built-in parsers.
Use detect_parser() to find the appropriate parser for a given file.
"""
from __future__ import annotations

import logging
from typing import Optional

from parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

_registry: list[BaseParser] = []


def register_parser(parser: BaseParser) -> None:
    """Register a parser instance in the global registry."""
    _registry.append(parser)
    logger.info(f"Registered parser: {parser.source_type} ({parser.supported_extensions})")


def detect_parser(content: bytes, filename: str) -> Optional[BaseParser]:
    """Find the first registered parser that can handle this file."""
    for parser in _registry:
        if parser.can_parse(content, filename):
            return parser
    return None


def get_parser_by_source(source_type: str) -> Optional[BaseParser]:
    """Look up a parser by its source_type string."""
    for parser in _registry:
        if parser.source_type == source_type:
            return parser
    return None


def list_parsers() -> list[dict]:
    """Return metadata for all registered parsers (for API responses)."""
    return [
        {
            "source_type": p.source_type,
            "extensions": p.supported_extensions,
        }
        for p in _registry
    ]


def init_parsers() -> None:
    """Auto-register all built-in parsers. Called at app startup."""
    from parsers.nessus_parser import NessusParser
    register_parser(NessusParser())
    # Future parsers:
    # from parsers.qualys_parser import QualysParser
    # register_parser(QualysParser())
