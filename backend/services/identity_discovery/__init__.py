"""Identity discovery — pulls public-SERP-indexed employee records and
surfaces them as ``asset_type='identity'`` rows.

This package separates the source layer (where data comes from) from the
discovery service (consent checks, lifecycle, asset upsert) so a future
provider (Hunter, Apollo, manual import) can slot in by implementing
``IdentitySource`` without touching the orchestration.
"""

from .canonicalize import (
    canonicalize_linkedin_slug,
    extract_linkedin_slug,
)
from .consent import (
    IDENTITY_DISCOVERY_PURPOSE,
    is_identity_discovery_permitted,
)
from .sources import (
    IdentityRecord,
    IdentitySource,
    SourceResult,
)
from .ddg_linkedin import DdgLinkedInSource
from .discovery import run_identity_discovery
from .lifecycle import STALE_AFTER_ABSENT_RUNS, apply_discovery_result
from .scheduler import run_weekly_dispatch

__all__ = [
    "DdgLinkedInSource",
    "IDENTITY_DISCOVERY_PURPOSE",
    "IdentityRecord",
    "IdentitySource",
    "SourceResult",
    "STALE_AFTER_ABSENT_RUNS",
    "apply_discovery_result",
    "canonicalize_linkedin_slug",
    "extract_linkedin_slug",
    "is_identity_discovery_permitted",
    "run_identity_discovery",
    "run_weekly_dispatch",
]
