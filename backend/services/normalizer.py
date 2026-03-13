"""
Cross-source vulnerability normalization.

Computes a normalized_id for each finding that can be used to correlate
the same vulnerability across different scanner sources.
"""
from typing import Optional


def compute_normalized_id(finding_data: dict) -> Optional[str]:
    """Compute a cross-source canonical vulnerability identity.

    Strategy (Phase 1 — intentionally simple):
      1. If the finding has CVE references, use the first CVE as the normalized ID.
         CVE is the most universal cross-source identifier.
      2. Otherwise return None — no cross-source identity available yet.

    In future phases, this can be extended with:
      - VulnIdentityMap table lookups
      - Description/software similarity matching
      - NVD CPE-based correlation
    """
    cves = finding_data.get("cves") or []
    if cves:
        return cves[0]
    return None
