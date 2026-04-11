"""CPE → CVE correlation.

Takes CPE 2.3 strings produced by the scanner's inference layer
(``hakuna-scanner/app/ingest/cpe_infer.py``, stored on ``asset_ports.cpe_list``)
and finds matching CVEs in the threat intel ``ThreatCVE`` table.

Design
------
The NVD feed ingest at ``backend/threat_intel/threat_intel_sync.py`` stores
the parsed vendor/product/version components in ``ThreatCVE.affected_products``
(JSON list of dicts), NOT the raw CPE 2.3 URI. So we can't do a raw-string
match on either side; we have to:

  1. Parse the scanner's CPE 2.3 string into (vendor, product, version)
  2. Call the existing product/version matcher
     (``services.downstream_impact._query_threat_intel_cves``)
     — it already handles NVD version-range semantics
     (versionStartIncluding / versionEndExcluding / etc.) and CVSS/KEV/exploit
     enrichment. Reusing it keeps CVE matching consistent across EASM, SBOM,
     and VM scanner data paths.

Version handling
----------------
Many CPEs the inference layer emits use ``version=*`` because the httpx
``-tech-detect`` output is often name-only (``"Nginx"`` not ``"Nginx:1.18.0"``).
Version-range CVE matching can't do anything useful with ``*``, so this module
skips those CPEs with a debug log. The versioned cases — caught by the Server
header parser path in cpe_infer.py — are the ones that produce real findings.
Version coverage will improve in Gap #2 (favicon hashing + JARM).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParsedCpe:
    vendor: str
    product: str
    version: str   # "*" means unknown / any — not usable for version-range matching

    @property
    def has_version(self) -> bool:
        return self.version not in ("", "*")


def parse_cpe(cpe: str) -> ParsedCpe | None:
    """Parse a CPE 2.3 or 2.2 URI into (vendor, product, version).

    Supports both formats:
      cpe:2.3:a:vendor:product:version:...   (CPE 2.3)
      cpe:/a:vendor:product:version           (CPE 2.2)

    Returns None on malformed input. Never raises.
    """
    if not cpe or not isinstance(cpe, str):
        return None

    parts = cpe.split(":")
    try:
        # CPE 2.3: cpe:2.3:{part}:{vendor}:{product}:{version}:...
        if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
            vendor = parts[3].strip().lower()
            product = parts[4].strip().lower()
            version = parts[5].strip()
            if not vendor or not product:
                return None
            return ParsedCpe(vendor=vendor, product=product, version=version or "*")

        # CPE 2.2: cpe:/{part}:{vendor}:{product}[:{version}]
        if len(parts) >= 4 and parts[0] == "cpe" and parts[1].startswith("/"):
            vendor = parts[2].strip().lower()
            product = parts[3].strip().lower()
            version = parts[4].strip() if len(parts) >= 5 else "*"
            if not vendor or not product:
                return None
            return ParsedCpe(vendor=vendor, product=product, version=version or "*")
    except (IndexError, AttributeError):
        return None

    return None


def match_cves_for_cpes(
    db: Session,
    cpe_list: list[str] | None,
) -> list[dict[str, Any]]:
    """Return a deduplicated list of CVEs affecting any CPE in ``cpe_list``.

    Each CVE is a dict with ``cve_id``, ``cvss3_score``, ``severity``,
    ``in_kev``, ``has_public_exploit``, ``description``, and ``matched_cpe``
    (the CPE that triggered the match, for traceability).

    Skips CPEs without a concrete version — version-range matching can't
    produce meaningful results for ``cpe:2.3:a:nginx:nginx:*``. Those CPEs
    still route Nuclei templates (see the tech-gated router in
    hakuna-vm-scanner) but can't correlate to CVEs without version data.

    Uses the existing ``_query_threat_intel_cves`` helper from
    downstream_impact so CVE matching semantics stay consistent across EASM,
    SBOM, and VM scanner paths. Never raises.
    """
    if not cpe_list:
        return []

    # Lazy import to avoid circular dependency via downstream_impact → easm
    from services.downstream_impact import _query_threat_intel_cves

    seen_cve_ids: list[str] = []  # list not set, so order reflects discovery
    cves_by_id: dict[str, dict[str, Any]] = {}

    for cpe_str in cpe_list:
        parsed = parse_cpe(cpe_str)
        if parsed is None:
            logger.debug("cpe_matcher: unparseable CPE %r, skipping", cpe_str)
            continue
        if not parsed.has_version:
            logger.debug(
                "cpe_matcher: %s has no version, skipping CVE lookup "
                "(routing-only CPE)", cpe_str,
            )
            continue

        try:
            matches = _query_threat_intel_cves(
                db, parsed.product, parsed.version, exclude_cve_ids=seen_cve_ids,
            )
        except Exception as exc:  # noqa: BLE001 — never raise into caller
            logger.warning(
                "cpe_matcher: _query_threat_intel_cves failed for %s: %s",
                cpe_str, exc,
            )
            continue

        for cve in matches:
            cid = cve.get("cve_id")
            if not cid or cid in cves_by_id:
                continue
            seen_cve_ids.append(cid)
            enriched = dict(cve)
            enriched["matched_cpe"] = cpe_str
            cves_by_id[cid] = enriched

    return list(cves_by_id.values())
