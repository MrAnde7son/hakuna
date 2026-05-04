"""
Downstream Impact Assessment for Aggregated Remediation Recommendations

Before surfacing an upgrade/migration recommendation, this module checks
whether the target version still has known CVEs — and if so, warns the user.

Primary data source: the scan's own findings.  If the scan has other findings
for the same component that are NOT resolved by this recommendation, those
CVEs still affect the target version.

Secondary data source: ThreatCVE table (NVD/KEV data) for enrichment when
available.
"""

import logging
import re
from typing import Optional, List, Dict, Any, Tuple

from sqlalchemy import Text, cast
from sqlalchemy.orm import Session

from models.threat_intel_models import ThreatCVE
from models.models import Finding

logger = logging.getLogger(__name__)

# Severity weights for net_severity_delta calculation
_SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 0.5}

# Map Nessus severity int → label
_SEVERITY_LABELS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# Verdict multipliers applied to efficiency_score
VERDICT_MULTIPLIERS = {"safe": 1.0, "needs_review": 0.75, "high_risk": 0.3}


def _parse_version_tuple(version_str: str) -> Tuple:
    """
    Parse a version string into a comparable tuple of ints.
    "6.0.13" → (6, 0, 13), "14.17.1" → (14, 17, 1).
    Non-numeric segments are kept as strings for fallback comparison.
    """
    parts = re.split(r'[.\-_]', version_str.strip())
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(p)
    return tuple(result)


def _version_lte(version: str, ceiling: str) -> bool:
    """Check if version <= ceiling using semantic comparison."""
    try:
        return _parse_version_tuple(version) <= _parse_version_tuple(ceiling)
    except (TypeError, ValueError):
        return version <= ceiling


def _classify_severity(cvss3_score: Optional[float]) -> str:
    """Map a CVSS3 score to a severity label."""
    if cvss3_score is None:
        return "low"
    if cvss3_score >= 9.0:
        return "critical"
    if cvss3_score >= 7.0:
        return "high"
    if cvss3_score >= 4.0:
        return "medium"
    return "low"


def _severity_label(severity_int: int) -> str:
    """Map Nessus severity integer to label."""
    return _SEVERITY_LABELS.get(severity_int, "low")


def _finding_cve_to_dict(cve_id: str, finding: Finding) -> dict:
    """Build a CVE dict from a scan finding."""
    return {
        "cve_id": cve_id,
        "cvss3_score": finding.cvss3_score,
        "severity": _severity_label(finding.severity or 0),
        "in_kev": getattr(finding, "is_kev", False) or False,
        "has_public_exploit": getattr(finding, "exploit_available", False) or False,
        "description": (finding.synopsis or "")[:200],
    }


def _compute_severity_delta(
    resolved_cves: List[Dict[str, Any]],
    introduced_cves: List[Dict[str, Any]],
) -> float:
    """
    Compute net severity delta: weighted sum of resolved CVE severities
    minus weighted sum of introduced CVE severities.

    Positive = net improvement, Negative = net regression.
    """
    resolved_weight = sum(
        _SEVERITY_WEIGHTS.get(c.get("severity", "low"), 0.5)
        for c in resolved_cves
    )
    introduced_weight = sum(
        _SEVERITY_WEIGHTS.get(c.get("severity", "low"), 0.5)
        for c in introduced_cves
    )
    return round(resolved_weight - introduced_weight, 2)


def _compute_verdict(
    resolved_cves: List[Dict[str, Any]],
    introduced_cves: List[Dict[str, Any]],
    net_severity_delta: float,
) -> str:
    """
    Determine the verdict for a downstream impact assessment.

    - high_risk: any remaining CVE is critical, OR remaining critical+high
      count >= resolved critical+high count
    - needs_review: remaining CVEs exist with medium+ severity
    - safe: all remaining CVEs are low/informational, or none at all
    """
    if not introduced_cves:
        return "safe"

    introduced_severities = [c.get("severity", "low") for c in introduced_cves]
    resolved_severities = [c.get("severity", "low") for c in resolved_cves]

    intro_crit = introduced_severities.count("critical")
    intro_high = introduced_severities.count("high")
    intro_crit_high = intro_crit + intro_high

    resolved_crit = resolved_severities.count("critical")
    resolved_high = resolved_severities.count("high")
    resolved_crit_high = resolved_crit + resolved_high

    if intro_crit > 0:
        return "high_risk"
    if intro_crit_high >= resolved_crit_high and intro_crit_high > 0:
        return "high_risk"

    if any(s in ("medium", "high") for s in introduced_severities):
        return "needs_review"

    return "safe"


def _find_remaining_cves_from_scan(
    db: Session,
    scan_id: int,
    component: str,
    resolved_finding_ids: List[int],
    resolved_cve_ids: List[str],
) -> List[Dict[str, Any]]:
    """
    Find CVEs from scan findings for the same component that are NOT
    resolved by this recommendation.  These represent vulnerabilities
    that still affect the target version.
    """
    resolved_ids_set = set(resolved_finding_ids or [])
    resolved_cves_set = set(resolved_cve_ids or [])

    # Search for findings matching the component name
    # Use LIKE with the component name to catch variants
    comp_pattern = "%" + component + "%"
    candidate_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.plugin_name.like(comp_pattern),
            Finding.severity > 0,  # skip info
        )
        .all()
    )

    remaining_cves = {}  # cve_id → dict (deduped)
    for f in candidate_findings:
        if f.id in resolved_ids_set:
            continue
        if not f.cves:
            continue
        for cve_id in f.cves:
            if cve_id in resolved_cves_set:
                continue
            if cve_id not in remaining_cves:
                remaining_cves[cve_id] = _finding_cve_to_dict(cve_id, f)

    return list(remaining_cves.values())


def _build_resolved_cves(
    db: Session,
    resolved_finding_ids: List[int],
    resolved_cve_ids: List[str],
) -> List[Dict[str, Any]]:
    """Build resolved CVE severity info from scan findings."""
    resolved_cves = []
    severity_by_cve = {}
    if resolved_finding_ids:
        resolved_findings = (
            db.query(Finding)
            .filter(Finding.id.in_(resolved_finding_ids[:500]))
            .all()
        )
        for f in resolved_findings:
            sev = _severity_label(f.severity or 0)
            for cve_id in (f.cves or []):
                if cve_id not in severity_by_cve or _SEVERITY_WEIGHTS.get(sev, 0) > _SEVERITY_WEIGHTS.get(severity_by_cve[cve_id], 0):
                    severity_by_cve[cve_id] = sev
    resolved_cves = [
        {"cve_id": cve_id, "severity": severity_by_cve.get(cve_id, "medium"),
         "cvss3_score": None}
        for cve_id in (resolved_cve_ids or [])
    ]
    return resolved_cves


def _assess_version(
    db: Session,
    scan_id: int,
    component: str,
    version: str,
    resolved_finding_ids: List[int],
    resolved_cve_ids: List[str],
    resolved_cves: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Assess a single target version: find remaining CVEs and compute verdict.
    Returns a dict with verdict, remaining CVEs, and deltas.
    """
    remaining = _find_remaining_cves_from_scan(
        db, scan_id, component, resolved_finding_ids, resolved_cve_ids,
    )

    ti_cves = _query_threat_intel_cves(db, component, version, resolved_cve_ids)
    scan_cve_ids = {c["cve_id"] for c in remaining}
    for ti_cve in ti_cves:
        if ti_cve["cve_id"] not in scan_cve_ids:
            remaining.append(ti_cve)

    net_cve_delta = len(resolved_cve_ids or []) - len(remaining)
    net_severity_delta = _compute_severity_delta(resolved_cves, remaining)
    verdict = _compute_verdict(resolved_cves, remaining, net_severity_delta)

    return {
        "verdict": verdict,
        "net_cve_delta": net_cve_delta,
        "net_severity_delta": net_severity_delta,
        "introduced_cves": remaining,
    }


def assess_downstream_impact(
    db: Session,
    scan_id: int,
    component: str,
    to_version: str,
    resolved_finding_ids: List[int],
    resolved_cve_ids: List[str],
    candidate_versions: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Assess the downstream impact of upgrading to a target version.

    Uses the scan's own findings as ground truth: if there are other
    findings for the same component NOT resolved by this recommendation,
    those CVEs still affect the target version.

    candidate_versions: list of {"version", "finding_ids", "cve_ids"} from
    sibling recommendations.  For each alternative, the resolved set is
    the union of the primary's resolved CVEs + the alternative's resolved CVEs
    (upgrading to a higher version fixes everything the lower version fixes too).

    Returns a downstream_impact dict or None if assessment can't run.
    """
    if not component or not to_version:
        return None

    try:
        resolved_cves = _build_resolved_cves(db, resolved_finding_ids, resolved_cve_ids)

        # Assess the primary target version
        primary = _assess_version(
            db, scan_id, component, to_version,
            resolved_finding_ids, resolved_cve_ids, resolved_cves,
        )

        # Assess alternative versions if verdict is not safe
        alternative_versions = []
        if primary["verdict"] != "safe" and candidate_versions:
            for candidate in candidate_versions[:10]:
                alt_ver = candidate["version"]
                # Combined resolved set: primary + alternative's findings/CVEs
                combined_finding_ids = list(
                    set(resolved_finding_ids) | set(candidate.get("finding_ids", []))
                )
                combined_cve_ids = list(
                    set(resolved_cve_ids) | set(candidate.get("cve_ids", []))
                )
                combined_resolved = _build_resolved_cves(
                    db, combined_finding_ids, combined_cve_ids,
                )
                alt = _assess_version(
                    db, scan_id, component, alt_ver,
                    combined_finding_ids, combined_cve_ids, combined_resolved,
                )
                alternative_versions.append({
                    "version": alt_ver,
                    "introduced_cve_count": len(alt["introduced_cves"]),
                    "net_severity_delta": alt["net_severity_delta"],
                    "net_cve_delta": alt["net_cve_delta"],
                    "verdict": alt["verdict"],
                    "_combined_finding_ids": combined_finding_ids,
                    "_combined_cve_ids": combined_cve_ids,
                })
            # Sort by fewest remaining CVEs, then best severity delta
            alternative_versions.sort(
                key=lambda x: (x["introduced_cve_count"], -x["net_severity_delta"]),
            )
            alternative_versions = alternative_versions[:3]

        return {
            "verdict": primary["verdict"],
            "net_cve_delta": primary["net_cve_delta"],
            "net_severity_delta": primary["net_severity_delta"],
            "introduced_cves": primary["introduced_cves"],
            "alternative_versions": alternative_versions,
        }

    except Exception as e:
        logger.warning("Downstream impact assessment failed for %s@%s: %s",
                       component, to_version, e)
        return None


def _version_in_range(version: str, prod: dict) -> bool:
    """
    Check if a version falls within the NVD CPE version range.

    NVD uses four range fields:
      versionStartIncluding / versionStartExcluding — lower bound
      versionEndIncluding / versionEndExcluding — upper bound

    A CVE with versionEndExcluding="6.0.25" affects versions < 6.0.25.
    A CVE with versionEndIncluding="6.0.25" affects versions <= 6.0.25.
    If only a cpe_version is present (exact match in CPE URI), match exactly.
    """
    start_inc = prod.get("versionStartIncluding")
    start_exc = prod.get("versionStartExcluding")
    end_inc = prod.get("versionEndIncluding")
    end_exc = prod.get("versionEndExcluding")
    cpe_ver = prod.get("cpe_version")

    has_range = any([start_inc, start_exc, end_inc, end_exc])

    if not has_range:
        # Exact CPE version match only
        if cpe_ver:
            return version == cpe_ver
        # No version info at all — can't determine
        return False

    # Check lower bound
    if start_inc:
        try:
            if _parse_version_tuple(version) < _parse_version_tuple(start_inc):
                return False
        except (TypeError, ValueError):
            pass
    if start_exc:
        try:
            if _parse_version_tuple(version) <= _parse_version_tuple(start_exc):
                return False
        except (TypeError, ValueError):
            pass

    # Check upper bound
    if end_inc:
        try:
            if _parse_version_tuple(version) > _parse_version_tuple(end_inc):
                return False
        except (TypeError, ValueError):
            pass
    elif end_exc:
        try:
            if _parse_version_tuple(version) >= _parse_version_tuple(end_exc):
                return False
        except (TypeError, ValueError):
            pass

    return True


def _product_name_matches(prod_name: str, component: str) -> bool:
    """Check if a CPE product name matches a component name."""
    prod_lower = prod_name.lower()
    comp_lower = component.lower().strip()

    # Direct substring match
    if comp_lower in prod_lower or prod_lower in comp_lower:
        return True

    # Normalize: ".NET" → "net", "Node.js" → "nodejs"
    comp_slug = re.sub(r'[^a-z0-9]', '', comp_lower)
    prod_slug = re.sub(r'[^a-z0-9]', '', prod_lower)
    if comp_slug and prod_slug and (comp_slug in prod_slug or prod_slug in comp_slug):
        return True

    return False


def _query_threat_intel_cves(
    db: Session, component: str, version: str, exclude_cve_ids: List[str],
) -> List[Dict[str, Any]]:
    """
    Query ThreatCVE table for CVEs affecting component@version.
    Uses NVD version range data (versionStartIncluding, versionEndExcluding, etc.)
    Returns empty list if no threat intel data is available.
    """
    if not component or not version:
        return []

    comp_lower = component.lower().strip()
    # Clean trailing dots from version (e.g., "6.0.13." → "6.0.13")
    version = version.rstrip(".")

    exclude_set = set(exclude_cve_ids or [])

    try:
        sp = db.begin_nested()
        # affected_products is a JSON column; Postgres has no LIKE/ILIKE
        # operator on json, so cast to text first. Without this the query
        # raises ``operator does not exist: json ~~ unknown`` and the
        # except-block below silently returns [], producing zero CVE
        # matches for every CPE.
        candidates = (
            db.query(ThreatCVE)
            .filter(ThreatCVE.affected_products.isnot(None))
            .filter(cast(ThreatCVE.affected_products, Text).ilike("%" + comp_lower + "%"))
            .all()
        )
        sp.commit()
    except Exception:
        sp.rollback()
        return []

    matched = []
    for cve in candidates:
        if cve.cve_id in exclude_set:
            continue
        products = cve.affected_products
        if not products or not isinstance(products, list):
            continue
        for prod in products:
            if not isinstance(prod, dict):
                continue
            prod_name = prod.get("product") or ""
            if not _product_name_matches(prod_name, component):
                continue
            if _version_in_range(version, prod):
                matched.append({
                    "cve_id": cve.cve_id,
                    "cvss2_score": cve.cvss2_score,
                    "cvss3_score": cve.cvss3_score,
                    "cvss3_vector": cve.cvss3_vector,
                    "cvss4_score": cve.cvss4_score,
                    "cvss4_vector": cve.cvss4_vector,
                    "severity": _classify_severity(cve.cvss3_score),
                    "in_kev": cve.in_kev or False,
                    "has_public_exploit": cve.has_public_exploit or False,
                    "epss_score": cve.epss_score,
                    "epss_percentile": cve.epss_percentile,
                    "ransomware_linked": bool(
                        cve.kev_ransomware_use
                        and cve.kev_ransomware_use.lower() not in ("", "unknown")
                    ),
                    "trending_in_news": cve.trending_in_news or False,
                    "exploit_count": cve.exploit_count or 0,
                    "exploit_maturity_level": cve.exploit_maturity_level,
                    "description": (cve.description or "")[:200],
                })
                break
    return matched
