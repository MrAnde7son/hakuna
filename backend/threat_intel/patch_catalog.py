"""
Patch Catalog — unified query layer across MSRCPatch + PatchAdvisory.

Provides a single interface for the remediation engine to ask:
"given CVE-XXXX-YYYY, what patches are available, for which platforms,
and what is their metadata?"
"""
import logging
from typing import List, Optional

from sqlalchemy import or_, func, desc, String
from sqlalchemy.orm import Session

from models.threat_intel_models import MSRCPatch, PatchAdvisory
from services import patch_reliability as reliability_svc

logger = logging.getLogger(__name__)


def _cve_json_filter(cve_id: str):
    """
    Build a cross-DB filter for JSON array column containing a CVE ID.
    SQLite stores JSON as text, so LIKE works. PostgreSQL has native JSONB operators
    but LIKE on the cast also works and keeps the code portable.
    """
    # Both SQLite and PG: the JSON array is stored as '["CVE-2024-1234", ...]'
    # A LIKE match on the serialized string is safe for CVE IDs (no regex chars).
    pattern = f'%"{cve_id}"%'
    return PatchAdvisory.cve_ids.cast(String).like(pattern)


def get_patches_for_cve(db: Session, cve_id: str) -> list:
    """
    Query across MSRCPatch + PatchAdvisory for all patches addressing a CVE.

    Returns a normalized list of dicts:
    [
        {
            "source": "microsoft" | "ubuntu" | "debian" | ...,
            "advisory_id": "KB5034763" | "USN-1234-1" | ...,
            "title": str,
            "severity": str,
            "release_date": str,
            "url": str,
            "affected_packages": [...],
        }
    ]
    """
    cve_id = cve_id.strip().upper()
    results = []

    # 1. Microsoft patches (MSRCPatch — indexed on cve_id)
    msrc_records = db.query(MSRCPatch).filter(MSRCPatch.cve_id == cve_id).all()
    for r in msrc_records:
        results.append({
            "source": "microsoft",
            "reliability_source": "msrc",
            "advisory_id": r.kb_id,
            "title": f"{r.kb_id} — {r.product_name}" if r.product_name else r.kb_id,
            "severity": r.severity,
            "impact": r.impact,
            "release_date": r.release_date,
            "url": r.article_url,
            "affected_packages": [{"name": r.product_name, "product_id": r.product_id}],
            "supersedes": r.supercedence,
            "restart_required": r.restart_required,
        })

    # 2. Non-Microsoft patch advisories (filter via SQL LIKE on JSON text)
    advisories = (
        db.query(PatchAdvisory)
        .filter(_cve_json_filter(cve_id))
        .all()
    )
    for adv in advisories:
        results.append({
            "source": adv.source,
            "reliability_source": adv.source,
            "advisory_id": adv.source_advisory_id,
            "title": adv.title,
            "severity": adv.severity,
            "release_date": adv.release_date,
            "url": adv.advisory_url,
            "affected_packages": adv.affected_packages or [],
        })

    # 3. Annotate each patch with its reliability record (single bulk query).
    _attach_reliability(db, results)

    return results


def _attach_reliability(db: Session, patches: list) -> None:
    """
    Bulk-load reliability for a list of patch dicts and merge it in-place.
    Patches without a matching reliability record get the "unknown" shape.
    """
    pairs = [
        (p.get("reliability_source") or p.get("source") or "", p.get("advisory_id") or "")
        for p in patches
    ]
    records = reliability_svc.get_reliability_map(db, pairs)
    for p in patches:
        key = (
            (p.get("reliability_source") or p.get("source") or "").strip().lower(),
            (p.get("advisory_id") or "").strip(),
        )
        p["reliability"] = reliability_svc.reliability_to_dict(records.get(key))


def get_patch_coverage_summary(db: Session, cve_ids: list) -> dict:
    """
    For a list of CVEs, return patch coverage summary.

    Returns:
    {
        "CVE-2024-1234": {"has_patch": true, "sources": ["microsoft", "ubuntu"], "patch_count": 3},
        "CVE-2024-5678": {"has_patch": false, "sources": [], "patch_count": 0},
    }
    """
    cve_ids = [c.strip().upper() for c in cve_ids if c]
    result = {cve_id: {"has_patch": False, "sources": [], "patch_count": 0} for cve_id in cve_ids}

    # Microsoft patches (indexed)
    msrc_records = db.query(MSRCPatch.cve_id).filter(MSRCPatch.cve_id.in_(cve_ids)).all()
    for (cve_id,) in msrc_records:
        if cve_id in result:
            if "microsoft" not in result[cve_id]["sources"]:
                result[cve_id]["sources"].append("microsoft")
            result[cve_id]["patch_count"] += 1
            result[cve_id]["has_patch"] = True

    # Non-Microsoft advisories — one SQL LIKE query per CVE
    for cve_id in cve_ids:
        rows = (
            db.query(PatchAdvisory.source)
            .filter(_cve_json_filter(cve_id))
            .all()
        )
        for (source,) in rows:
            if source not in result[cve_id]["sources"]:
                result[cve_id]["sources"].append(source)
            result[cve_id]["patch_count"] += 1
            result[cve_id]["has_patch"] = True

    return result


def get_unpatched_cves(db: Session, cve_ids: list) -> list:
    """Return CVEs from the input list that have no known patches in any source."""
    coverage = get_patch_coverage_summary(db, cve_ids)
    return [cve_id for cve_id, info in coverage.items() if not info["has_patch"]]


def get_patch_stats(db: Session) -> dict:
    """
    Return aggregate stats for the patch catalog.
    All queries use COUNT aggregations — no full table scans.
    """
    from models.threat_intel_models import PatchReliability

    # MSRC count
    msrc_count = db.query(func.count(MSRCPatch.id)).scalar() or 0
    msrc_cves = db.query(func.count(func.distinct(MSRCPatch.cve_id))).scalar() or 0

    # PatchAdvisory counts by source (GROUP BY, no row loading)
    source_counts = (
        db.query(PatchAdvisory.source, func.count(PatchAdvisory.id))
        .group_by(PatchAdvisory.source)
        .all()
    )
    by_source = {"microsoft": msrc_count}
    for source, count in source_counts:
        by_source[source] = count

    total_advisories = msrc_count + sum(c for _, c in source_counts)

    # Recent advisories (small LIMIT query)
    recent = (
        db.query(PatchAdvisory)
        .order_by(desc(PatchAdvisory.created_at))
        .limit(10)
        .all()
    )
    recent_list = [
        {
            "source": r.source,
            "advisory_id": r.source_advisory_id,
            "title": r.title,
            "severity": r.severity,
            "release_date": r.release_date,
            "cve_count": len(r.cve_ids) if r.cve_ids else 0,
        }
        for r in recent
    ]

    # Reliability rollup — one aggregate query grouped by status.
    reliability_counts = dict(
        db.query(PatchReliability.status, func.count(PatchReliability.id))
        .group_by(PatchReliability.status)
        .all()
    )

    return {
        "total_advisories": total_advisories,
        "by_source": by_source,
        "msrc_cves_covered": msrc_cves,
        "recent_advisories": recent_list,
        "reliability": {
            "stable": reliability_counts.get("stable", 0),
            "known_issues": reliability_counts.get("known_issues", 0),
            "recalled": reliability_counts.get("recalled", 0),
            "unknown": reliability_counts.get("unknown", 0),
            "scored_total": sum(reliability_counts.values()),
        },
    }
