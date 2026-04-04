"""Record per-source observations for assets and findings.

Every time a source (scanner, integration, EASM) creates or updates an asset
or finding, call the appropriate ``record_*`` function to capture what that
source reported.  The merged row stays as the single source of truth, while
observation rows let the UI show a per-source breakdown on the detail page.

When ``source_priority`` is configured in dedup_config, ``rollup_asset``
re-projects the merged asset from its observations so that higher-priority
sources win for each field.
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models.models import Asset, AssetObservation, Finding, FindingObservation

logger = logging.getLogger(__name__)

# Fields on Asset that can be rolled up from observation raw_fields.
# Maps raw_fields key → Asset column name (when they differ).
_ASSET_FIELD_MAP: dict[str, str] = {
    "ip": "ip",
    "ip_address": "ip",            # integration builder uses ip_address
    "hostname": "hostname",
    "fqdn": "fqdn",
    "os": "os",
    "netbios_name": "netbios_name",
    "mac_address": "mac_address",
    "device_type": "device_type",
    "system_type": "system_type",
    "is_credentialed": "is_credentialed",
    "is_internet_facing": "is_internet_facing",
    "environment_tag": "environment_tag",
    "environment": "environment_tag",   # integration builder alias
    "criticality": "criticality",
    "asset_type": "asset_type",
}

# Columns that should never be overwritten by rollup (computed or lifecycle).
_ROLLUP_SKIP = {
    "id", "scan_id", "risk_score", "critical_count", "high_count",
    "medium_count", "low_count", "info_count", "first_seen", "last_seen",
    "times_seen", "asset_status", "stale_since", "source_id", "source_system",
    "source_systems", "user_edited_fields",
}

# Finding fields eligible for rollup.
_FINDING_FIELD_MAP: dict[str, str] = {
    "title": "plugin_name",
    "plugin_name": "plugin_name",
    "plugin_id": "plugin_id",
    "description": "description",
    "synopsis": "synopsis",
    "solution": "solution",
    "severity": "severity",
    "severity_label": "severity_label",
    "cvss_score": "cvss3_score",
    "cvss3_score": "cvss3_score",
    "cvss_vector": "cvss3_vector",
    "cvss3_vector": "cvss3_vector",
    "vpr_score": "vpr_score",
    "exploit_available": "exploit_available",
    "exploit_maturity": "exploit_maturity",
    "port": "port",
    "protocol": "protocol",
    "plugin_output": "plugin_output",
    "plugin_family": "plugin_family",
}


# ── Asset observations ──────────────────────────────────

def record_observation(
    db: Session,
    *,
    asset_id: int,
    source_system: str,
    raw_fields: dict,
    scan_id: Optional[int] = None,
    org_id: Optional[int] = None,
) -> None:
    """Upsert an AssetObservation row for (asset_id, source_system)."""
    if not source_system:
        return

    existing = (
        db.query(AssetObservation)
        .filter(
            AssetObservation.asset_id == asset_id,
            AssetObservation.source_system == source_system,
        )
        .first()
    )

    now = datetime.utcnow()
    if existing:
        existing.raw_fields = raw_fields
        existing.last_seen = now
        existing.times_seen = (existing.times_seen or 1) + 1
        if scan_id:
            existing.scan_id = scan_id
    else:
        db.add(AssetObservation(
            asset_id=asset_id,
            source_system=source_system,
            scan_id=scan_id,
            org_id=org_id,
            raw_fields=raw_fields,
            first_seen=now,
            last_seen=now,
            times_seen=1,
        ))


def reassign_observations(db: Session, old_asset_id: int, new_asset_id: int) -> None:
    """Move asset observations from a duplicate to the survivor during dedup merge."""
    _reassign(db, AssetObservation, "asset_id", old_asset_id, new_asset_id)


# ── Finding observations ────────────────────────────────

def record_finding_observation(
    db: Session,
    *,
    finding_id: int,
    source_system: str,
    raw_fields: dict,
    scan_id: Optional[int] = None,
    org_id: Optional[int] = None,
) -> None:
    """Upsert a FindingObservation row for (finding_id, source_system)."""
    if not source_system:
        return

    existing = (
        db.query(FindingObservation)
        .filter(
            FindingObservation.finding_id == finding_id,
            FindingObservation.source_system == source_system,
        )
        .first()
    )

    now = datetime.utcnow()
    if existing:
        existing.raw_fields = raw_fields
        existing.last_seen = now
        existing.times_seen = (existing.times_seen or 1) + 1
        if scan_id:
            existing.scan_id = scan_id
    else:
        db.add(FindingObservation(
            finding_id=finding_id,
            source_system=source_system,
            scan_id=scan_id,
            org_id=org_id,
            raw_fields=raw_fields,
            first_seen=now,
            last_seen=now,
            times_seen=1,
        ))


def reassign_finding_observations(db: Session, old_finding_id: int, new_finding_id: int) -> None:
    """Move finding observations from a duplicate to the survivor during dedup merge."""
    _reassign(db, FindingObservation, "finding_id", old_finding_id, new_finding_id)


# ── Rollup: project observations → merged record ────────

def rollup_asset(db: Session, asset_id: int, source_priority: dict) -> None:
    """Re-project merged asset fields from its observations using source priority.

    ``source_priority`` is a dict like::

        {
            "*":    ["crowdstrike", "nessus", "wiz"],
            "fqdn": ["crowdstrike", "wiz", "nessus"],
        }

    For each field, walk the priority list for that field (falling back to ``*``).
    The first source that has a non-null value wins.  Sources not in the list are
    tried last in observation-order.
    """
    if not source_priority:
        return

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return

    user_edited = set(asset.user_edited_fields or [])

    observations = (
        db.query(AssetObservation)
        .filter(AssetObservation.asset_id == asset_id)
        .all()
    )
    if not observations:
        return

    obs_by_source: dict[str, dict] = {
        obs.source_system: obs.raw_fields or {}
        for obs in observations
    }

    # Collect all unique target columns we can roll up
    target_columns: set[str] = set()
    for raw in obs_by_source.values():
        for raw_key in raw:
            col = _ASSET_FIELD_MAP.get(raw_key)
            if col and col not in _ROLLUP_SKIP:
                target_columns.add(col)

    default_priority = source_priority.get("*", [])

    for col in target_columns:
        if col in user_edited:
            continue

        # Build ordered source list: explicit priority first, then remaining sources
        field_priority = source_priority.get(col, default_priority)
        remaining = [s for s in obs_by_source if s not in field_priority]
        ordered_sources = list(field_priority) + remaining

        # Reverse-map: which raw_fields keys map to this column?
        raw_keys = [k for k, v in _ASSET_FIELD_MAP.items() if v == col]

        for src in ordered_sources:
            raw = obs_by_source.get(src)
            if not raw:
                continue
            # Try each raw key that maps to this column
            for rk in raw_keys:
                val = raw.get(rk)
                if val is not None and val != "":
                    setattr(asset, col, val)
                    break
            else:
                continue
            break  # found a value, move to next column


def rollup_finding(db: Session, finding_id: int, source_priority: dict) -> None:
    """Re-project merged finding fields from its observations using source priority."""
    if not source_priority:
        return

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return

    user_edited = set(finding.user_edited_fields or [])

    observations = (
        db.query(FindingObservation)
        .filter(FindingObservation.finding_id == finding_id)
        .all()
    )
    if not observations:
        return

    obs_by_source: dict[str, dict] = {
        obs.source_system: obs.raw_fields or {}
        for obs in observations
    }

    target_columns: set[str] = set()
    for raw in obs_by_source.values():
        for raw_key in raw:
            col = _FINDING_FIELD_MAP.get(raw_key)
            if col:
                target_columns.add(col)

    default_priority = source_priority.get("*", [])

    for col in target_columns:
        if col in user_edited:
            continue

        field_priority = source_priority.get(col, default_priority)
        remaining = [s for s in obs_by_source if s not in field_priority]
        ordered_sources = list(field_priority) + remaining

        raw_keys = [k for k, v in _FINDING_FIELD_MAP.items() if v == col]

        for src in ordered_sources:
            raw = obs_by_source.get(src)
            if not raw:
                continue
            for rk in raw_keys:
                val = raw.get(rk)
                if val is not None and val != "":
                    setattr(finding, col, val)
                    break
            else:
                continue
            break


def rollup_all_assets(db: Session, source_priority: dict, org_id: Optional[int] = None) -> int:
    """Re-rollup all assets (optionally filtered to an org). Returns count updated."""
    if not source_priority or not any(source_priority.values()):
        return 0

    q = db.query(Asset.id)
    if org_id:
        from models.models import Scan
        q = q.join(Scan, Asset.scan_id == Scan.id).filter(Scan.org_id == org_id)

    asset_ids = [row[0] for row in q.all()]
    for aid in asset_ids:
        rollup_asset(db, aid, source_priority)

    db.commit()
    return len(asset_ids)


# ── Shared helper ────────────────────────────────────────

def _reassign(db: Session, model, fk_field: str, old_id: int, new_id: int) -> None:
    """Generic reassign-or-merge logic for observation rows."""
    old_obs = db.query(model).filter(getattr(model, fk_field) == old_id).all()
    for obs in old_obs:
        existing = (
            db.query(model)
            .filter(
                getattr(model, fk_field) == new_id,
                model.source_system == obs.source_system,
            )
            .first()
        )
        if existing:
            if obs.last_seen and (not existing.last_seen or obs.last_seen > existing.last_seen):
                existing.raw_fields = obs.raw_fields
                existing.last_seen = obs.last_seen
            if obs.first_seen and (not existing.first_seen or obs.first_seen < existing.first_seen):
                existing.first_seen = obs.first_seen
            existing.times_seen = (existing.times_seen or 1) + (obs.times_seen or 1)
            db.delete(obs)
        else:
            setattr(obs, fk_field, new_id)
