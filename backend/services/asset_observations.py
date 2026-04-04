"""Record per-source observations for assets and findings.

Every time a source (scanner, integration, EASM) creates or updates an asset
or finding, call the appropriate ``record_*`` function to capture what that
source reported.  The merged row stays as the single source of truth, while
observation rows let the UI show a per-source breakdown on the detail page.
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models.models import AssetObservation, FindingObservation

logger = logging.getLogger(__name__)


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
