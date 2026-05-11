"""Asset upsert + staleness lifecycle for identity discovery.

Identities live in the same ``assets`` table as everything else, keyed by
``asset_identity = {"source": "linkedin", "slug": "<canonical>"}``. We
follow the ``code_repo`` precedent — hostname is left null, identity-
specific metadata lives in ``asset_attributes``.

Staleness rule:
    A present identity resets its absence counter and is marked active.
    An absent identity (linked to this org's identity scan but not in
    the current run's slug set) increments its counter; at 3 consecutive
    successful runs absent it transitions to ``asset_status='stale'``.
    No-signal runs (rate-limited, blocked, or empty SERP — see
    ``SourceResult.is_no_signal``) do NOT increment counters. This is
    the safeguard against silent mass-pruning when DDGS soft-blocks us.

Suppression:
    Slugs on the ``identity_suppressions`` list are filtered out of
    every run's record set before upsert, AND any existing identity
    asset matching a suppressed slug is hard-deleted on the next run —
    this is the GDPR Article 17 enforcement point.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from models.models import Asset, IdentitySuppression, Scan
from services.asset_observations import record_observation
from .sources import IdentityRecord, SourceResult

logger = logging.getLogger(__name__)

# Number of consecutive successful runs an identity must be absent from
# before transitioning to ``stale``. Chosen to absorb the most likely DDGS
# instability — a single bad-result run shouldn't propagate to a status
# flip even if records came back. Adjust here, not at call sites.
STALE_AFTER_ABSENT_RUNS = 3

_ABSENT_COUNT_KEY = "identity_absent_count"


def _get_or_create_identity_scan(db: Session, org_id: int) -> Scan:
    """Return the rolling Scan row for this org's identity discovery.

    One scan per (org, source_type='identity_discovery'). Created on first
    run; subsequent runs update ``last_run_at`` / ``run_count``. This keeps
    the scans table from filling with empty per-run rows and matches the
    "rolling discovery" pattern used by other periodic enrichment jobs.
    """
    scan = (
        db.query(Scan)
        .filter(Scan.org_id == org_id, Scan.source_type == "identity_discovery")
        .first()
    )
    if scan is None:
        scan = Scan(
            org_id=org_id,
            filename=f"identity-discovery-org-{org_id}",
            scan_name="Identity Discovery",
            source_type="identity_discovery",
            status="running",
        )
        db.add(scan)
        db.flush()
    return scan


def _suppressed_slugs(db: Session, org_id: int, source: str) -> set[str]:
    rows = (
        db.query(IdentitySuppression.slug)
        .filter(
            IdentitySuppression.org_id == org_id,
            IdentitySuppression.source == source,
        )
        .all()
    )
    return {r[0] for r in rows}


def _existing_identity_assets(
    db: Session, *, org_id: int, scan_id: int, source: str,
) -> dict[str, Asset]:
    """Map ``slug -> Asset`` for every identity asset owned by this scan.

    Looked up by (scan_id, asset_type='identity') and then narrowed by
    the source field of asset_identity. That keeps a future Hunter/Apollo
    source from colliding with the LinkedIn source within the same org.
    """
    rows = (
        db.query(Asset)
        .filter(Asset.scan_id == scan_id, Asset.asset_type == "identity")
        .all()
    )
    out: dict[str, Asset] = {}
    for a in rows:
        ident = a.asset_identity or {}
        if ident.get("source") != source:
            continue
        slug = ident.get("slug")
        if slug:
            out[slug] = a
    return out


def _bump_easm_data(asset: Asset, **updates) -> None:
    """Mutate ``easm_data`` JSONB and flag it modified so SQLAlchemy
    persists the change. JSONB mutation otherwise goes unseen."""
    data = dict(asset.easm_data or {})
    data.update(updates)
    asset.easm_data = data
    flag_modified(asset, "easm_data")


def apply_discovery_result(
    db: Session, *, org_id: int, source: str, result: SourceResult,
) -> dict:
    """Upsert assets from a ``SourceResult`` and run the staleness pass.

    Returns ``{
        "scan_id": int,
        "no_signal": bool,
        "created": int,
        "updated": int,
        "stale_now": int,        # transitioned to stale this run
        "deleted_suppressed": int,
        "skipped_suppressed": int,
    }``.

    No-signal runs only bump the scan heartbeat and run any pending
    suppression deletions. They never touch absence counters or status.
    """
    scan = _get_or_create_identity_scan(db, org_id)
    now = datetime.utcnow()
    scan.last_run_at = now
    scan.run_count = (scan.run_count or 0) + 1

    suppressed = _suppressed_slugs(db, org_id, source)
    existing = _existing_identity_assets(
        db, org_id=org_id, scan_id=scan.id, source=source,
    )

    # GDPR enforcement: hard-delete any existing identity assets whose
    # slug has been suppressed. Runs every cycle — including no-signal —
    # because the user's right to erasure must not depend on whether
    # DDGS happens to be cooperating today.
    deleted_suppressed = 0
    for slug in list(existing.keys()):
        if slug in suppressed:
            db.delete(existing.pop(slug))
            deleted_suppressed += 1

    if result.is_no_signal:
        scan.status = "completed"
        db.flush()
        logger.info(
            "Identity discovery no-signal run org=%s source=%s suppressed_deletes=%d",
            org_id, source, deleted_suppressed,
        )
        return {
            "scan_id": scan.id,
            "no_signal": True,
            "created": 0,
            "updated": 0,
            "stale_now": 0,
            "deleted_suppressed": deleted_suppressed,
            "skipped_suppressed": 0,
        }

    created = 0
    updated = 0
    skipped_suppressed = 0
    seen_slugs: set[str] = set()

    records: list[IdentityRecord] = result.records or []
    for record in records:
        if record.slug in suppressed:
            skipped_suppressed += 1
            continue
        seen_slugs.add(record.slug)

        asset = existing.get(record.slug)
        if asset is None:
            asset = Asset(
                scan_id=scan.id,
                asset_type="identity",
                asset_identity={"source": source, "slug": record.slug},
                asset_attributes={
                    "display_name": record.display_name,
                    "title": record.title,
                    "profile_url": record.url,
                },
                source_systems=["identity_discovery"],
                first_seen=now,
                last_seen=now,
                times_seen=1,
                asset_status="active",
            )
            _bump_easm_data(asset, **{_ABSENT_COUNT_KEY: 0})
            db.add(asset)
            db.flush()
            existing[record.slug] = asset
            created += 1
        else:
            attrs = dict(asset.asset_attributes or {})
            if record.display_name:
                attrs["display_name"] = record.display_name
            if record.title:
                attrs["title"] = record.title
            if record.url:
                attrs["profile_url"] = record.url
            asset.asset_attributes = attrs
            flag_modified(asset, "asset_attributes")
            asset.last_seen = now
            asset.times_seen = (asset.times_seen or 0) + 1
            asset.asset_status = "active"
            asset.stale_since = None
            _bump_easm_data(asset, **{_ABSENT_COUNT_KEY: 0})
            updated += 1

        # Record an AssetObservation so the asset detail "Sources" tab
        # shows where this identity came from — same provenance pattern
        # as GitHub/npm assets in services/easm.py:_import_github_npm_assets.
        record_observation(
            db,
            asset_id=asset.id,
            source_system=f"identity_discovery:{source}",
            raw_fields={
                "slug": record.slug,
                "display_name": record.display_name,
                "title": record.title,
                "profile_url": record.url,
            },
            scan_id=scan.id,
            org_id=org_id,
        )

    # Staleness pass: identities present in the existing set but not in
    # this run's slug set get their absence counter bumped. Only on
    # successful runs (we're past the no-signal early return).
    stale_now = 0
    for slug, asset in existing.items():
        if slug in seen_slugs:
            continue
        prev = (asset.easm_data or {}).get(_ABSENT_COUNT_KEY) or 0
        new_count = prev + 1
        _bump_easm_data(asset, **{_ABSENT_COUNT_KEY: new_count})
        if new_count >= STALE_AFTER_ABSENT_RUNS and asset.asset_status != "stale":
            asset.asset_status = "stale"
            asset.stale_since = now
            stale_now += 1

    # Generate breach-correlation findings on identities we just touched.
    # Wrapped so a failure here doesn't roll back the upsert work — the
    # finding pass is enrichment, not the discovery itself.
    breach_findings = {"created": 0, "updated": 0}
    try:
        touched_ids = [a.id for a in existing.values() if a.id is not None]
        if touched_ids:
            from .breach_correlation import correlate_breaches_for_identities
            breach_findings = correlate_breaches_for_identities(
                db, org_id=org_id, scan_id=scan.id, identity_asset_ids=touched_ids,
            )
    except Exception:
        logger.exception(
            "Breach correlation failed for org=%s (non-fatal)", org_id,
        )

    scan.status = "completed"
    db.flush()

    logger.info(
        "Identity discovery org=%s source=%s created=%d updated=%d "
        "stale_now=%d deleted_suppressed=%d skipped_suppressed=%d "
        "breach_findings_created=%d",
        org_id, source, created, updated, stale_now,
        deleted_suppressed, skipped_suppressed,
        breach_findings.get("created", 0),
    )
    return {
        "scan_id": scan.id,
        "no_signal": False,
        "created": created,
        "updated": updated,
        "stale_now": stale_now,
        "deleted_suppressed": deleted_suppressed,
        "skipped_suppressed": skipped_suppressed,
        "breach_findings_created": breach_findings.get("created", 0),
        "breach_findings_updated": breach_findings.get("updated", 0),
    }
