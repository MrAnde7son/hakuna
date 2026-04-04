"""
Asset Relationship Engine ��� infers directional edges between assets.

Primary use case: DNS record assets that CNAME to cloud workloads
(ALB, Cloud Run, S3, App Service, etc.) get linked via `resolves_to`
edges to a materialized cloud_instance asset.
"""
import logging
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.models import Asset, AssetRelationship, Scan
from services.field_mapper import workload_to_canonical_id

logger = logging.getLogger(__name__)

# Connector-specific paths where workload dicts live inside easm_data
_WORKLOAD_PATHS = [
    ("godaddy_dns", "workload"),
    ("cloudflare_dns", "target"),
    ("aws_route53", "workload"),
    ("gcp_clouddns", "workload"),
    ("azure_dns", "workload"),
]


def _extract_workloads(easm_data: dict) -> list[tuple[str, dict]]:
    """Extract all workload dicts from an asset's easm_data blob.

    Returns list of (connector_name, workload_dict) tuples.
    """
    if not easm_data or not isinstance(easm_data, dict):
        return []
    results = []
    for connector, key in _WORKLOAD_PATHS:
        connector_data = easm_data.get(connector)
        if not isinstance(connector_data, dict):
            continue
        workload = connector_data.get(key)
        if isinstance(workload, dict) and workload.get("provider"):
            results.append((connector, workload))
    return results


def _find_or_create_cloud_asset(
    db: Session, org_id: int, scan_id: int, workload: dict, connector: str,
    cloud_cache: dict[str, Asset],
) -> tuple[Asset, bool]:
    """Find an existing cloud_instance asset matching this workload, or create one.

    Returns (asset, was_created).
    """
    canonical_id = workload_to_canonical_id(workload)
    provider = workload.get("provider", "unknown")

    # Check in-memory cache first
    if canonical_id in cloud_cache:
        return cloud_cache[canonical_id], False

    # Query existing cloud_instance assets in this org
    org_scan_ids = db.query(Scan.id).filter(Scan.org_id == org_id).scalar_subquery()
    candidates = (
        db.query(Asset)
        .filter(
            Asset.asset_type == "cloud_instance",
            Asset.scan_id.in_(org_scan_ids),
        )
        .all()
    )
    for asset in candidates:
        identity = asset.asset_identity or {}
        if (identity.get("cloud_provider") == provider
                and identity.get("instance_id") == canonical_id):
            cloud_cache[canonical_id] = asset
            return asset, False

    # Create new cloud_instance asset
    service = workload.get("service", "unknown")
    name_part = canonical_id.split(":", 2)[-1]
    cloud_asset = Asset(
        scan_id=scan_id,
        hostname=f"{provider}:{service}:{name_part}",
        asset_type="cloud_instance",
        asset_identity={
            "cloud_provider": provider,
            "instance_id": canonical_id,
        },
        asset_attributes=workload,
        is_internet_facing=True,
        environment_tag="cloud",
        source_system=connector,
        source_systems=[connector],
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        times_seen=1,
    )
    db.add(cloud_asset)
    db.flush()
    cloud_cache[canonical_id] = cloud_asset
    return cloud_asset, True


def _create_relationship(
    db: Session, org_id: int, source_asset_id: int, target_asset_id: int,
    relationship_type: str, source_detail: dict,
) -> bool:
    """Create a relationship edge idempotently. Returns True if created."""
    # Check existence first to avoid savepoint overhead in common case
    existing = db.query(AssetRelationship.id).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.source_asset_id == source_asset_id,
        AssetRelationship.target_asset_id == target_asset_id,
        AssetRelationship.relationship_type == relationship_type,
    ).first()
    if existing:
        return False

    rel = AssetRelationship(
        org_id=org_id,
        source_asset_id=source_asset_id,
        target_asset_id=target_asset_id,
        relationship_type=relationship_type,
        source_detail=source_detail,
    )
    db.add(rel)
    try:
        db.flush()
        return True
    except IntegrityError:
        db.rollback()
        return False


def infer_dns_to_cloud_relationships(db: Session, org_id: int, scan_id: int) -> dict:
    """Materialize cloud resource assets and resolves_to edges from DNS workload metadata.

    Called as a post-ingest pipeline step after dedup and before EASM enrichment.
    """
    assets = (
        db.query(Asset)
        .filter(Asset.scan_id == scan_id, Asset.easm_data.isnot(None))
        .all()
    )

    cloud_assets_created = 0
    relationships_created = 0
    relationships_existing = 0
    cloud_cache: dict[str, Asset] = {}

    for asset in assets:
        workloads = _extract_workloads(asset.easm_data)
        if not workloads:
            continue

        for connector, workload in workloads:
            cloud_asset, was_created = _find_or_create_cloud_asset(
                db, org_id, scan_id, workload, connector, cloud_cache,
            )
            if was_created:
                cloud_assets_created += 1

            # Provenance metadata for the edge
            connector_data = (asset.easm_data or {}).get(connector, {})
            record_type = connector_data.get("record_type", "CNAME")

            created = _create_relationship(
                db, org_id,
                source_asset_id=asset.id,
                target_asset_id=cloud_asset.id,
                relationship_type="resolves_to",
                source_detail={"connector": connector, "dns_record_type": record_type},
            )
            if created:
                relationships_created += 1
            else:
                relationships_existing += 1

    if relationships_created or cloud_assets_created:
        db.commit()

    return {
        "cloud_assets_created": cloud_assets_created,
        "relationships_created": relationships_created,
        "relationships_existing": relationships_existing,
    }


def reassign_relationships(db: Session, old_asset_id: int, new_asset_id: int) -> None:
    """Repoint relationship edges from old_asset to new_asset during dedup merge.

    Handles self-loops (deleted) and duplicates (deleted).
    """
    for direction in ("source_asset_id", "target_asset_id"):
        col = getattr(AssetRelationship, direction)
        edges = db.query(AssetRelationship).filter(col == old_asset_id).all()

        for edge in edges:
            new_src = new_asset_id if direction == "source_asset_id" else edge.source_asset_id
            new_tgt = new_asset_id if direction == "target_asset_id" else edge.target_asset_id

            if new_src == new_tgt:
                db.delete(edge)
                continue

            existing = db.query(AssetRelationship).filter(
                AssetRelationship.org_id == edge.org_id,
                AssetRelationship.source_asset_id == new_src,
                AssetRelationship.target_asset_id == new_tgt,
                AssetRelationship.relationship_type == edge.relationship_type,
            ).first()

            if existing:
                db.delete(edge)
            else:
                setattr(edge, direction, new_asset_id)
