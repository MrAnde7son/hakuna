"""Read helpers over the unified edge graph (`asset_relationships`).

Phase 2 read path. Today, blast-radius and the finding correlator each
do their own graph walks against scattered tables (`InventoryNetConn`
for ports, `AssetRelationship` for infra/auth, ad-hoc joins for
sessions). This module is the single point that returns shaped views
of the unified edge graph so callers don't replicate the SQL.

These helpers do not invent new semantics — they expose what's already
in the table after the producers (EASM, VM scanner, audit agents,
inventory materializer, knowledge graph) have written it.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from sqlalchemy.orm import Session

from models.asset_edges import (
    ASSET_TO_ASSET_AUTH,
    ASSET_TO_ASSET_COERCE,
    ASSET_TO_ASSET_PORT,
    INTERNET_TO_ASSET,
    USER_TO_ASSET,
)
from models.models import AssetRelationship


# Edge types that prove src→dst reachability for blast-radius purposes.
REACHABILITY_EDGE_TYPES = (
    ASSET_TO_ASSET_PORT,
    ASSET_TO_ASSET_AUTH,
    ASSET_TO_ASSET_COERCE,
    # Legacy types still in use by inventory_graph_extractor — fold them
    # in so the migration is purely additive.
    "connects_to",
    "trusts_domain",
    "member_of_domain",
    "shares_credential_with",
    "runs_as_principal",
    # Infra edges that already drove the blast-radius "follow infra" hop.
    "resolves_to",
    "alias_of",
)


def list_outbound_edges(
    db: Session,
    *,
    org_id: int,
    src_asset_ids: Iterable[int],
    edge_types: Iterable[str] | None = None,
) -> dict[int, list[AssetRelationship]]:
    """Return outbound edges for each src asset, grouped by source_asset_id.

    `edge_types` defaults to `REACHABILITY_EDGE_TYPES`.
    """
    src_ids = [int(a) for a in src_asset_ids if a]
    if not src_ids:
        return {}
    types = list(edge_types) if edge_types else list(REACHABILITY_EDGE_TYPES)

    rows = (
        db.query(AssetRelationship)
        .filter(
            AssetRelationship.org_id == org_id,
            AssetRelationship.source_asset_id.in_(src_ids),
            AssetRelationship.relationship_type.in_(types),
        )
        .all()
    )
    grouped: dict[int, list[AssetRelationship]] = defaultdict(list)
    for r in rows:
        grouped[r.source_asset_id].append(r)
    return grouped


def reachable_targets(
    db: Session,
    *,
    org_id: int,
    src_asset_ids: Iterable[int],
    edge_types: Iterable[str] | None = None,
) -> dict[int, set[int]]:
    """Map src_asset_id → {target_asset_ids reachable via any qualifying edge}.

    Used by the blast-radius bulk computation. The result is the same as
    walking `asset_relationships` directly, but keyed and deduped for
    callers.
    """
    grouped = list_outbound_edges(
        db, org_id=org_id, src_asset_ids=src_asset_ids, edge_types=edge_types,
    )
    out: dict[int, set[int]] = {}
    for src, edges in grouped.items():
        targets: set[int] = set()
        for edge in edges:
            if edge.target_asset_id is not None and edge.target_asset_id != src:
                targets.add(edge.target_asset_id)
        if targets:
            out[src] = targets
    return out


def internet_facing_assets(db: Session, *, org_id: int) -> set[int]:
    """Asset IDs with at least one `internet_to_asset` edge in the org."""
    rows = (
        db.query(AssetRelationship.target_asset_id)
        .filter(
            AssetRelationship.org_id == org_id,
            AssetRelationship.relationship_type == INTERNET_TO_ASSET,
            AssetRelationship.target_asset_id.isnot(None),
        )
        .distinct()
        .all()
    )
    return {row[0] for row in rows if row[0] is not None}


def privileged_user_to_asset_edges(
    db: Session,
    *,
    org_id: int,
    asset_ids: Iterable[int],
) -> dict[int, list[AssetRelationship]]:
    """`user_to_asset` edges (privileged sessions / admin grants) for the
    given assets. Keyed by `target_asset_id`.
    """
    ids = [int(a) for a in asset_ids if a]
    if not ids:
        return {}
    rows = (
        db.query(AssetRelationship)
        .filter(
            AssetRelationship.org_id == org_id,
            AssetRelationship.relationship_type == USER_TO_ASSET,
            AssetRelationship.target_asset_id.in_(ids),
        )
        .all()
    )
    grouped: dict[int, list[AssetRelationship]] = defaultdict(list)
    for r in rows:
        grouped[r.target_asset_id].append(r)
    return grouped
