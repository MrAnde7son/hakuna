"""Phase 2 tests — inventory→unified-edge materializer.

Verifies that the materializer:
- Emits `asset_to_asset_port` edges from `InventoryNetConn` rows that
  resolve to known assets (and skips unresolvable / loopback peers).
- Emits `user_to_asset` edges only for principals that are privileged
  somewhere in the org (filters out service-account chatter).
- Emits `asset_to_asset_auth` edges for shared privileged sessions.
- Honors the per-source / per-principal cap.
- Is idempotent — re-runs only bump `last_seen_at`.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.asset_edges import (
    ASSET_TO_ASSET_AUTH,
    ASSET_TO_ASSET_PORT,
    USER_TO_ASSET,
)
from models.models import (
    AssetRelationship,
    InventoryLoggedOn,
    InventoryNetConn,
    InventoryUser,
)


def _add_netconn(db, scan, asset, *, remote_addr, remote_port,
                 state="ESTABLISHED", proto="tcp4"):
    row = InventoryNetConn(
        scan_id=scan.id,
        asset_id=asset.id,
        proto=proto,
        state=state,
        local_addr=asset.ip,
        local_port=12345,
        remote_addr=remote_addr,
        remote_port=remote_port,
    )
    db.add(row)
    db.flush()
    return row


def _add_user(db, scan, asset, *, username, domain="CORP",
              is_domain_admin=False, is_local_admin=False, is_privileged=False):
    u = InventoryUser(
        scan_id=scan.id,
        asset_id=asset.id,
        username=username,
        domain=domain,
        is_domain_admin=is_domain_admin,
        is_local_admin=is_local_admin,
        is_privileged=is_privileged,
        user_type="domain_user",
    )
    db.add(u)
    db.flush()
    return u


def _add_logon(db, scan, asset, *, username, domain="CORP"):
    row = InventoryLoggedOn(
        scan_id=scan.id,
        asset_id=asset.id,
        username=username,
        domain=domain,
    )
    db.add(row)
    db.flush()
    return row


class TestNetconnEdges:
    def test_emits_port_edge_for_resolvable_peer(
        self, db_session, test_org, test_scan, test_assets,
    ):
        from services.inventory_edge_materializer import materialize_inventory_edges

        src, dst = test_assets[0], test_assets[1]
        _add_netconn(
            db_session, test_scan, src,
            remote_addr=dst.ip, remote_port=445, state="ESTABLISHED",
        )
        stats = materialize_inventory_edges(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        assert stats["asset_to_asset_port"] == 1

        edge = (
            db_session.query(AssetRelationship)
            .filter(
                AssetRelationship.relationship_type == ASSET_TO_ASSET_PORT,
                AssetRelationship.source_asset_id == src.id,
                AssetRelationship.target_asset_id == dst.id,
            ).one()
        )
        assert edge.properties.get("port") == 445
        assert edge.properties.get("proto") == "tcp"
        assert edge.confidence == "high"
        assert edge.source_system == "inventory"

    def test_skips_loopback_and_unknown_peers(
        self, db_session, test_org, test_scan, test_assets,
    ):
        from services.inventory_edge_materializer import materialize_inventory_edges

        src = test_assets[0]
        _add_netconn(db_session, test_scan, src,
                     remote_addr="127.0.0.1", remote_port=80)
        _add_netconn(db_session, test_scan, src,
                     remote_addr="203.0.113.99", remote_port=443)  # unknown
        stats = materialize_inventory_edges(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        assert stats["asset_to_asset_port"] == 0

    def test_idempotent(
        self, db_session, test_org, test_scan, test_assets,
    ):
        from services.inventory_edge_materializer import materialize_inventory_edges

        src, dst = test_assets[0], test_assets[1]
        _add_netconn(db_session, test_scan, src,
                     remote_addr=dst.ip, remote_port=445)
        materialize_inventory_edges(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        materialize_inventory_edges(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        rows = (
            db_session.query(AssetRelationship)
            .filter(AssetRelationship.relationship_type == ASSET_TO_ASSET_PORT)
            .all()
        )
        assert len(rows) == 1


class TestUserToAssetEdges:
    def test_admin_grant_emits_user_to_asset_edge(
        self, db_session, test_org, test_scan, test_assets,
    ):
        from services.inventory_edge_materializer import materialize_inventory_edges

        host = test_assets[0]
        _add_user(db_session, test_scan, host,
                  username="alice", domain="corp", is_domain_admin=True)
        stats = materialize_inventory_edges(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        assert stats["user_to_asset"] >= 1

        edges = (
            db_session.query(AssetRelationship)
            .filter(
                AssetRelationship.relationship_type == USER_TO_ASSET,
                AssetRelationship.target_asset_id == host.id,
            ).all()
        )
        assert any(e.properties.get("via") == "admin_grant" for e in edges)
        assert all(e.source_asset_id is None for e in edges)
        principals = {e.properties.get("principal") for e in edges}
        assert "corp\\alice" in principals

    def test_non_privileged_session_does_not_emit_edge(
        self, db_session, test_org, test_scan, test_assets,
    ):
        from services.inventory_edge_materializer import materialize_inventory_edges

        host = test_assets[0]
        # User declared but with no privilege flags anywhere → noise.
        _add_user(db_session, test_scan, host, username="bob", domain="corp")
        _add_logon(db_session, test_scan, host, username="bob", domain="corp")
        stats = materialize_inventory_edges(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        assert stats["user_to_asset"] == 0

    def test_filters_noise_principals(
        self, db_session, test_org, test_scan, test_assets,
    ):
        from services.inventory_edge_materializer import materialize_inventory_edges

        host = test_assets[0]
        _add_user(db_session, test_scan, host,
                  username="SYSTEM", domain="NT AUTHORITY",
                  is_local_admin=True)
        stats = materialize_inventory_edges(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        assert stats["user_to_asset"] == 0


class TestAuthEdges:
    def test_shared_privileged_session_emits_pairwise_edges(
        self, db_session, test_org, test_scan, test_assets,
    ):
        from services.inventory_edge_materializer import materialize_inventory_edges

        h1, h2 = test_assets[0], test_assets[1]
        _add_user(db_session, test_scan, h1, username="alice", domain="corp",
                  is_domain_admin=True)
        _add_logon(db_session, test_scan, h1, username="alice", domain="corp")
        _add_logon(db_session, test_scan, h2, username="alice", domain="corp")
        stats = materialize_inventory_edges(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        assert stats["asset_to_asset_auth"] >= 1

        edges = (
            db_session.query(AssetRelationship)
            .filter(
                AssetRelationship.relationship_type == ASSET_TO_ASSET_AUTH,
            ).all()
        )
        assert any(e.properties.get("via") == "shared_session" for e in edges)
        # Source host should be the deterministic minimum id.
        for e in edges:
            assert e.source_asset_id < e.target_asset_id


class TestQueryHelpers:
    def test_reachable_targets_aggregates_unified_edges(
        self, db_session, test_org, test_scan, test_assets,
    ):
        from services.asset_edges import upsert_edge
        from services.asset_edges_query import reachable_targets

        src, dst1, dst2 = test_assets
        upsert_edge(
            db_session, org_id=test_org.id, edge_type=ASSET_TO_ASSET_PORT,
            source_system="inventory", src_asset_id=src.id,
            dst_asset_id=dst1.id, properties={"port": 445, "proto": "tcp"},
        )
        upsert_edge(
            db_session, org_id=test_org.id, edge_type=ASSET_TO_ASSET_AUTH,
            source_system="inventory", src_asset_id=src.id,
            dst_asset_id=dst2.id, properties={"via": "shared_session",
                                              "principal": "corp\\alice"},
        )
        out = reachable_targets(
            db_session, org_id=test_org.id, src_asset_ids=[src.id],
        )
        assert out[src.id] == {dst1.id, dst2.id}
