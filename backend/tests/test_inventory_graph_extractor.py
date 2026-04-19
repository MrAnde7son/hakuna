"""Tests for services/inventory_graph_extractor.py.

Each test seeds Inventory* rows against the in-memory SQLite fixture and
asserts the expected AssetRelationship edges are produced, idempotent on
re-run, and respect the safety caps that prevent O(N²) blowups from
low-signal principals.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.models import (
    Asset,
    AssetRelationship,
    InventoryDomainTrust,
    InventoryLoggedOn,
    InventoryNetConn,
    InventoryScheduledTask,
    InventoryService,
    InventoryUser,
)
from services.inventory_graph_extractor import (
    MAX_EDGES_PER_SHARED_USER,
    extract_inventory_edges,
)


def _asset(db, scan, ip=None, hostname=None):
    a = Asset(
        scan_id=scan.id,
        hostname=hostname or (f"host-{ip}" if ip else "host"),
        ip=ip,
        asset_type="host",
    )
    db.add(a)
    db.flush()
    return a


# ───────────────── netconn ─────────────────

class TestNetconnEdges:
    def test_established_connection_creates_edge(self, db_session, test_org, test_scan):
        client = _asset(db_session, test_scan, ip="10.0.0.10")
        server = _asset(db_session, test_scan, ip="10.0.0.20")

        db_session.add(InventoryNetConn(
            scan_id=test_scan.id, asset_id=client.id,
            proto="tcp4", state="ESTABLISHED",
            local_addr="10.0.0.10", local_port=54321,
            remote_addr="10.0.0.20", remote_port=443,
            source_plugin="64582",
        ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)

        assert stats["connects_to"] == 1
        edge = db_session.query(AssetRelationship).filter_by(relationship_type="connects_to").one()
        assert edge.source_asset_id == client.id
        assert edge.target_asset_id == server.id
        assert edge.confidence == "high"
        assert edge.properties["remote_port"] == 443

    def test_loopback_and_multicast_skipped(self, db_session, test_org, test_scan):
        host = _asset(db_session, test_scan, ip="10.0.0.10")
        for remote in ("127.0.0.1", "224.0.0.251", "0.0.0.0", "169.254.1.1"):
            db_session.add(InventoryNetConn(
                scan_id=test_scan.id, asset_id=host.id,
                proto="tcp4", state="ESTABLISHED",
                remote_addr=remote, remote_port=80,
            ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)
        assert stats["connects_to"] == 0

    def test_unresolved_remote_skipped(self, db_session, test_org, test_scan):
        host = _asset(db_session, test_scan, ip="10.0.0.10")
        db_session.add(InventoryNetConn(
            scan_id=test_scan.id, asset_id=host.id,
            proto="tcp4", state="ESTABLISHED",
            remote_addr="8.8.8.8", remote_port=53,
        ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)
        assert stats["connects_to"] == 0
        assert db_session.query(AssetRelationship).count() == 0

    def test_idempotent_rerun(self, db_session, test_org, test_scan):
        client = _asset(db_session, test_scan, ip="10.0.0.10")
        _asset(db_session, test_scan, ip="10.0.0.20")
        db_session.add(InventoryNetConn(
            scan_id=test_scan.id, asset_id=client.id,
            proto="tcp4", state="ESTABLISHED",
            remote_addr="10.0.0.20", remote_port=443,
        ))
        db_session.flush()

        extract_inventory_edges(db_session, test_org.id, test_scan.id)
        extract_inventory_edges(db_session, test_org.id, test_scan.id)

        assert db_session.query(AssetRelationship).filter_by(
            relationship_type="connects_to"
        ).count() == 1


# ───────────────── AD trust + membership ─────────────────

class TestADEdges:
    def test_trust_edge_to_member_server(self, db_session, test_org, test_scan):
        dc_source = _asset(db_session, test_scan, hostname="dc1.corp.local")
        dc_trusted = _asset(db_session, test_scan, hostname="dc1.research.local")

        # dc_source enumerated a trust to research.local (marks it as the source DC).
        db_session.add(InventoryDomainTrust(
            scan_id=test_scan.id, asset_id=dc_source.id,
            trusted_domain="research.local",
            source_domain="corp.local",
            trust_direction="outbound",
            trust_type="uplevel",
            is_transitive=True,
        ))
        # dc_trusted has an AD user in research.local — makes it a DC of that domain.
        db_session.add(InventoryUser(
            scan_id=test_scan.id, asset_id=dc_trusted.id,
            username="admin", domain="research.local", user_type="domain_user",
        ))
        # dc_trusted also enumerated its own domain (marks it as a DC).
        db_session.add(InventoryDomainTrust(
            scan_id=test_scan.id, asset_id=dc_trusted.id,
            trusted_domain="other.local",
            source_domain="research.local",
            trust_direction="bidirectional",
        ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)

        trust_edges = db_session.query(AssetRelationship).filter_by(
            relationship_type="trusts_domain"
        ).all()
        assert any(
            e.source_asset_id == dc_source.id and e.target_asset_id == dc_trusted.id
            for e in trust_edges
        )
        assert stats["trusts_domain"] >= 1

    def test_membership_edges_to_dc(self, db_session, test_org, test_scan):
        dc = _asset(db_session, test_scan, hostname="dc1.corp.local")
        workstation = _asset(db_session, test_scan, hostname="ws1.corp.local")

        # dc acts as a DC via trust enumeration.
        db_session.add(InventoryDomainTrust(
            scan_id=test_scan.id, asset_id=dc.id,
            trusted_domain="other.local",
            source_domain="corp.local",
        ))
        # workstation has a domain user → infers membership in corp.local.
        db_session.add(InventoryUser(
            scan_id=test_scan.id, asset_id=workstation.id,
            username="alice", domain="corp.local", user_type="domain_user",
        ))
        db_session.flush()

        extract_inventory_edges(db_session, test_org.id, test_scan.id)

        edges = db_session.query(AssetRelationship).filter_by(
            relationship_type="member_of_domain"
        ).all()
        assert any(
            e.source_asset_id == workstation.id and e.target_asset_id == dc.id
            for e in edges
        )


# ───────────────── identity ─────────────────

class TestIdentityEdges:
    def test_shared_session_creates_pairwise_edges(self, db_session, test_org, test_scan):
        hosts = [_asset(db_session, test_scan, hostname=f"h{i}") for i in range(3)]
        for h in hosts:
            db_session.add(InventoryLoggedOn(
                scan_id=test_scan.id, asset_id=h.id,
                username="alice", domain="corp",
            ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)

        # 3 hosts → 3 pairwise edges.
        assert stats["shares_credential_with"] == 3
        edges = db_session.query(AssetRelationship).filter_by(
            relationship_type="shares_credential_with"
        ).all()
        pairs = {(min(e.source_asset_id, e.target_asset_id),
                  max(e.source_asset_id, e.target_asset_id)) for e in edges}
        assert len(pairs) == 3

    def test_noise_principal_skipped(self, db_session, test_org, test_scan):
        """SYSTEM on every host must NOT create a clique."""
        hosts = [_asset(db_session, test_scan, hostname=f"h{i}") for i in range(4)]
        for h in hosts:
            db_session.add(InventoryLoggedOn(
                scan_id=test_scan.id, asset_id=h.id,
                username="SYSTEM", domain="NT AUTHORITY",
            ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)
        assert stats["shares_credential_with"] == 0

    def test_shared_session_respects_cap(self, db_session, test_org, test_scan):
        """A principal on too many hosts caps edge count."""
        n = 20  # 20 hosts → 190 possible pairs, cap is 100.
        hosts = [_asset(db_session, test_scan, hostname=f"h{i}") for i in range(n)]
        for h in hosts:
            db_session.add(InventoryLoggedOn(
                scan_id=test_scan.id, asset_id=h.id,
                username="svc_backup", domain="corp",
            ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)
        assert stats["shares_credential_with"] <= MAX_EDGES_PER_SHARED_USER

    def test_runs_as_edge_targets_sessions(self, db_session, test_org, test_scan):
        svc_host = _asset(db_session, test_scan, hostname="svc1")
        db_host = _asset(db_session, test_scan, hostname="db1")

        db_session.add(InventoryService(
            scan_id=test_scan.id, asset_id=svc_host.id,
            service_name="BackupAgent",
            display_name="Backup Agent",
            run_as_user="CORP\\svc_backup",
        ))
        db_session.add(InventoryLoggedOn(
            scan_id=test_scan.id, asset_id=db_host.id,
            username="svc_backup", domain="CORP",
        ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)

        assert stats["runs_as_principal"] == 1
        edge = db_session.query(AssetRelationship).filter_by(
            relationship_type="runs_as_principal"
        ).one()
        assert edge.source_asset_id == svc_host.id
        assert edge.target_asset_id == db_host.id
        assert edge.properties["principal"] == "corp\\svc_backup"

    def test_runs_as_targets_local_admins(self, db_session, test_org, test_scan):
        svc_host = _asset(db_session, test_scan, hostname="svc1")
        admin_host = _asset(db_session, test_scan, hostname="target1")

        db_session.add(InventoryScheduledTask(
            scan_id=test_scan.id, asset_id=svc_host.id,
            task_uri="\\BackupTask",
            run_as_user="corp\\svc_backup",
        ))
        db_session.add(InventoryUser(
            scan_id=test_scan.id, asset_id=admin_host.id,
            username="svc_backup", domain="corp",
            is_local_admin=True, user_type="domain_user",
        ))
        db_session.flush()

        extract_inventory_edges(db_session, test_org.id, test_scan.id)

        assert db_session.query(AssetRelationship).filter_by(
            relationship_type="runs_as_principal"
        ).count() == 1


# ───────────────── misc ─────────────────

class TestIdempotency:
    def test_no_edges_when_no_inventory(self, db_session, test_org, test_scan):
        _asset(db_session, test_scan, ip="10.0.0.1")
        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)
        assert all(v == 0 for v in stats.values())

    def test_self_edges_rejected(self, db_session, test_org, test_scan):
        host = _asset(db_session, test_scan, ip="10.0.0.10")
        # netconn where remote IP resolves back to the same asset.
        db_session.add(InventoryNetConn(
            scan_id=test_scan.id, asset_id=host.id,
            proto="tcp4", state="ESTABLISHED",
            remote_addr="10.0.0.10", remote_port=8080,
        ))
        db_session.flush()

        stats = extract_inventory_edges(db_session, test_org.id, test_scan.id)
        assert stats["connects_to"] == 0
