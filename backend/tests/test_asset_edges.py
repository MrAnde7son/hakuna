"""Tests for the unified asset-edge substrate (Phase 1 of the
cross-scan chain coordinator).

Covers:
- `services.asset_edges.compute_properties_hash` determinism
- `services.asset_edges.upsert_edge` create / re-observe / dedup
- `write_easm_internet_edges` per-port emission
- `write_kev_cve_edges_for_scan` only emits for KEV findings
- `emit_edge` agent tool — type allowlist + parameter handling
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.asset_edges import (
    AGENT_EMITTABLE_EDGE_TYPES,
    ASSET_TO_ASSET_COERCE,
    CVE_ON_ASSET,
    INTERNET_TO_ASSET,
    USER_TO_ASSET,
)
from models.models import AssetRelationship, Finding
from services.asset_edges import (
    compute_properties_hash,
    upsert_edge,
    write_easm_internet_edges,
    write_kev_cve_edges_for_scan,
    write_sbom_kev_edge,
)


# ── compute_properties_hash ─────────────────────────────────


class TestPropertiesHash:
    def test_empty_returns_empty_string(self):
        assert compute_properties_hash(None) == ""
        assert compute_properties_hash({}) == ""

    def test_deterministic(self):
        h1 = compute_properties_hash({"port": 443, "protocol": "tcp"})
        h2 = compute_properties_hash({"protocol": "tcp", "port": 443})
        assert h1 == h2
        assert len(h1) == 64

    def test_different_props_distinct(self):
        h1 = compute_properties_hash({"port": 443})
        h2 = compute_properties_hash({"port": 80})
        assert h1 != h2


# ── upsert_edge ─────────────────────────────────────────────


class TestUpsertEdge:
    def test_creates_new_edge(self, db_session, test_org, test_assets):
        edge = upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=USER_TO_ASSET,
            source_system="audit_agent",
            dst_asset_id=test_assets[0].id,
            properties={"auth": "anonymous"},
            enabled_by_finding_id=42,
        )
        assert edge is not None
        assert edge.relationship_type == USER_TO_ASSET
        assert edge.target_asset_id == test_assets[0].id
        assert edge.source_asset_id is None
        assert edge.source_system == "audit_agent"
        assert edge.enabled_by_findings == [42]
        assert edge.properties_hash != ""

    def test_re_observe_bumps_last_seen_and_merges_findings(self, db_session, test_org, test_assets):
        e1 = upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=USER_TO_ASSET,
            source_system="audit_agent",
            dst_asset_id=test_assets[0].id,
            properties={"auth": "anonymous"},
            confidence="medium",
            enabled_by_finding_id=10,
        )
        first_seen = e1.last_seen_at
        e2 = upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=USER_TO_ASSET,
            source_system="audit_agent",
            dst_asset_id=test_assets[0].id,
            properties={"auth": "anonymous"},
            confidence="high",  # stronger
            enabled_by_finding_id=11,
        )
        assert e1.id == e2.id  # same row
        assert e2.last_seen_at >= first_seen
        assert set(e2.enabled_by_findings) == {10, 11}
        assert e2.confidence == "high"  # took the stronger one

    def test_different_properties_create_distinct_edges(self, db_session, test_org, test_assets):
        e1 = upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
            dst_asset_id=test_assets[0].id,
            properties={"port": 443},
        )
        e2 = upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
            dst_asset_id=test_assets[0].id,
            properties={"port": 22},
        )
        assert e1.id != e2.id

    def test_rejects_unknown_edge_type(self, db_session, test_org, test_assets):
        edge = upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type="not_a_real_edge",
            source_system="test",
            dst_asset_id=test_assets[0].id,
        )
        assert edge is None

    def test_rejects_no_endpoints(self, db_session, test_org):
        edge = upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
        )
        assert edge is None

    def test_weight_takes_max(self, db_session, test_org, test_assets):
        e1 = upsert_edge(
            db_session, org_id=test_org.id, edge_type=USER_TO_ASSET,
            source_system="audit_agent", dst_asset_id=test_assets[0].id,
            weight=0.4,
        )
        e2 = upsert_edge(
            db_session, org_id=test_org.id, edge_type=USER_TO_ASSET,
            source_system="audit_agent", dst_asset_id=test_assets[0].id,
            weight=0.9,
        )
        assert e1.id == e2.id
        assert e2.weight == pytest.approx(0.9)
        # Lower weight on subsequent observation must not regress the row.
        e3 = upsert_edge(
            db_session, org_id=test_org.id, edge_type=USER_TO_ASSET,
            source_system="audit_agent", dst_asset_id=test_assets[0].id,
            weight=0.2,
        )
        assert e3.weight == pytest.approx(0.9)


# ── write_easm_internet_edges ──────────────────────────────


class TestEasmInternetEdges:
    def test_emits_one_edge_per_port(self, db_session, test_org, test_assets):
        n = write_easm_internet_edges(
            db_session,
            org_id=test_org.id,
            asset_id=test_assets[0].id,
            open_ports=[443, 80, 22, 22],  # 22 dup
        )
        assert n == 3
        edges = db_session.query(AssetRelationship).filter(
            AssetRelationship.org_id == test_org.id,
            AssetRelationship.target_asset_id == test_assets[0].id,
            AssetRelationship.relationship_type == INTERNET_TO_ASSET,
        ).all()
        assert len(edges) == 3
        ports = {e.properties.get("port") for e in edges}
        assert ports == {443, 80, 22}
        assert all(e.source_asset_id is None for e in edges)
        assert all(e.source_system == "easm" for e in edges)

    def test_handles_dict_port_entries(self, db_session, test_org, test_assets):
        # EASM occasionally emits {"port": 443, "proto": "tcp"} dicts.
        n = write_easm_internet_edges(
            db_session,
            org_id=test_org.id,
            asset_id=test_assets[0].id,
            open_ports=[{"port": 443, "proto": "tcp"}, {"port": "80"}],
        )
        assert n == 2

    def test_no_ports_emits_catchall(self, db_session, test_org, test_assets):
        n = write_easm_internet_edges(
            db_session,
            org_id=test_org.id,
            asset_id=test_assets[0].id,
            open_ports=None,
        )
        assert n == 1
        edges = db_session.query(AssetRelationship).filter(
            AssetRelationship.relationship_type == INTERNET_TO_ASSET,
            AssetRelationship.target_asset_id == test_assets[0].id,
        ).all()
        assert len(edges) == 1
        assert edges[0].properties == {"port": "any"}

    def test_idempotent_re_run(self, db_session, test_org, test_assets):
        write_easm_internet_edges(
            db_session, org_id=test_org.id,
            asset_id=test_assets[0].id, open_ports=[443, 80],
        )
        write_easm_internet_edges(
            db_session, org_id=test_org.id,
            asset_id=test_assets[0].id, open_ports=[443, 80, 22],
        )
        edges = db_session.query(AssetRelationship).filter(
            AssetRelationship.target_asset_id == test_assets[0].id,
            AssetRelationship.relationship_type == INTERNET_TO_ASSET,
        ).all()
        assert len(edges) == 3  # 443 + 80 + 22, no duplicates


# ── write_kev_cve_edges_for_scan ───────────────────────────


class TestKevCveEdges:
    def _make_kev_finding(self, db_session, test_org, test_scan, asset, cves, is_kev):
        f = Finding(
            scan_id=test_scan.id,
            asset_id=asset.id,
            plugin_id="vmscan-1",
            plugin_name="t",
            severity=4,
            cves=cves,
            is_kev=is_kev,
        )
        db_session.add(f)
        db_session.flush()
        from sqlalchemy import text
        db_session.execute(
            text("UPDATE findings SET org_id = :org_id WHERE id = :id"),
            {"org_id": test_org.id, "id": f.id},
        )
        return f

    def test_emits_one_edge_per_kev_cve(self, db_session, test_org, test_scan, test_assets):
        f1 = self._make_kev_finding(
            db_session, test_org, test_scan, test_assets[0],
            cves=["CVE-2023-1234", "CVE-2023-5678"], is_kev=True,
        )
        # Non-KEV finding — must be ignored.
        self._make_kev_finding(
            db_session, test_org, test_scan, test_assets[0],
            cves=["CVE-2024-9999"], is_kev=False,
        )
        n = write_kev_cve_edges_for_scan(
            db_session, org_id=test_org.id, scan_id=test_scan.id,
        )
        assert n == 2  # two KEV CVEs on the one finding
        edges = db_session.query(AssetRelationship).filter(
            AssetRelationship.relationship_type == CVE_ON_ASSET,
        ).all()
        cves = {e.properties.get("cve") for e in edges}
        assert cves == {"CVE-2023-1234", "CVE-2023-5678"}
        assert all(e.target_asset_id == test_assets[0].id for e in edges)
        assert all(e.source_asset_id is None for e in edges)
        assert all(f1.id in (e.enabled_by_findings or []) for e in edges)

    def test_idempotent(self, db_session, test_org, test_scan, test_assets):
        self._make_kev_finding(
            db_session, test_org, test_scan, test_assets[0],
            cves=["CVE-2023-1234"], is_kev=True,
        )
        write_kev_cve_edges_for_scan(db_session, org_id=test_org.id, scan_id=test_scan.id)
        write_kev_cve_edges_for_scan(db_session, org_id=test_org.id, scan_id=test_scan.id)
        edges = db_session.query(AssetRelationship).filter(
            AssetRelationship.relationship_type == CVE_ON_ASSET,
        ).all()
        assert len(edges) == 1


# ── write_sbom_kev_edge ────────────────────────────────────


class TestSbomKevEdge:
    def test_emits_edge_with_sbom_source(self, db_session, test_org, test_assets):
        edge = write_sbom_kev_edge(
            db_session,
            org_id=test_org.id,
            asset_id=test_assets[0].id,
            cve_id="CVE-2024-1234",
            finding_id=None,
            component_name="openssl",
            component_version="1.1.1",
        )
        assert edge is not None
        assert edge.source_system == "sbom"
        assert edge.relationship_type == CVE_ON_ASSET
        assert edge.target_asset_id == test_assets[0].id
        assert edge.source_asset_id is None
        assert edge.properties == {
            "cve": "CVE-2024-1234",
            "kev": True,
            "component": "openssl",
            "version": "1.1.1",
        }

    def test_rejects_non_cve_id(self, db_session, test_org, test_assets):
        edge = write_sbom_kev_edge(
            db_session,
            org_id=test_org.id,
            asset_id=test_assets[0].id,
            cve_id="not-a-cve",
        )
        assert edge is None

    def test_idempotent(self, db_session, test_org, test_assets):
        write_sbom_kev_edge(
            db_session, org_id=test_org.id, asset_id=test_assets[0].id,
            cve_id="CVE-2024-1234", component_name="openssl", component_version="1.1.1",
        )
        write_sbom_kev_edge(
            db_session, org_id=test_org.id, asset_id=test_assets[0].id,
            cve_id="CVE-2024-1234", component_name="openssl", component_version="1.1.1",
        )
        edges = db_session.query(AssetRelationship).filter(
            AssetRelationship.relationship_type == CVE_ON_ASSET,
            AssetRelationship.source_system == "sbom",
        ).all()
        assert len(edges) == 1


# ── emit_edge agent tool ───────────────────────────────────


class TestEmitEdgeTool:
    def test_emit_edge_in_registry(self):
        # Side-effect import populates the registry.
        from agents.agent_tools import TOOL_REGISTRY
        import agents.tools  # noqa: F401
        assert "emit_edge" in TOOL_REGISTRY

    def test_emits_coerce_edge(self, db_session, test_org, test_assets):
        from agents.tools.emit_edge import emit_edge_tool
        result = emit_edge_tool(db_session, {
            "edge_type": "asset_to_asset_coerce",
            "src_asset_id": test_assets[0].id,
            "properties": {"pipe": "spoolss"},
            "confidence": "confirmed",
            "enabled_by_finding_id": 7,
            "_org_id": test_org.id,
            "_agent_id": "smb-1",
            "_agent_run_id": "run-1",
        })
        assert result["status"] == "emitted"
        assert result["edge_type"] == "asset_to_asset_coerce"
        assert result["src_asset_id"] == test_assets[0].id
        assert result["dst_asset_id"] is None
        edge = db_session.query(AssetRelationship).filter_by(id=result["edge_id"]).one()
        assert edge.source_system == "audit_agent"
        assert 7 in (edge.enabled_by_findings or [])
        assert edge.source_detail.get("agent_id") == "smb-1"

    def test_rejects_non_emittable_type(self, db_session, test_org, test_assets):
        from agents.tools.emit_edge import emit_edge_tool
        result = emit_edge_tool(db_session, {
            "edge_type": "internet_to_asset",  # producer-only
            "dst_asset_id": test_assets[0].id,
            "_org_id": test_org.id,
        })
        assert "error" in result
        assert "not emittable" in result["error"]

    def test_rejects_missing_org_id(self, db_session, test_assets):
        from agents.tools.emit_edge import emit_edge_tool
        result = emit_edge_tool(db_session, {
            "edge_type": "user_to_asset",
            "dst_asset_id": test_assets[0].id,
        })
        assert "error" in result

    def test_emit_edge_only_allows_safe_types(self):
        # Sanity-check: producer-owned types must not leak into the agent
        # allowlist.
        forbidden = {"internet_to_asset", "cve_on_asset", "resolves_to",
                     "shares_certificate", "same_jarm_cluster"}
        assert forbidden.isdisjoint(AGENT_EMITTABLE_EDGE_TYPES)
        assert ASSET_TO_ASSET_COERCE in AGENT_EMITTABLE_EDGE_TYPES
