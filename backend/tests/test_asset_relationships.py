"""
Tests for the asset relationship graph system:
- workload_to_canonical_id normalization
- DNS → cloud workload inference engine
- Dedup relationship reassignment
- API endpoints
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.field_mapper import workload_to_canonical_id


# ═══════════════════════════════════════════════════════════
# workload_to_canonical_id
# ═══════════════════════════════════════════════════════════

class TestWorkloadToCanonicalId:
    def test_aws_alb(self):
        w = {"provider": "aws", "service": "alb", "name": "my-alb-123", "region": "us-east-1"}
        assert workload_to_canonical_id(w) == "aws:alb:my-alb-123"

    def test_aws_s3(self):
        w = {"provider": "aws", "service": "s3", "bucket": "my-bucket", "region": "us-west-2"}
        assert workload_to_canonical_id(w) == "aws:s3:my-bucket"

    def test_aws_cloudfront(self):
        w = {"provider": "aws", "service": "cloudfront", "dist_id": "d1234abcdef"}
        assert workload_to_canonical_id(w) == "aws:cloudfront:d1234abcdef"

    def test_aws_api_gateway(self):
        w = {"provider": "aws", "service": "api_gateway", "api_id": "abc123", "region": "eu-west-1"}
        assert workload_to_canonical_id(w) == "aws:api_gateway:abc123"

    def test_aws_lambda(self):
        w = {"provider": "aws", "service": "lambda", "function_url": "abc123def", "region": "us-east-1"}
        assert workload_to_canonical_id(w) == "aws:lambda:abc123def"

    def test_gcp_cloud_run(self):
        w = {"provider": "gcp", "service": "cloud_run", "name": "my-service-abc123-uc"}
        assert workload_to_canonical_id(w) == "gcp:cloud_run:my-service-abc123-uc"

    def test_gcp_app_engine(self):
        w = {"provider": "gcp", "service": "app_engine", "app": "my-project"}
        assert workload_to_canonical_id(w) == "gcp:app_engine:my-project"

    def test_gcp_cloud_functions(self):
        w = {"provider": "gcp", "service": "cloud_functions", "project": "us-central1-my-project"}
        assert workload_to_canonical_id(w) == "gcp:cloud_functions:us-central1-my-project"

    def test_gcp_firebase(self):
        w = {"provider": "gcp", "service": "firebase_hosting", "site": "my-app"}
        assert workload_to_canonical_id(w) == "gcp:firebase_hosting:my-app"

    def test_azure_app_service(self):
        w = {"provider": "azure", "service": "app_service", "app": "my-app"}
        assert workload_to_canonical_id(w) == "azure:app_service:my-app"

    def test_azure_traffic_manager(self):
        w = {"provider": "azure", "service": "traffic_manager", "profile": "my-profile"}
        assert workload_to_canonical_id(w) == "azure:traffic_manager:my-profile"

    def test_azure_front_door(self):
        w = {"provider": "azure", "service": "front_door", "name": "my-fd"}
        assert workload_to_canonical_id(w) == "azure:front_door:my-fd"

    def test_azure_blob_storage(self):
        w = {"provider": "azure", "service": "blob_storage", "account": "myaccount"}
        assert workload_to_canonical_id(w) == "azure:blob_storage:myaccount"

    def test_azure_sql_database(self):
        w = {"provider": "azure", "service": "sql_database", "server": "myserver"}
        assert workload_to_canonical_id(w) == "azure:sql_database:myserver"

    def test_missing_fields_fallback(self):
        w = {"provider": "aws", "service": "unknown_service"}
        assert workload_to_canonical_id(w) == "aws:unknown_service:unknown"

    def test_empty_dict_fallback(self):
        assert workload_to_canonical_id({}) == "unknown:unknown:unknown"


# ═══════════════════════════════════════════════════════════
# Inference engine (DB-dependent)
# ═══════════════════════════════════════════════════════════

class TestInferDnsToCloudRelationships:
    """Tests for the relationship inference engine using in-memory SQLite."""

    def test_creates_cloud_asset_and_edge(self, db_session, test_org, test_scan):
        from models.models import Asset, AssetRelationship
        from services.asset_relationship_engine import infer_dns_to_cloud_relationships

        dns_asset = Asset(
            scan_id=test_scan.id,
            hostname="api.example.com",
            fqdn="api.example.com",
            asset_type="host",
            easm_data={
                "cloudflare_dns": {
                    "target": {"provider": "gcp", "service": "cloud_run", "name": "my-svc-abc123"},
                    "record_type": "CNAME",
                }
            },
        )
        db_session.add(dns_asset)
        db_session.flush()

        result = infer_dns_to_cloud_relationships(db_session, test_org.id, test_scan.id)

        assert result["cloud_assets_created"] == 1
        assert result["relationships_created"] == 1

        # Verify cloud asset was created
        cloud = db_session.query(Asset).filter(Asset.asset_type == "cloud_instance").first()
        assert cloud is not None
        assert cloud.asset_identity["cloud_provider"] == "gcp"
        assert cloud.asset_identity["instance_id"] == "gcp:cloud_run:my-svc-abc123"
        assert cloud.is_internet_facing is True

        # Verify edge
        rel = db_session.query(AssetRelationship).first()
        assert rel.source_asset_id == dns_asset.id
        assert rel.target_asset_id == cloud.id
        assert rel.relationship_type == "resolves_to"
        assert rel.source_detail["connector"] == "cloudflare_dns"

    def test_dedup_same_cloud_target(self, db_session, test_org, test_scan):
        """Two DNS records pointing to the same ALB should create 1 cloud asset, 2 edges."""
        from models.models import Asset, AssetRelationship
        from services.asset_relationship_engine import infer_dns_to_cloud_relationships

        workload = {"provider": "aws", "service": "alb", "name": "shared-alb", "region": "us-east-1"}
        for hostname in ("api.example.com", "www.example.com"):
            asset = Asset(
                scan_id=test_scan.id,
                hostname=hostname,
                fqdn=hostname,
                asset_type="host",
                easm_data={"aws_route53": {"workload": workload, "record_type": "A"}},
            )
            db_session.add(asset)
        db_session.flush()

        result = infer_dns_to_cloud_relationships(db_session, test_org.id, test_scan.id)

        assert result["cloud_assets_created"] == 1
        assert result["relationships_created"] == 2

        clouds = db_session.query(Asset).filter(Asset.asset_type == "cloud_instance").all()
        assert len(clouds) == 1

        edges = db_session.query(AssetRelationship).all()
        assert len(edges) == 2
        assert {e.target_asset_id for e in edges} == {clouds[0].id}

    def test_idempotent_rerun(self, db_session, test_org, test_scan):
        """Running inference twice should not create duplicate edges."""
        from models.models import Asset, AssetRelationship
        from services.asset_relationship_engine import infer_dns_to_cloud_relationships

        asset = Asset(
            scan_id=test_scan.id,
            hostname="app.example.com",
            asset_type="host",
            easm_data={
                "gcp_clouddns": {
                    "workload": {"provider": "gcp", "service": "app_engine", "app": "my-project"},
                    "record_type": "CNAME",
                }
            },
        )
        db_session.add(asset)
        db_session.flush()

        r1 = infer_dns_to_cloud_relationships(db_session, test_org.id, test_scan.id)
        assert r1["relationships_created"] == 1

        r2 = infer_dns_to_cloud_relationships(db_session, test_org.id, test_scan.id)
        assert r2["relationships_created"] == 0
        assert r2["relationships_existing"] == 1
        assert r2["cloud_assets_created"] == 0

        assert db_session.query(AssetRelationship).count() == 1

    def test_no_workload_skipped(self, db_session, test_org, test_scan):
        """Assets without workload data should be skipped."""
        from models.models import Asset
        from services.asset_relationship_engine import infer_dns_to_cloud_relationships

        asset = Asset(
            scan_id=test_scan.id,
            hostname="plain.example.com",
            asset_type="host",
            easm_data={"cloudflare_dns": {"record_type": "A", "ttl": 300}},
        )
        db_session.add(asset)
        db_session.flush()

        result = infer_dns_to_cloud_relationships(db_session, test_org.id, test_scan.id)
        assert result["cloud_assets_created"] == 0
        assert result["relationships_created"] == 0

    def test_multiple_connectors_on_same_asset(self, db_session, test_org, test_scan):
        """An asset with workloads from two connectors creates two cloud targets."""
        from models.models import Asset, AssetRelationship
        from services.asset_relationship_engine import infer_dns_to_cloud_relationships

        asset = Asset(
            scan_id=test_scan.id,
            hostname="multi.example.com",
            asset_type="host",
            easm_data={
                "godaddy_dns": {
                    "workload": {"provider": "aws", "service": "cloudfront", "dist_id": "d111"},
                    "record_type": "CNAME",
                },
                "cloudflare_dns": {
                    "target": {"provider": "aws", "service": "s3", "bucket": "my-bucket"},
                    "record_type": "CNAME",
                },
            },
        )
        db_session.add(asset)
        db_session.flush()

        result = infer_dns_to_cloud_relationships(db_session, test_org.id, test_scan.id)
        assert result["cloud_assets_created"] == 2
        assert result["relationships_created"] == 2


# ═══════════════════════════════════════════════════════════
# Dedup relationship reassignment
# ═══════════════════════════════════════════════════════════

class TestReassignRelationships:

    def test_repoint_edges(self, db_session, test_org, test_scan):
        """Edges from old asset get repointed to survivor."""
        from models.models import Asset, AssetRelationship
        from services.asset_relationship_engine import reassign_relationships

        a = Asset(scan_id=test_scan.id, hostname="a.test", asset_type="host")
        b = Asset(scan_id=test_scan.id, hostname="b.test", asset_type="host")
        cloud = Asset(scan_id=test_scan.id, hostname="cloud.test", asset_type="cloud_instance")
        db_session.add_all([a, b, cloud])
        db_session.flush()

        rel = AssetRelationship(
            org_id=test_org.id, source_asset_id=a.id,
            target_asset_id=cloud.id, relationship_type="resolves_to",
        )
        db_session.add(rel)
        db_session.flush()

        # Merge a → b (b is survivor)
        reassign_relationships(db_session, a.id, b.id)
        db_session.flush()

        updated = db_session.query(AssetRelationship).filter(AssetRelationship.id == rel.id).first()
        assert updated.source_asset_id == b.id
        assert updated.target_asset_id == cloud.id

    def test_delete_self_loop(self, db_session, test_org, test_scan):
        """If merging two assets that are linked, the self-loop gets deleted."""
        from models.models import Asset, AssetRelationship
        from services.asset_relationship_engine import reassign_relationships

        a = Asset(scan_id=test_scan.id, hostname="a.test", asset_type="host")
        b = Asset(scan_id=test_scan.id, hostname="b.test", asset_type="host")
        db_session.add_all([a, b])
        db_session.flush()

        rel = AssetRelationship(
            org_id=test_org.id, source_asset_id=a.id,
            target_asset_id=b.id, relationship_type="resolves_to",
        )
        db_session.add(rel)
        db_session.flush()

        # Merge a → b: edge a→b becomes b→b (self-loop) and should be deleted
        reassign_relationships(db_session, a.id, b.id)
        db_session.flush()

        assert db_session.query(AssetRelationship).count() == 0

    def test_delete_duplicate_on_merge(self, db_session, test_org, test_scan):
        """If repointing would create a duplicate, delete instead."""
        from models.models import Asset, AssetRelationship
        from services.asset_relationship_engine import reassign_relationships

        a = Asset(scan_id=test_scan.id, hostname="a.test", asset_type="host")
        b = Asset(scan_id=test_scan.id, hostname="b.test", asset_type="host")
        cloud = Asset(scan_id=test_scan.id, hostname="cloud.test", asset_type="cloud_instance")
        db_session.add_all([a, b, cloud])
        db_session.flush()

        # Both a and b already have edges to cloud
        r1 = AssetRelationship(org_id=test_org.id, source_asset_id=a.id,
                               target_asset_id=cloud.id, relationship_type="resolves_to")
        r2 = AssetRelationship(org_id=test_org.id, source_asset_id=b.id,
                               target_asset_id=cloud.id, relationship_type="resolves_to")
        db_session.add_all([r1, r2])
        db_session.flush()

        # Merge a → b: a→cloud would become b→cloud which already exists
        reassign_relationships(db_session, a.id, b.id)
        db_session.flush()

        edges = db_session.query(AssetRelationship).all()
        assert len(edges) == 1
        assert edges[0].source_asset_id == b.id


# ═══════════════════════════════════════════════════════════
# API endpoints
# ═══════════════════════════════════════════════════════════

class TestAssetRelationshipAPI:

    def _create_assets_and_edge(self, db_session, test_org, test_scan):
        from models.models import Asset, AssetRelationship
        dns = Asset(scan_id=test_scan.id, hostname="api.example.com", asset_type="host")
        cloud = Asset(scan_id=test_scan.id, hostname="gcp:cloud_run:my-svc",
                      asset_type="cloud_instance",
                      asset_identity={"cloud_provider": "gcp", "instance_id": "gcp:cloud_run:my-svc"})
        db_session.add_all([dns, cloud])
        db_session.flush()
        rel = AssetRelationship(
            org_id=test_org.id, source_asset_id=dns.id,
            target_asset_id=cloud.id, relationship_type="resolves_to",
            source_detail={"connector": "cloudflare_dns"},
        )
        db_session.add(rel)
        db_session.flush()
        return dns, cloud, rel

    def test_get_relationships(self, db_session, test_org, test_scan, authed_client):
        dns, cloud, rel = self._create_assets_and_edge(db_session, test_org, test_scan)

        resp = authed_client.get(f"/api/assets/{dns.id}/relationships")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["direction"] == "outbound"
        assert data[0]["relationship_type"] == "resolves_to"
        assert data[0]["related_asset"]["id"] == cloud.id

    def test_get_relationships_inbound(self, db_session, test_org, test_scan, authed_client):
        dns, cloud, rel = self._create_assets_and_edge(db_session, test_org, test_scan)

        resp = authed_client.get(f"/api/assets/{cloud.id}/relationships")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["direction"] == "inbound"
        assert data[0]["related_asset"]["id"] == dns.id

    def test_asset_graph(self, db_session, test_org, test_scan, authed_client):
        dns, cloud, rel = self._create_assets_and_edge(db_session, test_org, test_scan)

        resp = authed_client.get(f"/api/asset-graph?asset_ids={dns.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1
        # Blast-radius-compatible format: string node IDs, prefixed
        edge = data["edges"][0]
        assert edge["source"] == f"asset-{dns.id}"
        assert edge["target"] == f"asset-{cloud.id}"
        assert edge["type"] == "resolves_to"
        assert "data" in edge and "label" in edge["data"]
        # Nodes use {id: "asset-N", type: "asset", data: {...}} format
        node_ids = {n["id"] for n in data["nodes"]}
        assert f"asset-{dns.id}" in node_ids
        assert f"asset-{cloud.id}" in node_ids
        for node in data["nodes"]:
            assert node["type"] == "asset"
            assert "data" in node and "label" in node["data"]

    def test_create_relationship(self, db_session, test_org, test_scan, authed_client):
        from models.models import Asset
        a = Asset(scan_id=test_scan.id, hostname="a.test", asset_type="host")
        b = Asset(scan_id=test_scan.id, hostname="b.test", asset_type="host")
        db_session.add_all([a, b])
        db_session.flush()

        resp = authed_client.post("/api/asset-relationships", json={
            "source_asset_id": a.id, "target_asset_id": b.id, "relationship_type": "alias_of",
        })
        assert resp.status_code == 200
        assert resp.json()["relationship_type"] == "alias_of"

    def test_delete_relationship(self, db_session, test_org, test_scan, authed_client):
        dns, cloud, rel = self._create_assets_and_edge(db_session, test_org, test_scan)

        resp = authed_client.delete(f"/api/asset-relationships/{rel.id}")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

        from models.models import AssetRelationship
        assert db_session.query(AssetRelationship).count() == 0
