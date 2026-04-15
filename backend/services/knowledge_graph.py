"""Asset Knowledge Graph — builds and queries the asset relationship graph.

Materializes infrastructure relationships from enrichment data:
- Shared certificates (SANs, issuer)
- Same JARM fingerprint (potential shared infrastructure / C2)
- Same IP (shared hosting)
- DNS resolution chains (CNAME → A → cloud workload)
- Technology co-occurrence (same tech stack pattern)

Provides graph traversal APIs for:
- Blast radius analysis (what's reachable from a compromised asset?)
- Infrastructure clustering (group assets by shared signals)
- Attack path construction (chain findings across related assets)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


async def materialize_graph_edges(db: Session, org_id: int) -> dict:
    """Scan enrichment data and materialize relationship edges.

    Called post-enrichment to build/refresh the graph from:
    - TLS certificate SANs (shared_certificate edges)
    - JARM fingerprints (same_jarm_cluster edges)
    - Shared IPs (same_ip edges)
    - DNS CNAME chains (resolves_to edges — already built by asset_relationship_engine)

    Returns summary of edges created/updated.
    """
    stats = {"shared_cert": 0, "same_jarm": 0, "same_ip": 0}

    # ── Shared certificate edges ──
    # Find assets that share TLS certificate SANs
    cert_rows = await db.execute(
        text("""
            SELECT ap.asset_id, ap.port, ap.tls_cert
            FROM asset_ports ap
            JOIN assets a ON a.id = ap.asset_id
            WHERE a.org_id = :org_id
              AND ap.tls_cert IS NOT NULL
              AND ap.tls_cert::text != '{}'
        """),
        {"org_id": org_id},
    )

    # Group assets by certificate fingerprint (issuer + subject)
    cert_groups: dict[str, list[int]] = defaultdict(list)
    for row in cert_rows.fetchall():
        cert = row.tls_cert
        if not isinstance(cert, dict):
            continue
        # Use issuer+subject as fingerprint (sans are per-cert, not per-asset)
        fingerprint = f"{cert.get('issuer', '')}|{cert.get('subject', '')}"
        if fingerprint and fingerprint != "|":
            cert_groups[fingerprint].append(row.asset_id)

    for fingerprint, asset_ids in cert_groups.items():
        if len(asset_ids) < 2:
            continue
        unique_ids = list(set(asset_ids))
        # Create pairwise edges for small clusters, skip huge ones (CDN certs)
        if len(unique_ids) > 50:
            continue
        for i, src_id in enumerate(unique_ids):
            for tgt_id in unique_ids[i + 1:]:
                await _upsert_edge(
                    db, org_id, src_id, tgt_id,
                    "shares_certificate", "high",
                    weight=0.9,
                    properties={"cert_fingerprint": fingerprint[:200]},
                )
                stats["shared_cert"] += 1

    # ── Same JARM cluster edges ──
    jarm_rows = await db.execute(
        text("""
            SELECT ap.asset_id, ap.tls_cert->>'jarm_hash' as jarm_hash
            FROM asset_ports ap
            JOIN assets a ON a.id = ap.asset_id
            WHERE a.org_id = :org_id
              AND ap.tls_cert->>'jarm_hash' IS NOT NULL
              AND ap.tls_cert->>'jarm_hash' != ''
              AND ap.tls_cert->>'jarm_hash' != '00000000000000000000000000000000000000000000000000000000000000000000'
        """),
        {"org_id": org_id},
    )

    jarm_groups: dict[str, list[int]] = defaultdict(list)
    for row in jarm_rows.fetchall():
        jarm_groups[row.jarm_hash].append(row.asset_id)

    for jarm_hash, asset_ids in jarm_groups.items():
        unique_ids = list(set(asset_ids))
        if len(unique_ids) < 2 or len(unique_ids) > 50:
            continue
        for i, src_id in enumerate(unique_ids):
            for tgt_id in unique_ids[i + 1:]:
                await _upsert_edge(
                    db, org_id, src_id, tgt_id,
                    "same_jarm_cluster", "medium",
                    weight=0.7,
                    properties={"jarm_hash": jarm_hash},
                )
                stats["same_jarm"] += 1

    # ── Same IP edges ──
    ip_rows = await db.execute(
        text("""
            SELECT id, host(ip) as ip_str
            FROM assets
            WHERE org_id = :org_id
              AND ip IS NOT NULL
              AND cdn_provider IS NULL
        """),
        {"org_id": org_id},
    )

    ip_groups: dict[str, list[int]] = defaultdict(list)
    for row in ip_rows.fetchall():
        if row.ip_str:
            ip_groups[row.ip_str].append(row.id)

    for ip_str, asset_ids in ip_groups.items():
        if len(asset_ids) < 2 or len(asset_ids) > 20:
            continue
        for i, src_id in enumerate(asset_ids):
            for tgt_id in asset_ids[i + 1:]:
                await _upsert_edge(
                    db, org_id, src_id, tgt_id,
                    "same_ip", "high",
                    weight=0.8,
                    properties={"shared_ip": ip_str},
                )
                stats["same_ip"] += 1

    await db.commit()
    logger.info("org=%d graph materialized: %s", org_id, stats)
    return stats


async def build_clusters(db: Session, org_id: int) -> dict:
    """Build infrastructure clusters from graph edges.

    Groups assets by shared signals and creates/updates AssetCluster records.
    """
    stats = {"clusters_created": 0, "clusters_updated": 0}

    for cluster_type, rel_type, pivot_key in [
        ("shared_certificate", "shares_certificate", "cert_fingerprint"),
        ("same_jarm", "same_jarm_cluster", "jarm_hash"),
        ("shared_ip_range", "same_ip", "shared_ip"),
    ]:
        # Get all edges of this type
        edges = await db.execute(
            text("""
                SELECT source_asset_id, target_asset_id, properties
                FROM asset_relationships
                WHERE org_id = :org_id AND relationship_type = :rel_type
            """),
            {"org_id": org_id, "rel_type": rel_type},
        )

        # Build adjacency and group by pivot value
        pivot_groups: dict[str, set[int]] = defaultdict(set)
        for row in edges.fetchall():
            props = row.properties or {}
            pivot = props.get(pivot_key, "unknown")
            pivot_groups[pivot].add(row.source_asset_id)
            pivot_groups[pivot].add(row.target_asset_id)

        for pivot_value, asset_id_set in pivot_groups.items():
            asset_ids = sorted(asset_id_set)
            if len(asset_ids) < 2:
                continue

            # Upsert cluster
            existing = await db.execute(
                text("""
                    SELECT id FROM asset_clusters
                    WHERE org_id = :org_id AND cluster_type = :ctype AND pivot_value = :pivot
                """),
                {"org_id": org_id, "ctype": cluster_type, "pivot": pivot_value[:500]},
            )
            row = existing.fetchone()
            if row:
                await db.execute(
                    text("""
                        UPDATE asset_clusters SET
                            asset_ids = :aids, asset_count = :cnt, updated_at = :now
                        WHERE id = :id
                    """),
                    {"aids": asset_ids, "cnt": len(asset_ids), "now": datetime.utcnow(), "id": row.id},
                )
                stats["clusters_updated"] += 1
            else:
                await db.execute(
                    text("""
                        INSERT INTO asset_clusters (org_id, cluster_type, pivot_value, asset_ids, asset_count, label, created_at, updated_at)
                        VALUES (:org_id, :ctype, :pivot, :aids, :cnt, :label, :now, :now)
                    """),
                    {
                        "org_id": org_id, "ctype": cluster_type,
                        "pivot": pivot_value[:500], "aids": asset_ids,
                        "cnt": len(asset_ids),
                        "label": f"{cluster_type}: {len(asset_ids)} assets",
                        "now": datetime.utcnow(),
                    },
                )
                stats["clusters_created"] += 1

    await db.commit()
    logger.info("org=%d clusters built: %s", org_id, stats)
    return stats


async def get_blast_radius(db: Session, org_id: int, asset_id: int, max_depth: int = 3) -> dict:
    """BFS traversal from a starting asset to find all reachable assets.

    Returns the subgraph reachable within max_depth hops, with edges and
    risk scores for blast radius analysis.
    """
    visited: set[int] = {asset_id}
    queue: list[tuple[int, int]] = [(asset_id, 0)]  # (asset_id, depth)
    edges: list[dict] = []
    nodes: list[dict] = []

    while queue:
        current_id, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        # Get all edges from current node
        result = await db.execute(
            text("""
                SELECT ar.target_asset_id as neighbor_id, ar.relationship_type, ar.weight, ar.confidence,
                       a.hostname, a.ip, a.risk_score, a.criticality, a.asset_type
                FROM asset_relationships ar
                JOIN assets a ON a.id = ar.target_asset_id
                WHERE ar.org_id = :org_id AND ar.source_asset_id = :aid
                UNION ALL
                SELECT ar.source_asset_id as neighbor_id, ar.relationship_type, ar.weight, ar.confidence,
                       a.hostname, a.ip, a.risk_score, a.criticality, a.asset_type
                FROM asset_relationships ar
                JOIN assets a ON a.id = ar.source_asset_id
                WHERE ar.org_id = :org_id AND ar.target_asset_id = :aid
            """),
            {"org_id": org_id, "aid": current_id},
        )

        for row in result.fetchall():
            edges.append({
                "source": current_id,
                "target": row.neighbor_id,
                "type": row.relationship_type,
                "weight": row.weight,
                "confidence": row.confidence,
            })
            if row.neighbor_id not in visited:
                visited.add(row.neighbor_id)
                nodes.append({
                    "id": row.neighbor_id,
                    "hostname": row.hostname,
                    "ip": str(row.ip) if row.ip else None,
                    "risk_score": row.risk_score,
                    "criticality": row.criticality,
                    "asset_type": row.asset_type,
                    "depth": depth + 1,
                })
                queue.append((row.neighbor_id, depth + 1))

    # Get root node info
    root = await db.execute(
        text("SELECT hostname, ip, risk_score, criticality, asset_type FROM assets WHERE id = :id AND org_id = :org_id"),
        {"id": asset_id, "org_id": org_id},
    )
    root_row = root.fetchone()
    if root_row:
        nodes.insert(0, {
            "id": asset_id,
            "hostname": root_row.hostname,
            "ip": str(root_row.ip) if root_row.ip else None,
            "risk_score": root_row.risk_score,
            "criticality": root_row.criticality,
            "asset_type": root_row.asset_type,
            "depth": 0,
        })

    return {
        "root_asset_id": asset_id,
        "nodes": nodes,
        "edges": edges,
        "total_reachable": len(visited),
        "max_depth_reached": max(n["depth"] for n in nodes) if nodes else 0,
    }


async def get_asset_graph(db: Session, org_id: int, limit: int = 500) -> dict:
    """Get the full asset graph for visualization (limited to top N assets by risk)."""
    # Get top assets by risk score
    assets_result = await db.execute(
        text("""
            SELECT id, hostname, host(ip) as ip, risk_score, criticality, asset_type,
                   critical_count, high_count
            FROM assets
            WHERE org_id = :org_id AND liveness_state = 'confirmed_alive'
            ORDER BY risk_score DESC NULLS LAST
            LIMIT :limit
        """),
        {"org_id": org_id, "limit": limit},
    )

    asset_ids = []
    nodes = []
    for row in assets_result.fetchall():
        asset_ids.append(row.id)
        nodes.append({
            "id": row.id,
            "hostname": row.hostname,
            "ip": row.ip,
            "risk_score": row.risk_score,
            "criticality": row.criticality,
            "asset_type": row.asset_type,
            "critical_count": row.critical_count,
            "high_count": row.high_count,
        })

    if not asset_ids:
        return {"nodes": [], "edges": [], "clusters": []}

    # Get edges between these assets
    edges_result = await db.execute(
        text("""
            SELECT source_asset_id, target_asset_id, relationship_type, weight, confidence
            FROM asset_relationships
            WHERE org_id = :org_id
              AND source_asset_id = ANY(:ids)
              AND target_asset_id = ANY(:ids)
        """),
        {"org_id": org_id, "ids": asset_ids},
    )

    edges = [
        {
            "source": row.source_asset_id,
            "target": row.target_asset_id,
            "type": row.relationship_type,
            "weight": row.weight,
            "confidence": row.confidence,
        }
        for row in edges_result.fetchall()
    ]

    # Get clusters
    clusters_result = await db.execute(
        text("""
            SELECT id, cluster_type, label, pivot_value, asset_ids, asset_count
            FROM asset_clusters
            WHERE org_id = :org_id
            ORDER BY asset_count DESC
            LIMIT 50
        """),
        {"org_id": org_id},
    )

    clusters = [
        {
            "id": row.id,
            "type": row.cluster_type,
            "label": row.label,
            "pivot_value": row.pivot_value,
            "asset_ids": row.asset_ids,
            "asset_count": row.asset_count,
        }
        for row in clusters_result.fetchall()
    ]

    return {"nodes": nodes, "edges": edges, "clusters": clusters}


async def _upsert_edge(
    db: Session,
    org_id: int,
    source_id: int,
    target_id: int,
    rel_type: str,
    confidence: str,
    weight: float = 1.0,
    properties: dict | None = None,
):
    """Insert or update a relationship edge."""
    import json as _json
    await db.execute(
        text("""
            INSERT INTO asset_relationships (org_id, source_asset_id, target_asset_id,
                                             relationship_type, confidence, weight, properties, created_at, updated_at)
            VALUES (:org_id, :src, :tgt, :rel, :conf, :w, :props, NOW(), NOW())
            ON CONFLICT ON CONSTRAINT uq_asset_relationship
            DO UPDATE SET confidence = :conf, weight = :w, properties = :props, updated_at = NOW()
        """),
        {
            "org_id": org_id, "src": source_id, "tgt": target_id,
            "rel": rel_type, "conf": confidence, "w": weight,
            "props": _json.dumps(properties or {}),
        },
    )
