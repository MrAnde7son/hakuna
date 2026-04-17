"""Cross-finding correlation — links findings across scanners and generates attack paths.

Two main functions:
1. CVE-based correlation: groups findings by CVE across source_types (Nessus + Nuclei + EASM)
   and updates source_systems to reflect multi-scanner corroboration.
2. Attack path generation: BFS from internet-facing assets with critical/high findings
   through the knowledge graph to build exploitable chains.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.database import DATABASE_URL

_SQLITE = DATABASE_URL.startswith("sqlite")

logger = logging.getLogger(__name__)


def correlate_findings(db: Session, org_id: int, scan_id: int | None = None) -> dict:
    """Run cross-finding correlation for an org.

    1. Groups findings by CVE across sources → updates source_systems, adds corroboration
    2. Generates attack paths through the knowledge graph
    3. Narrates high/critical attack paths via LLM + ranks mitigations

    Returns stats dict.
    """
    stats = {"corroborated": 0, "attack_paths_created": 0, "narrated": 0}

    # ── Step 1: CVE-based cross-source correlation ──
    corr = _correlate_by_cve(db, org_id)
    stats["corroborated"] = corr

    # ── Step 2: Attack path generation ──
    paths = _generate_attack_paths(db, org_id)
    stats["attack_paths_created"] = paths

    # ── Step 3: LLM narration of high/critical chains (best-effort) ──
    try:
        from services.attack_chain_narrator import narrate_attack_paths
        narration = narrate_attack_paths(db, org_id, min_severity="High", max_paths=20)
        stats["narrated"] = narration.get("processed", 0)
    except Exception as e:
        logger.warning("Attack chain narration failed for org %d: %s", org_id, e)

    return stats


def _correlate_by_cve(db: Session, org_id: int) -> int:
    """Find findings from different scanners that share CVEs, and mark them as corroborated.

    When multiple scanners (e.g. Nessus + Nuclei) report the same CVE on the same asset,
    update both findings' source_systems to include all contributing sources.
    """
    # Get all findings with CVEs for this org
    cves_not_empty = "CAST(f.cves AS TEXT) != '[]'" if _SQLITE else "f.cves::text != '[]'"
    result = db.execute(
        text(f"""
            SELECT f.id, f.asset_id, f.source_type, f.source_systems, f.cves, f.custom_fields
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            JOIN scans s ON s.id = f.scan_id
            WHERE s.org_id = :org_id
              AND f.cves IS NOT NULL
              AND {cves_not_empty}
              AND f.workflow_status NOT IN ('false_positive', 'accepted_risk')
        """),
        {"org_id": org_id},
    )
    rows = result.fetchall()
    if not rows:
        return 0

    # Group by (asset_id, cve) → list of (finding_id, source_type)
    cve_groups: dict[tuple[int, str], list[tuple[int, str, list]]] = defaultdict(list)
    for row in rows:
        cves = row.cves if isinstance(row.cves, list) else []
        for cve in cves:
            if cve and cve.startswith("CVE-"):
                key = (row.asset_id, cve)
                cve_groups[key].append((row.id, row.source_type, row.source_systems or []))

    corroborated = 0

    for (asset_id, cve), findings in cve_groups.items():
        # Only interesting if multiple source types confirm the same CVE on the same asset
        source_types = set(f[1] for f in findings)
        if len(source_types) < 2:
            continue

        # Build merged source_systems
        all_sources = set()
        for _, src_type, src_systems in findings:
            all_sources.add(src_type)
            all_sources.update(src_systems)
        merged_sources = sorted(all_sources)

        # Update all findings in this group
        corr_data = {
            "corroborated": True,
            "sources": merged_sources,
            "cve": cve,
            "confidence": "high" if len(source_types) >= 3 else "medium",
        }
        for finding_id, _, _ in findings:
            if _SQLITE:
                # SQLite: read-modify-write the JSON column in Python
                row = db.execute(text("SELECT custom_fields FROM findings WHERE id = :id"), {"id": finding_id}).fetchone()
                cf = json.loads(row.custom_fields) if row and row.custom_fields else {}
                cf["corroboration"] = corr_data
                db.execute(
                    text("UPDATE findings SET source_systems = :sources, custom_fields = :cf WHERE id = :id"),
                    {"id": finding_id, "sources": json.dumps(merged_sources), "cf": json.dumps(cf)},
                )
            else:
                db.execute(
                    text("""
                        UPDATE findings SET
                            source_systems = :sources,
                            custom_fields = jsonb_set(
                                COALESCE(custom_fields, '{}')::jsonb,
                                '{corroboration}',
                                :corr_data::jsonb
                            )
                        WHERE id = :id
                    """),
                    {"id": finding_id, "sources": json.dumps(merged_sources), "corr_data": json.dumps(corr_data)},
                )
            corroborated += 1

    db.commit()
    logger.info("org=%d CVE correlation: corroborated=%d findings", org_id, corroborated)
    return corroborated


def _generate_attack_paths(db: Session, org_id: int) -> int:
    """Generate attack paths by traversing the knowledge graph from internet-facing assets.

    Starting from internet-facing assets with critical/high findings, follows
    graph edges to find chains of exploitable assets.
    """
    # Find internet-facing assets with critical/high findings
    entry_points = db.execute(
        text("""
            SELECT DISTINCT a.id, a.hostname, a.ip, a.risk_score
            FROM assets a
            JOIN findings f ON f.asset_id = a.id
            JOIN scans s ON s.id = a.scan_id
            WHERE s.org_id = :org_id
              AND a.is_internet_facing = true
              AND f.severity >= 3
              AND f.workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
            ORDER BY a.risk_score DESC NULLS LAST
            LIMIT 100
        """),
        {"org_id": org_id},
    )
    entry_assets = entry_points.fetchall()
    if not entry_assets:
        return 0

    paths_created = 0
    now = datetime.utcnow()

    for entry in entry_assets:
        # BFS from this entry point through graph edges
        chains = _bfs_attack_chains(db, org_id, entry.id, max_depth=3)

        for chain in chains:
            if len(chain) < 2:
                continue

            # Build attack path title
            steps_desc = []
            max_severity = 0
            steps_json = []
            for step in chain:
                steps_desc.append(f"{step['hostname']} ({step['finding_name']})")
                max_severity = max(max_severity, step["severity"])
                steps_json.append({
                    "asset_id": step["asset_id"],
                    "hostname": step["hostname"],
                    "finding_id": step["finding_id"],
                    "finding_name": step["finding_name"],
                    "severity": step["severity"],
                    "relationship_type": step.get("edge_type", "entry"),
                })

            severity_label = {4: "Critical", 3: "High", 2: "Medium"}.get(max_severity, "Info")
            title = " → ".join(steps_desc)[:500]

            # Insert attack path
            db.execute(
                text("""
                    INSERT INTO attack_paths (
                        org_id, title, severity, steps, entry_asset_id,
                        target_asset_id, chain_length, created_at
                    ) VALUES (
                        :org_id, :title, :severity, :steps, :entry_id,
                        :target_id, :chain_len, :now
                    )
                """),
                {
                    "org_id": org_id,
                    "title": title,
                    "severity": severity_label,
                    "steps": json.dumps(steps_json),
                    "entry_id": chain[0]["asset_id"],
                    "target_id": chain[-1]["asset_id"],
                    "chain_len": len(chain),
                    "now": now,
                },
            )
            paths_created += 1

    db.commit()
    logger.info("org=%d attack paths generated: %d", org_id, paths_created)
    return paths_created


def _bfs_attack_chains(
    db: Session, org_id: int, start_asset_id: int, max_depth: int = 3
) -> list[list[dict]]:
    """BFS from a starting asset through graph edges, collecting finding-bearing chains.

    Returns list of chains, where each chain is a list of steps:
    [{"asset_id", "hostname", "finding_id", "finding_name", "severity", "edge_type"}]
    """
    # Get the starting asset's top finding
    start_finding = db.execute(
        text("""
            SELECT f.id, f.plugin_name, f.severity, a.hostname
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            JOIN scans s ON s.id = f.scan_id
            WHERE f.asset_id = :aid AND s.org_id = :org_id
              AND f.severity >= 3
              AND f.workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
            ORDER BY f.severity DESC, f.priority_score DESC NULLS LAST
            LIMIT 1
        """),
        {"aid": start_asset_id, "org_id": org_id},
    )
    start_row = start_finding.fetchone()
    if not start_row:
        return []

    start_step = {
        "asset_id": start_asset_id,
        "hostname": start_row.hostname or "unknown",
        "finding_id": start_row.id,
        "finding_name": start_row.plugin_name or "Unknown",
        "severity": start_row.severity,
        "edge_type": "entry",
    }

    chains: list[list[dict]] = []
    visited: set[int] = {start_asset_id}
    queue: list[tuple[list[dict], int]] = [([start_step], 0)]

    while queue:
        current_chain, depth = queue.pop(0)
        if depth >= max_depth:
            if len(current_chain) >= 2:
                chains.append(current_chain)
            continue

        current_asset_id = current_chain[-1]["asset_id"]

        # Find neighbors through graph edges
        neighbors = db.execute(
            text("""
                SELECT DISTINCT
                    CASE WHEN ar.source_asset_id = :aid THEN ar.target_asset_id ELSE ar.source_asset_id END as neighbor_id,
                    ar.relationship_type,
                    a.hostname
                FROM asset_relationships ar
                JOIN assets a ON a.id = CASE WHEN ar.source_asset_id = :aid THEN ar.target_asset_id ELSE ar.source_asset_id END
                WHERE ar.org_id = :org_id
                  AND (ar.source_asset_id = :aid OR ar.target_asset_id = :aid)
            """),
            {"org_id": org_id, "aid": current_asset_id},
        )

        found_extension = False
        for neighbor in neighbors.fetchall():
            if neighbor.neighbor_id in visited:
                continue

            # Check if neighbor has high/critical findings
            finding = db.execute(
                text("""
                    SELECT id, plugin_name, severity
                    FROM findings
                    WHERE asset_id = :aid
                      AND severity >= 2
                      AND workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
                    ORDER BY severity DESC, priority_score DESC NULLS LAST
                    LIMIT 1
                """),
                {"aid": neighbor.neighbor_id},
            )
            finding_row = finding.fetchone()
            if not finding_row:
                continue

            visited.add(neighbor.neighbor_id)
            new_step = {
                "asset_id": neighbor.neighbor_id,
                "hostname": neighbor.hostname or "unknown",
                "finding_id": finding_row.id,
                "finding_name": finding_row.plugin_name or "Unknown",
                "severity": finding_row.severity,
                "edge_type": neighbor.relationship_type,
            }
            new_chain = current_chain + [new_step]
            queue.append((new_chain, depth + 1))
            found_extension = True

        # If no extensions found and chain has 2+ steps, save it
        if not found_extension and len(current_chain) >= 2:
            chains.append(current_chain)

    # Limit to top 50 chains by max severity and length
    chains.sort(key=lambda c: (max(s["severity"] for s in c), len(c)), reverse=True)
    return chains[:50]
