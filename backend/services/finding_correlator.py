"""Cross-finding correlation — links findings across scanners and generates attack paths.

Two main functions:
1. CVE-based correlation: groups findings by CVE across source_types (Nessus + Nuclei + EASM)
   and updates source_systems to reflect multi-scanner corroboration.
2. Attack path generation: assume-breach BFS over the asset_relationship graph
   from any asset with an exploitable finding to any crown-jewel target.
   Every path carries structured explainability (entry_reason, target_reason,
   numeric score + breakdown, and per-step why_reachable/what_enables strings).
"""

from __future__ import annotations

import json
import logging
import math
from collections import defaultdict
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def correlate_findings(db: Session, org_id: int, scan_id: int | None = None) -> dict:
    """Run cross-finding correlation for an org.

    1. Groups findings by CVE across sources → updates source_systems, adds corroboration
    2. Generates attack paths through the knowledge graph
    3. Ranks `recommended_mitigations` for EVERY path (pure statistics, no LLM)
    4. Generates LLM narratives for top-severity chains (best-effort)

    Returns stats dict.
    """
    stats = {
        "corroborated": 0,
        "attack_paths_created": 0,
        "mitigations_ranked": 0,
        "narrated": 0,
    }

    # ── Step 1: CVE-based cross-source correlation ──
    corr = _correlate_by_cve(db, org_id)
    stats["corroborated"] = corr

    # ── Step 2: Attack path generation ──
    paths = _generate_attack_paths(db, org_id)
    stats["attack_paths_created"] = paths

    # ── Step 3: Mitigation ranking — always run, does not depend on LLM.
    # A Critical chain should have ranked mitigations even if the narrator
    # didn't pick it up (top-N budget) or the LLM provider was down.
    try:
        from services.attack_chain_narrator import rank_all_mitigations
        stats["mitigations_ranked"] = rank_all_mitigations(db, org_id)
    except Exception as e:
        logger.warning("Mitigation ranking failed for org %d: %s", org_id, e)

    # ── Step 4: LLM narration of high/critical chains (best-effort) ──
    try:
        from services.attack_chain_narrator import narrate_attack_paths
        # Narrate up to 50 top-scoring High/Critical chains per run. The
        # narrator orders by `score DESC`, so a high-score Critical path
        # can't lose its narrative to a shorter chain of equal severity.
        narration = narrate_attack_paths(db, org_id, min_severity="High", max_paths=50)
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
    result = db.execute(
        text("""
            SELECT f.id, f.asset_id, f.source_type, f.source_systems, f.cves, f.custom_fields
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            JOIN scans s ON s.id = f.scan_id
            WHERE s.org_id = :org_id
              AND f.cves IS NOT NULL
              AND f.cves::text != '[]'
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
            # Release the writer lock periodically so other writers
            # (scheduler, live uploads) aren't starved during a large
            # correlation run.
            if corroborated % 50 == 0:
                db.commit()

    db.commit()
    logger.info("org=%d CVE correlation: corroborated=%d findings", org_id, corroborated)
    return corroborated


# ═══════════════════════════════════════════════════════════════════
# Attack path generation — assume-breach entry/target model
# ═══════════════════════════════════════════════════════════════════


def _generate_attack_paths(db: Session, org_id: int) -> int:
    """Generate attack paths using an asymmetric entry/target model.

    Entry set    = any asset with an exploitable (severity ≥ 3) finding.
                   No internet-facing gate — assume-breach, insider-threat,
                   and phishing scenarios are all valid origins.
    Target set   = crown-jewel assets: domain controllers (graph-inferred),
                   criticality ≥ 8, internet-facing egress, or hosts holding
                   critical findings.
    Path         = BFS through asset_relationship edges, terminating when
                   we reach a target asset.

    Every row is persisted with:
      - entry_reason  ("critical_finding+internet_facing+has_exploit")
      - target_reason ("domain_controller", "high_criticality=9")
      - score         (0-100) + score_breakdown (json)
      - steps[].why_reachable + steps[].what_enables (per-hop prose)
    """
    # Wipe stale auto-generated paths so re-runs are idempotent; preserve any
    # row a curator already narrated. Commit immediately so the DELETE's
    # BEGIN-IMMEDIATE lock is released before we start the (long) BFS phase.
    db.execute(
        text("DELETE FROM attack_paths WHERE org_id = :org_id AND narrative IS NULL"),
        {"org_id": org_id},
    )
    db.commit()

    targets = _build_target_set(db, org_id)
    if not targets:
        logger.info("org=%d no candidate targets — skipping attack paths", org_id)
        return 0

    entries = _build_entry_set(db, org_id)
    if not entries:
        logger.info("org=%d no candidate entries — skipping attack paths", org_id)
        return 0

    now = datetime.utcnow()
    # Keep only the highest-scoring path per (entry, target) pair.
    best_per_pair: dict[tuple[int, int], dict] = {}

    for entry in entries:
        chains = _bfs_attack_chains(
            db, org_id,
            start=entry,
            target_index=targets,
            max_depth=4,
        )
        for chain in chains:
            target_meta = targets[chain[-1]["asset_id"]]
            score, breakdown = _score_chain(entry, chain, target_meta)
            key = (chain[0]["asset_id"], chain[-1]["asset_id"])
            prev = best_per_pair.get(key)
            if prev and prev["score"] >= score:
                continue
            best_per_pair[key] = {
                "chain": chain,
                "score": score,
                "breakdown": breakdown,
                "entry_reason": entry["reason"],
                "target_reason": target_meta["reason"],
                "severity_label": _chain_severity_label(chain),
                "title": _chain_title(chain),
            }

    # Batch-commit every N inserts so other writers (scheduler, live uploads)
    # aren't blocked behind one long transaction.
    paths_created = 0
    COMMIT_BATCH = 25
    for (entry_id, target_id), path in best_per_pair.items():
        db.execute(
            text("""
                INSERT INTO attack_paths (
                    org_id, title, severity, steps, entry_asset_id,
                    target_asset_id, chain_length, created_at,
                    entry_reason, target_reason, score, score_breakdown
                ) VALUES (
                    :org_id, :title, :severity, :steps, :entry_id,
                    :target_id, :chain_len, :now,
                    :entry_reason, :target_reason, :score, :breakdown
                )
            """),
            {
                "org_id": org_id,
                "title": path["title"],
                "severity": path["severity_label"],
                "steps": json.dumps(path["chain"]),
                "entry_id": entry_id,
                "target_id": target_id,
                "chain_len": len(path["chain"]),
                "now": now,
                "entry_reason": path["entry_reason"],
                "target_reason": path["target_reason"],
                "score": path["score"],
                "breakdown": json.dumps(path["breakdown"]),
            },
        )
        paths_created += 1
        if paths_created % COMMIT_BATCH == 0:
            db.commit()

    # Final flush for the tail batch.
    db.commit()
    logger.info(
        "org=%d attack paths generated: %d (entries=%d targets=%d)",
        org_id, paths_created, len(entries), len(targets),
    )
    return paths_created


# ── Entry + target construction ──────────────────────────────────────


def _build_entry_set(db: Session, org_id: int) -> list[dict]:
    """Every asset with a live severity ≥ 3 finding is a candidate entry.

    The `reason` string joins every applicable factor with '+' so the UI can
    show *all* drivers, not just the primary one.
    """
    query = text("""
        SELECT
            a.id, a.hostname, a.ip, a.risk_score, a.is_internet_facing,
            MAX(f.severity) AS max_severity,
            BOOL_OR(COALESCE(f.exploit_available, FALSE)) AS has_exploit
        FROM assets a
        JOIN findings f ON f.asset_id = a.id
        JOIN scans s ON s.id = a.scan_id
        WHERE s.org_id = :org_id
          AND f.severity >= 3
          AND f.workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
        GROUP BY a.id, a.hostname, a.ip, a.risk_score, a.is_internet_facing
        ORDER BY MAX(f.severity) DESC, a.risk_score DESC NULLS LAST
        LIMIT 200
    """)

    rows = db.execute(query, {"org_id": org_id}).fetchall()
    entries: list[dict] = []
    for row in rows:
        reasons: list[str] = []
        sev_label = {4: "critical", 3: "high"}.get(row.max_severity, "medium")
        reasons.append(f"{sev_label}_finding")
        if row.is_internet_facing:
            reasons.append("internet_facing")
        if row.has_exploit:
            reasons.append("has_exploit")
        entries.append({
            "asset_id": row.id,
            "hostname": row.hostname or "unknown",
            "ip": str(row.ip) if row.ip else None,
            "max_severity": row.max_severity,
            "is_internet_facing": bool(row.is_internet_facing),
            "has_exploit": bool(row.has_exploit),
            "reason": "+".join(reasons),
        })
    return entries


def _build_target_set(db: Session, org_id: int) -> dict[int, dict]:
    """Identify crown-jewel assets.

    Reasons (first match wins as the primary label; all factors flow into
    the score via bonuses):
      1. domain_controller  — inferred from member_of_domain / trusts_domain edges
      2. high_criticality=N — business-critical (criticality ≥ 8)
      3. internet_facing_target — external egress / fallback target
      4. has_critical_finding  — any live severity 4 finding
    """
    result: dict[int, dict] = {}

    # DC heuristic: legacy edges from `inventory_graph_extractor` pinpoint
    # DCs. The unified `asset_to_asset_auth` (via=domain_trust) carries
    # the same signal, but the legacy extractor still runs alongside the
    # Phase 2 materializer, so reading either source is equivalent.
    dc_rows = db.execute(
        text("""
            SELECT DISTINCT ar.target_asset_id AS asset_id
            FROM asset_relationships ar
            WHERE ar.org_id = :org_id
              AND ar.relationship_type = 'member_of_domain'
              AND ar.target_asset_id IS NOT NULL
            UNION
            SELECT DISTINCT ar.source_asset_id AS asset_id
            FROM asset_relationships ar
            WHERE ar.org_id = :org_id
              AND ar.relationship_type = 'trusts_domain'
              AND ar.source_asset_id IS NOT NULL
        """),
        {"org_id": org_id},
    ).fetchall()
    for row in dc_rows:
        result[row.asset_id] = {
            "asset_id": row.asset_id,
            "reason": "domain_controller",
            "criticality": 10,
        }

    # High criticality / internet-facing / critical findings.
    crown_rows = db.execute(
        text("""
            SELECT a.id, a.hostname, a.criticality, a.is_internet_facing,
                   MAX(f.severity) AS max_sev
            FROM assets a
            JOIN scans s ON s.id = a.scan_id
            LEFT JOIN findings f ON f.asset_id = a.id
                 AND f.workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
            WHERE s.org_id = :org_id
              AND (
                COALESCE(a.criticality, 5) >= 8
                OR a.is_internet_facing = TRUE
                OR f.severity >= 4
              )
            GROUP BY a.id, a.hostname, a.criticality, a.is_internet_facing
        """),
        {"org_id": org_id},
    ).fetchall()

    for row in crown_rows:
        crit = row.criticality or 5
        if row.id in result:
            result[row.id]["criticality"] = max(result[row.id]["criticality"], crit)
            continue
        if crit >= 8:
            reason = f"high_criticality={crit}"
        elif row.is_internet_facing:
            reason = "internet_facing_target"
        elif (row.max_sev or 0) >= 4:
            reason = "has_critical_finding"
        else:
            continue
        result[row.id] = {"asset_id": row.id, "reason": reason, "criticality": crit}

    return result


# ── BFS ──────────────────────────────────────────────────────────────


def _bfs_attack_chains(
    db: Session,
    org_id: int,
    *,
    start: dict,
    target_index: dict[int, dict],
    max_depth: int = 4,
) -> list[list[dict]]:
    """BFS from `start` through asset_relationship edges until a target is
    reached. Returns every target-terminated chain up to `max_depth` hops.
    """
    start_asset_id = start["asset_id"]

    start_row = db.execute(
        text("""
            SELECT f.id, f.plugin_name, f.severity, f.exploit_available, a.hostname
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            JOIN scans s ON s.id = a.scan_id
            WHERE f.asset_id = :aid AND s.org_id = :org_id
              AND f.severity >= 3
              AND f.workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
            ORDER BY f.severity DESC, f.priority_score DESC
            LIMIT 1
        """),
        {"aid": start_asset_id, "org_id": org_id},
    ).fetchone()
    if not start_row:
        return []

    start_step = {
        "asset_id": start_asset_id,
        "hostname": start_row.hostname or "unknown",
        "finding_id": start_row.id,
        "finding_name": start_row.plugin_name or "Unknown",
        "severity": start_row.severity,
        "edge_type": "entry",
        "pivot_quality": "entry",
        "why_reachable": _describe_entry(start),
        "what_enables": _describe_what_enables(
            start_row.plugin_name, start_row.severity,
            bool(start_row.exploit_available),
        ),
    }

    # An attack *path* requires at least one hop. Zero-hop "paths" where
    # entry == target tell the user the crown jewel is itself vulnerable,
    # which is already visible on the findings page — surfacing it as a
    # path adds noise without new information.
    chains: list[list[dict]] = []

    queue: list[tuple[list[dict], set[int], int]] = [
        ([start_step], {start_asset_id}, 0)
    ]

    while queue:
        current_chain, visited, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        current_asset_id = current_chain[-1]["asset_id"]

        # Phase 2: traverse the unified edge graph. Filter out edge
        # types whose endpoints are pseudo (cve_on_asset / internet_to_asset
        # / user_to_asset have NULL on one side) or whose semantics
        # don't represent host→host hops.
        neighbors = db.execute(
            text("""
                SELECT
                    CASE WHEN ar.source_asset_id = :aid
                         THEN ar.target_asset_id
                         ELSE ar.source_asset_id END AS neighbor_id,
                    ar.relationship_type,
                    ar.confidence,
                    ar.weight,
                    ar.properties,
                    a.hostname
                FROM asset_relationships ar
                JOIN assets a ON a.id =
                    CASE WHEN ar.source_asset_id = :aid
                         THEN ar.target_asset_id
                         ELSE ar.source_asset_id END
                WHERE ar.org_id = :org_id
                  AND (ar.source_asset_id = :aid OR ar.target_asset_id = :aid)
                  AND ar.relationship_type NOT IN (
                      'cve_on_asset', 'internet_to_asset',
                      'user_to_asset', 'principal_to_domain'
                  )
            """),
            {"org_id": org_id, "aid": current_asset_id},
        ).fetchall()

        for neighbor in neighbors:
            if neighbor.neighbor_id in visited:
                continue

            # Prefer a finding that matches the observed netconn port — that's
            # the one most likely to be the real exploit target. Fall back to
            # the highest-severity finding when no port match exists.
            finding_row = _select_best_finding_for_edge(
                db, neighbor.neighbor_id,
                neighbor.relationship_type, neighbor.properties,
            )
            if not finding_row:
                continue

            finding_port = _extract_finding_port(finding_row.port)
            why_reachable, pivot_quality = _describe_edge(
                neighbor.relationship_type, neighbor.properties,
                finding_port=finding_port,
            )
            new_step = {
                "asset_id": neighbor.neighbor_id,
                "hostname": neighbor.hostname or "unknown",
                "finding_id": finding_row.id,
                "finding_name": finding_row.plugin_name or "Unknown",
                "finding_port": finding_port,
                "severity": finding_row.severity,
                "edge_type": neighbor.relationship_type,
                "edge_confidence": neighbor.confidence,
                "edge_weight": float(neighbor.weight or 1.0),
                "pivot_quality": pivot_quality,
                "exploit_path_verified": pivot_quality == "exploit_path_verified",
                "why_reachable": why_reachable,
                "what_enables": _describe_what_enables(
                    finding_row.plugin_name, finding_row.severity,
                    bool(finding_row.exploit_available),
                ),
            }
            new_visited = visited | {neighbor.neighbor_id}
            new_chain = current_chain + [new_step]

            if neighbor.neighbor_id in target_index:
                chains.append(new_chain)
            queue.append((new_chain, new_visited, depth + 1))

    return chains


# ── Scoring ──────────────────────────────────────────────────────────


def _score_chain(
    entry: dict, chain: list[dict], target: dict
) -> tuple[float, dict]:
    """Return (score, breakdown) — a transparent 0-100 ranking.

    Factors:
      base                = entry_severity*6 + target_criticality*4    (0-64)
      length_bonus        = log1p(chain_length) * 5                    (0-10)
      bonuses             = {exploit, IF-entry, DC-target} +5 each     (0-15)
      confidence_factor   = product of edge confidences (1.0/0.75/0.5)

      score = min((base + length_bonus + bonus_total) * confidence, 100)
    """
    entry_sev = entry["max_severity"]
    target_crit = target.get("criticality", 5)
    chain_len = len(chain)

    conf_map = {"high": 1.0, "medium": 0.75, "low": 0.5}
    real_edges = [s for s in chain if s.get("edge_type") != "entry"]
    if real_edges:
        conf_factor = 1.0
        for step in real_edges:
            conf_factor *= conf_map.get(step.get("edge_confidence", "medium"), 0.75)
    else:
        conf_factor = 1.0

    base = (entry_sev * 6) + (target_crit * 4)
    length_bonus = round(math.log1p(chain_len) * 5, 2)

    bonuses: list[dict] = []
    if entry.get("has_exploit"):
        bonuses.append({"label": "exploit_available", "value": 5})
    if entry.get("is_internet_facing"):
        bonuses.append({"label": "internet_facing_entry", "value": 5})
    if target.get("reason") == "domain_controller":
        bonuses.append({"label": "domain_controller_target", "value": 5})
    # Verified-exploit-path bonus: each hop where the netconn port matches
    # the target finding's port is the strongest signal we can emit. Cap at
    # one application so a 4-hop chain of SMB connections doesn't stack.
    if any(s.get("exploit_path_verified") for s in chain):
        bonuses.append({"label": "exploit_path_verified", "value": 10})

    bonus_total = sum(b["value"] for b in bonuses)
    raw = (base + length_bonus + bonus_total) * conf_factor
    score = round(min(raw, 100.0), 2)

    breakdown = {
        "entry_severity": entry_sev,
        "target_criticality": target_crit,
        "chain_length": chain_len,
        "base": base,
        "length_bonus": length_bonus,
        "confidence_factor": round(conf_factor, 3),
        "bonuses": bonuses,
        "formula": "(entry_sev*6 + target_crit*4 + log1p(len)*5 + bonuses) * confidence",
    }
    return score, breakdown


# ── Step-enrichment helpers ──────────────────────────────────────────


def _chain_severity_label(chain: list[dict]) -> str:
    max_sev = max((s["severity"] for s in chain), default=0)
    return {4: "Critical", 3: "High", 2: "Medium"}.get(max_sev, "Info")


def _chain_title(chain: list[dict]) -> str:
    parts = [f"{s['hostname']} ({s['finding_name']})" for s in chain]
    return " → ".join(parts)[:500]


def _describe_entry(entry: dict) -> str:
    sev_label = {4: "critical", 3: "high"}.get(entry["max_severity"], "medium")
    pieces = [f"Exploitable {sev_label}-severity finding"]
    if entry.get("is_internet_facing"):
        pieces.append("on an internet-facing asset")
    if entry.get("has_exploit"):
        pieces.append("with a known public exploit")
    return " ".join(pieces) + "."


# Ports observable in netstat fall into two buckets:
#   - service ports: a process is bound here (SMB on 445, RDP on 3389, etc.)
#   - ephemeral ports: OS-assigned for the client side of a TCP connection
# A netconn row like srv1:12345 → peer:55068 pairs an ephemeral client port
# (12345) with an ephemeral remote port (55068), which means NEITHER side is
# exposing a known service — we're just seeing an observed TCP session.
# Treating 55068 as if it were a pivot primitive (like 445) is misleading,
# so we degrade the message to pure "reachability" when the port is
# ephemeral.
_IANA_EPHEMERAL_START = 49152  # IANA dynamic/private range

# Well-known service ports — names matter more than numbers to defenders.
_SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "Portmap",
    135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS-SSN", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-Submission", 636: "LDAPS",
    873: "Rsync", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2181: "ZooKeeper", 2375: "Docker",
    2379: "etcd", 3268: "LDAP-GC", 3269: "LDAPS-GC",
    3306: "MySQL", 3389: "RDP", 4505: "SaltStack", 4506: "SaltStack",
    5000: "Docker-Registry", 5353: "mDNS", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5985: "WinRM",
    5986: "WinRM-TLS", 6379: "Redis", 7001: "WebLogic",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9000: "HTTP-alt",
    9092: "Kafka", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}


def _describe_port(port: int | None) -> tuple[str | None, str]:
    """Return (service_name_or_None, pivot_quality) for a port.

    pivot_quality:
      "service_exposed" — well-known service port, real pivot signal
      "reachability"    — ephemeral or unknown; proves hosts can talk only
    """
    if port is None:
        return None, "reachability"
    if port in _SERVICE_PORTS:
        return _SERVICE_PORTS[port], "service_exposed"
    if port >= _IANA_EPHEMERAL_START:
        return None, "reachability"
    # Non-ephemeral but not in our registry — treat as service.
    return None, "service_exposed"


def _select_best_finding_for_edge(
    db: Session, asset_id: int, rel_type: str | None, properties,
):
    """Pick the neighbor's finding that best matches this edge.

    For `connects_to` edges carrying a remote_port, we prefer a finding whose
    port matches — that's the one the netconn is most likely evidence of. If
    nothing matches (or the edge isn't port-bearing), fall back to the
    highest-severity live finding.
    """
    remote_port = None
    if rel_type in ("connects_to", "asset_to_asset_port"):
        props = properties or {}
        if isinstance(props, str):
            try: props = json.loads(props)
            except Exception: props = {}
        remote_port = props.get("remote_port") or props.get("port")

    if remote_port:
        # Port can be stored as a string ("445", "445/tcp") so compare as
        # text via LIKE after prefix match. Keep a single finding even when
        # multiple match — highest severity wins.
        match = db.execute(
            text("""
                SELECT id, plugin_name, severity, exploit_available, port
                FROM findings
                WHERE asset_id = :aid
                  AND severity >= 2
                  AND workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
                  AND (
                    port = :p_str
                    OR port LIKE :p_slash
                    OR port LIKE :p_rev_slash
                  )
                ORDER BY severity DESC, priority_score DESC
                LIMIT 1
            """),
            {
                "aid": asset_id,
                "p_str": str(remote_port),
                "p_slash": f"{remote_port}/%",       # e.g. "445/tcp"
                "p_rev_slash": f"%/{remote_port}",    # e.g. "tcp/445"
            },
        ).fetchone()
        if match:
            return match

    # Fall back to the plain highest-severity live finding.
    return db.execute(
        text("""
            SELECT id, plugin_name, severity, exploit_available, port
            FROM findings
            WHERE asset_id = :aid
              AND severity >= 2
              AND workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
            ORDER BY severity DESC, priority_score DESC
            LIMIT 1
        """),
        {"aid": asset_id},
    ).fetchone()


def _extract_finding_port(raw) -> int | None:
    """Normalize a finding's port column to an int.

    Nessus stores it as string: "445", "445/tcp", "tcp/445", or "0"/"" for
    plugin findings that aren't port-specific. Return None for 0 / empty so
    callers can treat it as "no port info" rather than "port zero".
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # Pull the first integer-looking token.
    for piece in s.replace(",", "/").split("/"):
        piece = piece.strip()
        if piece.isdigit():
            p = int(piece)
            return p if 1 <= p <= 65535 else None
    return None


def _describe_edge(
    rel_type: str | None, properties, *, finding_port: int | None = None,
) -> tuple[str, str]:
    """Return (prose, pivot_quality) for an edge.

    pivot_quality (strongest first):
      "exploit_path_verified" — netconn port matches the target's finding
                                port. Real exploit primitive.
      "port_mismatch"   — netconn hit a different port than where the
                          target's finding sits — NOT a proven exploit path.
      "service_exposed" — target exposes a service the attacker can reach
      "identity"        — credential / AD trust primitive (domain, session, runs-as)
      "inference"       — weaker signal (shared cert, JARM, same IP)
      "entry"           — synthesized for the starting foothold
    """
    rel_type = rel_type or "unknown"
    props = properties or {}
    if isinstance(props, str):
        try:
            props = json.loads(props)
        except Exception:
            props = {}

    if rel_type in ("connects_to", "asset_to_asset_port"):
        # `asset_to_asset_port` (Phase 1+2) carries the port in `port`,
        # while the legacy `connects_to` edge stored it as `remote_port`.
        port = props.get("remote_port") or props.get("port")
        service, quality = _describe_port(port)
        state = (props.get("state") or "").lower()
        state_lbl = f" ({state})" if state else ""

        # ── Finding ↔ port correlation: the strongest signal we can emit.
        # If the netconn's port matches the port the target's finding sits
        # on, we have observed evidence of the exact vulnerable service
        # being reachable — promote the edge to "exploit_path_verified".
        # If they differ and both are known, explicitly flag the mismatch
        # so the UI doesn't imply a pivot that isn't proven.
        if port is not None and finding_port:
            if finding_port == port:
                svc_lbl = f" ({service})" if service else ""
                return (
                    f"Target's finding is on port {finding_port}{svc_lbl} — "
                    f"observed network connection to that exact port confirms "
                    f"the service is reachable.",
                    "exploit_path_verified",
                )
            return (
                f"Observed traffic to port {port}, but the target's finding "
                f"is on port {finding_port} — not a proven exploit path "
                f"through this edge.",
                "port_mismatch",
            )

        if service:
            return (
                f"Target exposes {service} on port {port}{state_lbl} — "
                f"observed in network data.",
                quality,
            )
        if port is not None and port >= _IANA_EPHEMERAL_START:
            return (
                f"Observed a TCP session between these hosts. Port {port} is "
                f"ephemeral (client-side), so this shows reachability only — "
                f"not that the target's finding is exploitable through it.",
                quality,
            )
        return (
            f"Observed network reachability between these hosts"
            f"{' on port ' + str(port) if port else ''}{state_lbl}.",
            quality,
        )
    if rel_type == "trusts_domain":
        td = props.get("trusted_domain", "another domain")
        direction = props.get("trust_direction") or "trust"
        return (
            f"AD {direction} trust to {td} enables principal reuse.",
            "identity",
        )
    if rel_type == "member_of_domain":
        dom = props.get("domain", "the domain")
        return (
            f"Joined to {dom} — domain credentials control this host.",
            "identity",
        )
    if rel_type == "shares_credential_with":
        p = props.get("principal", "a shared account")
        return (
            f"Shared session from principal '{p}' bridges both hosts.",
            "identity",
        )
    if rel_type == "runs_as_principal":
        p = props.get("principal", "a domain principal")
        return (
            f"Service/task runs as '{p}', who has access to the target.",
            "identity",
        )
    if rel_type == "resolves_to":
        conn = props.get("connector", "DNS")
        return (f"DNS record ({conn}) resolves to this workload.", "inference")
    if rel_type == "shares_certificate":
        return (
            "Shares a TLS certificate — likely same infrastructure owner.",
            "inference",
        )
    if rel_type == "same_jarm_cluster":
        return (
            "Matching JARM fingerprint — same TLS stack/tenant.",
            "inference",
        )
    if rel_type == "same_ip":
        return ("Both hostnames resolve to the same IP.", "inference")
    if rel_type == "asset_to_asset_auth":
        via = props.get("via") or "auth"
        principal = props.get("principal")
        if via == "domain_trust":
            td = props.get("trusted_domain", "another domain")
            direction = props.get("direction") or "trust"
            return (
                f"AD {direction} trust to {td} enables principal reuse.",
                "identity",
            )
        if via == "shared_session" and principal:
            return (
                f"Shared session from principal '{principal}' bridges both hosts.",
                "identity",
            )
        return (f"Auth-graph edge ({via}) bridges these hosts.", "identity")
    if rel_type == "asset_to_asset_coerce":
        pipe = props.get("pipe") or props.get("primitive") or "coerce primitive"
        return (
            f"Coercion edge — '{pipe}' reachable; attacker can force "
            f"target authentication outbound to a relay.",
            "identity",
        )
    if rel_type == "local_root":
        return (
            "Same-host privilege escalation collapses two hops into one.",
            "identity",
        )
    if rel_type == "entry":
        return ("Starting foothold.", "entry")
    return (f"Reachable via '{rel_type}' edge.", "reachability")


def _describe_what_enables(
    plugin_name: str | None, severity: int, has_exploit: bool,
) -> str:
    sev_label = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(severity, "Info")
    name = plugin_name or "this finding"
    tail = " (public exploit available)" if has_exploit else ""
    return f"{sev_label}: {name}{tail}"
