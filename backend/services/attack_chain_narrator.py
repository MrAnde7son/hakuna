"""Attack chain LLM narrative + mitigation ranking.

Extends the BFS-based finding correlator (services.finding_correlator) with
human-readable attack narratives and prioritized mitigation recommendations.

For each AttackPath of severity Critical or High with chain_length >= 2:
  1. Build a structured context (findings chain + asset metadata at each step)
  2. Ask the LLM to produce a 2-4 paragraph attacker-POV narrative
  3. Rank mitigations by how many *other* attack paths each finding participates
     in — the highest-participation finding breaks the most chains when fixed

Cost-controlled: only runs on High/Critical severity chains with length >= 2.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Iterable

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from services.llm_provider import call_llm

logger = logging.getLogger(__name__)


_NARRATIVE_SYSTEM_PROMPT = """You are a senior offensive security consultant writing an attack-path analysis \
for a defensive team. You describe, from an attacker's perspective, how the given chain of \
findings could be exploited in sequence to move from an initial entry point deeper into the environment.

Keep the tone professional and precise. 2-4 short paragraphs. Cover:
  - The initial entry vector and why it's reachable
  - How each subsequent step builds on the previous one (what access each step grants)
  - The realistic impact at the end of the chain
  - Any non-obvious assumptions (auth required, pivot difficulty)

Do NOT include disclaimers, recommendations, or bulleted lists. Prose only."""


def narrate_attack_paths(
    db: Session,
    org_id: int,
    min_severity: str = "High",
    max_paths: int = 20,
) -> dict:
    """Generate LLM narratives and mitigation rankings for recent attack paths.

    Only processes paths without an existing narrative (narrative IS NULL),
    severity at or above `min_severity`, and chain_length >= 2.

    Returns {"processed": int, "skipped": int, "no_llm": bool}.
    """
    # Severity ordering for filtering
    sev_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    min_rank = sev_rank.get(min_severity, 3)
    eligible_severities = [s for s, r in sev_rank.items() if r >= min_rank]

    rows = db.execute(
        text("""
            SELECT id, title, severity, steps, entry_asset_id, target_asset_id, chain_length
            FROM attack_paths
            WHERE org_id = :org_id
              AND narrative IS NULL
              AND chain_length >= 2
              AND severity IN :severities
            ORDER BY
                COALESCE(score, 0) DESC,
                CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 ELSE 3 END,
                chain_length DESC,
                id DESC
            LIMIT :limit
        """).bindparams(bindparam("severities", expanding=True)),
        {
            "org_id": org_id,
            "severities": list(eligible_severities),
            "limit": max_paths,
        },
    ).fetchall()

    if not rows:
        return {"processed": 0, "skipped": 0, "no_candidates": True}

    processed = 0
    skipped_no_llm = 0

    for row in rows:
        steps = _parse_steps(row.steps)
        if not steps:
            continue

        # Build LLM context
        context = _build_narrative_context(db, row, steps)
        narrative = call_llm(
            system_prompt=_NARRATIVE_SYSTEM_PROMPT,
            user_prompt=json.dumps(context, indent=2),
            max_tokens=1024,
            model_env="LLM_NARRATIVE_MODEL",
            db=db,
        )

        if not narrative:
            skipped_no_llm += 1
            continue

        # Mitigation ranking is now populated upfront for every path via
        # rank_all_mitigations(); here we only write the LLM-derived prose.
        db.execute(
            text(
                "UPDATE attack_paths SET narrative = :narrative WHERE id = :id"
            ),
            {"id": row.id, "narrative": narrative.strip()},
        )
        processed += 1

    db.commit()
    logger.info(
        "org=%d attack chain narration: processed=%d skipped_no_llm=%d candidates=%d",
        org_id, processed, skipped_no_llm, len(rows),
    )
    return {
        "processed": processed,
        "skipped_no_llm": skipped_no_llm,
        "candidates": len(rows),
    }


def _build_narrative_context(db: Session, path_row, steps: list[dict]) -> dict:
    """Build a structured JSON context for the LLM describing the path."""
    # Fetch asset metadata + CVE data for each step
    enriched_steps = []
    for step in steps:
        asset_info = {}
        if step.get("asset_id"):
            asset_row = db.execute(
                text("""
                    SELECT hostname, host(ip) as ip, is_internet_facing, criticality,
                           os, asset_type, easm_data
                    FROM assets WHERE id = :id
                """) if _is_postgres(db) else text("""
                    SELECT hostname, ip, is_internet_facing, criticality,
                           os, asset_type, easm_data
                    FROM assets WHERE id = :id
                """),
                {"id": step["asset_id"]},
            ).fetchone()
            if asset_row:
                easm = _parse_json(asset_row.easm_data) or {}
                tech_stack = easm.get("tech_stack") or []
                asset_info = {
                    "hostname": asset_row.hostname,
                    "ip": str(asset_row.ip) if asset_row.ip else None,
                    "internet_facing": bool(asset_row.is_internet_facing),
                    "criticality": asset_row.criticality,
                    "os": asset_row.os,
                    "asset_type": asset_row.asset_type,
                    "tech_stack": tech_stack[:15] if isinstance(tech_stack, list) else [],
                }

        cve_list: list = []
        if step.get("finding_id"):
            f_row = db.execute(
                text("""
                    SELECT cves, description, plugin_output
                    FROM findings WHERE id = :id
                """),
                {"id": step["finding_id"]},
            ).fetchone()
            if f_row:
                cve_list = _parse_json(f_row.cves) or []
                step = {
                    **step,
                    "cves": cve_list[:5],
                    "description": (f_row.description or "")[:400],
                    "evidence": (f_row.plugin_output or "")[:300],
                }

        enriched_steps.append({
            **step,
            "asset": asset_info,
        })

    return {
        "path_title": path_row.title,
        "severity": path_row.severity,
        "chain_length": path_row.chain_length,
        "steps": enriched_steps,
    }


def rank_all_mitigations(db: Session, org_id: int) -> int:
    """Compute and persist `recommended_mitigations` for every attack path
    in the org. Independent of LLM narration — mitigation ranking is pure
    statistics (chain participation counts) and must always be populated,
    even for paths the narrator skipped due to its top-N budget.

    Returns the number of rows updated.
    """
    paths = db.execute(
        text(
            "SELECT id, steps FROM attack_paths WHERE org_id = :org_id"
        ),
        {"org_id": org_id},
    ).fetchall()
    if not paths:
        return 0

    # Count each finding's cross-path participation once. If the same finding
    # appears twice in the same chain, still count it only once for that chain.
    finding_to_paths: Counter[int] = Counter()
    parsed_steps: dict[int, list[dict]] = {}
    for p in paths:
        steps = _parse_steps(p.steps)
        parsed_steps[p.id] = steps
        seen_in_this_path: set[int] = set()
        for step in steps:
            fid = step.get("finding_id")
            if fid and fid not in seen_in_this_path:
                finding_to_paths[fid] += 1
                seen_in_this_path.add(fid)

    updated = 0
    # Commit periodically so the SQLite writer lock doesn't stay held the
    # full duration — matches the pattern in finding_correlator.
    COMMIT_BATCH = 50
    for p in paths:
        steps = parsed_steps.get(p.id) or []
        if not steps:
            continue
        mitigations = _rank_mitigations(steps, finding_to_paths)
        db.execute(
            text(
                "UPDATE attack_paths SET recommended_mitigations = :m WHERE id = :id"
            ),
            {"id": p.id, "m": json.dumps(mitigations)},
        )
        updated += 1
        if updated % COMMIT_BATCH == 0:
            db.commit()
    db.commit()
    logger.info("org=%d mitigations ranked for %d attack paths", org_id, updated)
    return updated


def _rank_mitigations(steps: list[dict], finding_to_paths: Counter[int]) -> list[dict]:
    """Return a list of mitigation recommendations sorted by chains_broken desc.

    Each entry: {finding_id, finding_name, severity, chains_broken, action}.
    """
    unique: dict[int, dict] = {}
    for step in steps:
        fid = step.get("finding_id")
        if not fid or fid in unique:
            continue
        unique[fid] = {
            "finding_id": fid,
            "finding_name": step.get("finding_name") or "Unknown",
            "severity": step.get("severity"),
            "chains_broken": finding_to_paths.get(fid, 1),
            "action": f"Remediate finding {fid} ({step.get('finding_name') or 'Unknown'})",
        }
    ranked = sorted(unique.values(), key=lambda m: (-m["chains_broken"], -int(m["severity"] or 0)))
    return ranked


def _parse_steps(raw) -> list[dict]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        try:
            val = json.loads(raw)
            return val if isinstance(val, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _parse_json(raw):
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    return None


def _is_postgres(db: Session) -> bool:
    try:
        return str(db.get_bind().url).startswith("postgresql")
    except Exception:
        return False
