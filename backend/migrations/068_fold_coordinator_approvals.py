"""Fold ``coordinator_pending_approvals`` into ``agent_approvals``.

Two parallel approval queues drift over time: the Chain Coordinator's
HITL approvals (Phase 4 patterns like ``cred_found``) lived in
``coordinator_pending_approvals``, while every other approval — paused
agent runs, MCP external calls, agent-drafted feed actions — lived in
``agent_approvals``. The unified queue UI and the agentic feed entry
pattern (``approval_id`` in ``proposed_actions``) couldn't see the
coordinator queue, so half the HITL surface was invisible to the new UX.

This migration backfills any pre-existing rows from the legacy table
into ``agent_approvals`` with ``source='coordinator'``,
``tool_name='dispatch_chain_hypothesis'``, and the coordinator-specific
fields (pattern, protocol, mission, asset_id, score, score_factors,
rationale, consumed_by_scan_id) packed into ``tool_input`` JSON.

A precomputed ``dedup_key`` of
``f"{asset_id}|{pattern}|{protocol}|{mission}"`` is also stored in
``tool_input`` so the coordinator's hot-path lookup is a cheap exact
match against ``tool_input->>'dedup_key'`` rather than four separate
JSON field comparisons.

The legacy table is left intact (no DROP) so a rollback can re-point
the read path back at it without data loss. A future migration can
drop it once we've confirmed the unified path is stable in prod.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _table_exists(conn, table: str) -> bool:
    return table in inspect(conn).get_table_names()


def _column_exists(conn, table: str, column: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column}).fetchone()
        return row is not None
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == column for r in rows)


def _index_exists(conn, name: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM pg_indexes WHERE indexname = :n"
        ), {"n": name}).fetchone()
        return row is not None
    rows = conn.execute(text(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = :n"
    ), {"n": name}).fetchall()
    return bool(rows)


def upgrade():
    with engine.begin() as conn:
        if not _table_exists(conn, "agent_approvals"):
            print("[!] agent_approvals missing — coordinator fold aborted")
            return

        # ── 1. agent_approvals.dedup_key ─────────────────────────────
        # Stable external id used to dedup approvals from the same source
        # entity. Coordinator approvals encode the (asset, pattern,
        # protocol, mission) tuple here so lookup is an indexed exact
        # match. NULL for sources that don't need it (paused agent runs).
        if not _column_exists(conn, "agent_approvals", "dedup_key"):
            conn.execute(text(
                "ALTER TABLE agent_approvals ADD COLUMN dedup_key VARCHAR(255)"
            ))
            print("[+] agent_approvals.dedup_key added")
        if not _index_exists(conn, "ix_agent_approvals_dedup_key"):
            conn.execute(text(
                "CREATE INDEX ix_agent_approvals_dedup_key "
                "ON agent_approvals (dedup_key)"
            ))
            print("[+] ix_agent_approvals_dedup_key created")

        if not _table_exists(conn, "coordinator_pending_approvals"):
            print("[i] coordinator_pending_approvals not present — column added, no rows to fold")
            return

        # Skip rows that have already been folded. We mark folded rows by
        # writing source='coordinator' AND tool_input->>'legacy_id'=<old.id>
        # so re-running the migration is a no-op.
        if _is_pg:
            # tool_input is a `json` column (not `jsonb`), so the `?` key-existence
            # operator isn't defined on it — cast before checking.
            existing_ids = {
                int(r[0]) for r in conn.execute(text("""
                    SELECT (tool_input->>'legacy_id')::int
                    FROM agent_approvals
                    WHERE source = 'coordinator'
                      AND tool_input::jsonb ? 'legacy_id'
                """)).fetchall() if r[0] is not None
            }
        else:
            existing_ids = set()

        rows = conn.execute(text("""
            SELECT id, org_id, asset_id, pattern, protocol, mission,
                   rationale, score, score_factors, status,
                   decided_by, decided_at, consumed_by_scan_id,
                   created_at, last_seen_at
              FROM coordinator_pending_approvals
        """)).fetchall()

        moved = 0
        for r in rows:
            (legacy_id, org_id, asset_id, pattern, protocol, mission,
             rationale, score, score_factors, status,
             decided_by, decided_at, consumed_by_scan_id,
             created_at, last_seen_at) = r
            if legacy_id in existing_ids:
                continue
            # Build tool_input payload that mirrors the legacy columns
            # plus a dedup_key for fast hot-path lookup. JSON keyed on
            # the same tuple the legacy unique index used.
            import json as _json
            dedup_key = f"{asset_id or ''}|{pattern}|{protocol}|{mission}"
            tool_input = {
                "legacy_id": legacy_id,
                "dedup_key": dedup_key,
                "asset_id": asset_id,
                "pattern": pattern,
                "protocol": protocol,
                "mission": mission,
                "rationale": rationale,
                "score": float(score) if score is not None else 0.0,
                "score_factors": (
                    score_factors if isinstance(score_factors, dict)
                    else (_json.loads(score_factors) if score_factors else {})
                ),
                "consumed_by_scan_id": consumed_by_scan_id,
                "last_seen_at": last_seen_at.isoformat() if last_seen_at else None,
            }
            conn.execute(
                text("""
                    INSERT INTO agent_approvals (
                        org_id, agent_id, agent_run_id, source,
                        tool_name, tool_input,
                        messages_snapshot, assistant_content,
                        provider, model_name, current_step, tool_use_id,
                        status, requested_at, decided_at, decided_by,
                        rejection_reason, dedup_key
                    ) VALUES (
                        :org_id, NULL, NULL, 'coordinator',
                        'dispatch_chain_hypothesis', CAST(:tool_input AS json),
                        CAST('[]' AS json), CAST('[]' AS json),
                        NULL, NULL, 0, NULL,
                        :status, :requested_at, :decided_at, NULL,
                        NULL, :dedup_key
                    )
                """),
                {
                    "org_id": org_id,
                    "tool_input": _json.dumps(tool_input),
                    "status": status,
                    "requested_at": created_at,
                    "decided_at": decided_at,
                    "dedup_key": dedup_key,
                },
            )
            moved += 1

        print(f"[+] folded {moved} coordinator approvals into agent_approvals "
              f"(skipped {len(rows) - moved} already-folded)")


def downgrade():
    """Remove folded coordinator rows from ``agent_approvals``. Legacy
    table is untouched so the data is preserved there.
    """
    with engine.begin() as conn:
        if not _table_exists(conn, "agent_approvals"):
            return
        result = conn.execute(text("""
            DELETE FROM agent_approvals
            WHERE source = 'coordinator'
        """))
        print(f"Migration 068 reverted: removed {result.rowcount} folded rows")


if __name__ == "__main__":
    print("Running migration: 068_fold_coordinator_approvals")
    upgrade()
    print("Done.")
