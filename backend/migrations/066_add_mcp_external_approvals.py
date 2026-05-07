"""Support external (MCP) approval requests and 24h org-wide grants.

Two changes:

1. ``agent_approvals`` gets a ``source`` column ('internal_agent' default,
   'mcp_external' for calls coming through ``/api/mcp``). MCP rows have
   ``agent_id`` and ``agent_run_id`` NULL — there's no run behind them —
   so the legacy NOT NULL constraints on those columns are dropped.

2. New ``org_action_grants`` table backs the "Approve and auto-approve
   same tool for 24h" decision in the queue. One row per outstanding
   grant; expired rows are filtered at query time and reaped lazily.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _column_exists(conn, table: str, column: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column}).fetchone()
        return row is not None
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == column for r in rows)


def _table_exists(conn, table: str) -> bool:
    return table in inspect(conn).get_table_names()


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
        # ── 1. agent_approvals.source ────────────────────────────────
        if not _column_exists(conn, "agent_approvals", "source"):
            conn.execute(text(
                "ALTER TABLE agent_approvals ADD COLUMN source VARCHAR(32) "
                "DEFAULT 'internal_agent'"
            ))
            # Backfill explicit value for existing rows so the audit trail
            # doesn't silently rely on the column default.
            conn.execute(text(
                "UPDATE agent_approvals SET source = 'internal_agent' "
                "WHERE source IS NULL"
            ))
            print("[+] agent_approvals.source added")

        # Drop NOT NULL on agent_id / agent_run_id so external MCP rows
        # (no agent, no run) can land. SQLite has no DROP NOT NULL — for
        # the test-suite SQLite path we tolerate the existing constraint
        # because conftest creates the table from the (updated) ORM model
        # which already declares them nullable.
        if _is_pg:
            conn.execute(text(
                "ALTER TABLE agent_approvals ALTER COLUMN agent_id DROP NOT NULL"
            ))
            conn.execute(text(
                "ALTER TABLE agent_approvals ALTER COLUMN agent_run_id DROP NOT NULL"
            ))
            print("[+] agent_approvals.agent_id / agent_run_id made nullable")

        # ── 2. org_action_grants table ───────────────────────────────
        if not _table_exists(conn, "org_action_grants"):
            if _is_pg:
                conn.execute(text("""
                    CREATE TABLE org_action_grants (
                        id SERIAL PRIMARY KEY,
                        org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        action_name VARCHAR(128) NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        granted_via_approval_id INTEGER REFERENCES agent_approvals(id) ON DELETE SET NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            else:
                conn.execute(text("""
                    CREATE TABLE org_action_grants (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        action_name VARCHAR(128) NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        granted_via_approval_id INTEGER REFERENCES agent_approvals(id) ON DELETE SET NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            print("[+] org_action_grants table created")

        for idx, cols in [
            ("ix_org_action_grants_org_id", "org_id"),
            ("ix_org_action_grants_lookup", "org_id, action_name, expires_at"),
        ]:
            if not _index_exists(conn, idx):
                conn.execute(text(f"CREATE INDEX {idx} ON org_action_grants ({cols})"))
                print(f"[+] {idx} created")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_org_action_grants_lookup"))
        conn.execute(text("DROP INDEX IF EXISTS ix_org_action_grants_org_id"))
        conn.execute(text("DROP TABLE IF EXISTS org_action_grants"))
        if _is_pg:
            conn.execute(text(
                "ALTER TABLE agent_approvals DROP COLUMN IF EXISTS source"
            ))
        print("Migration 066: reverted.")


if __name__ == "__main__":
    print("Running migration: 066_add_mcp_external_approvals")
    upgrade()
    print("Done.")
