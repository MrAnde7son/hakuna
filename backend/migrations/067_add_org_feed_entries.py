"""Org feed entries — agent-authored narrative stream per org.

Foundation for the "agent at the center of action" UX: every meaningful
system event (scan complete, asset created, validated chain emitted, …)
fires an agent that posts a narrative entry here. The user lands on a
feed and reads what the agents observed and did, instead of pulling a
dashboard.

Schema is intentionally conservative — one table, no joins required for
the feed list query (org_id + created_at index covers it). Proposed
actions live as JSONB so a single entry can carry multiple inline
approve/reject buttons that point into the existing agent_approvals
queue.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


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
        if not _table_exists(conn, "org_feed_entries"):
            if _is_pg:
                conn.execute(text("""
                    CREATE TABLE org_feed_entries (
                        id SERIAL PRIMARY KEY,
                        org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
                        agent_run_id INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
                        kind VARCHAR(32) NOT NULL,
                        headline VARCHAR(280) NOT NULL,
                        body_md TEXT,
                        event_type VARCHAR(64),
                        event_ref JSONB DEFAULT '{}'::jsonb,
                        proposed_actions JSONB DEFAULT '[]'::jsonb,
                        severity VARCHAR(16) DEFAULT 'info',
                        status VARCHAR(32) NOT NULL DEFAULT 'open',
                        read_by JSONB DEFAULT '[]'::jsonb,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            else:
                conn.execute(text("""
                    CREATE TABLE org_feed_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
                        agent_run_id INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
                        kind VARCHAR(32) NOT NULL,
                        headline VARCHAR(280) NOT NULL,
                        body_md TEXT,
                        event_type VARCHAR(64),
                        event_ref TEXT DEFAULT '{}',
                        proposed_actions TEXT DEFAULT '[]',
                        severity VARCHAR(16) DEFAULT 'info',
                        status VARCHAR(32) NOT NULL DEFAULT 'open',
                        read_by TEXT DEFAULT '[]',
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            print("[+] org_feed_entries table created")

        for idx, cols in [
            # Primary list query: feed for an org, newest first.
            ("ix_org_feed_entries_org_created", "org_id, created_at DESC"),
            # Status filter (open vs acted/dismissed) is the second axis the UI
            # filters on; co-locate with org for an org-scoped lookup.
            ("ix_org_feed_entries_org_status", "org_id, status"),
        ]:
            if not _index_exists(conn, idx):
                conn.execute(text(f"CREATE INDEX {idx} ON org_feed_entries ({cols})"))
                print(f"[+] {idx} created")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_org_feed_entries_org_status"))
        conn.execute(text("DROP INDEX IF EXISTS ix_org_feed_entries_org_created"))
        conn.execute(text("DROP TABLE IF EXISTS org_feed_entries"))
        print("Migration 067: reverted.")


if __name__ == "__main__":
    print("Running migration: 067_add_org_feed_entries")
    upgrade()
    print("Done.")
