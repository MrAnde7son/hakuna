"""
Migration: Add relay agents for on-prem integration connectivity.

- Creates relay_agents table
- Adds relay_agent_id column to integrations table

Safe to run multiple times (checks for table/column existence before adding).
Works with both SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/018_add_relay_agents.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _table_exists(conn, table: str) -> bool:
    insp = inspect(conn)
    return table in insp.get_table_names()


def _column_exists(conn, table: str, column: str) -> bool:
    insp = inspect(conn)
    cols = [c["name"] for c in insp.get_columns(table)]
    return column in cols


def upgrade():
    with engine.begin() as conn:
        # Create relay_agents table
        if not _table_exists(conn, "relay_agents"):
            conn.execute(text("""
                CREATE TABLE relay_agents (
                    id TEXT PRIMARY KEY,
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    token_prefix TEXT,
                    status TEXT DEFAULT 'disconnected',
                    last_seen_at TIMESTAMP,
                    agent_version TEXT,
                    ip_address TEXT,
                    allowed_hosts JSON DEFAULT '[]',
                    credentials_mode TEXT DEFAULT 'agent_local',
                    labels JSON DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by TEXT
                )
            """))
            conn.execute(text("CREATE INDEX ix_relay_agents_org_id ON relay_agents(org_id)"))
            print("[+] Created relay_agents table")
        else:
            print("[=] relay_agents table already exists")

        # Add relay_agent_id to integrations
        if _table_exists(conn, "integrations"):
            if not _column_exists(conn, "integrations", "relay_agent_id"):
                conn.execute(text(
                    "ALTER TABLE integrations ADD COLUMN relay_agent_id TEXT REFERENCES relay_agents(id)"
                ))
                print("[+] Added relay_agent_id to integrations")
            else:
                print("[=] integrations.relay_agent_id already exists")


def downgrade():
    with engine.begin() as conn:
        # Remove relay_agent_id from integrations
        if _is_pg and _table_exists(conn, "integrations"):
            if _column_exists(conn, "integrations", "relay_agent_id"):
                conn.execute(text("ALTER TABLE integrations DROP COLUMN relay_agent_id"))
                print("[-] Dropped relay_agent_id from integrations")

        # Drop relay_agents table
        if _table_exists(conn, "relay_agents"):
            conn.execute(text("DROP TABLE relay_agents"))
            print("[-] Dropped relay_agents table")


if __name__ == "__main__":
    print("Running migration: 018_add_relay_agents")
    upgrade()
    print("Done.")
