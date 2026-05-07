"""Add `org_memory_facts` — org-scoped, agent-shared knowledge layer.

Distinct from per-agent scratchpad and Agent.memory: this captures HOW each
customer triages (priority rules, owner conventions, business context) so
every agent in the org benefits. Append-only — supersede via insertion of a
new row whose predecessor's `superseded_by` points at it.
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
        if not _table_exists(conn, "org_memory_facts"):
            json_type = "JSONB" if _is_pg else "JSON"
            if _is_pg:
                conn.execute(text(f"""
                    CREATE TABLE org_memory_facts (
                        id SERIAL PRIMARY KEY,
                        org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        namespace VARCHAR(64) NOT NULL,
                        key VARCHAR(255) NOT NULL,
                        value {json_type} NOT NULL,
                        confidence FLOAT NOT NULL DEFAULT 0.8,
                        source_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
                        source_run_id INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
                        evidence {json_type},
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        superseded_by INTEGER REFERENCES org_memory_facts(id) ON DELETE SET NULL
                    )
                """))
            else:
                conn.execute(text(f"""
                    CREATE TABLE org_memory_facts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        namespace VARCHAR(64) NOT NULL,
                        key VARCHAR(255) NOT NULL,
                        value {json_type} NOT NULL,
                        confidence FLOAT NOT NULL DEFAULT 0.8,
                        source_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
                        source_run_id INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
                        evidence {json_type},
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        superseded_by INTEGER REFERENCES org_memory_facts(id) ON DELETE SET NULL
                    )
                """))
            print("[+] org_memory_facts table created")

        for idx, cols in [
            ("ix_org_memory_org_id", "org_id"),
            ("ix_org_memory_org_namespace", "org_id, namespace"),
            ("ix_org_memory_key", "org_id, namespace, key"),
        ]:
            if not _index_exists(conn, idx):
                conn.execute(text(f"CREATE INDEX {idx} ON org_memory_facts ({cols})"))
                print(f"[+] {idx} created")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_org_memory_key"))
        conn.execute(text("DROP INDEX IF EXISTS ix_org_memory_org_namespace"))
        conn.execute(text("DROP INDEX IF EXISTS ix_org_memory_org_id"))
        conn.execute(text("DROP TABLE IF EXISTS org_memory_facts"))
        print("Migration 065: reverted.")


if __name__ == "__main__":
    print("Running migration: 065_add_org_memory")
    upgrade()
    print("Done.")
