"""Migration: Add knowledge graph support.

Adds `weight` and `properties` columns to `asset_relationships` and creates the
`asset_clusters` table used for infrastructure clustering (shared certs, JARM,
IP ranges, tech stacks).

Safe to run multiple times. Works with both SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/034_knowledge_graph.py
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


def upgrade():
    with engine.begin() as conn:
        # asset_relationships: weight + properties
        if _table_exists(conn, "asset_relationships"):
            if not _column_exists(conn, "asset_relationships", "weight"):
                conn.execute(text(
                    "ALTER TABLE asset_relationships ADD COLUMN weight FLOAT DEFAULT 1.0"
                ))
                print("[+] Added asset_relationships.weight")
            if not _column_exists(conn, "asset_relationships", "properties"):
                json_type = "JSONB" if _is_pg else "JSON"
                default = "'{}'::jsonb" if _is_pg else "'{}'"
                conn.execute(text(
                    f"ALTER TABLE asset_relationships ADD COLUMN properties {json_type} DEFAULT {default}"
                ))
                print("[+] Added asset_relationships.properties")

        # asset_clusters table
        if not _table_exists(conn, "asset_clusters"):
            if _is_pg:
                conn.execute(text("""
                    CREATE TABLE asset_clusters (
                        id SERIAL PRIMARY KEY,
                        org_id INTEGER NOT NULL REFERENCES organizations(id),
                        cluster_type VARCHAR NOT NULL,
                        label VARCHAR,
                        pivot_value VARCHAR,
                        asset_ids JSONB DEFAULT '[]'::jsonb,
                        asset_count INTEGER DEFAULT 0,
                        cluster_metadata JSONB DEFAULT '{}'::jsonb,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            else:
                conn.execute(text("""
                    CREATE TABLE asset_clusters (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        org_id INTEGER NOT NULL REFERENCES organizations(id),
                        cluster_type VARCHAR NOT NULL,
                        label VARCHAR,
                        pivot_value VARCHAR,
                        asset_ids JSON DEFAULT '[]',
                        asset_count INTEGER DEFAULT 0,
                        cluster_metadata JSON DEFAULT '{}',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_asset_cluster_org ON asset_clusters(org_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_asset_cluster_type ON asset_clusters(org_id, cluster_type)"
            ))
            print("[+] Created asset_clusters table")
        else:
            print("[=] asset_clusters table already exists")


def downgrade():
    with engine.begin() as conn:
        if _table_exists(conn, "asset_clusters"):
            conn.execute(text("DROP TABLE asset_clusters"))
        if _is_pg:
            for col in ("weight", "properties"):
                if _column_exists(conn, "asset_relationships", col):
                    conn.execute(text(f"ALTER TABLE asset_relationships DROP COLUMN {col}"))
        else:
            print("SQLite does not support DROP COLUMN easily — skipping column drops.")


if __name__ == "__main__":
    print("Running migration: 034_knowledge_graph")
    upgrade()
    print("Done.")
