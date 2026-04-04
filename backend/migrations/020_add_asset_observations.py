"""
Migration: Create asset_observations and finding_observations tables.

Stores per-source raw field snapshots so the UI can show what each
scanner/integration contributed to the merged asset or finding.

Safe to run multiple times (checks for table existence before creating).

Usage:
    cd backend
    python migrations/020_add_asset_observations.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine


def _table_exists(conn, table: str) -> bool:
    insp = inspect(conn)
    return table in insp.get_table_names()


def upgrade():
    with engine.connect() as conn:
        if not _table_exists(conn, "asset_observations"):
            conn.execute(text("""
                CREATE TABLE asset_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    source_system VARCHAR NOT NULL,
                    scan_id INTEGER REFERENCES scans(id),
                    org_id INTEGER REFERENCES organizations(id),
                    raw_fields TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    times_seen INTEGER DEFAULT 1,
                    UNIQUE(asset_id, source_system)
                )
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_asset_observations_asset_id
                ON asset_observations(asset_id)
            """))

        if not _table_exists(conn, "finding_observations"):
            conn.execute(text("""
                CREATE TABLE finding_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                    source_system VARCHAR NOT NULL,
                    scan_id INTEGER REFERENCES scans(id),
                    org_id INTEGER REFERENCES organizations(id),
                    raw_fields TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    times_seen INTEGER DEFAULT 1,
                    UNIQUE(finding_id, source_system)
                )
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_finding_observations_finding_id
                ON finding_observations(finding_id)
            """))

        conn.commit()
        print("Migration 020: asset_observations + finding_observations tables created.")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS finding_observations"))
        conn.execute(text("DROP TABLE IF EXISTS asset_observations"))
        conn.commit()
        print("Migration 020: observation tables dropped.")


if __name__ == "__main__":
    upgrade()
