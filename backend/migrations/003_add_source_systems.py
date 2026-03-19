"""
Migration: Add source_systems JSON column to assets and findings tables.

Tracks all data sources that contributed to each record (e.g. ["nessus", "easm"]).
Backfills existing records from source_type (findings) and scan source_type (assets).

Safe to run multiple times (checks for column existence before adding).
Works with both SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/003_add_source_systems.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _column_exists(conn, table: str, column: str) -> bool:
    insp = inspect(conn)
    columns = [c["name"] for c in insp.get_columns(table)]
    return column in columns


def upgrade():
    with engine.connect() as conn:
        # Add source_systems column to assets
        if not _column_exists(conn, "assets", "source_systems"):
            if _is_pg:
                conn.execute(text("ALTER TABLE assets ADD COLUMN source_systems JSONB DEFAULT '[]'"))
            else:
                conn.execute(text("ALTER TABLE assets ADD COLUMN source_systems TEXT DEFAULT '[]'"))
            print("Added source_systems column to assets table.")

        # Add source_systems column to findings
        if not _column_exists(conn, "findings", "source_systems"):
            if _is_pg:
                conn.execute(text("ALTER TABLE findings ADD COLUMN source_systems JSONB DEFAULT '[]'"))
            else:
                conn.execute(text("ALTER TABLE findings ADD COLUMN source_systems TEXT DEFAULT '[]'"))
            print("Added source_systems column to findings table.")

        # Backfill assets: derive from scan.source_type
        if _is_pg:
            conn.execute(text("""
                UPDATE assets
                SET source_systems = jsonb_build_array(COALESCE(
                    (SELECT s.source_type FROM scans s WHERE s.id = assets.scan_id),
                    'nessus'
                ))
                WHERE source_systems IS NULL OR source_systems = '[]'::jsonb
            """))
        else:
            conn.execute(text("""
                UPDATE assets
                SET source_systems = '["' || COALESCE(
                    (SELECT s.source_type FROM scans s WHERE s.id = assets.scan_id),
                    'nessus'
                ) || '"]'
                WHERE source_systems IS NULL OR source_systems = '[]'
            """))
        print("Backfilled assets.source_systems from scan.source_type.")

        # Backfill findings: derive from source_type column
        if _is_pg:
            conn.execute(text("""
                UPDATE findings
                SET source_systems = jsonb_build_array(COALESCE(source_type, 'nessus'))
                WHERE source_systems IS NULL OR source_systems = '[]'::jsonb
            """))
        else:
            conn.execute(text("""
                UPDATE findings
                SET source_systems = '["' || COALESCE(source_type, 'nessus') || '"]'
                WHERE source_systems IS NULL OR source_systems = '[]'
            """))
        print("Backfilled findings.source_systems from source_type.")

        conn.commit()
        print("Migration complete: source_systems columns added and backfilled.")


def downgrade():
    with engine.connect() as conn:
        if _is_pg:
            conn.execute(text("ALTER TABLE assets DROP COLUMN IF EXISTS source_systems"))
            conn.execute(text("ALTER TABLE findings DROP COLUMN IF EXISTS source_systems"))
            conn.commit()
            print("Dropped source_systems columns.")
        else:
            print("SQLite does not support DROP COLUMN. To downgrade, recreate the tables without source_systems.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--downgrade", action="store_true")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    else:
        upgrade()
