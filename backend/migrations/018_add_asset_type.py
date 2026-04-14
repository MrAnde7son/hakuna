"""
Migration: Add asset_type, asset_identity, asset_attributes columns to assets table.

Enables multi-type asset model: hosts, web apps, cloud instances, APIs, identities,
containers, code repos, k8s workloads, and user-defined custom types.

Safe to run multiple times (checks for column existence before adding).

Usage:
    cd backend
    python migrations/018_add_asset_type.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine, DATABASE_URL


def _column_exists(conn, table: str, column: str) -> bool:
    insp = inspect(conn)
    columns = [c["name"] for c in insp.get_columns(table)]
    return column in columns


def upgrade():
    with engine.connect() as conn:
        if not _column_exists(conn, "assets", "asset_type"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN asset_type VARCHAR DEFAULT 'host'"))
        if not _column_exists(conn, "assets", "asset_identity"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN asset_identity TEXT"))  # JSON stored as TEXT in SQLite
        if not _column_exists(conn, "assets", "asset_attributes"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN asset_attributes TEXT"))  # JSON stored as TEXT in SQLite

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_assets_asset_type
            ON assets(asset_type)
        """))

        # Backfill existing rows as host type
        conn.execute(text("UPDATE assets SET asset_type = 'host' WHERE asset_type IS NULL"))

        # Backfill asset_identity from existing IP/hostname/fqdn for host assets
        if DATABASE_URL.startswith("postgresql"):
            conn.execute(text("""
                UPDATE assets
                SET asset_identity = jsonb_build_object(
                    'ip', COALESCE(ip, ''),
                    'hostname', COALESCE(hostname, ''),
                    'fqdn', COALESCE(fqdn, '')
                )::json
                WHERE asset_identity IS NULL
            """))
        else:
            conn.execute(text("""
                UPDATE assets
                SET asset_identity = json_object(
                    'ip', COALESCE(ip, ''),
                    'hostname', COALESCE(hostname, ''),
                    'fqdn', COALESCE(fqdn, '')
                )
                WHERE asset_identity IS NULL
            """))

        conn.commit()
        print("Migration complete: asset_type, asset_identity, asset_attributes columns added to assets.")


def downgrade():
    print("SQLite does not support DROP COLUMN. To downgrade, recreate the table without these columns.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--downgrade", action="store_true")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    else:
        upgrade()
