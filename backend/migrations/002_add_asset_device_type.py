"""
Migration: Add device_type, cpe, and os_confidence columns to assets table.

These columns are populated by Nessus plugins 11936 (OS Identification)
and 45590 (Common Platform Enumeration) during scan upload.

Safe to run multiple times (checks for column existence before adding).

Usage:
    cd backend
    python migrations/002_add_asset_device_type.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine


def _column_exists(conn, table: str, column: str) -> bool:
    insp = inspect(conn)
    columns = [c["name"] for c in insp.get_columns(table)]
    return column in columns


def upgrade():
    with engine.connect() as conn:
        if not _column_exists(conn, "assets", "device_type"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN device_type VARCHAR"))
        if not _column_exists(conn, "assets", "cpe"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN cpe TEXT"))  # JSON stored as TEXT in SQLite
        if not _column_exists(conn, "assets", "os_confidence"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN os_confidence INTEGER"))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_assets_device_type
            ON assets(device_type)
        """))

        conn.commit()
        print("Migration complete: device_type, cpe, os_confidence columns added to assets.")


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
