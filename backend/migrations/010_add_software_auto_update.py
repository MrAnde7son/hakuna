"""
Migration: Add auto_update_status column to inventory_software.

Stores whether a software product's auto-update mechanism is enabled,
disabled, or unknown — derived by correlating known updater services
(e.g. GoogleUpdaterService, wuauserv) with installed software.

Safe to run multiple times. Works with SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/010_add_software_auto_update.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine


def _col_exists(conn, table: str, col: str) -> bool:
    insp = inspect(conn)
    return col in {c["name"] for c in insp.get_columns(table)}


def upgrade():
    with engine.connect() as conn:
        if not _col_exists(conn, "inventory_software", "auto_update_status"):
            conn.execute(text("ALTER TABLE inventory_software ADD COLUMN auto_update_status VARCHAR"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_inventory_software_auto_update_status ON inventory_software (auto_update_status)"))
            print("Added auto_update_status column with index.")
        else:
            print("auto_update_status already exists, skipping.")

        conn.commit()


def downgrade():
    db_url = str(engine.url)
    if "sqlite" in db_url:
        print("SQLite does not support DROP COLUMN — skipping downgrade.")
        return
    with engine.connect() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_inventory_software_auto_update_status"))
        conn.execute(text("ALTER TABLE inventory_software DROP COLUMN IF EXISTS auto_update_status"))
        conn.commit()
        print("Dropped auto_update_status column and index.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--downgrade", action="store_true")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    else:
        upgrade()
