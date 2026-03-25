"""
Migration: Add startup_type and run_as_user columns to inventory_services.

These fields are populated from Nessus plugin 44401 (Service Configuration
Details) and complement the running-service list from plugin 10456.

Safe to run multiple times. Works with SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/009_add_service_startup_user.py
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
        if not _col_exists(conn, "inventory_services", "startup_type"):
            conn.execute(text("ALTER TABLE inventory_services ADD COLUMN startup_type VARCHAR"))
            print("Added startup_type column.")
        else:
            print("startup_type already exists, skipping.")

        if not _col_exists(conn, "inventory_services", "run_as_user"):
            conn.execute(text("ALTER TABLE inventory_services ADD COLUMN run_as_user VARCHAR"))
            print("Added run_as_user column.")
        else:
            print("run_as_user already exists, skipping.")

        conn.commit()


def downgrade():
    # SQLite does not support DROP COLUMN before 3.35; skip for SQLite
    db_url = str(engine.url)
    if "sqlite" in db_url:
        print("SQLite does not support DROP COLUMN — skipping downgrade.")
        return
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE inventory_services DROP COLUMN IF EXISTS startup_type"))
        conn.execute(text("ALTER TABLE inventory_services DROP COLUMN IF EXISTS run_as_user"))
        conn.commit()
        print("Dropped startup_type and run_as_user columns.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--downgrade", action="store_true")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    else:
        upgrade()
