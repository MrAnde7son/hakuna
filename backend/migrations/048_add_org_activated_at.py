"""Add organizations.activated_at — PLG activation milestone.

Set once per org by the scan ingest pipeline the first time a scan with
≥1 finding completes. Used to fire the `activated` PostHog event exactly
once per org and as the cohort anchor for retention/conversion analysis.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
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


def upgrade():
    with engine.begin() as conn:
        if not _column_exists(conn, "organizations", "activated_at"):
            conn.execute(text(
                "ALTER TABLE organizations ADD COLUMN activated_at TIMESTAMP NULL"
            ))
            print("[+] Added organizations.activated_at")
        else:
            print("Migration 048: organizations.activated_at already exists; nothing to do.")


def downgrade():
    if not _is_pg:
        print("Migration 048: SQLite downgrade skipped (DROP COLUMN requires 3.35+).")
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE organizations DROP COLUMN IF EXISTS activated_at"))
    print("Migration 048: organizations.activated_at dropped.")


if __name__ == "__main__":
    upgrade()
