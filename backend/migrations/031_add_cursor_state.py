"""
Migration: Add cursor_state column to integrations table.

Enables incremental sync by persisting the last-fetched position
(timestamp, offset, token) across pull integration runs.

Usage:
    cd backend
    python migrations/031_add_cursor_state.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine


def upgrade():
    insp = inspect(engine)
    existing = {c["name"] for c in insp.get_columns("integrations")}

    with engine.connect() as conn:
        if "cursor_state" not in existing:
            conn.execute(text("""
                ALTER TABLE integrations ADD COLUMN cursor_state JSON
            """))
        conn.commit()
        print("Migration 031: cursor_state column added to integrations")


def downgrade():
    print("Migration 031: downgrade is a no-op (SQLite cannot drop columns)")


if __name__ == "__main__":
    upgrade()
