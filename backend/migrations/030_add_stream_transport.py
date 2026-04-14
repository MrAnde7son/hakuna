"""
Migration: Add stream_config column to integrations table.

Supports Vector.dev streaming transport for syslog, HEC, and file-tail
ingestion with VRL transforms.

Usage:
    cd backend
    python migrations/030_add_stream_transport.py
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
        if "stream_config" not in existing:
            conn.execute(text("""
                ALTER TABLE integrations ADD COLUMN stream_config JSON
            """))
        conn.commit()
        print("Migration 030: stream_config column added to integrations")


def downgrade():
    print("Migration 030: downgrade is a no-op (SQLite cannot drop columns)")


if __name__ == "__main__":
    upgrade()
