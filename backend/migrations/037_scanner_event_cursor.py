"""Create scanner_event_cursors table for the scanner → workflow event bridge."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def upgrade():
    """Create scanner_event_cursors table."""
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scanner_event_cursors (
                    id SERIAL PRIMARY KEY,
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    last_event_at TIMESTAMP,
                    last_event_id VARCHAR,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_scanner_event_cursor_org UNIQUE (org_id)
                )
            """))
        else:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scanner_event_cursors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER NOT NULL UNIQUE REFERENCES organizations(id),
                    last_event_at TIMESTAMP,
                    last_event_id VARCHAR,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scanner_event_cursors_org ON scanner_event_cursors(org_id)"))

    print("Migration 037: scanner_event_cursors table created.")


def downgrade():
    """Drop scanner_event_cursors table."""
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS scanner_event_cursors"))
    print("Migration 037: scanner_event_cursors table dropped.")


if __name__ == "__main__":
    upgrade()
