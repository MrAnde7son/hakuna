"""
Migration: Add last_enriched and last_js_fingerprinted columns to assets.

These timestamps track when EASM enrichment and JS fingerprinting last ran
for each asset, so the scanner can skip recently-processed assets.

Usage:
    cd backend
    python migrations/027_add_asset_enrichment_columns.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine


def _column_exists(conn, table, column):
    """Check whether a column already exists (works for both SQLite and PG)."""
    if "postgresql" in str(engine.url):
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column}).fetchone()
    else:
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
        row = next((r for r in rows if r[1] == column), None)
    return row is not None


def upgrade():
    with engine.connect() as conn:
        for col in ("last_enriched", "last_js_fingerprinted"):
            if not _column_exists(conn, "assets", col):
                col_type = "TIMESTAMP" if "postgresql" in str(engine.url) else "DATETIME"
                conn.execute(text(f"ALTER TABLE assets ADD COLUMN {col} {col_type}"))
        conn.commit()


def downgrade():
    if "postgresql" in str(engine.url):
        with engine.connect() as conn:
            for col in ("last_enriched", "last_js_fingerprinted"):
                if _column_exists(conn, "assets", col):
                    conn.execute(text(f"ALTER TABLE assets DROP COLUMN {col}"))
            conn.commit()
    else:
        print("SQLite does not support DROP COLUMN easily — skipping downgrade.")


if __name__ == "__main__":
    upgrade()
    print("027 — added last_enriched + last_js_fingerprinted to assets.")
