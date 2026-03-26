"""
Migration: Add AI token quota columns to organizations.

Tracks monthly token consumption for Pro plan limits.
Safe to run multiple times. Works with SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/011_add_ai_token_quota.py
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
        if not _col_exists(conn, "organizations", "ai_tokens_used"):
            conn.execute(text("ALTER TABLE organizations ADD COLUMN ai_tokens_used INTEGER DEFAULT 0"))
            print("Added ai_tokens_used column.")
        else:
            print("ai_tokens_used already exists, skipping.")

        if not _col_exists(conn, "organizations", "ai_tokens_reset_at"):
            conn.execute(text("ALTER TABLE organizations ADD COLUMN ai_tokens_reset_at DATETIME"))
            print("Added ai_tokens_reset_at column.")
        else:
            print("ai_tokens_reset_at already exists, skipping.")

        conn.commit()


def downgrade():
    db_url = str(engine.url)
    if "sqlite" in db_url:
        print("SQLite does not support DROP COLUMN — skipping downgrade.")
        return
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE organizations DROP COLUMN IF EXISTS ai_tokens_used"))
        conn.execute(text("ALTER TABLE organizations DROP COLUMN IF EXISTS ai_tokens_reset_at"))
        conn.commit()
        print("Dropped ai_tokens_used and ai_tokens_reset_at columns.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--downgrade", action="store_true")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    else:
        upgrade()
