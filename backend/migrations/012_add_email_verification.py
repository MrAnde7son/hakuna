"""
Migration: Add email verification columns to users.

Tracks whether a user has verified their email address.
Safe to run multiple times. Works with SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/012_add_email_verification.py
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
        if not _col_exists(conn, "users", "email_verified"):
            conn.execute(text("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE"))
            # Existing users are considered verified (they registered before this feature)
            conn.execute(text("UPDATE users SET email_verified = TRUE"))
            # Google OAuth users are always verified
            conn.execute(text("UPDATE users SET email_verified = TRUE WHERE google_id IS NOT NULL"))
            print("Added email_verified column (existing users set to verified).")
        else:
            print("email_verified already exists, skipping.")

        if not _col_exists(conn, "users", "email_verify_token"):
            conn.execute(text("ALTER TABLE users ADD COLUMN email_verify_token VARCHAR"))
            print("Added email_verify_token column.")
        else:
            print("email_verify_token already exists, skipping.")

        if not _col_exists(conn, "users", "email_verify_expires"):
            conn.execute(text("ALTER TABLE users ADD COLUMN email_verify_expires TIMESTAMP"))
            print("Added email_verify_expires column.")
        else:
            print("email_verify_expires already exists, skipping.")

        conn.commit()


def downgrade():
    db_url = str(engine.url)
    if "sqlite" in db_url:
        print("SQLite does not support DROP COLUMN — skipping downgrade.")
        return
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS email_verified"))
        conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS email_verify_token"))
        conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS email_verify_expires"))
        conn.commit()


if __name__ == "__main__":
    upgrade()
    print("Done.")
