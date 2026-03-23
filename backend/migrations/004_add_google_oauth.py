"""
Migration: Add Google OAuth support to users table.

- Adds google_id column (unique, indexed) for linking Google accounts
- Makes hashed_password nullable (Google-only users have no password)

Safe to run multiple times (checks for column existence before adding).
Works with both SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/004_add_google_oauth.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _column_exists(conn, table: str, column: str) -> bool:
    insp = inspect(conn)
    columns = [c["name"] for c in insp.get_columns(table)]
    return column in columns


def upgrade():
    with engine.connect() as conn:
        # Add google_id column
        if not _column_exists(conn, "users", "google_id"):
            conn.execute(text("ALTER TABLE users ADD COLUMN google_id VARCHAR"))
            print("Added google_id column to users table.")

            # Create unique index on google_id
            if _is_pg:
                conn.execute(text(
                    "CREATE UNIQUE INDEX ix_users_google_id ON users (google_id) WHERE google_id IS NOT NULL"
                ))
            else:
                conn.execute(text(
                    "CREATE UNIQUE INDEX ix_users_google_id ON users (google_id)"
                ))
            print("Created unique index on users.google_id.")
        else:
            print("google_id column already exists, skipping.")

        # Make hashed_password nullable (PostgreSQL only — SQLite columns are already nullable)
        if _is_pg:
            conn.execute(text("ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL"))
            print("Made hashed_password nullable.")

        conn.commit()
        print("Migration complete: Google OAuth columns added.")


def downgrade():
    with engine.connect() as conn:
        if _is_pg:
            conn.execute(text("DROP INDEX IF EXISTS ix_users_google_id"))
            conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS google_id"))
            conn.execute(text("ALTER TABLE users ALTER COLUMN hashed_password SET NOT NULL"))
            conn.commit()
            print("Dropped google_id column and restored hashed_password NOT NULL.")
        else:
            conn.execute(text("DROP INDEX IF EXISTS ix_users_google_id"))
            conn.commit()
            print("Dropped google_id index. SQLite does not support DROP COLUMN.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--downgrade", action="store_true")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    else:
        upgrade()
