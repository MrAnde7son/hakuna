"""
Migration: Add org_invites table for self-serve MSSP client onboarding.

Creates the org_invites table which stores tokenized invite links that
MSSP admins can send to prospective client organizations.

Safe to run multiple times (checks for table existence before creating).
Works with both SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/008_add_org_invites.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine


def _table_exists(conn, table: str) -> bool:
    insp = inspect(conn)
    return table in insp.get_table_names()


def upgrade():
    with engine.connect() as conn:
        if not _table_exists(conn, "org_invites"):
            conn.execute(text("""
                CREATE TABLE org_invites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token VARCHAR NOT NULL UNIQUE,
                    mssp_org_id INTEGER NOT NULL REFERENCES organizations(id),
                    invited_email VARCHAR,
                    client_org_name VARCHAR,
                    expires_at DATETIME NOT NULL,
                    accepted_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text("CREATE UNIQUE INDEX ix_org_invites_token ON org_invites (token)"))
            conn.execute(text("CREATE INDEX ix_org_invites_mssp_org ON org_invites (mssp_org_id)"))
            conn.commit()
            print("Created org_invites table.")
        else:
            print("org_invites table already exists, skipping.")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS org_invites"))
        conn.commit()
        print("Dropped org_invites table.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--downgrade", action="store_true")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    else:
        upgrade()
