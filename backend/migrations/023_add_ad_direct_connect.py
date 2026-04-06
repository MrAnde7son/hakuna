"""
Migration: Add columns for AD/LDAP direct-connect integration.

Extends inventory_users and inventory_groups with source tracking fields
for direct AD connector (not scanner-based). Also creates
identity_group_memberships join table.

Safe to run multiple times (checks for column/table existence).
Works with both SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/023_add_ad_direct_connect.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _table_exists(conn, table: str) -> bool:
    insp = inspect(conn)
    return table in insp.get_table_names()


def _column_exists(conn, table: str, column: str) -> bool:
    insp = inspect(conn)
    cols = [c["name"] for c in insp.get_columns(table)]
    return column in cols


def upgrade():
    with engine.begin() as conn:
        # --- inventory_users: new columns ---
        if _table_exists(conn, "inventory_users"):
            new_cols = {
                "is_locked": "BOOLEAN DEFAULT 0",
                "email": "VARCHAR",
                "upn": "VARCHAR",
                "source": "VARCHAR",
                "source_id": "VARCHAR",
                "org_id": "INTEGER",
                "last_synced_at": "TIMESTAMP" if _is_pg else "DATETIME",
                "password_age_days": "INTEGER",
                "last_logon_days_ago": "INTEGER",
            }
            for col_name, col_type in new_cols.items():
                if not _column_exists(conn, "inventory_users", col_name):
                    conn.execute(text(
                        f"ALTER TABLE inventory_users ADD COLUMN {col_name} {col_type}"
                    ))

            # Make scan_id and asset_id nullable (SQLite doesn't support ALTER COLUMN,
            # so we only do this on PostgreSQL)
            if _is_pg:
                conn.execute(text(
                    "ALTER TABLE inventory_users ALTER COLUMN scan_id DROP NOT NULL"
                ))
                conn.execute(text(
                    "ALTER TABLE inventory_users ALTER COLUMN asset_id DROP NOT NULL"
                ))

        # --- inventory_groups: new columns ---
        if _table_exists(conn, "inventory_groups"):
            new_cols = {
                "source": "VARCHAR",
                "source_id": "VARCHAR",
                "org_id": "INTEGER",
                "group_scope": "VARCHAR",
                "group_type": "VARCHAR",
                "member_count": "INTEGER",
                "last_synced_at": "TIMESTAMP" if _is_pg else "DATETIME",
            }
            for col_name, col_type in new_cols.items():
                if not _column_exists(conn, "inventory_groups", col_name):
                    conn.execute(text(
                        f"ALTER TABLE inventory_groups ADD COLUMN {col_name} {col_type}"
                    ))

            if _is_pg:
                conn.execute(text(
                    "ALTER TABLE inventory_groups ALTER COLUMN scan_id DROP NOT NULL"
                ))
                conn.execute(text(
                    "ALTER TABLE inventory_groups ALTER COLUMN asset_id DROP NOT NULL"
                ))

        # --- identity_group_memberships: new table ---
        if not _table_exists(conn, "identity_group_memberships"):
            auto_inc = "SERIAL" if _is_pg else "INTEGER"
            ts_type = "TIMESTAMP" if _is_pg else "DATETIME"
            pk_suffix = "" if _is_pg else " PRIMARY KEY AUTOINCREMENT"

            conn.execute(text(f"""
                CREATE TABLE identity_group_memberships (
                    id {auto_inc}{pk_suffix},
                    org_id INTEGER NOT NULL,
                    identity_source VARCHAR NOT NULL,
                    identity_source_id VARCHAR NOT NULL,
                    group_source VARCHAR NOT NULL,
                    group_source_id VARCHAR NOT NULL,
                    group_name VARCHAR,
                    synced_at {ts_type}
                    {"" if not _is_pg else ", PRIMARY KEY (id)"}
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_igm_org_id ON identity_group_memberships(org_id)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_igm_identity ON identity_group_memberships(identity_source, identity_source_id)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_igm_group ON identity_group_memberships(group_source, group_source_id)"
            ))

    print("Migration 023: AD direct-connect columns and tables applied.")


def downgrade():
    with engine.begin() as conn:
        if _table_exists(conn, "identity_group_memberships"):
            conn.execute(text("DROP TABLE identity_group_memberships"))

        # Note: SQLite does not support DROP COLUMN. On PostgreSQL, we could
        # remove the added columns, but it's safer to leave them in place.

    print("Migration 023: Rolled back identity_group_memberships table.")


if __name__ == "__main__":
    upgrade()
