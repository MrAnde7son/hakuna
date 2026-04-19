"""Add auth_profiles table for authenticated VM scans.

Stores a web-app login flow (URL, step sequence, success condition) and
references an integration_credentials row for the actual secrets. The
cached_session_blob column holds an AES-256-GCM encrypted cookie+header
bundle produced by services.session_broker; session_credential_hash
auto-invalidates the cache when the underlying credential is rotated.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _sqlite_has_column(conn, table: str, column: str) -> bool:
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == column for r in rows)


def _ensure_profile_type(conn):
    """Idempotently add profile_type + relax form_login fields to nullable.

    Needed for dev databases that ran an earlier revision of this migration
    (pre-profile_type). Postgres supports ADD COLUMN IF NOT EXISTS natively;
    for SQLite we probe PRAGMA first. Relaxing NOT NULL on existing SQLite
    columns requires a table rebuild — we skip that here since the columns
    were nullable from rev 1 of this migration for everyone except the
    tiny window where the initial draft enforced NOT NULL.
    """
    if _is_pg:
        conn.execute(text("ALTER TABLE auth_profiles ADD COLUMN IF NOT EXISTS profile_type VARCHAR NOT NULL DEFAULT 'form_login'"))
        conn.execute(text("ALTER TABLE auth_profiles ALTER COLUMN login_url DROP NOT NULL"))
        conn.execute(text("ALTER TABLE auth_profiles ALTER COLUMN login_flow DROP NOT NULL"))
        conn.execute(text("ALTER TABLE auth_profiles ALTER COLUMN success_condition DROP NOT NULL"))
    else:
        if not _sqlite_has_column(conn, "auth_profiles", "profile_type"):
            conn.execute(text("ALTER TABLE auth_profiles ADD COLUMN profile_type VARCHAR NOT NULL DEFAULT 'form_login'"))


def upgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS auth_profiles (
                    id VARCHAR PRIMARY KEY,
                    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    name VARCHAR NOT NULL,
                    profile_type VARCHAR NOT NULL DEFAULT 'form_login',
                    credential_id VARCHAR NOT NULL REFERENCES integration_credentials(id),
                    login_url VARCHAR,
                    login_flow JSONB DEFAULT '[]'::jsonb,
                    success_condition JSONB DEFAULT '{}'::jsonb,
                    session_ttl_seconds INTEGER NOT NULL DEFAULT 900,
                    cached_session_blob TEXT,
                    session_expires_at TIMESTAMP,
                    session_credential_hash VARCHAR,
                    created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW(),
                    CONSTRAINT uq_auth_profile_org_name UNIQUE (org_id, name)
                )
            """))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_auth_profiles_org_id ON auth_profiles (org_id)"
            ))
            _ensure_profile_type(conn)
        else:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS auth_profiles (
                    id VARCHAR PRIMARY KEY,
                    org_id INTEGER NOT NULL,
                    name VARCHAR NOT NULL,
                    profile_type VARCHAR NOT NULL DEFAULT 'form_login',
                    credential_id VARCHAR NOT NULL,
                    login_url VARCHAR,
                    login_flow JSON DEFAULT '[]',
                    success_condition JSON DEFAULT '{}',
                    session_ttl_seconds INTEGER NOT NULL DEFAULT 900,
                    cached_session_blob TEXT,
                    session_expires_at TIMESTAMP,
                    session_credential_hash VARCHAR,
                    created_by_user_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_auth_profile_org_name UNIQUE (org_id, name)
                )
            """))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_auth_profiles_org_id ON auth_profiles (org_id)"
            ))
            _ensure_profile_type(conn)

    print("Migration 042: auth_profiles table created.")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS auth_profiles"))
    print("Migration 042: auth_profiles table dropped.")


if __name__ == "__main__":
    upgrade()
