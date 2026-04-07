"""
Migration: Add patch catalog tables (patch_advisories, patch_advisory_platforms)

Multi-source patch advisory aggregation for Linux distros, Apple, and third-party apps.
Extends existing MSRC patch coverage with Ubuntu USN, Debian DSA, RHEL RHSA,
Amazon ALAS, Apple security updates, Chrome, Firefox, and Adobe advisories.

Usage:
    cd backend
    python migrations/024_add_patch_catalog.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine

_is_pg = "postgresql" in str(engine.url)
_PK = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
_JSON = "JSONB" if _is_pg else "JSON"


def upgrade():
    with engine.connect() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS patch_advisories (
                id {_PK},
                source VARCHAR NOT NULL,
                source_advisory_id VARCHAR NOT NULL,
                title VARCHAR,
                description TEXT,
                severity VARCHAR,
                release_date VARCHAR,
                advisory_url VARCHAR,
                affected_packages {_JSON} DEFAULT '[]',
                cve_ids {_JSON} DEFAULT '[]',
                raw_data {_JSON},
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (source, source_advisory_id)
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_advisories_source
            ON patch_advisories (source)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_advisories_source_advisory_id
            ON patch_advisories (source_advisory_id)
        """))

        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS patch_advisory_platforms (
                id {_PK},
                advisory_id INTEGER NOT NULL REFERENCES patch_advisories(id) ON DELETE CASCADE,
                platform VARCHAR NOT NULL,
                architecture VARCHAR,
                product_name VARCHAR,
                product_version_min VARCHAR,
                product_version_max VARCHAR
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_advisory_platforms_advisory
            ON patch_advisory_platforms (advisory_id)
        """))

        conn.commit()
        print("Migration 024: patch_advisories + patch_advisory_platforms created successfully")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS patch_advisory_platforms"))
        conn.execute(text("DROP TABLE IF EXISTS patch_advisories"))
        conn.commit()
        print("Migration 024: patch catalog tables dropped")


if __name__ == "__main__":
    upgrade()
