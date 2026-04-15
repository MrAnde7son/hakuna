"""
Migration: Add ingest_endpoints table.

Token-authenticated push endpoints for SIEM event ingestion via HTTP,
HEC, or webhook with HMAC signature verification.

Usage:
    cd backend
    python migrations/029_add_ingest_endpoints.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine

_is_pg = "postgresql" in str(engine.url)
_PK = "VARCHAR PRIMARY KEY" if _is_pg else "VARCHAR PRIMARY KEY"


def upgrade():
    with engine.connect() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS ingest_endpoints (
                id {_PK},
                org_id INTEGER NOT NULL REFERENCES organizations(id),
                integration_id VARCHAR REFERENCES integrations(id),
                name VARCHAR NOT NULL,
                token_hash VARCHAR NOT NULL,
                token_prefix VARCHAR,
                hmac_secret_hash VARCHAR NOT NULL,
                parser_type VARCHAR NOT NULL DEFAULT 'json',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP,
                request_count INTEGER DEFAULT 0
            )
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_ingest_endpoints_org
            ON ingest_endpoints (org_id)
        """))
        conn.commit()
        print("Migration 029: ingest_endpoints created successfully")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS ingest_endpoints"))
        conn.commit()
        print("Migration 029: ingest_endpoints dropped")


if __name__ == "__main__":
    upgrade()
