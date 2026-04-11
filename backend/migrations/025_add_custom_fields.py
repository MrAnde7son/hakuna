"""
Migration: Add custom_field_definitions table and custom_fields JSON column
to assets and findings.

Enables per-org user-defined custom fields on Asset and Finding entities.
Values are resolved at ingest (mapping from source observation, formula
expression, or manual entry) and stored in a flat custom_fields JSON dict.

Usage:
    cd backend
    python migrations/025_add_custom_fields.py
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
            CREATE TABLE IF NOT EXISTS custom_field_definitions (
                id {_PK},
                org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                entity_type VARCHAR NOT NULL,
                key VARCHAR NOT NULL,
                label VARCHAR NOT NULL,
                description TEXT,
                data_type VARCHAR NOT NULL DEFAULT 'string',
                enum_values {_JSON},
                source_type VARCHAR NOT NULL DEFAULT 'manual',
                mapping_source VARCHAR,
                mapping_transform {_JSON},
                mapping_source_system VARCHAR,
                formula_expression TEXT,
                show_in_list BOOLEAN NOT NULL DEFAULT FALSE,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_by VARCHAR,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (org_id, entity_type, key)
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_custom_field_defs_org_entity
            ON custom_field_definitions (org_id, entity_type)
        """))

        # Add custom_fields JSON column to assets (if not exists)
        _add_json_column(conn, "assets", "custom_fields")
        _add_json_column(conn, "findings", "custom_fields")

        conn.commit()
        print("Migration 025: custom_field_definitions + assets.custom_fields + findings.custom_fields created successfully")


def _add_json_column(conn, table: str, column: str):
    """Add a JSON column if it doesn't already exist (portable between PG and SQLite)."""
    if _is_pg:
        conn.execute(text(f"""
            ALTER TABLE {table}
            ADD COLUMN IF NOT EXISTS {column} {_JSON} DEFAULT '{{}}'::jsonb
        """))
    else:
        # SQLite: no IF NOT EXISTS on ADD COLUMN. Probe PRAGMA first.
        existing = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
        if not any(row[1] == column for row in existing):
            conn.execute(text(f"""
                ALTER TABLE {table}
                ADD COLUMN {column} {_JSON} DEFAULT '{{}}'
            """))


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS custom_field_definitions"))
        if _is_pg:
            conn.execute(text("ALTER TABLE assets DROP COLUMN IF EXISTS custom_fields"))
            conn.execute(text("ALTER TABLE findings DROP COLUMN IF EXISTS custom_fields"))
        # SQLite can't drop columns cleanly without a table rebuild; leave in place on downgrade.
        conn.commit()
        print("Migration 025: custom_field_definitions dropped")


if __name__ == "__main__":
    upgrade()
