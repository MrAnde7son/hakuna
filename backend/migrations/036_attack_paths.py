"""Create attack_paths table for cross-finding correlation and attack chain visualization."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def upgrade():
    """Create attack_paths table."""
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS attack_paths (
                    id SERIAL PRIMARY KEY,
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    title VARCHAR(512) NOT NULL,
                    severity VARCHAR(32),
                    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
                    entry_asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                    target_asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                    chain_length INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS attack_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    title VARCHAR(512) NOT NULL,
                    severity VARCHAR(32),
                    steps JSON NOT NULL DEFAULT '[]',
                    entry_asset_id INTEGER REFERENCES assets(id),
                    target_asset_id INTEGER REFERENCES assets(id),
                    chain_length INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_attack_paths_org ON attack_paths(org_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_attack_paths_severity ON attack_paths(org_id, severity)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_attack_paths_entry ON attack_paths(entry_asset_id)"))

    print("Migration 036: Attack paths table created.")


def downgrade():
    """Drop attack_paths table."""
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS attack_paths"))
    print("Migration 036: Attack paths table dropped.")


if __name__ == "__main__":
    upgrade()
