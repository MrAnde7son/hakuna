"""
Migration: Add siem_events table.

Hot-tier storage for SIEM events (last 72h in Postgres). Supports dedup
by org_id + dedup_hash, composite index for time-range queries.

Usage:
    cd backend
    python migrations/028_add_siem_events.py
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
            CREATE TABLE IF NOT EXISTS siem_events (
                id {_PK},
                org_id INTEGER NOT NULL REFERENCES organizations(id),
                event_time TIMESTAMP NOT NULL,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                source_system VARCHAR NOT NULL,
                source_id VARCHAR,
                event_type VARCHAR NOT NULL,
                event_category VARCHAR,
                severity VARCHAR DEFAULT 'info',
                action VARCHAR,
                outcome VARCHAR,
                asset_id INTEGER REFERENCES assets(id),
                user_name VARCHAR,
                source_ip VARCHAR,
                dest_ip VARCHAR,
                host_name VARCHAR,
                message TEXT,
                raw JSON,
                normalized JSON,
                dedup_hash VARCHAR NOT NULL,
                integration_id VARCHAR REFERENCES integrations(id),
                UNIQUE (org_id, dedup_hash)
            )
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_siem_events_org
            ON siem_events (org_id)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_siem_events_event_time
            ON siem_events (event_time)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_siem_events_source_system
            ON siem_events (source_system)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_siem_events_event_type
            ON siem_events (event_type)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_siem_events_asset_id
            ON siem_events (asset_id)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_siem_events_dedup_hash
            ON siem_events (dedup_hash)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_siem_events_org_time
            ON siem_events (org_id, event_time DESC)
        """))
        conn.commit()
        print("Migration 028: siem_events created successfully")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS siem_events"))
        conn.commit()
        print("Migration 028: siem_events dropped")


if __name__ == "__main__":
    upgrade()
