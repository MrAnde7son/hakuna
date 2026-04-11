"""
Migration: Add patch reliability tracking (patch_reliability, patch_reliability_signals).

Layers reliability scoring onto the existing patch catalog (MSRCPatch +
PatchAdvisory) without modifying either. Keyed by (patch_source, patch_ref) so
a single reliability record works for Microsoft KBs, Ubuntu USNs, RHEL RHSAs,
Chrome/Firefox releases, etc.

The signals table is append-only — it's the audit trail behind each score and
lets the scorer be re-run with tuned weights without losing history.

Usage:
    cd backend
    python migrations/026_add_patch_reliability.py
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
            CREATE TABLE IF NOT EXISTS patch_reliability (
                id {_PK},
                patch_source VARCHAR NOT NULL,
                patch_ref VARCHAR NOT NULL,
                score FLOAT NOT NULL DEFAULT 1.0,
                status VARCHAR NOT NULL DEFAULT 'stable',
                recalled_at TIMESTAMP,
                recall_reason TEXT,
                known_issues {_JSON} DEFAULT '[]',
                factors {_JSON} DEFAULT '{{}}',
                signal_count INTEGER DEFAULT 0,
                last_signal_at TIMESTAMP,
                last_scored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (patch_source, patch_ref)
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_reliability_source
            ON patch_reliability (patch_source)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_reliability_ref
            ON patch_reliability (patch_ref)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_reliability_status
            ON patch_reliability (status)
        """))

        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS patch_reliability_signals (
                id {_PK},
                patch_source VARCHAR NOT NULL,
                patch_ref VARCHAR NOT NULL,
                signal_source VARCHAR NOT NULL,
                signal_type VARCHAR NOT NULL,
                weight FLOAT NOT NULL,
                org_id INTEGER,
                fingerprint VARCHAR,
                detail {_JSON},
                observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_reliability_signals_source
            ON patch_reliability_signals (patch_source)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_reliability_signals_ref
            ON patch_reliability_signals (patch_source, patch_ref)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_reliability_signals_observed
            ON patch_reliability_signals (observed_at)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_reliability_signals_org
            ON patch_reliability_signals (org_id)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_patch_reliability_signals_fingerprint
            ON patch_reliability_signals (fingerprint)
        """))

        conn.commit()
        print("Migration 026: patch_reliability + patch_reliability_signals created successfully")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS patch_reliability_signals"))
        conn.execute(text("DROP TABLE IF EXISTS patch_reliability"))
        conn.commit()
        print("Migration 026: patch reliability tables dropped")


if __name__ == "__main__":
    upgrade()
