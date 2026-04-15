"""
Migration: Add suppression_rules table, extend alerts with exposure/suppression columns,
           extend detection_rules with asset_filter column.

Usage:
    cd backend
    python migrations/033_add_incidents_entities_suppression.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine

_is_pg = "postgresql" in str(engine.url)
_PK = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"


def upgrade():
    with engine.connect() as conn:

        # ── Suppression Rules ────────────────────────────
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS suppression_rules (
                id {_PK},
                org_id INTEGER NOT NULL REFERENCES organizations(id),
                name VARCHAR NOT NULL,
                description TEXT,
                conditions JSON,
                conditions_logic VARCHAR DEFAULT 'AND',
                rule_id INTEGER REFERENCES detection_rules(id),
                reason VARCHAR,
                enabled BOOLEAN DEFAULT TRUE,
                expires_at TIMESTAMP,
                created_by INTEGER REFERENCES users(id),
                suppressed_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_suppression_rules_org ON suppression_rules (org_id)"))

        # ── Extend alerts table ──────────────────────────
        alert_columns = [
            ("entity_type", "VARCHAR"),
            ("entity_value", "VARCHAR"),
            ("asset_criticality", "INTEGER"),
            ("open_vulnerabilities", "INTEGER"),
            ("internet_facing", "BOOLEAN"),
            ("exposure_context", "JSON"),
            ("suppressed", "BOOLEAN DEFAULT FALSE"),
            ("suppression_rule_id", "INTEGER REFERENCES suppression_rules(id)"),
            ("triage_reason", "VARCHAR"),
            ("notes", "TEXT"),
        ]
        for col_name, col_def in alert_columns:
            try:
                conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_def}"))
            except Exception:
                pass  # Column already exists

        # ── Extend detection_rules with asset_filter ─────
        try:
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN asset_filter JSON"))
        except Exception:
            pass

        conn.commit()
        print("Migration 033: suppression_rules created, alerts + detection_rules extended")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS suppression_rules"))
        conn.commit()
        print("Migration 033: suppression_rules dropped")


if __name__ == "__main__":
    upgrade()
