"""
Migration: Add detection_rules and alerts tables.

Usage:
    cd backend
    python migrations/032_add_detection_rules_and_alerts.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine

_is_pg = "postgresql" in str(engine.url)
_PK = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"


def upgrade():
    with engine.connect() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS detection_rules (
                id {_PK},
                org_id INTEGER NOT NULL REFERENCES organizations(id),
                name VARCHAR NOT NULL,
                description TEXT,
                severity VARCHAR DEFAULT 'medium',
                enabled BOOLEAN DEFAULT TRUE,
                query JSON,
                window_seconds INTEGER DEFAULT 300,
                threshold INTEGER DEFAULT 1,
                group_by JSON,
                schedule_minutes INTEGER DEFAULT 5,
                mitre_techniques JSON,
                source VARCHAR DEFAULT 'manual',
                sigma_rule_id VARCHAR,
                last_run_at TIMESTAMP,
                last_alert_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_detection_rules_org ON detection_rules (org_id)"))

        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS alerts (
                id {_PK},
                org_id INTEGER NOT NULL REFERENCES organizations(id),
                rule_id INTEGER NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
                fired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                severity VARCHAR DEFAULT 'medium',
                status VARCHAR DEFAULT 'open',
                event_count INTEGER DEFAULT 0,
                group_key VARCHAR,
                first_event_id VARCHAR,
                last_event_id VARCHAR,
                context JSON,
                asset_id INTEGER REFERENCES assets(id),
                assigned_to INTEGER REFERENCES users(id),
                campaign_id INTEGER REFERENCES campaigns(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_org_status ON alerts (org_id, status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_rule ON alerts (rule_id)"))
        conn.commit()
        print("Migration 032: detection_rules + alerts created successfully")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alerts"))
        conn.execute(text("DROP TABLE IF EXISTS detection_rules"))
        conn.commit()
        print("Migration 032: detection_rules + alerts dropped")


if __name__ == "__main__":
    upgrade()
