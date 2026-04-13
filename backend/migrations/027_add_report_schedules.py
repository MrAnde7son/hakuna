"""
Migration: Add report_schedules table.

Enables scheduling automated PDF delivery of saved report templates by email
on a daily/weekly/monthly or cron-based cadence.

Usage:
    cd backend
    python migrations/027_add_report_schedules.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine

_is_pg = "postgresql" in str(engine.url)
_PK = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"


def upgrade():
    with engine.connect() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS report_schedules (
                id {_PK},
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                report_template_id INTEGER NOT NULL REFERENCES report_templates(id) ON DELETE CASCADE,
                name VARCHAR,
                recipients TEXT NOT NULL,
                subject_template VARCHAR,
                body_template TEXT,
                format VARCHAR DEFAULT 'pdf',
                frequency VARCHAR DEFAULT 'weekly',
                day_of_week INTEGER,
                day_of_month INTEGER,
                hour INTEGER DEFAULT 8,
                minute INTEGER DEFAULT 0,
                cron_expression VARCHAR,
                timezone VARCHAR DEFAULT 'UTC',
                is_enabled BOOLEAN DEFAULT TRUE,
                last_run_at TIMESTAMP,
                last_status VARCHAR,
                last_error TEXT,
                next_run_at TIMESTAMP,
                created_by VARCHAR,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_report_schedules_org
            ON report_schedules (org_id)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_report_schedules_template
            ON report_schedules (report_template_id)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_report_schedules_enabled_next
            ON report_schedules (is_enabled, next_run_at)
        """))
        conn.commit()
        print("Migration 027: report_schedules created successfully")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS report_schedules"))
        conn.commit()
        print("Migration 027: report_schedules dropped")


if __name__ == "__main__":
    upgrade()
