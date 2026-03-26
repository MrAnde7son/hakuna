"""
Migration: Add notification system tables.

Creates notifications, notification_reads, and user_page_visits tables.
Safe to run multiple times. Works with SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/013_add_notifications.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine

_is_pg = "postgresql" in str(engine.url)
_PK = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"


def _table_exists(conn, table: str) -> bool:
    insp = inspect(conn)
    return table in insp.get_table_names()


def upgrade():
    with engine.connect() as conn:
        if not _table_exists(conn, "notifications"):
            conn.execute(text(f"""
                CREATE TABLE notifications (
                    id {_PK},
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    category VARCHAR NOT NULL,
                    title VARCHAR NOT NULL,
                    body TEXT,
                    link VARCHAR,
                    entity_type VARCHAR,
                    entity_id INTEGER,
                    metadata JSON DEFAULT '{{}}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text("CREATE INDEX ix_notifications_org_created ON notifications(org_id, created_at)"))
            conn.execute(text("CREATE INDEX ix_notifications_category ON notifications(category)"))
            print("Created notifications table.")
        else:
            print("notifications table already exists, skipping.")

        if not _table_exists(conn, "notification_reads"):
            conn.execute(text(f"""
                CREATE TABLE notification_reads (
                    id {_PK},
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
                    read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, notification_id)
                )
            """))
            conn.execute(text("CREATE INDEX ix_notification_reads_user ON notification_reads(user_id)"))
            print("Created notification_reads table.")
        else:
            print("notification_reads table already exists, skipping.")

        if not _table_exists(conn, "user_page_visits"):
            conn.execute(text(f"""
                CREATE TABLE user_page_visits (
                    id {_PK},
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    page_key VARCHAR NOT NULL,
                    last_visited_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, page_key)
                )
            """))
            conn.execute(text("CREATE INDEX ix_user_page_visit_user ON user_page_visits(user_id)"))
            print("Created user_page_visits table.")
        else:
            print("user_page_visits table already exists, skipping.")

        conn.commit()


def downgrade():
    db_url = str(engine.url)
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS notification_reads"))
        conn.execute(text("DROP TABLE IF EXISTS notifications"))
        conn.execute(text("DROP TABLE IF EXISTS user_page_visits"))
        conn.commit()


if __name__ == "__main__":
    upgrade()
    print("Done.")
