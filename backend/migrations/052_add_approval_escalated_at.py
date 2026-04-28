"""Add escalated_at column to agent_approvals.

Tracks when a pending approval was escalated to an external channel
(Slack/email) so the periodic ``escalate_overdue_approvals`` job
doesn't double-send. NULL = never escalated; populated = sent at that
timestamp via the integration referenced in the notification metadata.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _column_exists(conn, table: str, column: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column}).fetchone()
        return row is not None
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == column for r in rows)


def upgrade():
    with engine.begin() as conn:
        if _column_exists(conn, "agent_approvals", "escalated_at"):
            print("Migration 052: escalated_at already present; nothing to do.")
            return
        conn.execute(text(
            "ALTER TABLE agent_approvals ADD COLUMN escalated_at TIMESTAMP NULL"
        ))
        print("[+] agent_approvals.escalated_at added")


def downgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("ALTER TABLE agent_approvals DROP COLUMN IF EXISTS escalated_at"))
        else:
            # SQLite can't drop columns easily; leave it.
            pass
        print("Migration 052: reverted.")


if __name__ == "__main__":
    upgrade()
