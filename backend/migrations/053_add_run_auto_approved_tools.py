"""Add auto_approved_tools column to agent_runs.

Stores tool names the user has bulk-approved for the remainder of a
single run (via "Approve all <tool> for this run" in the approval queue).
Future calls of these tools skip both the HITL gate and the per-call
NeedsApproval gate.
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
        if _column_exists(conn, "agent_runs", "auto_approved_tools"):
            print("Migration 053: auto_approved_tools already present; nothing to do.")
            return
        if _is_pg:
            conn.execute(text(
                "ALTER TABLE agent_runs ADD COLUMN auto_approved_tools JSONB DEFAULT '[]'::jsonb"
            ))
        else:
            conn.execute(text(
                "ALTER TABLE agent_runs ADD COLUMN auto_approved_tools JSON DEFAULT '[]'"
            ))
        print("[+] agent_runs.auto_approved_tools added")


def downgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("ALTER TABLE agent_runs DROP COLUMN IF EXISTS auto_approved_tools"))
        else:
            pass
        print("Migration 053: reverted.")


if __name__ == "__main__":
    upgrade()
