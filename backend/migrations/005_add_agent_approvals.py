"""
Migration: Add agent_approvals table for human-in-the-loop (HITL) approval system.

Creates the agent_approvals table that stores pending/decided approval requests
for write-tool calls made by agents running in HITL mode.

Usage:
    cd backend
    python migrations/005_add_agent_approvals.py
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
            CREATE TABLE IF NOT EXISTS agent_approvals (
                id {_PK},
                org_id INTEGER REFERENCES organizations(id),
                agent_run_id INTEGER NOT NULL REFERENCES agent_runs(id),
                agent_id INTEGER NOT NULL REFERENCES agents(id),

                tool_name VARCHAR NOT NULL,
                tool_input JSON,

                messages_snapshot JSON,
                assistant_content JSON,
                provider VARCHAR,
                model_name VARCHAR,
                current_step INTEGER DEFAULT 0,
                tool_use_id VARCHAR,

                status VARCHAR DEFAULT 'pending',
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                decided_at TIMESTAMP,
                decided_by INTEGER REFERENCES users(id),
                rejection_reason TEXT
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_agent_approvals_agent_run_id ON agent_approvals (agent_run_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_agent_approvals_agent_id ON agent_approvals (agent_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_agent_approvals_org_id ON agent_approvals (org_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_agent_approvals_status ON agent_approvals (status)"))
        conn.commit()
    print("✓ Created agent_approvals table")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS agent_approvals"))
        conn.commit()
    print("✓ Dropped agent_approvals table")


if __name__ == "__main__":
    upgrade()
