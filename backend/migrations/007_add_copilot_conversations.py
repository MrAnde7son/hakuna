"""
Migration: Add copilot_conversations table for the Security Copilot chat system.

Creates a table to store multi-turn conversations between users and the copilot agent.

Usage:
    cd backend
    python migrations/007_add_copilot_conversations.py
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
            CREATE TABLE IF NOT EXISTS copilot_conversations (
                id {_PK},
                org_id INTEGER REFERENCES organizations(id),
                user_id INTEGER REFERENCES users(id),
                title VARCHAR DEFAULT 'New conversation',
                messages JSON DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_copilot_conversations_org_id ON copilot_conversations (org_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_copilot_conversations_user_id ON copilot_conversations (user_id)"))
        conn.commit()
    print("✓ Created copilot_conversations table")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS copilot_conversations"))
        conn.commit()
    print("✓ Dropped copilot_conversations table")


if __name__ == "__main__":
    upgrade()
