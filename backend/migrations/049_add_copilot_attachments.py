"""Add copilot_attachments — files users drop into the Security Copilot chat.

Bytes are stored inline (LargeBinary / BYTEA) so a tool can resolve an
attachment_id to the file contents in one query. Capped to the same
MAX_SCAN_UPLOAD_BYTES that `/api/upload` enforces.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _table_exists(conn, table: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
        ), {"t": table}).fetchone()
        return row is not None
    rows = conn.execute(text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=:t"
    ), {"t": table}).fetchall()
    return len(rows) > 0


def upgrade():
    with engine.begin() as conn:
        if _table_exists(conn, "copilot_attachments"):
            print("Migration 049: copilot_attachments already exists; nothing to do.")
            return

        if _is_pg:
            conn.execute(text("""
                CREATE TABLE copilot_attachments (
                    id SERIAL PRIMARY KEY,
                    org_id INTEGER REFERENCES organizations(id),
                    user_id INTEGER REFERENCES users(id),
                    conversation_id INTEGER REFERENCES copilot_conversations(id),
                    filename TEXT NOT NULL,
                    content_type TEXT,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    content BYTEA NOT NULL,
                    consumed_at TIMESTAMP NULL,
                    consumed_by_tool TEXT,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """))
            conn.execute(text("CREATE INDEX ix_copilot_attachments_org_id ON copilot_attachments(org_id)"))
            conn.execute(text("CREATE INDEX ix_copilot_attachments_user_id ON copilot_attachments(user_id)"))
            conn.execute(text("CREATE INDEX ix_copilot_attachments_conversation_id ON copilot_attachments(conversation_id)"))
            conn.execute(text("CREATE INDEX ix_copilot_attachments_created_at ON copilot_attachments(created_at)"))
        else:
            conn.execute(text("""
                CREATE TABLE copilot_attachments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER,
                    user_id INTEGER,
                    conversation_id INTEGER,
                    filename TEXT NOT NULL,
                    content_type TEXT,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    content BLOB NOT NULL,
                    consumed_at TIMESTAMP NULL,
                    consumed_by_tool TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text("CREATE INDEX ix_copilot_attachments_org_id ON copilot_attachments(org_id)"))
            conn.execute(text("CREATE INDEX ix_copilot_attachments_user_id ON copilot_attachments(user_id)"))
            conn.execute(text("CREATE INDEX ix_copilot_attachments_conversation_id ON copilot_attachments(conversation_id)"))
        print("[+] Created copilot_attachments table")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS copilot_attachments"))
        print("Migration 049: copilot_attachments dropped.")


if __name__ == "__main__":
    upgrade()
