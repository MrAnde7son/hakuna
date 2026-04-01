"""
Migration: Strip context metadata from copilot conversation messages.

The frontend was previously concatenating page context metadata (e.g.
"[User is currently viewing: ...]", APP_ROUTES_CONTEXT) into the user
message before sending to the backend. This metadata was stored in the
conversation history and displayed when loading past conversations.

This migration strips that prefix from all existing user messages.

Safe to run multiple times. Works with SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/016_clean_copilot_context_metadata.py
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sqlalchemy import text
from core.database import engine

CONTEXT_END_MARKER = "acknowledge the active filters."


def _strip_context(content: str) -> str:
    """Remove context metadata prefix from a user message."""
    idx = content.find(CONTEXT_END_MARKER)
    if idx == -1:
        return content
    return content[idx + len(CONTEXT_END_MARKER):].lstrip()


def upgrade():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT id, messages FROM copilot_conversations")).fetchall()
        updated = 0
        for row in rows:
            conv_id = row[0]
            raw = row[1]
            if not raw:
                continue
            messages = json.loads(raw) if isinstance(raw, str) else raw
            changed = False
            for msg in messages:
                if msg.get("role") != "user" or not msg.get("content"):
                    continue
                cleaned = _strip_context(msg["content"])
                if cleaned != msg["content"]:
                    msg["content"] = cleaned
                    changed = True
            if changed:
                conn.execute(
                    text("UPDATE copilot_conversations SET messages = :msgs WHERE id = :id"),
                    {"msgs": json.dumps(messages), "id": conv_id},
                )
                updated += 1
        print(f"Cleaned {updated} conversation(s)")


def downgrade():
    print("Downgrade not supported — original context metadata is not recoverable.")


if __name__ == "__main__":
    upgrade()
