"""
Migration: Add slack_channel_id and slack_channel_name to campaigns table.

Supports the "Create Slack Channel" feature on campaign detail pages,
which creates a Slack channel and invites all campaign collaborators.

Usage:
    cd backend
    python migrations/006_add_campaign_slack_fields.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine


def upgrade():
    with engine.connect() as conn:
        # Check existing columns (SQLite doesn't support IF NOT EXISTS on ALTER TABLE)
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(campaigns)"))}
        if "slack_channel_id" not in existing:
            conn.execute(text("ALTER TABLE campaigns ADD COLUMN slack_channel_id VARCHAR"))
        if "slack_channel_name" not in existing:
            conn.execute(text("ALTER TABLE campaigns ADD COLUMN slack_channel_name VARCHAR"))
        conn.commit()
    print("✓ Added slack_channel_id and slack_channel_name to campaigns")


def downgrade():
    with engine.connect() as conn:
        # SQLite does not support DROP COLUMN before 3.35; safe to leave for SQLite
        try:
            conn.execute(text("ALTER TABLE campaigns DROP COLUMN slack_channel_id"))
            conn.execute(text("ALTER TABLE campaigns DROP COLUMN slack_channel_name"))
            conn.commit()
        except Exception as e:
            print(f"  (downgrade skipped: {e})")
    print("✓ Removed slack fields from campaigns")


if __name__ == "__main__":
    upgrade()
