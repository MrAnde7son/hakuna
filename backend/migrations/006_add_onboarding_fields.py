"""
Migration: Add onboarding fields to users table.

Adds onboarding_completed (boolean) and onboarding_state (JSON) columns
to track first-run wizard progress per user.

Usage:
    cd backend
    python migrations/006_add_onboarding_fields.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine


def upgrade():
    with engine.connect() as conn:
        # Add onboarding_completed column
        try:
            conn.execute(text(
                "ALTER TABLE users ADD COLUMN onboarding_completed BOOLEAN DEFAULT 0"
            ))
        except Exception:
            pass  # Column may already exist

        # Add onboarding_state JSON column
        try:
            conn.execute(text(
                "ALTER TABLE users ADD COLUMN onboarding_state JSON DEFAULT '{}'"
            ))
        except Exception:
            pass  # Column may already exist

        conn.commit()
    print("Migration 006: Added onboarding fields to users table.")


def downgrade():
    # SQLite doesn't support DROP COLUMN before 3.35.0
    print("Migration 006 downgrade: Manual removal of onboarding_completed and onboarding_state columns needed.")


if __name__ == "__main__":
    upgrade()
