"""Add campaign collaboration tables for CampaignsV2 external invitees.

New tables
  campaign_share_links    — one passcode-gated URL per external invitee
  campaign_collaborators  — internal user OR external email attached to a campaign
  campaign_activity       — unified feed: comments, agent turns, automation events

Alters
  campaigns.automations_config JSON — agents / workflows chosen at launch
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")
JSON_TYPE = "JSONB" if _is_pg else "JSON"
PK = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"


def _column_exists(conn, table: str, column: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column}).fetchone()
        return row is not None
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == column for r in rows)


def _table_exists(conn, table: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
        ), {"t": table}).fetchone()
        return row is not None
    row = conn.execute(text(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = :t"
    ), {"t": table}).fetchone()
    return row is not None


def upgrade():
    with engine.begin() as conn:
        # ─── campaigns.automations_config ──────────────────────────
        if not _column_exists(conn, "campaigns", "automations_config"):
            conn.execute(text(
                f"ALTER TABLE campaigns ADD COLUMN automations_config {JSON_TYPE}"
            ))
            print("[+] Added campaigns.automations_config")

        # ─── campaign_share_links ──────────────────────────────────
        if not _table_exists(conn, "campaign_share_links"):
            conn.execute(text(f"""
                CREATE TABLE campaign_share_links (
                    id {PK},
                    campaign_id INTEGER NOT NULL,
                    org_id INTEGER NOT NULL,
                    share_token VARCHAR(64) NOT NULL UNIQUE,
                    passcode_hash VARCHAR(255) NOT NULL,
                    passcode_version INTEGER DEFAULT 1,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    revoked_at TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    lock_until TIMESTAMP,
                    allowed_automations {JSON_TYPE},
                    permissions {JSON_TYPE}
                )
            """))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_campaign_share_links_campaign "
                "ON campaign_share_links(campaign_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_campaign_share_links_org "
                "ON campaign_share_links(org_id)"
            ))
            print("[+] Created campaign_share_links")

        # ─── campaign_collaborators ───────────────────────────────
        if not _table_exists(conn, "campaign_collaborators"):
            conn.execute(text(f"""
                CREATE TABLE campaign_collaborators (
                    id {PK},
                    campaign_id INTEGER NOT NULL,
                    share_link_id INTEGER,
                    user_id INTEGER,
                    external_email VARCHAR(255),
                    external_name VARCHAR(255),
                    invited_by INTEGER,
                    invited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP,
                    role VARCHAR(32) DEFAULT 'external_owner'
                )
            """))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_campaign_collab_campaign "
                "ON campaign_collaborators(campaign_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_campaign_collab_share_link "
                "ON campaign_collaborators(share_link_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_campaign_collab_user "
                "ON campaign_collaborators(user_id)"
            ))
            print("[+] Created campaign_collaborators")

        # ─── campaign_activity ────────────────────────────────────
        if not _table_exists(conn, "campaign_activity"):
            conn.execute(text(f"""
                CREATE TABLE campaign_activity (
                    id {PK},
                    campaign_id INTEGER NOT NULL,
                    author_type VARCHAR(16) NOT NULL,
                    author_user_id INTEGER,
                    author_collaborator_id INTEGER,
                    author_display_name VARCHAR(255),
                    kind VARCHAR(32) NOT NULL DEFAULT 'comment',
                    body TEXT,
                    extra {JSON_TYPE},
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_campaign_activity_campaign "
                "ON campaign_activity(campaign_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_campaign_activity_created "
                "ON campaign_activity(campaign_id, created_at)"
            ))
            print("[+] Created campaign_activity")

    print("Migration 045: campaign collaboration tables ready.")


def downgrade():
    with engine.begin() as conn:
        for t in ("campaign_activity", "campaign_collaborators", "campaign_share_links"):
            conn.execute(text(f"DROP TABLE IF EXISTS {t}"))
        if _is_pg:
            conn.execute(text(
                "ALTER TABLE campaigns DROP COLUMN IF EXISTS automations_config"
            ))
        else:
            print("Migration 045: SQLite ALTER DROP COLUMN skipped (3.35+ only).")
    print("Migration 045: campaign collaboration tables dropped.")


if __name__ == "__main__":
    upgrade()
