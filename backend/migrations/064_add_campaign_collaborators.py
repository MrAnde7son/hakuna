"""Add `campaign_collaborators` and scope integrations to campaigns.

Lets a campaign owner invite an external email (no Hakuna account) into one
specific campaign as a contributor. The invite carries a hashed magic-link
token; accepting it issues a short-lived JWT scoped to that campaign only.

Also adds `campaign_id` (nullable) to `integrations` so collaborator-created
integrations don't leak across campaigns. NULL = org-level (today's behavior),
non-NULL = scoped to that campaign and visible only to its members.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _table_exists(conn, table: str) -> bool:
    return table in inspect(conn).get_table_names()


def _column_exists(conn, table: str, column: str) -> bool:
    cols = [c["name"] for c in inspect(conn).get_columns(table)]
    return column in cols


def _index_exists(conn, name: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM pg_indexes WHERE indexname = :n"
        ), {"n": name}).fetchone()
        return row is not None
    rows = conn.execute(text(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = :n"
    ), {"n": name}).fetchall()
    return bool(rows)


def upgrade():
    with engine.begin() as conn:
        # An older `campaign_collaborators` table exists in some DBs from a
        # prior, never-shipped iteration of this feature (share-link based,
        # with `external_email`/`share_link_id` columns). It has no `email`
        # column, so the new model is incompatible. When detected, drop it
        # along with the FK from `campaign_activity` that referenced it.
        if (
            _table_exists(conn, "campaign_collaborators")
            and not _column_exists(conn, "campaign_collaborators", "email")
        ):
            if _is_pg and _table_exists(conn, "campaign_activity"):
                conn.execute(text(
                    "ALTER TABLE campaign_activity "
                    "DROP CONSTRAINT IF EXISTS "
                    "campaign_activity_author_collaborator_id_fkey"
                ))
            conn.execute(text("DROP TABLE campaign_collaborators CASCADE"
                              if _is_pg else "DROP TABLE campaign_collaborators"))
            print("[+] dropped legacy campaign_collaborators table")

        if not _table_exists(conn, "campaign_collaborators"):
            conn.execute(text("""
                CREATE TABLE campaign_collaborators (
                    id SERIAL PRIMARY KEY,
                    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    email VARCHAR NOT NULL,
                    role VARCHAR NOT NULL DEFAULT 'contributor',
                    invite_token_hash VARCHAR(64) NOT NULL UNIQUE,
                    invited_by_user_id INTEGER REFERENCES users(id),
                    invited_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    accepted_at TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    last_seen_at TIMESTAMP,
                    revoked_at TIMESTAMP
                )
            """) if _is_pg else text("""
                CREATE TABLE campaign_collaborators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    email VARCHAR NOT NULL,
                    role VARCHAR NOT NULL DEFAULT 'contributor',
                    invite_token_hash VARCHAR(64) NOT NULL UNIQUE,
                    invited_by_user_id INTEGER REFERENCES users(id),
                    invited_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    accepted_at TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    last_seen_at TIMESTAMP,
                    revoked_at TIMESTAMP
                )
            """))
            print("[+] campaign_collaborators table created")

        # Backfill org_id for tables that pre-date its addition (e.g. created
        # via init_db() from an earlier model snapshot). Derive from the parent
        # campaign so existing rows stay valid.
        if not _column_exists(conn, "campaign_collaborators", "org_id"):
            conn.execute(text(
                "ALTER TABLE campaign_collaborators ADD COLUMN org_id INTEGER "
                "REFERENCES organizations(id)"
            ))
            conn.execute(text(
                "UPDATE campaign_collaborators AS cc "
                "SET org_id = c.org_id FROM campaigns AS c "
                "WHERE cc.campaign_id = c.id AND cc.org_id IS NULL"
            ) if _is_pg else text(
                "UPDATE campaign_collaborators SET org_id = ("
                "  SELECT org_id FROM campaigns WHERE campaigns.id = campaign_collaborators.campaign_id"
                ") WHERE org_id IS NULL"
            ))
            if _is_pg:
                conn.execute(text(
                    "ALTER TABLE campaign_collaborators ALTER COLUMN org_id SET NOT NULL"
                ))
            print("[+] campaign_collaborators.org_id added and backfilled")

        for idx, cols in [
            ("ix_campaign_collaborators_campaign_id", "campaign_id"),
            ("ix_campaign_collaborators_org_id", "org_id"),
            ("ix_campaign_collaborators_email", "email"),
            ("ix_campaign_collaborators_token_hash", "invite_token_hash"),
        ]:
            if not _index_exists(conn, idx):
                conn.execute(text(f"CREATE INDEX {idx} ON campaign_collaborators ({cols})"))
                print(f"[+] {idx} created")

        # uniqueness: one active row per (campaign, email) — soft via partial index on PG
        if _is_pg and not _index_exists(conn, "uq_campaign_collaborator_active"):
            conn.execute(text(
                "CREATE UNIQUE INDEX uq_campaign_collaborator_active "
                "ON campaign_collaborators (campaign_id, email) "
                "WHERE revoked_at IS NULL"
            ))
            print("[+] uq_campaign_collaborator_active created")

        if not _column_exists(conn, "integrations", "campaign_id"):
            conn.execute(text(
                "ALTER TABLE integrations ADD COLUMN campaign_id INTEGER "
                "REFERENCES campaigns(id) ON DELETE CASCADE"
            ))
            print("[+] integrations.campaign_id added")

        if not _index_exists(conn, "ix_integrations_campaign_id"):
            conn.execute(text("CREATE INDEX ix_integrations_campaign_id ON integrations (campaign_id)"))
            print("[+] ix_integrations_campaign_id created")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_integrations_campaign_id"))
        # SQLite can't drop columns easily; PG handles it cleanly.
        if _is_pg:
            conn.execute(text("ALTER TABLE integrations DROP COLUMN IF EXISTS campaign_id"))
        conn.execute(text("DROP INDEX IF EXISTS uq_campaign_collaborator_active"))
        conn.execute(text("DROP INDEX IF EXISTS ix_campaign_collaborators_token_hash"))
        conn.execute(text("DROP INDEX IF EXISTS ix_campaign_collaborators_email"))
        conn.execute(text("DROP INDEX IF EXISTS ix_campaign_collaborators_org_id"))
        conn.execute(text("DROP INDEX IF EXISTS ix_campaign_collaborators_campaign_id"))
        conn.execute(text("DROP TABLE IF EXISTS campaign_collaborators"))
        print("Migration 064: reverted.")


if __name__ == "__main__":
    print("Running migration: 064_add_campaign_collaborators")
    upgrade()
    print("Done.")
