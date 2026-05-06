"""Add `api_tokens` — long-lived programmatic access credentials.

Customers connecting their own agents (MCP clients, CI jobs) need a credential
that doesn't expire every 8 hours like the user JWT. API tokens are stored
hashed; the plaintext is shown once at creation. Auth in core/auth.py accepts
either a JWT or a `hak_…` API token in the Authorization bearer header.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _table_exists(conn, table: str) -> bool:
    return table in inspect(conn).get_table_names()


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
        if not _table_exists(conn, "api_tokens"):
            json_type = "JSONB" if _is_pg else "JSON"
            conn.execute(text(f"""
                CREATE TABLE api_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    name VARCHAR NOT NULL,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    token_prefix VARCHAR(12) NOT NULL,
                    scopes {json_type} NOT NULL DEFAULT '[]',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    revoked_at TIMESTAMP
                )
            """) if _is_pg else text(f"""
                CREATE TABLE api_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    name VARCHAR NOT NULL,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    token_prefix VARCHAR(12) NOT NULL,
                    scopes {json_type} NOT NULL DEFAULT '[]',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    revoked_at TIMESTAMP
                )
            """))
            print("[+] api_tokens table created")

        for idx, cols in [
            ("ix_api_tokens_user_id", "user_id"),
            ("ix_api_tokens_org_id", "org_id"),
            ("ix_api_tokens_token_hash", "token_hash"),
        ]:
            if not _index_exists(conn, idx):
                conn.execute(text(f"CREATE INDEX {idx} ON api_tokens ({cols})"))
                print(f"[+] {idx} created")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_api_tokens_token_hash"))
        conn.execute(text("DROP INDEX IF EXISTS ix_api_tokens_org_id"))
        conn.execute(text("DROP INDEX IF EXISTS ix_api_tokens_user_id"))
        conn.execute(text("DROP TABLE IF EXISTS api_tokens"))
        print("Migration 063: reverted.")


if __name__ == "__main__":
    print("Running migration: 063_add_api_tokens")
    upgrade()
    print("Done.")
