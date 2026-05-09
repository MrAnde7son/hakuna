"""Add domain-claim and join-request schema to support multi-user signup
into the same tenant.

Today every public signup creates a brand-new ``Organization`` — two
people from the same company who both hit ``/api/auth/register`` end up
in disconnected tenants with no way to find each other. This migration
adds the storage to fix that:

  * ``organizations.claimed_domain`` — the corporate email domain this
    tenant owns (``acme.com``). UNIQUE so two orgs can't claim it.
    Auto-populated from the founder's email at signup unless the
    domain is on the public-email blocklist (gmail.com, etc.).
  * ``organizations.domain_join_mode`` — ``disabled | request | auto``.
    Default ``disabled`` so existing orgs are unchanged on upgrade.
  * ``organizations.domain_join_default_role`` — role assigned to
    auto-joined users (default ``viewer``).
  * ``org_join_requests`` — pending join requests when the mode is
    ``request``. Stores hashed_password so approval doesn't need to
    re-collect it.

Backfill: for every existing org we leave ``claimed_domain`` NULL.
Backfilling from ``easm_domain`` would silently auto-claim a domain
that admins never opted into and could collide with another org that
later wants to claim it. Org admins can claim explicitly post-upgrade
from the new Domain Settings panel.
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
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column}).fetchone()
        return row is not None
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == column for r in rows)


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
        # ── 1. organizations columns ──────────────────────────────
        if not _column_exists(conn, "organizations", "claimed_domain"):
            conn.execute(text(
                "ALTER TABLE organizations ADD COLUMN claimed_domain VARCHAR(253)"
            ))
            print("[+] organizations.claimed_domain added")

        if not _index_exists(conn, "ix_organizations_claimed_domain"):
            # Partial unique on Postgres so multiple orgs can keep NULL;
            # SQLite doesn't support partial unique cleanly, so use a
            # plain unique index — NULLs are still allowed there.
            if _is_pg:
                conn.execute(text(
                    "CREATE UNIQUE INDEX ix_organizations_claimed_domain "
                    "ON organizations (claimed_domain) "
                    "WHERE claimed_domain IS NOT NULL"
                ))
            else:
                conn.execute(text(
                    "CREATE UNIQUE INDEX ix_organizations_claimed_domain "
                    "ON organizations (claimed_domain)"
                ))
            print("[+] ix_organizations_claimed_domain created")

        if not _column_exists(conn, "organizations", "domain_join_mode"):
            conn.execute(text(
                "ALTER TABLE organizations ADD COLUMN domain_join_mode "
                "VARCHAR(20) NOT NULL DEFAULT 'disabled'"
            ))
            print("[+] organizations.domain_join_mode added")

        if not _column_exists(conn, "organizations", "domain_join_default_role"):
            conn.execute(text(
                "ALTER TABLE organizations ADD COLUMN domain_join_default_role "
                "VARCHAR(50) NOT NULL DEFAULT 'viewer'"
            ))
            print("[+] organizations.domain_join_default_role added")

        # ── 2. org_join_requests table ────────────────────────────
        if not _table_exists(conn, "org_join_requests"):
            conn.execute(text("""
                CREATE TABLE org_join_requests (
                    id              SERIAL PRIMARY KEY,
                    org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    email           VARCHAR(255) NOT NULL,
                    hashed_password VARCHAR(255) NOT NULL,
                    display_name    VARCHAR(255),
                    requested_role  VARCHAR(50) NOT NULL DEFAULT 'viewer',
                    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
                    denial_reason   TEXT,
                    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at      TIMESTAMP NOT NULL,
                    decided_at      TIMESTAMP,
                    decided_by_user_id INTEGER REFERENCES users(id)
                )
            """) if _is_pg else text("""
                CREATE TABLE org_join_requests (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    email           VARCHAR(255) NOT NULL,
                    hashed_password VARCHAR(255) NOT NULL,
                    display_name    VARCHAR(255),
                    requested_role  VARCHAR(50) NOT NULL DEFAULT 'viewer',
                    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
                    denial_reason   TEXT,
                    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at      TIMESTAMP NOT NULL,
                    decided_at      TIMESTAMP,
                    decided_by_user_id INTEGER REFERENCES users(id)
                )
            """))
            print("[+] org_join_requests created")

        if not _index_exists(conn, "ix_org_join_requests_email"):
            conn.execute(text(
                "CREATE INDEX ix_org_join_requests_email ON org_join_requests (email)"
            ))
            print("[+] ix_org_join_requests_email created")

        if not _index_exists(conn, "ix_org_join_requests_org_status"):
            conn.execute(text(
                "CREATE INDEX ix_org_join_requests_org_status "
                "ON org_join_requests (org_id, status)"
            ))
            print("[+] ix_org_join_requests_org_status created")


def downgrade():
    with engine.begin() as conn:
        if _table_exists(conn, "org_join_requests"):
            conn.execute(text("DROP TABLE org_join_requests"))
            print("[-] org_join_requests dropped")
        if _index_exists(conn, "ix_organizations_claimed_domain"):
            conn.execute(text("DROP INDEX ix_organizations_claimed_domain"))
        for col in ("domain_join_default_role", "domain_join_mode", "claimed_domain"):
            if _column_exists(conn, "organizations", col):
                conn.execute(text(f"ALTER TABLE organizations DROP COLUMN {col}"))
                print(f"[-] organizations.{col} dropped")


if __name__ == "__main__":
    print("Running migration: 069_add_domain_claim_and_join_requests")
    upgrade()
    print("Done.")
