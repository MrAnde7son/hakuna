"""Foundation tables and flags for identity discovery (EASM enrichment slice 2).

Identity discovery infers the people who work at an org from public SERP
data (LinkedIn). It surfaces them as ``asset_type='identity'`` rows in the
existing ``assets`` table — same prioritization, tagging, and campaign
machinery applies — but the discovery path needs three storage primitives
that don't fit anywhere else:

* ``organizations.identity_discovery_enabled`` — per-org kill switch
  (default off). The job hard-skips when false; org admins flip it on from
  the consent UI. Decoupled from the consent row so a tenant can disable
  discovery without revoking the audit trail.

* ``data_processing_consents`` — typed consent ledger. Each row is the
  acknowledgment that an org admin granted us a lawful basis for a
  particular processing purpose (LinkedIn ToS / GDPR lawful basis for
  identity discovery). ``acknowledgment_text`` snapshots what the user saw
  at grant time so we have proof even if the legal copy changes. Expiry is
  per-row so we can vary it later by purpose; identity discovery defaults
  to 365 days at the API layer.

* ``identity_suppressions`` — GDPR Article 17 right-to-erasure list.
  Hard-deleting a person's row from ``assets`` doesn't stop tomorrow's
  discovery run from re-creating it. Suppressions are the durable "do not
  rediscover" signal — the source layer filters slugs in this table out of
  every result set. Per-org so erasure in one tenant doesn't affect others.

The purpose column on consents is broad on purpose — future purposes
(LLM training, dark-web monitoring, third-party share) can reuse the same
ledger without another migration.
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
        # ── 1. organizations.identity_discovery_enabled ──────────────
        if not _column_exists(conn, "organizations", "identity_discovery_enabled"):
            # Default false everywhere — operators must opt in explicitly
            # by granting consent through the dedicated API.
            conn.execute(text(
                "ALTER TABLE organizations ADD COLUMN identity_discovery_enabled "
                "BOOLEAN NOT NULL DEFAULT FALSE"
            ))
            print("[+] organizations.identity_discovery_enabled added")

        # ── 2. data_processing_consents ──────────────────────────────
        if not _table_exists(conn, "data_processing_consents"):
            conn.execute(text("""
                CREATE TABLE data_processing_consents (
                    id                     SERIAL PRIMARY KEY,
                    org_id                 INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    purpose                VARCHAR(64) NOT NULL,
                    granted_by_user_id     INTEGER REFERENCES users(id),
                    granted_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at             TIMESTAMP,
                    revoked_at             TIMESTAMP,
                    acknowledgment_text    TEXT NOT NULL,
                    metadata               JSON
                )
            """) if _is_pg else text("""
                CREATE TABLE data_processing_consents (
                    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id                 INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    purpose                VARCHAR(64) NOT NULL,
                    granted_by_user_id     INTEGER REFERENCES users(id),
                    granted_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at             TIMESTAMP,
                    revoked_at             TIMESTAMP,
                    acknowledgment_text    TEXT NOT NULL,
                    metadata               JSON
                )
            """))
            print("[+] data_processing_consents created")

        if not _index_exists(conn, "ix_consents_org_purpose"):
            # Composite for the hot lookup: "is there an active consent
            # for (org, purpose)?" — exactly the question the discovery
            # worker asks on every run.
            conn.execute(text(
                "CREATE INDEX ix_consents_org_purpose "
                "ON data_processing_consents (org_id, purpose)"
            ))
            print("[+] ix_consents_org_purpose created")

        # ── 3. identity_suppressions ─────────────────────────────────
        if not _table_exists(conn, "identity_suppressions"):
            conn.execute(text("""
                CREATE TABLE identity_suppressions (
                    id                     SERIAL PRIMARY KEY,
                    org_id                 INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    source                 VARCHAR(32) NOT NULL,
                    slug                   VARCHAR(255) NOT NULL,
                    suppressed_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    suppressed_by_user_id  INTEGER REFERENCES users(id),
                    reason                 TEXT
                )
            """) if _is_pg else text("""
                CREATE TABLE identity_suppressions (
                    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id                 INTEGER NOT NULL,
                    source                 VARCHAR(32) NOT NULL,
                    slug                   VARCHAR(255) NOT NULL,
                    suppressed_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    suppressed_by_user_id  INTEGER,
                    reason                 TEXT
                )
            """))
            print("[+] identity_suppressions created")

        if not _index_exists(conn, "uq_identity_suppression"):
            # Unique on (org, source, slug). Suppression list is the
            # GDPR erasure backstop — there's no value to multiple rows
            # for the same person.
            conn.execute(text(
                "CREATE UNIQUE INDEX uq_identity_suppression "
                "ON identity_suppressions (org_id, source, slug)"
            ))
            print("[+] uq_identity_suppression created")


def downgrade():
    with engine.begin() as conn:
        if _index_exists(conn, "uq_identity_suppression"):
            conn.execute(text("DROP INDEX uq_identity_suppression"))
        if _table_exists(conn, "identity_suppressions"):
            conn.execute(text("DROP TABLE identity_suppressions"))
            print("[-] identity_suppressions dropped")
        if _index_exists(conn, "ix_consents_org_purpose"):
            conn.execute(text("DROP INDEX ix_consents_org_purpose"))
        if _table_exists(conn, "data_processing_consents"):
            conn.execute(text("DROP TABLE data_processing_consents"))
            print("[-] data_processing_consents dropped")
        if _column_exists(conn, "organizations", "identity_discovery_enabled"):
            conn.execute(text(
                "ALTER TABLE organizations DROP COLUMN identity_discovery_enabled"
            ))
            print("[-] organizations.identity_discovery_enabled dropped")


if __name__ == "__main__":
    print("Running migration: 071_identity_discovery_foundation")
    upgrade()
    print("Done.")
