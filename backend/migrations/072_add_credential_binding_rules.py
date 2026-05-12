"""Credential→asset binding rules.

Adds the ``credential_binding_rules`` table so admins can say "for assets
matching X, use credential Y for protocol Z" instead of passing
``credential_id`` on every audit kickoff. Rules evaluate top-down by
priority (lower number wins, like firewall rules); the first match
returns its credential.

Schema rationale:
  - All match conditions are nullable. NULL is the wildcard — a rule with
    only ``device_type='ip_camera'`` matches every camera regardless of
    asset_type / CIDR / tag.
  - ``priority`` integer rather than ordered position so the API can
    insert new rules without renumbering siblings.
  - ON DELETE CASCADE on both org_id and credential_id so deleting a
    credential or an org cleans up its binding rules automatically.
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
        if not _table_exists(conn, "credential_binding_rules"):
            conn.execute(text("""
                CREATE TABLE credential_binding_rules (
                    id                 SERIAL PRIMARY KEY,
                    org_id             INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    credential_id      VARCHAR NOT NULL REFERENCES integration_credentials(id) ON DELETE CASCADE,
                    name               VARCHAR NOT NULL,
                    description        TEXT,
                    priority           INTEGER NOT NULL DEFAULT 100,
                    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
                    audit_protocol     VARCHAR,
                    asset_type         VARCHAR,
                    device_type        VARCHAR,
                    cidr               VARCHAR,
                    hostname_pattern   VARCHAR,
                    tag                VARCHAR,
                    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_by_user_id INTEGER REFERENCES users(id)
                )
            """) if _is_pg else text("""
                CREATE TABLE credential_binding_rules (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id             INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    credential_id      VARCHAR NOT NULL REFERENCES integration_credentials(id) ON DELETE CASCADE,
                    name               VARCHAR NOT NULL,
                    description        TEXT,
                    priority           INTEGER NOT NULL DEFAULT 100,
                    enabled            BOOLEAN NOT NULL DEFAULT 1,
                    audit_protocol     VARCHAR,
                    asset_type         VARCHAR,
                    device_type        VARCHAR,
                    cidr               VARCHAR,
                    hostname_pattern   VARCHAR,
                    tag                VARCHAR,
                    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_by_user_id INTEGER REFERENCES users(id)
                )
            """))
            print("[+] credential_binding_rules created")

        if not _index_exists(conn, "ix_credential_binding_org_protocol"):
            # Hot path: list enabled rules for (org, protocol) sorted by
            # priority — exactly the query the resolver runs per audit.
            conn.execute(text(
                "CREATE INDEX ix_credential_binding_org_protocol "
                "ON credential_binding_rules (org_id, audit_protocol, enabled, priority)"
            ))
            print("[+] ix_credential_binding_org_protocol created")


def downgrade():
    with engine.begin() as conn:
        if _index_exists(conn, "ix_credential_binding_org_protocol"):
            conn.execute(text("DROP INDEX ix_credential_binding_org_protocol"))
        if _table_exists(conn, "credential_binding_rules"):
            conn.execute(text("DROP TABLE credential_binding_rules"))
            print("[-] credential_binding_rules dropped")


if __name__ == "__main__":
    upgrade()
