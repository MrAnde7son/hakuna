"""Add relay_type column to relay_agents.

Distinguishes customer-deployed on-prem agents (``agent``, default) from
the Hakuna-managed cloud scanner (``cloud_scanner``) that runs in GCP and
handles internet-reachable assets without a customer deployment.

Selection logic in ``services/audit_auto_trigger._pick_relay`` reads this
column to route public-asset audits to the cloud scanner and private-asset
audits to the customer's relay.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _column_exists(conn, table: str, column: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column}).fetchone()
        return row is not None
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == column for r in rows)


def upgrade():
    with engine.begin() as conn:
        if _column_exists(conn, "relay_agents", "relay_type"):
            print("Migration 050: relay_type already present; nothing to do.")
            return

        if _is_pg:
            conn.execute(text(
                "ALTER TABLE relay_agents "
                "ADD COLUMN relay_type VARCHAR NOT NULL DEFAULT 'agent'"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_relay_agents_org_type_status "
                "ON relay_agents(org_id, relay_type, status)"
            ))
        else:
            conn.execute(text(
                "ALTER TABLE relay_agents "
                "ADD COLUMN relay_type VARCHAR NOT NULL DEFAULT 'agent'"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_relay_agents_org_type_status "
                "ON relay_agents(org_id, relay_type, status)"
            ))
        print("[+] relay_agents.relay_type added")


def downgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("DROP INDEX IF EXISTS ix_relay_agents_org_type_status"))
            conn.execute(text("ALTER TABLE relay_agents DROP COLUMN IF EXISTS relay_type"))
        else:
            conn.execute(text("DROP INDEX IF EXISTS ix_relay_agents_org_type_status"))
            # SQLite can't drop columns easily; leave it.
        print("Migration 050: reverted.")


if __name__ == "__main__":
    upgrade()
