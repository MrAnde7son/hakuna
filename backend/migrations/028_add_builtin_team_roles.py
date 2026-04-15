"""
Migration: Seed built-in team roles (VM, SOC, IAM, GRC, CloudSec, …).

Adds two columns to custom_roles:
  - is_builtin         BOOLEAN  — flag for roles seeded from core.builtin_team_roles
  - scope_owner_role   VARCHAR  — if set, restricts finding/asset visibility to
                                  resources whose resolved owner_role matches

Then seeds one built-in `Team: <ROLE>` role per ownership team for every
existing organization. Idempotent — re-running is safe.

Usage:
    cd backend
    python migrations/028_add_builtin_team_roles.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.database import engine
from core.builtin_team_roles import seed_builtin_team_roles_for_all_orgs

_is_pg = "postgresql" in str(engine.url)


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
    with engine.connect() as conn:
        if not _column_exists(conn, "custom_roles", "is_builtin"):
            default = "FALSE" if _is_pg else "0"
            conn.execute(text(
                f"ALTER TABLE custom_roles ADD COLUMN is_builtin BOOLEAN NOT NULL DEFAULT {default}"
            ))
            print("Migration 028: added custom_roles.is_builtin")

        if not _column_exists(conn, "custom_roles", "scope_owner_role"):
            conn.execute(text(
                "ALTER TABLE custom_roles ADD COLUMN scope_owner_role VARCHAR"
            ))
            print("Migration 028: added custom_roles.scope_owner_role")

        conn.commit()

    # Seed built-in team roles for every existing org.
    with Session(engine) as session:
        results = seed_builtin_team_roles_for_all_orgs(session)
        total = sum(results.values())
        print(f"Migration 028: seeded {total} built-in team roles across {len(results)} orgs")


def downgrade():
    """Remove the built-in team roles and drop the new columns."""
    with engine.connect() as conn:
        conn.execute(text(
            "DELETE FROM custom_roles WHERE is_builtin = TRUE" if _is_pg
            else "DELETE FROM custom_roles WHERE is_builtin = 1"
        ))
        if _is_pg:
            conn.execute(text("ALTER TABLE custom_roles DROP COLUMN IF EXISTS scope_owner_role"))
            conn.execute(text("ALTER TABLE custom_roles DROP COLUMN IF EXISTS is_builtin"))
        # SQLite doesn't support DROP COLUMN in older versions — leave the columns
        # in place on downgrade. The rows are gone, which is the important part.
        conn.commit()
        print("Migration 028: downgrade complete")


if __name__ == "__main__":
    upgrade()
