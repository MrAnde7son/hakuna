"""Add profile_type column to auth_profiles (and relax form_login-only fields).

Migration 042 originally shipped without profile_type. Dev databases that
picked up that revision need this follow-up to add the column. Fresh installs
get profile_type from 042 directly; for them, this migration is a no-op.

profile_type values:
  - 'static'      references a credential; scanner gets headers as-is
  - 'form_login'  drives Playwright through a login flow (default)
  - future: 'oauth_authz_code', 'totp', 'saml_sso'
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _sqlite_has_column(conn, table: str, column: str) -> bool:
    try:
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    except Exception:
        return False
    return any(r[1] == column for r in rows)


def upgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text(
                "ALTER TABLE auth_profiles ADD COLUMN IF NOT EXISTS "
                "profile_type VARCHAR NOT NULL DEFAULT 'form_login'"
            ))
            # Relax form_login-only fields — needed when the very first 042
            # draft was applied (it had NOT NULL on login_url/login_flow/
            # success_condition). Idempotent: DROP NOT NULL is a no-op if
            # the column is already nullable.
            for col in ("login_url", "login_flow", "success_condition"):
                try:
                    conn.execute(text(f"ALTER TABLE auth_profiles ALTER COLUMN {col} DROP NOT NULL"))
                except Exception:
                    pass
        else:
            if not _sqlite_has_column(conn, "auth_profiles", "profile_type"):
                conn.execute(text(
                    "ALTER TABLE auth_profiles ADD COLUMN "
                    "profile_type VARCHAR NOT NULL DEFAULT 'form_login'"
                ))
            # SQLite doesn't support DROP NOT NULL; the original 042 used
            # the nullable form from its first committed revision for
            # fresh installs, so no rebuild is needed here.

    print("Migration 043: auth_profiles.profile_type ensured.")


def downgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("ALTER TABLE auth_profiles DROP COLUMN IF EXISTS profile_type"))
        # SQLite: can't drop columns cleanly before 3.35 — skip.
    print("Migration 043: profile_type dropped (pg only).")


if __name__ == "__main__":
    upgrade()
