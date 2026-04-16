"""Add narrative + recommended_mitigations columns to attack_paths."""

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
    """Add narrative (TEXT) and recommended_mitigations (JSON) columns."""
    json_type = "JSONB" if _is_pg else "JSON"
    with engine.begin() as conn:
        if not _column_exists(conn, "attack_paths", "narrative"):
            conn.execute(text("ALTER TABLE attack_paths ADD COLUMN narrative TEXT"))
            print("[+] Added attack_paths.narrative")
        if not _column_exists(conn, "attack_paths", "recommended_mitigations"):
            conn.execute(text(
                f"ALTER TABLE attack_paths ADD COLUMN recommended_mitigations {json_type}"
            ))
            print("[+] Added attack_paths.recommended_mitigations")
    print("Migration 038: attack_paths narrative + mitigations added.")


def downgrade():
    """Remove narrative + recommended_mitigations columns (Postgres only)."""
    if not _is_pg:
        print("Migration 038: SQLite downgrade skipped (DROP COLUMN requires 3.35+).")
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE attack_paths DROP COLUMN IF EXISTS narrative"))
        conn.execute(text("ALTER TABLE attack_paths DROP COLUMN IF EXISTS recommended_mitigations"))
    print("Migration 038: attack_paths narrative columns removed.")


if __name__ == "__main__":
    upgrade()
