"""Add explainability columns to attack_paths.

Adds:
  - entry_reason   VARCHAR(64)  — short label (e.g. 'critical_finding', 'internet_facing+critical')
  - target_reason  VARCHAR(64)  — short label (e.g. 'domain_controller', 'high_criticality=9')
  - score          FLOAT        — computed priority score (≈0-100)
  - score_breakdown JSON/JSONB — structured factors behind the score

Backfills `score` to 0.0 and leaves reason columns NULL for existing rows —
they'll be populated on the next correlation run.
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
    json_type = "JSONB" if _is_pg else "JSON"
    with engine.begin() as conn:
        if not _column_exists(conn, "attack_paths", "entry_reason"):
            conn.execute(text(
                "ALTER TABLE attack_paths ADD COLUMN entry_reason VARCHAR(64)"
            ))
            print("[+] Added attack_paths.entry_reason")
        if not _column_exists(conn, "attack_paths", "target_reason"):
            conn.execute(text(
                "ALTER TABLE attack_paths ADD COLUMN target_reason VARCHAR(64)"
            ))
            print("[+] Added attack_paths.target_reason")
        if not _column_exists(conn, "attack_paths", "score"):
            conn.execute(text(
                "ALTER TABLE attack_paths ADD COLUMN score FLOAT DEFAULT 0.0"
            ))
            print("[+] Added attack_paths.score")
        if not _column_exists(conn, "attack_paths", "score_breakdown"):
            conn.execute(text(
                f"ALTER TABLE attack_paths ADD COLUMN score_breakdown {json_type}"
            ))
            print("[+] Added attack_paths.score_breakdown")

        # Index score so we can ORDER BY it efficiently on large orgs.
        try:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_attack_paths_score "
                "ON attack_paths(org_id, score)"
            ))
        except Exception as e:
            print(f"[!] Score index creation skipped: {e}")

    print("Migration 044: attack_paths explainability columns added.")


def downgrade():
    if not _is_pg:
        print("Migration 044: SQLite downgrade skipped (DROP COLUMN requires 3.35+).")
        return
    with engine.begin() as conn:
        for col in ("entry_reason", "target_reason", "score", "score_breakdown"):
            conn.execute(text(f"ALTER TABLE attack_paths DROP COLUMN IF EXISTS {col}"))
        conn.execute(text("DROP INDEX IF EXISTS ix_attack_paths_score"))
    print("Migration 044: attack_paths explainability columns removed.")


if __name__ == "__main__":
    upgrade()
