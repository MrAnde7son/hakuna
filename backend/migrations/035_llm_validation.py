"""Add LLM validation column to findings for AI-powered false positive detection."""

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
    """Add llm_validation JSON column to findings."""
    with engine.begin() as conn:
        if not _column_exists(conn, "findings", "llm_validation"):
            col_type = "JSONB" if _is_pg else "JSON"
            conn.execute(text(
                f"ALTER TABLE findings ADD COLUMN llm_validation {col_type} DEFAULT NULL"
            ))
            print("[+] Added findings.llm_validation")

        if _is_pg:
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_findings_llm_validation
                ON findings ((llm_validation->>'verdict'))
                WHERE llm_validation IS NOT NULL
            """))

    print("Migration 035: LLM validation column added to findings.")


def downgrade():
    """Remove llm_validation column from findings."""
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_findings_llm_validation"))
        if _is_pg:
            conn.execute(text("ALTER TABLE findings DROP COLUMN IF EXISTS llm_validation"))
        # SQLite doesn't support DROP COLUMN before 3.35.0; skip in dev
    print("Migration 035: LLM validation column removed.")


if __name__ == "__main__":
    upgrade()
