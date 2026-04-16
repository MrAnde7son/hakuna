"""Migration 038: LLM-assisted SIEM enrichment.

Adds:
- ingest_endpoints.field_extractors  — JSON spec produced by mapping_inference,
  applied at ingest time to fill canonical fields from unstructured payloads.
- alerts.triage_*                    — LLM triage verdict/summary written by
  alert_triage before notification fires.

Usage:
    cd backend
    python migrations/038_add_llm_enrichment.py
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
        # ── ingest_endpoints.field_extractors ──────────────
        if not _column_exists(conn, "ingest_endpoints", "field_extractors"):
            conn.execute(text(
                f"ALTER TABLE ingest_endpoints ADD COLUMN field_extractors {json_type} DEFAULT NULL"
            ))
            print("[+] Added ingest_endpoints.field_extractors")

        # ── alerts triage columns ──────────────────────────
        for col, sql in [
            ("triage_verdict",    "ALTER TABLE alerts ADD COLUMN triage_verdict VARCHAR"),
            ("triage_confidence", "ALTER TABLE alerts ADD COLUMN triage_confidence FLOAT"),
            ("triage_summary",    "ALTER TABLE alerts ADD COLUMN triage_summary TEXT"),
            ("triaged_at",        "ALTER TABLE alerts ADD COLUMN triaged_at TIMESTAMP"),
            ("triage_model",      "ALTER TABLE alerts ADD COLUMN triage_model VARCHAR"),
        ]:
            if not _column_exists(conn, "alerts", col):
                conn.execute(text(sql))
                print(f"[+] Added alerts.{col}")

        if _is_pg:
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_alerts_triage_verdict
                ON alerts (org_id, triage_verdict)
                WHERE triage_verdict IS NOT NULL
            """))

    print("Migration 038: LLM enrichment columns added.")


def downgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("DROP INDEX IF EXISTS ix_alerts_triage_verdict"))
            for col in ("field_extractors",):
                conn.execute(text(f"ALTER TABLE ingest_endpoints DROP COLUMN IF EXISTS {col}"))
            for col in ("triage_verdict", "triage_confidence", "triage_summary", "triaged_at", "triage_model"):
                conn.execute(text(f"ALTER TABLE alerts DROP COLUMN IF EXISTS {col}"))
        # SQLite: DROP COLUMN requires 3.35+; skip in dev.
    print("Migration 038: LLM enrichment columns removed (PG only).")


if __name__ == "__main__":
    upgrade()
