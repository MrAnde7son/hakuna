"""Migration 039: Adaptive Scan Plan persistence on assets.

Adds:
- assets.scan_plan              — JSONB scan plan produced by services/scan_planner
- assets.scan_plan_computed_at  — when the plan was last (re)computed
- assets.scan_plan_version      — monotonic counter; bumped on each replan
- assets.scan_plan_signature    — sha256 over (cpe_list, tech_stack, open_ports,
                                  endpoint_count, criticality, risk_score) used
                                  to short-circuit recomputation when nothing
                                  meaningful has changed since the last plan
- ix_assets_scan_plan_stale     — partial index for the "needs replanning" sweep
                                  (NULLS FIRST so unplanned assets surface first)

Backwards compatible: every column nullable; readers must tolerate NULL plans
and fall back to the legacy template-router code path.

Usage:
    cd backend
    python migrations/039_adaptive_scan_plan.py
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
    ts_type = "TIMESTAMPTZ" if _is_pg else "TIMESTAMP"
    with engine.begin() as conn:
        if not _column_exists(conn, "assets", "scan_plan"):
            conn.execute(text(f"ALTER TABLE assets ADD COLUMN scan_plan {json_type} DEFAULT NULL"))
            print("[+] Added assets.scan_plan")
        if not _column_exists(conn, "assets", "scan_plan_computed_at"):
            conn.execute(text(f"ALTER TABLE assets ADD COLUMN scan_plan_computed_at {ts_type} DEFAULT NULL"))
            print("[+] Added assets.scan_plan_computed_at")
        if not _column_exists(conn, "assets", "scan_plan_version"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN scan_plan_version INTEGER DEFAULT 0"))
            print("[+] Added assets.scan_plan_version")
        if not _column_exists(conn, "assets", "scan_plan_signature"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN scan_plan_signature VARCHAR(64) DEFAULT NULL"))
            print("[+] Added assets.scan_plan_signature")

        if _is_pg:
            # Partial index — invalidate_stale_plans() probes for NULL or stale
            # timestamps, and most assets will eventually have a plan, so the
            # NULLS FIRST ordering keeps the "never planned" set hot.
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_assets_scan_plan_stale
                ON assets (scan_plan_computed_at NULLS FIRST)
            """))

    print("Migration 039: adaptive scan plan columns added.")


def downgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("DROP INDEX IF EXISTS ix_assets_scan_plan_stale"))
            for col in (
                "scan_plan", "scan_plan_computed_at",
                "scan_plan_version", "scan_plan_signature",
            ):
                conn.execute(text(f"ALTER TABLE assets DROP COLUMN IF EXISTS {col}"))
        # SQLite: DROP COLUMN requires 3.35+; skip in dev.
    print("Migration 039: adaptive scan plan columns removed (PG only).")


if __name__ == "__main__":
    upgrade()
