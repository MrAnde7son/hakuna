"""Migration 039: brute-force login lockout + perf indexes.

Adds:
- users.failed_login_count / users.locked_until for account lockout.
- Compound indexes on the hot finding filter path.
- Compound index on scans (org_id, scan_name, scan_date) for dedup lookups.

Usage:
    cd backend
    python migrations/039_add_login_lockout.py
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
        # ── users: lockout columns ─────────────────────────
        if not _column_exists(conn, "users", "failed_login_count"):
            conn.execute(text(
                "ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0"
            ))
            print("[+] Added users.failed_login_count")
        if not _column_exists(conn, "users", "locked_until"):
            conn.execute(text(
                "ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL"
            ))
            print("[+] Added users.locked_until")

        # ── finding: hot-path indexes ──────────────────────
        # Heavy filter combos in list/dashboard queries.
        stmts = [
            "CREATE INDEX IF NOT EXISTS ix_finding_scan_asset ON findings (scan_id, asset_id)",
            "CREATE INDEX IF NOT EXISTS ix_finding_scan_severity_status "
            "ON findings (scan_id, severity, workflow_status)",
            "CREATE INDEX IF NOT EXISTS ix_finding_priority "
            "ON findings (priority_score)",
            "CREATE INDEX IF NOT EXISTS ix_asset_scan ON assets (scan_id)",
            "CREATE INDEX IF NOT EXISTS ix_scan_org_name_date "
            "ON scans (org_id, scan_name, scan_date)",
        ]
        for s in stmts:
            try:
                conn.execute(text(s))
            except Exception as e:
                # Tolerate missing columns on older schemas — log and continue.
                print(f"[!] Skipped index: {s[:60]}…  ({e})")

    print("Migration 039: login lockout + perf indexes applied.")


def downgrade():
    with engine.begin() as conn:
        for idx in (
            "ix_finding_scan_asset",
            "ix_finding_scan_severity_status",
            "ix_finding_priority",
            "ix_asset_scan",
            "ix_scan_org_name_date",
        ):
            conn.execute(text(f"DROP INDEX IF EXISTS {idx}"))
        if _is_pg:
            conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS failed_login_count"))
            conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS locked_until"))
    print("Migration 039: lockout columns + indexes removed (PG only).")


if __name__ == "__main__":
    upgrade()
