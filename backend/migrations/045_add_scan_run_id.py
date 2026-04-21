"""Add scan_run_id to findings and assets for VM rescan swap-on-success.

Each VM rescan mints a fresh run_id. New-run rows are written alongside
the previous run; the old run is dropped only at finalize so that a failed
rescan preserves the last known-good results.

Nullable because only VM scans stamp this field — Nessus/Qualys imports
leave it NULL.
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
        if not _column_exists(conn, "findings", "scan_run_id"):
            conn.execute(text("ALTER TABLE findings ADD COLUMN scan_run_id VARCHAR"))
            print("[+] Added findings.scan_run_id")
        if not _column_exists(conn, "assets", "scan_run_id"):
            conn.execute(text("ALTER TABLE assets ADD COLUMN scan_run_id VARCHAR"))
            print("[+] Added assets.scan_run_id")

        try:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_findings_scan_id_scan_run_id "
                "ON findings(scan_id, scan_run_id)"
            ))
        except Exception as e:
            print(f"[!] ix_findings_scan_id_scan_run_id skipped: {e}")
        try:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_assets_scan_id_scan_run_id "
                "ON assets(scan_id, scan_run_id)"
            ))
        except Exception as e:
            print(f"[!] ix_assets_scan_id_scan_run_id skipped: {e}")

    print("Migration 045: scan_run_id added to findings and assets.")


def downgrade():
    if not _is_pg:
        print("Migration 045: SQLite downgrade skipped (DROP COLUMN requires 3.35+).")
        return
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_findings_scan_id_scan_run_id"))
        conn.execute(text("DROP INDEX IF EXISTS ix_assets_scan_id_scan_run_id"))
        conn.execute(text("ALTER TABLE findings DROP COLUMN IF EXISTS scan_run_id"))
        conn.execute(text("ALTER TABLE assets DROP COLUMN IF EXISTS scan_run_id"))
    print("Migration 045: scan_run_id dropped.")


if __name__ == "__main__":
    upgrade()
