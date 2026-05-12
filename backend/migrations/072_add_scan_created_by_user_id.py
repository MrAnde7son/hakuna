"""Add scans.created_by_user_id so every scan row records the actor who
triggered it.

Pre-existing rows have no actor — the value stays NULL and that's fine.
Going forward, the EASM scan-domain / rescan / retry routes and any other
human-triggered scan path stamp this column. The audit log already records
"start" / "rescan" / "retry" events, but having the actor on the Scan row
itself means the Scans page can render "Started by …" without joining the
audit table.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

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


def _index_exists(conn, name: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM pg_indexes WHERE indexname = :n"
        ), {"n": name}).fetchone()
        return row is not None
    rows = conn.execute(text(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = :n"
    ), {"n": name}).fetchall()
    return bool(rows)


def upgrade():
    with engine.begin() as conn:
        if not _column_exists(conn, "scans", "created_by_user_id"):
            if _is_pg:
                conn.execute(text(
                    "ALTER TABLE scans ADD COLUMN created_by_user_id "
                    "INTEGER REFERENCES users(id)"
                ))
            else:
                conn.execute(text(
                    "ALTER TABLE scans ADD COLUMN created_by_user_id INTEGER "
                    "REFERENCES users(id)"
                ))
            print("[+] scans.created_by_user_id added")

        if not _index_exists(conn, "ix_scans_created_by_user_id"):
            conn.execute(text(
                "CREATE INDEX ix_scans_created_by_user_id "
                "ON scans (created_by_user_id)"
            ))
            print("[+] ix_scans_created_by_user_id created")


def downgrade():
    with engine.begin() as conn:
        if _index_exists(conn, "ix_scans_created_by_user_id"):
            conn.execute(text("DROP INDEX ix_scans_created_by_user_id"))
        if _column_exists(conn, "scans", "created_by_user_id"):
            conn.execute(text("ALTER TABLE scans DROP COLUMN created_by_user_id"))
            print("[-] scans.created_by_user_id dropped")


if __name__ == "__main__":
    print("Running migration: 072_add_scan_created_by_user_id")
    upgrade()
    print("Done.")
