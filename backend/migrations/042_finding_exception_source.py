"""Add source_system / source_id provenance columns to finding_exceptions.

Enables idempotent import of accepted risks, false positives, and severity
overrides from third-party VM tools (Tenable, Qualys, Rapid7, Vulcan, Nucleus)
via the integration builder — the pair uniquely identifies an exception in the
source system so re-runs update rather than duplicate.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine


def _has_column(conn, table: str, column: str) -> bool:
    insp = inspect(conn)
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade():
    with engine.begin() as conn:
        if not _has_column(conn, "finding_exceptions", "source_system"):
            conn.execute(text("ALTER TABLE finding_exceptions ADD COLUMN source_system VARCHAR"))
        if not _has_column(conn, "finding_exceptions", "source_id"):
            conn.execute(text("ALTER TABLE finding_exceptions ADD COLUMN source_id VARCHAR"))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_exception_source "
            "ON finding_exceptions (source_system, source_id)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_finding_exceptions_source_system "
            "ON finding_exceptions (source_system)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_finding_exceptions_source_id "
            "ON finding_exceptions (source_id)"
        ))
    print("Migration 042: finding_exceptions.source_system + source_id added.")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_exception_source"))
        conn.execute(text("DROP INDEX IF EXISTS ix_finding_exceptions_source_system"))
        conn.execute(text("DROP INDEX IF EXISTS ix_finding_exceptions_source_id"))
        # SQLite doesn't support DROP COLUMN pre-3.35; leave columns in place.
        try:
            conn.execute(text("ALTER TABLE finding_exceptions DROP COLUMN source_system"))
            conn.execute(text("ALTER TABLE finding_exceptions DROP COLUMN source_id"))
        except Exception as exc:
            print(f"Migration 042 downgrade: DROP COLUMN skipped ({exc}).")
    print("Migration 042: finding_exception source columns dropped.")


if __name__ == "__main__":
    upgrade()
