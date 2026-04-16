"""Dedupe tag_assignments and add partial unique indexes.

Collapses duplicate (tag_id, asset_id) and (tag_id, finding_id) rows — keeping
the earliest row (MIN(id)) per group — then enforces uniqueness going forward
via partial unique indexes (one side of each row is always NULL).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def upgrade():
    with engine.begin() as conn:
        # ── 1. Collapse duplicates: keep MIN(id) per (tag_id, asset_id) ─────────
        asset_before = conn.execute(text(
            "SELECT COUNT(*) FROM tag_assignments WHERE asset_id IS NOT NULL"
        )).scalar()
        conn.execute(text("""
            DELETE FROM tag_assignments
            WHERE asset_id IS NOT NULL
              AND id NOT IN (
                  SELECT MIN(id)
                  FROM tag_assignments
                  WHERE asset_id IS NOT NULL
                  GROUP BY tag_id, asset_id
              )
        """))
        asset_after = conn.execute(text(
            "SELECT COUNT(*) FROM tag_assignments WHERE asset_id IS NOT NULL"
        )).scalar()

        # ── 2. Collapse duplicates: keep MIN(id) per (tag_id, finding_id) ──────
        finding_before = conn.execute(text(
            "SELECT COUNT(*) FROM tag_assignments WHERE finding_id IS NOT NULL"
        )).scalar()
        conn.execute(text("""
            DELETE FROM tag_assignments
            WHERE finding_id IS NOT NULL
              AND id NOT IN (
                  SELECT MIN(id)
                  FROM tag_assignments
                  WHERE finding_id IS NOT NULL
                  GROUP BY tag_id, finding_id
              )
        """))
        finding_after = conn.execute(text(
            "SELECT COUNT(*) FROM tag_assignments WHERE finding_id IS NOT NULL"
        )).scalar()

        # ── 3. Enforce uniqueness via partial unique indexes ───────────────────
        # Both SQLite (3.8+) and PostgreSQL support partial indexes with the
        # same WHERE-clause syntax, so the DDL is portable.
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_tag_assignment_tag_asset
            ON tag_assignments (tag_id, asset_id)
            WHERE asset_id IS NOT NULL
        """))
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_tag_assignment_tag_finding
            ON tag_assignments (tag_id, finding_id)
            WHERE finding_id IS NOT NULL
        """))

    print(
        f"Migration 037: deduped tag_assignments — "
        f"assets {asset_before}→{asset_after} "
        f"(removed {asset_before - asset_after}), "
        f"findings {finding_before}→{finding_after} "
        f"(removed {finding_before - finding_after}). "
        f"Partial unique indexes created."
    )


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS uq_tag_assignment_tag_asset"))
        conn.execute(text("DROP INDEX IF EXISTS uq_tag_assignment_tag_finding"))
    print("Migration 037: dropped partial unique indexes on tag_assignments.")


if __name__ == "__main__":
    upgrade()
