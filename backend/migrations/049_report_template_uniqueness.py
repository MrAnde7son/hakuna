"""Dedupe report_templates and enforce (org_id, name) uniqueness.

Two bugs combined to produce duplicate OOTB dashboards in `report_templates`:

  1. The frontend OOTB seeding loop in ReportBuilder.jsx runs in `useEffect`,
     which React 18 StrictMode mounts twice in dev. Both runs read an empty
     template list and both POST every default dashboard.
  2. `POST /api/report-templates` had a TOCTOU name-uniqueness check but no
     DB constraint, so two concurrent inserts both succeeded.

This migration collapses any duplicate rows (keeping the lowest id per
`(COALESCE(org_id, 0), name)` group, redirecting any orphaned schedules
to the survivor) and creates a unique index that prevents recurrence.

Postgres-only (per CLAUDE.md — SQLite is not supported).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine


def upgrade():
    with engine.begin() as conn:
        before = conn.execute(text("SELECT COUNT(*) FROM report_templates")).scalar()

        # Find the surviving row id per (COALESCE(org_id, 0), name) group.
        survivors = conn.execute(text("""
            SELECT MIN(id) AS keep_id, name, COALESCE(org_id, 0) AS scope
            FROM report_templates
            GROUP BY name, COALESCE(org_id, 0)
        """)).mappings().all()

        # Repoint any schedules attached to a losing row at the survivor so we
        # don't lose user-configured deliveries when CASCADE wipes duplicates.
        for row in survivors:
            conn.execute(text("""
                UPDATE report_schedules
                SET report_template_id = :keep_id
                WHERE report_template_id IN (
                    SELECT id FROM report_templates
                    WHERE name = :name
                      AND COALESCE(org_id, 0) = :scope
                      AND id <> :keep_id
                )
            """), {"keep_id": row["keep_id"], "name": row["name"], "scope": row["scope"]})

        # Delete the duplicate templates.
        conn.execute(text("""
            DELETE FROM report_templates
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM report_templates
                GROUP BY name, COALESCE(org_id, 0)
            )
        """))

        after = conn.execute(text("SELECT COUNT(*) FROM report_templates")).scalar()

        # Enforce uniqueness on (org_id, name), treating NULL org_id as a
        # single shared scope (legacy global rows). COALESCE in an expression
        # index gives us NULL-aware uniqueness portably.
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_report_template_org_name
            ON report_templates (COALESCE(org_id, 0), name)
        """))

    print(
        f"Migration 049: deduped report_templates {before}→{after} "
        f"(removed {before - after}). Unique index uq_report_template_org_name created."
    )


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS uq_report_template_org_name"))
    print("Migration 049: dropped unique index on report_templates.")


if __name__ == "__main__":
    upgrade()
