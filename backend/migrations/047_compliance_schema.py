"""Compliance framework schema (PR 1).

Creates 9 tables:
  Canonical (no org_id, seeded from YAML in backend/compliance/frameworks/):
    - compliance_frameworks
    - compliance_controls
    - compliance_control_mappings
    - compliance_framework_releases

  Tenant-owned (org_id NOT NULL):
    - org_framework_subscriptions
    - compliance_compensating_controls
    - compliance_control_status
    - compliance_finding_status
    - compliance_report_runs

Idempotent: each table is created only if it doesn't already exist. The
boot-time `init_db()` path also calls Base.metadata.create_all, which
handles fresh installs; this migration exists for environments where
metadata.create_all has already run with the prior schema and we need an
explicit upgrade path.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect

from core.database import engine, Base
import models.models  # noqa: F401  — registers the new tables on Base.metadata


COMPLIANCE_TABLES = [
    "compliance_frameworks",
    "compliance_controls",
    "compliance_control_mappings",
    "compliance_framework_releases",
    "org_framework_subscriptions",
    "compliance_compensating_controls",
    "compliance_control_status",
    "compliance_finding_status",
    "compliance_report_runs",
]


def upgrade():
    insp = inspect(engine)
    existing = set(insp.get_table_names())
    to_create = [
        Base.metadata.tables[t]
        for t in COMPLIANCE_TABLES
        if t not in existing
    ]
    if not to_create:
        print("Migration 047: all compliance tables already exist; nothing to do.")
        return

    Base.metadata.create_all(bind=engine, tables=to_create)
    for t in to_create:
        print(f"[+] Created table {t.name}")
    print(f"Migration 047: created {len(to_create)} compliance tables.")


def downgrade():
    insp = inspect(engine)
    existing = set(insp.get_table_names())
    # Drop in reverse FK dependency order: tenant tables first, canonical last.
    drop_order = [
        "compliance_finding_status",
        "compliance_control_status",
        "compliance_compensating_controls",
        "org_framework_subscriptions",
        "compliance_report_runs",
        "compliance_framework_releases",
        "compliance_control_mappings",
        "compliance_controls",
        "compliance_frameworks",
    ]
    to_drop = [
        Base.metadata.tables[t]
        for t in drop_order
        if t in existing
    ]
    if not to_drop:
        print("Migration 047: no compliance tables present; nothing to drop.")
        return
    Base.metadata.drop_all(bind=engine, tables=to_drop)
    for t in to_drop:
        print(f"[-] Dropped table {t.name}")
    print(f"Migration 047: dropped {len(to_drop)} compliance tables.")


if __name__ == "__main__":
    upgrade()
