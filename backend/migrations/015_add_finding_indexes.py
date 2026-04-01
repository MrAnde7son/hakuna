"""
Migration: Add performance indexes to findings and assets tables.

Creates indexes on frequently queried columns in the findings and assets
tables to improve dashboard, filtering, and reporting query performance.

Safe to run multiple times. Works with SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/015_add_finding_indexes.py
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sqlalchemy import text, inspect
from core.database import engine

_is_pg = "postgresql" in str(engine.url)


def _index_exists(conn, index_name: str) -> bool:
    """Check whether an index already exists across all tables."""
    insp = inspect(conn)
    for table in insp.get_table_names():
        for idx in insp.get_indexes(table):
            if idx["name"] == index_name:
                return True
    return False


def upgrade():
    indexes = [
        ("ix_findings_scan_id", "findings", "scan_id"),
        ("ix_findings_asset_id", "findings", "asset_id"),
        ("ix_findings_severity", "findings", "severity"),
        ("ix_findings_priority_score", "findings", "priority_score"),
        ("ix_findings_sla_status", "findings", "sla_status"),
        ("ix_findings_workflow_status", "findings", "workflow_status"),
        ("ix_findings_exploit_available", "findings", "exploit_available"),
        ("ix_findings_scan_severity", "findings", "scan_id, severity"),
        ("ix_findings_scan_sla", "findings", "scan_id, sla_status"),
        ("ix_assets_scan_id", "assets", "scan_id"),
        ("ix_assets_risk_score", "assets", "risk_score"),
    ]
    with engine.begin() as conn:
        for idx_name, table, cols in indexes:
            if not _index_exists(conn, idx_name):
                conn.execute(text(f"CREATE INDEX {idx_name} ON {table} ({cols})"))
                print(f"  Created index {idx_name}")
            else:
                print(f"  Index {idx_name} already exists, skipping")


def downgrade():
    index_names = [
        "ix_findings_scan_id",
        "ix_findings_asset_id",
        "ix_findings_severity",
        "ix_findings_priority_score",
        "ix_findings_sla_status",
        "ix_findings_workflow_status",
        "ix_findings_exploit_available",
        "ix_findings_scan_severity",
        "ix_findings_scan_sla",
        "ix_assets_scan_id",
        "ix_assets_risk_score",
    ]
    with engine.begin() as conn:
        for idx_name in index_names:
            if _index_exists(conn, idx_name):
                conn.execute(text(f"DROP INDEX {idx_name}"))
                print(f"  Dropped index {idx_name}")


if __name__ == "__main__":
    print("Adding performance indexes to findings and assets tables...")
    upgrade()
    print("Done.")
