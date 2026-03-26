"""
Migration: Add security control validation tables.

Creates security_control_policies, security_control_policy_assignments,
control_assessments. Adds control_mitigation_status and control_mitigation_summary
to findings.

Safe to run multiple times. Works with SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/014_add_control_validation.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine

_is_pg = "postgresql" in str(engine.url)
_PK = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"


def _table_exists(conn, table: str) -> bool:
    insp = inspect(conn)
    return table in insp.get_table_names()


def _column_exists(conn, table: str, column: str) -> bool:
    insp = inspect(conn)
    cols = [c["name"] for c in insp.get_columns(table)]
    return column in cols


def upgrade():
    with engine.connect() as conn:
        # 1. security_control_policies
        if not _table_exists(conn, "security_control_policies"):
            conn.execute(text(f"""
                CREATE TABLE security_control_policies (
                    id {_PK},
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    product_key VARCHAR NOT NULL,
                    product_name VARCHAR,
                    vendor VARCHAR,
                    policy_external_id VARCHAR,
                    policy_name VARCHAR,
                    policy_type VARCHAR,
                    settings JSON NOT NULL,
                    raw_response JSON,
                    source_integration_id VARCHAR REFERENCES integrations(id),
                    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(org_id, product_key, policy_external_id)
                )
            """))
            conn.execute(text("CREATE INDEX ix_scp_org ON security_control_policies(org_id)"))
            conn.execute(text("CREATE INDEX ix_scp_product ON security_control_policies(product_key)"))
            conn.execute(text("CREATE INDEX ix_scp_type ON security_control_policies(policy_type)"))
            conn.execute(text("CREATE INDEX ix_scp_org_product ON security_control_policies(org_id, product_key)"))
            print("Created security_control_policies table.")
        else:
            print("security_control_policies table already exists, skipping.")

        # 2. security_control_policy_assignments
        if not _table_exists(conn, "security_control_policy_assignments"):
            conn.execute(text(f"""
                CREATE TABLE security_control_policy_assignments (
                    id {_PK},
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    policy_id INTEGER NOT NULL REFERENCES security_control_policies(id),
                    asset_id INTEGER NOT NULL REFERENCES assets(id),
                    assignment_source VARCHAR,
                    source_group_id VARCHAR,
                    source_group_name VARCHAR,
                    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(policy_id, asset_id)
                )
            """))
            conn.execute(text("CREATE INDEX ix_scpa_org ON security_control_policy_assignments(org_id)"))
            conn.execute(text("CREATE INDEX ix_scpa_policy ON security_control_policy_assignments(policy_id)"))
            conn.execute(text("CREATE INDEX ix_scpa_asset ON security_control_policy_assignments(asset_id)"))
            conn.execute(text("CREATE INDEX ix_scpa_org_asset ON security_control_policy_assignments(org_id, asset_id)"))
            print("Created security_control_policy_assignments table.")
        else:
            print("security_control_policy_assignments table already exists, skipping.")

        # 3. control_assessments
        if not _table_exists(conn, "control_assessments"):
            conn.execute(text(f"""
                CREATE TABLE control_assessments (
                    id {_PK},
                    org_id INTEGER NOT NULL REFERENCES organizations(id),
                    finding_id INTEGER NOT NULL REFERENCES findings(id),
                    asset_id INTEGER NOT NULL REFERENCES assets(id),
                    policy_id INTEGER NOT NULL REFERENCES security_control_policies(id),
                    verdict VARCHAR NOT NULL,
                    confidence VARCHAR NOT NULL,
                    explanation TEXT NOT NULL,
                    matched_techniques JSON DEFAULT '[]',
                    policy_settings_snapshot JSON,
                    assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(finding_id, policy_id)
                )
            """))
            conn.execute(text("CREATE INDEX ix_ca_org ON control_assessments(org_id)"))
            conn.execute(text("CREATE INDEX ix_ca_finding ON control_assessments(org_id, finding_id)"))
            conn.execute(text("CREATE INDEX ix_ca_asset ON control_assessments(org_id, asset_id)"))
            conn.execute(text("CREATE INDEX ix_ca_policy ON control_assessments(policy_id)"))
            print("Created control_assessments table.")
        else:
            print("control_assessments table already exists, skipping.")

        # 4. ALTER findings: add control validation columns
        if _table_exists(conn, "findings"):
            for col in ["control_mitigation_status", "control_mitigation_summary"]:
                if not _column_exists(conn, "findings", col):
                    conn.execute(text(f"ALTER TABLE findings ADD COLUMN {col} VARCHAR"))
                    print(f"Added {col} to findings.")
                else:
                    print(f"{col} already exists on findings, skipping.")

        conn.commit()
        print("Migration 014 complete.")


def downgrade():
    with engine.connect() as conn:
        for table in ["control_assessments", "security_control_policy_assignments", "security_control_policies"]:
            if _table_exists(conn, table):
                conn.execute(text(f"DROP TABLE {table}"))
                print(f"Dropped {table}.")
        conn.commit()


if __name__ == "__main__":
    upgrade()
