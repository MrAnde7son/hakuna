"""
Migration: Add firewall_policies table for firewall rule ingestion.

Stores normalised firewall policy rules pulled from vendor integrations
(Palo Alto, Fortinet, Check Point, etc.) so Hakuna can analyse zone
segmentation, shadow rules, and overly-permissive policies.

Safe to run multiple times (checks for table existence before creating).
Works with both SQLite and PostgreSQL.

Usage:
    cd backend
    python migrations/022_add_firewall_policies.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _table_exists(conn, table: str) -> bool:
    insp = inspect(conn)
    return table in insp.get_table_names()


def upgrade():
    with engine.begin() as conn:
        if not _table_exists(conn, "firewall_policies"):
            if _is_pg:
                conn.execute(text("""
                    CREATE TABLE firewall_policies (
                        id SERIAL PRIMARY KEY,
                        org_id INTEGER NOT NULL REFERENCES organizations(id),
                        vendor VARCHAR NOT NULL,
                        source_integration_id VARCHAR REFERENCES integrations(id),
                        rule_id VARCHAR NOT NULL,
                        rule_name VARCHAR,
                        from_zone VARCHAR,
                        to_zone VARCHAR,
                        src_cidrs JSONB DEFAULT '[]',
                        dst_cidrs JSONB DEFAULT '[]',
                        applications JSONB DEFAULT '[]',
                        services JSONB DEFAULT '[]',
                        action VARCHAR NOT NULL,
                        enabled BOOLEAN DEFAULT true,
                        logged BOOLEAN DEFAULT false,
                        nat BOOLEAN DEFAULT false,
                        raw_response JSONB,
                        synced_at TIMESTAMP NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            else:
                conn.execute(text("""
                    CREATE TABLE firewall_policies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        org_id INTEGER NOT NULL REFERENCES organizations(id),
                        vendor VARCHAR NOT NULL,
                        source_integration_id VARCHAR REFERENCES integrations(id),
                        rule_id VARCHAR NOT NULL,
                        rule_name VARCHAR,
                        from_zone VARCHAR,
                        to_zone VARCHAR,
                        src_cidrs JSON DEFAULT '[]',
                        dst_cidrs JSON DEFAULT '[]',
                        applications JSON DEFAULT '[]',
                        services JSON DEFAULT '[]',
                        action VARCHAR NOT NULL,
                        enabled BOOLEAN DEFAULT 1,
                        logged BOOLEAN DEFAULT 0,
                        nat BOOLEAN DEFAULT 0,
                        raw_response JSON,
                        synced_at DATETIME NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            conn.execute(text(
                "CREATE INDEX ix_fwp_org_vendor ON firewall_policies(org_id, vendor)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_fwp_action ON firewall_policies(org_id, action)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_firewall_policies_vendor ON firewall_policies(vendor)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_firewall_policies_rule_id ON firewall_policies(rule_id)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_firewall_policies_action ON firewall_policies(action)"
            ))
            conn.execute(text(
                "CREATE UNIQUE INDEX uq_fwp_org_vendor_rule ON firewall_policies(org_id, vendor, rule_id)"
            ))
            print("[+] Created firewall_policies table with indexes")
        else:
            print("[=] firewall_policies table already exists")


def downgrade():
    with engine.begin() as conn:
        if _table_exists(conn, "firewall_policies"):
            conn.execute(text("DROP TABLE firewall_policies"))
            print("[-] Dropped firewall_policies table")


if __name__ == "__main__":
    print("Running migration: 022_add_firewall_policies")
    upgrade()
    print("Done.")
