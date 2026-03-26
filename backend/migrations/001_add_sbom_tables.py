"""
Migration: Add SBOM tables (sbom_components, sbom_vulnerabilities)

This migration creates the SBOM tables. It is safe to run multiple times
(uses IF NOT EXISTS). Normally these tables are auto-created by
Base.metadata.create_all() in init_db(), but this script can be used
for explicit migration in production environments.

Usage:
    cd backend
    python migrations/001_add_sbom_tables.py
"""

import os
import sys

# Allow running from backend/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine

_is_pg = "postgresql" in str(engine.url)
_PK = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"


def upgrade():
    with engine.connect() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS sbom_components (
                id {_PK},
                scan_id INTEGER NOT NULL REFERENCES scans(id),
                asset_id INTEGER NOT NULL REFERENCES assets(id),
                software_id INTEGER REFERENCES inventory_software(id),
                name VARCHAR,
                version VARCHAR,
                vendor VARCHAR,
                cpe VARCHAR,
                purl VARCHAR,
                component_type VARCHAR,
                parent_component_id INTEGER REFERENCES sbom_components(id),
                is_running BOOLEAN DEFAULT 0,
                eol_date VARCHAR,
                eol_status VARCHAR DEFAULT 'unknown',
                cve_count INTEGER DEFAULT 0,
                max_severity INTEGER DEFAULT 0,
                max_cvss FLOAT,
                priority_tier VARCHAR,
                source_plugin VARCHAR,
                UNIQUE (scan_id, asset_id, name, version)
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_sbom_components_scan_id
            ON sbom_components(scan_id)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_sbom_components_asset_id
            ON sbom_components(asset_id)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_sbom_components_name
            ON sbom_components(name)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_sbom_components_component_type
            ON sbom_components(component_type)
        """))

        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS sbom_vulnerabilities (
                id {_PK},
                component_id INTEGER NOT NULL REFERENCES sbom_components(id),
                finding_id INTEGER REFERENCES findings(id),
                cve_id VARCHAR,
                severity INTEGER DEFAULT 0,
                cvss_score FLOAT,
                epss_score FLOAT,
                in_kev BOOLEAN DEFAULT 0,
                remediation_note TEXT,
                priority_tier VARCHAR,
                UNIQUE (component_id, cve_id)
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_sbom_vulnerabilities_component_id
            ON sbom_vulnerabilities(component_id)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_sbom_vulnerabilities_cve_id
            ON sbom_vulnerabilities(cve_id)
        """))

        conn.commit()
        print("Migration complete: sbom_components and sbom_vulnerabilities tables created.")


def downgrade():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS sbom_vulnerabilities"))
        conn.execute(text("DROP TABLE IF EXISTS sbom_components"))
        conn.commit()
        print("Downgrade complete: sbom tables dropped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--downgrade", action="store_true")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    else:
        upgrade()
