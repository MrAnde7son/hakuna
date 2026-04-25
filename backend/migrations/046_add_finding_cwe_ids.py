"""Add cwe_ids and cwe_names to findings.

CWE is the scanner-agnostic taxonomy compliance mappings key off. Scanner
parsers populate it at ingest when available (Nuclei classification.cwe-id,
EASM finding-type registry). The CVE→CWE propagation in
threat_intel_sync.enrich_findings_from_threat_intel backfills any finding
that carries a CVE by joining ThreatCVE.cwe_ids.

Two separate JSON columns so the list used for rule evaluation stays
machine-ids-only while cwe_names carries human strings for UI display
without a join.
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
        if not _column_exists(conn, "findings", "cwe_ids"):
            default = "'[]'::json" if _is_pg else "'[]'"
            conn.execute(text(
                f"ALTER TABLE findings ADD COLUMN cwe_ids JSON NOT NULL DEFAULT {default}"
            ))
            print("[+] Added findings.cwe_ids")

        if not _column_exists(conn, "findings", "cwe_names"):
            default = "'[]'::json" if _is_pg else "'[]'"
            conn.execute(text(
                f"ALTER TABLE findings ADD COLUMN cwe_names JSON NOT NULL DEFAULT {default}"
            ))
            print("[+] Added findings.cwe_names")

    print("Migration 046: cwe_ids and cwe_names added to findings.")


def downgrade():
    if not _is_pg:
        print("Migration 046: SQLite downgrade skipped (DROP COLUMN requires 3.35+).")
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE findings DROP COLUMN IF EXISTS cwe_ids"))
        conn.execute(text("ALTER TABLE findings DROP COLUMN IF EXISTS cwe_names"))
    print("Migration 046: cwe_ids and cwe_names dropped.")


if __name__ == "__main__":
    upgrade()
