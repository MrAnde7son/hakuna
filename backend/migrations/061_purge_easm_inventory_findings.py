"""Purge inventory-as-Finding rows now that DNS records, open ports, and
detected technologies are read directly from `Asset.easm_data` instead of
fanned out into the `findings` table.

Removes:
  - plugin_id LIKE 'EASM-PORT-%'      (one Info finding per open port)
  - plugin_id LIKE 'EASM-TECH-%'      (one Info finding per detected tech)
  - plugin_id = 'EASM-DNS-RECORDS'    (single Info bundle of all DNS records)

Real exposures stay: EASM-EXPOSED-DB-*, EASM-SUBDOMAIN-TAKEOVER,
EASM-TLS-*, EASM-HTTP-HEADER-WEAK, EASM-COOKIE-WEAK, etc. are not touched.

Downgrade is a no-op — the rows are regenerated on next EASM scan if
their emission code is ever restored.

Postgres-only (project policy: SQLite no longer supported at runtime).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


_TARGET_PREDICATE = """
    source_type = 'easm'
    AND (
         plugin_id LIKE 'EASM-PORT-%'
      OR plugin_id LIKE 'EASM-TECH-%'
      OR plugin_id = 'EASM-DNS-RECORDS'
    )
"""

# Tables that reference findings.id without ON DELETE CASCADE. These must be
# cleared explicitly before the parent rows can be removed. Tables already
# wired with CASCADE (compliance_finding_status, finding_observations,
# finding_tickets, tag_assignments) do not need an explicit step.
_NON_CASCADE_DEPENDENTS = (
    "automate_clicks",
    "campaign_findings",
    "control_assessments",
    "finding_ownership",
    "sbom_vulnerabilities",
)


def upgrade():
    if not _is_pg:
        print("Migration 061: Postgres only — skipped.")
        return
    with engine.begin() as conn:
        target_ids_sql = f"SELECT id FROM findings WHERE {_TARGET_PREDICATE}"
        for table in _NON_CASCADE_DEPENDENTS:
            r = conn.execute(text(
                f"DELETE FROM {table} WHERE finding_id IN ({target_ids_sql})"
            ))
            if r.rowcount:
                print(f"[+] {table}: cleared {r.rowcount} dependent rows")
        result = conn.execute(text(f"DELETE FROM findings WHERE {_TARGET_PREDICATE}"))
        print(f"Migration 061: purged {result.rowcount} inventory-as-Finding rows.")


def downgrade():
    print("Migration 061: no-op (rows would be regenerated on rescan if emission restored).")


if __name__ == "__main__":
    upgrade()
