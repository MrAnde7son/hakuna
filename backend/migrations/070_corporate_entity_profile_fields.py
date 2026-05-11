"""Add company-profile fields to ``corporate_entities`` so the EASM pipeline
can auto-fill onboarding gaps (industry, size, founding year, homepage) from
Wikidata.

Today ``corporate_entities`` only carries legal/jurisdictional fields from
GLEIF and Wikidata's relationship graph — no industry classification, no
employee headcount, no founding year. Onboarding collects ``industry`` and
``org_size`` into ``organizations.settings['onboarding']['profile']`` as
free-form JSON; users who skip the wizard leave it blank and downstream
benchmarks/cohorts fall back to ``industry='all'``.

This migration is the storage half of the fix. The Wikidata sync extension
populates these columns; an ``effective_company_profile`` helper merges
user-set onboarding values (which always win) with the fetched fallback.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

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


_NEW_COLUMNS = (
    # Free-form for v1 — the Wikidata P452 label is a string. A controlled
    # taxonomy (NAICS) can be layered later via a lookup table without
    # reshaping this column.
    ("industry", "VARCHAR(255)"),
    # Banded rather than raw int because Wikidata P1128 values are often
    # years stale; bands let us be useful without overclaiming precision.
    # Values: '1-10' | '11-50' | '51-200' | '201-1000' | '1k-10k' | '10k+'.
    ("employee_count_band", "VARCHAR(16)"),
    ("founded_year", "INTEGER"),
    ("homepage_url", "VARCHAR(512)"),
)


def upgrade():
    with engine.begin() as conn:
        for col, ddl in _NEW_COLUMNS:
            if not _column_exists(conn, "corporate_entities", col):
                conn.execute(text(
                    f"ALTER TABLE corporate_entities ADD COLUMN {col} {ddl}"
                ))
                print(f"[+] corporate_entities.{col} added")


def downgrade():
    with engine.begin() as conn:
        for col, _ddl in reversed(_NEW_COLUMNS):
            if _column_exists(conn, "corporate_entities", col):
                conn.execute(text(
                    f"ALTER TABLE corporate_entities DROP COLUMN {col}"
                ))
                print(f"[-] corporate_entities.{col} dropped")


if __name__ == "__main__":
    print("Running migration: 070_corporate_entity_profile_fields")
    upgrade()
    print("Done.")
