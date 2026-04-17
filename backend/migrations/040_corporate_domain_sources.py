"""Add domain_sources JSON column to corporate_entities.

Tracks per-domain provenance so the EASM subsidiary fan-out can scan only
high-confidence domains (wikidata_official, easm_name_match) automatically
and surface low-confidence ones (dns_probe) for operator confirmation.

Shape: {"acme.com": "wikidata_official", "foo.com": "dns_probe"}
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def upgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text(
                "ALTER TABLE corporate_entities "
                "ADD COLUMN IF NOT EXISTS domain_sources JSONB DEFAULT '{}'::jsonb"
            ))
        else:
            cols = conn.execute(text("PRAGMA table_info(corporate_entities)")).fetchall()
            if not any(c[1] == "domain_sources" for c in cols):
                conn.execute(text(
                    "ALTER TABLE corporate_entities ADD COLUMN domain_sources JSON DEFAULT '{}'"
                ))
    print("Migration 040: corporate_entities.domain_sources added.")


def downgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("ALTER TABLE corporate_entities DROP COLUMN IF EXISTS domain_sources"))
        else:
            # SQLite pre-3.35 cannot drop columns; leave as-is on downgrade.
            pass
    print("Migration 040: corporate_entities.domain_sources dropped (pg) / noop (sqlite).")


if __name__ == "__main__":
    upgrade()
