"""GIN indexes for JSON columns now that the asset property registry exposes
them as filterable in the column picker / rule builder.

`easm_data` carries open_ports, tech_stack, dns_records, etc.; `custom_fields`
carries per-org user-defined keys. Both are queried with `?` / `@>` /
`->>` operators from the new `/api/assets/schema`-driven filter executor —
GIN makes those scans index-backed instead of seq-scan.

Postgres-only (project policy: SQLite no longer supported at runtime).
The columns are declared as JSON in SQLAlchemy but Postgres `JSON` does
not support GIN; we cast to `JSONB` first via USING clause so existing
rows are converted in place.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _column_type(conn, table: str, column: str) -> str | None:
    row = conn.execute(text(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_name = :t AND column_name = :c"
    ), {"t": table, "c": column}).fetchone()
    return row[0] if row else None


def _index_exists(conn, name: str) -> bool:
    row = conn.execute(text(
        "SELECT 1 FROM pg_indexes WHERE indexname = :n"
    ), {"n": name}).fetchone()
    return row is not None


def upgrade():
    if not _is_pg:
        print("Migration 062: Postgres only — skipped.")
        return
    with engine.begin() as conn:
        for col in ("easm_data", "custom_fields"):
            dtype = _column_type(conn, "assets", col)
            if dtype is None:
                print(f"[!] assets.{col} not found — skipping")
                continue
            if dtype != "jsonb":
                conn.execute(text(
                    f"ALTER TABLE assets ALTER COLUMN {col} TYPE jsonb USING {col}::jsonb"
                ))
                print(f"[+] assets.{col} → jsonb")

            idx = f"ix_assets_{col}_gin"
            if not _index_exists(conn, idx):
                conn.execute(text(
                    f"CREATE INDEX {idx} ON assets USING GIN ({col})"
                ))
                print(f"[+] created {idx}")
            else:
                print(f"[=] {idx} already exists")

    print("Migration 062: GIN indexes ready.")


def downgrade():
    if not _is_pg:
        return
    with engine.begin() as conn:
        for col in ("easm_data", "custom_fields"):
            idx = f"ix_assets_{col}_gin"
            conn.execute(text(f"DROP INDEX IF EXISTS {idx}"))
        print("Migration 062: indexes dropped (column type left as jsonb).")


if __name__ == "__main__":
    upgrade()
