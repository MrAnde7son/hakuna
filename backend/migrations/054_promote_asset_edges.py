"""Promote `asset_relationships` to the unified edge substrate.

Phase 1 of the Cross-Scan Chain Coordinator (see
`docs/cross-scan-chain-coordinator-plan.md`). Existing infrastructure
relationships (resolves_to, shares_certificate, …) keep working; new edge
families (internet_to_asset, cve_on_asset, asset_to_asset_coerce, …) write
to the same table.

Schema changes:
- `source_asset_id`, `target_asset_id` → nullable (internet pseudo-source,
  domain/identity sinks).
- `enabled_by_findings` JSON[] — finding ids that justify the edge.
- `source_system` VARCHAR — producer tag (easm, vm_scanner, audit_agent, …).
- `last_seen_at` TIMESTAMP — re-observation time, distinct from updated_at.
- `properties_hash` VARCHAR(64) — sha256 of the canonical properties JSON,
  needed so multi-property edges (e.g. internet_to_asset port=443 vs port=22)
  don't collide on the unique key.
- New unique constraint includes `properties_hash`.
- Composite indexes on (org_id, relationship_type) and (source_system, last_seen_at).

Safe to run multiple times.
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


def _table_exists(conn, table: str) -> bool:
    return table in inspect(conn).get_table_names()


def _constraint_exists(conn, name: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM pg_constraint WHERE conname = :n"
        ), {"n": name}).fetchone()
        return row is not None
    return False  # SQLite — we can't easily introspect; rely on best-effort drop


def _index_exists(conn, name: str) -> bool:
    if _is_pg:
        row = conn.execute(text(
            "SELECT 1 FROM pg_indexes WHERE indexname = :n"
        ), {"n": name}).fetchone()
        return row is not None
    rows = conn.execute(text(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = :n"
    ), {"n": name}).fetchall()
    return bool(rows)


def upgrade():
    with engine.begin() as conn:
        if not _table_exists(conn, "asset_relationships"):
            print("[!] asset_relationships not found — nothing to promote.")
            return

        # 1. Drop NOT NULL on src/dst (nullable for internet/domain pseudo-endpoints)
        if _is_pg:
            conn.execute(text(
                "ALTER TABLE asset_relationships ALTER COLUMN source_asset_id DROP NOT NULL"
            ))
            conn.execute(text(
                "ALTER TABLE asset_relationships ALTER COLUMN target_asset_id DROP NOT NULL"
            ))
            print("[+] Made source_asset_id / target_asset_id nullable")
        else:
            # SQLite ALTER COLUMN is a tablerebuild dance; skip — dev DB only.
            print("[=] SQLite: nullability change skipped (rebuild required)")

        # 2. New columns
        json_type = "JSONB" if _is_pg else "JSON"
        json_default = "'[]'::jsonb" if _is_pg else "'[]'"
        ts_type = "TIMESTAMP" if _is_pg else "DATETIME"

        if not _column_exists(conn, "asset_relationships", "enabled_by_findings"):
            conn.execute(text(
                f"ALTER TABLE asset_relationships "
                f"ADD COLUMN enabled_by_findings {json_type} DEFAULT {json_default}"
            ))
            print("[+] Added asset_relationships.enabled_by_findings")

        if not _column_exists(conn, "asset_relationships", "source_system"):
            conn.execute(text(
                "ALTER TABLE asset_relationships ADD COLUMN source_system VARCHAR(64)"
            ))
            print("[+] Added asset_relationships.source_system")

        if not _column_exists(conn, "asset_relationships", "last_seen_at"):
            conn.execute(text(
                f"ALTER TABLE asset_relationships ADD COLUMN last_seen_at {ts_type}"
            ))
            # Backfill last_seen_at from updated_at for existing rows so the
            # column is queryable without NULL handling everywhere.
            conn.execute(text(
                "UPDATE asset_relationships SET last_seen_at = updated_at "
                "WHERE last_seen_at IS NULL"
            ))
            print("[+] Added asset_relationships.last_seen_at (backfilled from updated_at)")

        if not _column_exists(conn, "asset_relationships", "properties_hash"):
            conn.execute(text(
                "ALTER TABLE asset_relationships ADD COLUMN properties_hash VARCHAR(64) "
                "NOT NULL DEFAULT ''"
            ))
            print("[+] Added asset_relationships.properties_hash")

            # Backfill — legacy writers (knowledge_graph.py,
            # asset_relationship_engine.py) stored properties without a
            # hash. Compute a hash for any non-empty `properties` so
            # the new unique index doesn't accidentally collide future
            # upsert_edge writes with old rows.
            from services.asset_edges import compute_properties_hash
            rows = conn.execute(text(
                "SELECT id, properties FROM asset_relationships "
                "WHERE properties IS NOT NULL"
            )).fetchall()
            updated = 0
            for row in rows:
                rid, props = row[0], row[1]
                if not props or props == {}:
                    continue
                props_dict = props if isinstance(props, dict) else None
                if props_dict is None:
                    # JSON column may surface as a string in some drivers
                    try:
                        import json as _json
                        props_dict = _json.loads(props)
                    except Exception:
                        continue
                h = compute_properties_hash(props_dict)
                if h:
                    conn.execute(
                        text("UPDATE asset_relationships SET properties_hash = :h WHERE id = :i"),
                        {"h": h, "i": rid},
                    )
                    updated += 1
            if updated:
                print(f"[+] Backfilled properties_hash on {updated} legacy rows")

        # 3. Replace the old unique constraint. The existing
        # uq_asset_relationship is (org_id, source_asset_id, target_asset_id,
        # relationship_type) — promote to include properties_hash so
        # multi-property edges (port=443 vs port=22) don't collide.
        if _is_pg:
            if _constraint_exists(conn, "uq_asset_relationship"):
                conn.execute(text(
                    "ALTER TABLE asset_relationships DROP CONSTRAINT uq_asset_relationship"
                ))
                print("[+] Dropped old uq_asset_relationship")
            if not _constraint_exists(conn, "uq_asset_edge"):
                # In Postgres a UNIQUE constraint treats NULLs as distinct —
                # use a partial unique index on COALESCE'd surrogate values
                # so (NULL, asset, internet_to_asset, "") still dedupes.
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_edge "
                    "ON asset_relationships ("
                    "  org_id, "
                    "  COALESCE(source_asset_id, 0), "
                    "  COALESCE(target_asset_id, 0), "
                    "  relationship_type, "
                    "  properties_hash"
                    ")"
                ))
                print("[+] Created uq_asset_edge unique index")

        # 4. Helpful indexes for edge-type queries
        if not _index_exists(conn, "ix_asset_edge_type"):
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_asset_edge_type "
                "ON asset_relationships (org_id, relationship_type)"
            ))
            print("[+] Created ix_asset_edge_type")

        if not _index_exists(conn, "ix_asset_edge_source_system"):
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_asset_edge_source_system "
                "ON asset_relationships (source_system, last_seen_at)"
            ))
            print("[+] Created ix_asset_edge_source_system")


def downgrade():
    with engine.begin() as conn:
        if not _table_exists(conn, "asset_relationships"):
            return
        if _is_pg:
            for idx in ("ix_asset_edge_type", "ix_asset_edge_source_system", "uq_asset_edge"):
                conn.execute(text(f"DROP INDEX IF EXISTS {idx}"))
            for col in ("enabled_by_findings", "source_system", "last_seen_at", "properties_hash"):
                if _column_exists(conn, "asset_relationships", col):
                    conn.execute(text(f"ALTER TABLE asset_relationships DROP COLUMN {col}"))
            # Re-add legacy unique constraint
            conn.execute(text(
                "ALTER TABLE asset_relationships ADD CONSTRAINT uq_asset_relationship "
                "UNIQUE (org_id, source_asset_id, target_asset_id, relationship_type)"
            ))
        else:
            print("SQLite: downgrade skipped (column drops require table rebuild)")


if __name__ == "__main__":
    print("Running migration: 054_promote_asset_edges")
    upgrade()
    print("Done.")
