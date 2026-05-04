"""Make compliance_frameworks tenant-aware.

Adds three columns:
  - org_id      : NULL for built-in (YAML-loaded) frameworks; set for
                  tenant-imported frameworks.
  - created_by  : user who imported a tenant-private framework (NULL for builtins).
  - source      : 'builtin' | 'imported' — lets the UI label rows without
                  reasoning about org_id semantics.

Replaces the simple UNIQUE(slug) constraint with two partial unique indexes:
  - UNIQUE(slug) WHERE org_id IS NULL    — global slug namespace
  - UNIQUE(slug, org_id) WHERE org_id IS NOT NULL  — per-tenant namespace

This lets a tenant carry their own customised "iso_27001_2022" alongside
the global one without colliding. Lookups should prefer the tenant copy
when present and fall back to global.

Postgres-only (project policy: SQLite no longer supported at runtime).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _column_exists(conn, table: str, column: str) -> bool:
    row = conn.execute(text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = :t AND column_name = :c"
    ), {"t": table, "c": column}).fetchone()
    return row is not None


def _index_exists(conn, name: str) -> bool:
    row = conn.execute(text(
        "SELECT 1 FROM pg_indexes WHERE indexname = :n"
    ), {"n": name}).fetchone()
    return row is not None


def _constraint_exists(conn, table: str, name: str) -> bool:
    row = conn.execute(text(
        "SELECT 1 FROM information_schema.table_constraints "
        "WHERE table_name = :t AND constraint_name = :n"
    ), {"t": table, "n": name}).fetchone()
    return row is not None


def upgrade():
    if not _is_pg:
        raise RuntimeError("migration 060 requires Postgres")

    with engine.begin() as conn:
        if not _column_exists(conn, "compliance_frameworks", "org_id"):
            conn.execute(text(
                "ALTER TABLE compliance_frameworks "
                "ADD COLUMN org_id INTEGER NULL "
                "REFERENCES organizations(id) ON DELETE CASCADE"
            ))
            print("[+] compliance_frameworks.org_id added")

        if not _column_exists(conn, "compliance_frameworks", "created_by"):
            conn.execute(text(
                "ALTER TABLE compliance_frameworks "
                "ADD COLUMN created_by INTEGER NULL "
                "REFERENCES users(id) ON DELETE SET NULL"
            ))
            print("[+] compliance_frameworks.created_by added")

        if not _column_exists(conn, "compliance_frameworks", "source"):
            conn.execute(text(
                "ALTER TABLE compliance_frameworks "
                "ADD COLUMN source VARCHAR(32) NOT NULL DEFAULT 'builtin'"
            ))
            print("[+] compliance_frameworks.source added (default 'builtin')")

        # Drop any old simple-unique on slug. SQLAlchemy historically emitted
        # this in two shapes depending on whether unique=True hit the column-
        # level constraint path or merged with index=True into a unique index.
        # We have to clean up both: a CONSTRAINT (table-level) and an INDEX.
        for name in (
            "compliance_frameworks_slug_key",   # PG default for column-level unique
            "uq_compliance_frameworks_slug",
        ):
            if _constraint_exists(conn, "compliance_frameworks", name):
                conn.execute(text(
                    f"ALTER TABLE compliance_frameworks DROP CONSTRAINT IF EXISTS {name}"
                ))
                print(f"[-] dropped constraint {name}")

        # Re-create ix_compliance_frameworks_slug as a NON-unique index. The
        # original was UNIQUE because Column(unique=True, index=True) merged
        # both flags into a single unique btree. Tenant-private packs need to
        # share slugs with builtins, so we replace it with a plain lookup index
        # — uniqueness is enforced by the partial indexes added below.
        if _index_exists(conn, "ix_compliance_frameworks_slug"):
            conn.execute(text("DROP INDEX IF EXISTS ix_compliance_frameworks_slug"))
            print("[-] dropped (unique) ix_compliance_frameworks_slug")
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_compliance_frameworks_slug "
            "ON compliance_frameworks (slug)"
        ))
        print("[+] ix_compliance_frameworks_slug recreated as non-unique")

        if not _index_exists(conn, "uq_compliance_frameworks_slug_global"):
            conn.execute(text(
                "CREATE UNIQUE INDEX uq_compliance_frameworks_slug_global "
                "ON compliance_frameworks (slug) WHERE org_id IS NULL"
            ))
            print("[+] uq_compliance_frameworks_slug_global created")

        if not _index_exists(conn, "uq_compliance_frameworks_slug_tenant"):
            conn.execute(text(
                "CREATE UNIQUE INDEX uq_compliance_frameworks_slug_tenant "
                "ON compliance_frameworks (slug, org_id) WHERE org_id IS NOT NULL"
            ))
            print("[+] uq_compliance_frameworks_slug_tenant created")

        if not _index_exists(conn, "ix_compliance_frameworks_org_id"):
            conn.execute(text(
                "CREATE INDEX ix_compliance_frameworks_org_id "
                "ON compliance_frameworks (org_id)"
            ))
            print("[+] ix_compliance_frameworks_org_id created")

        # Backfill: every existing row pre-migration is a builtin global pack.
        # The DEFAULT clause covered new inserts; this covers any rows that
        # were created without source set (defensive — Postgres would already
        # have applied the default, but explicit beats clever here).
        conn.execute(text(
            "UPDATE compliance_frameworks SET source = 'builtin' "
            "WHERE source IS NULL OR source = ''"
        ))

        # ── compliance_frameworks: widen (slug, version) UNIQUE to include org_id ──
        # Without this, a tenant importing a pack whose (slug, version)
        # matches an existing builtin would hit the old constraint even
        # though their org_id differs.
        if _constraint_exists(conn, "compliance_frameworks",
                              "uq_compliance_framework_slug_version"):
            conn.execute(text(
                "ALTER TABLE compliance_frameworks "
                "DROP CONSTRAINT uq_compliance_framework_slug_version"
            ))
            print("[-] dropped uq_compliance_framework_slug_version")
        if not _constraint_exists(conn, "compliance_frameworks",
                                  "uq_compliance_framework_slug_version_org"):
            conn.execute(text(
                "ALTER TABLE compliance_frameworks "
                "ADD CONSTRAINT uq_compliance_framework_slug_version_org "
                "UNIQUE (slug, version, org_id)"
            ))
            print("[+] added uq_compliance_framework_slug_version_org")

        # ── compliance_control_mappings: scope mapping_key per control ──
        # The original UNIQUE(mapping_key) prevented two tenants from importing
        # the same pack — they'd collide on the second import. Replace with
        # UNIQUE(control_id, mapping_key); compliance_finding_status already
        # carries control_id so its (finding_id, control_id, mapping_key)
        # constraint stays unambiguous.
        if _constraint_exists(conn, "compliance_control_mappings",
                              "uq_compliance_control_mapping_key"):
            conn.execute(text(
                "ALTER TABLE compliance_control_mappings "
                "DROP CONSTRAINT uq_compliance_control_mapping_key"
            ))
            print("[-] dropped uq_compliance_control_mapping_key")
        if not _constraint_exists(conn, "compliance_control_mappings",
                                  "uq_compliance_control_mapping_control_key"):
            conn.execute(text(
                "ALTER TABLE compliance_control_mappings "
                "ADD CONSTRAINT uq_compliance_control_mapping_control_key "
                "UNIQUE (control_id, mapping_key)"
            ))
            print("[+] added uq_compliance_control_mapping_control_key")

    print("Migration 060: compliance_frameworks is now tenant-aware.")


def downgrade():
    if not _is_pg:
        return
    with engine.begin() as conn:
        for idx in (
            "uq_compliance_frameworks_slug_global",
            "uq_compliance_frameworks_slug_tenant",
            "ix_compliance_frameworks_org_id",
        ):
            conn.execute(text(f"DROP INDEX IF EXISTS {idx}"))

        # Refuse to drop columns if any tenant-private rows exist — silently
        # losing imported frameworks would be bad.
        cnt = conn.execute(text(
            "SELECT COUNT(*) FROM compliance_frameworks WHERE org_id IS NOT NULL"
        )).scalar()
        if cnt:
            raise RuntimeError(
                f"downgrade aborted: {cnt} tenant-private frameworks present; "
                "delete them via the API or DB first"
            )

        conn.execute(text("ALTER TABLE compliance_frameworks DROP COLUMN IF EXISTS source"))
        conn.execute(text("ALTER TABLE compliance_frameworks DROP COLUMN IF EXISTS created_by"))
        conn.execute(text("ALTER TABLE compliance_frameworks DROP COLUMN IF EXISTS org_id"))
        conn.execute(text(
            "ALTER TABLE compliance_frameworks "
            "ADD CONSTRAINT compliance_frameworks_slug_key UNIQUE (slug)"
        ))
        print("Migration 060: reverted.")


if __name__ == "__main__":
    upgrade()
