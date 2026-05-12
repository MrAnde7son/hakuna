"""Rewrite every FK pointing at a tenant-scoped parent table to use
``ON DELETE CASCADE`` so deleting an organization (or any of its scans,
users, assets, etc.) prunes child rows automatically.

Background: the previous ``DELETE /api/orgs/{id}`` handler tried to
disable referential-integrity triggers via
``SET session_replication_role = 'replica'``. That requires PostgreSQL
superuser, which Cloud SQL never grants — so org delete was broken in
production. Adding proper cascades on the FKs removes the privilege
dependency and lets ``db.delete(org)`` do its job.

We rewrite FKs whose ``ON DELETE`` action is NO ACTION or RESTRICT
(``confdeltype IN ('a', 'r')``). FKs that were deliberately set to
``CASCADE`` or ``SET NULL`` are left alone — those are intentional
decisions (e.g. ``attack_paths.entry_asset_id`` uses ``SET NULL`` so
the path record survives when an asset gets pruned).

Self-referential FKs (``organizations.parent_org_id`` →
``organizations.id``) are skipped — cascading would auto-delete every
sub-org when an MSSP parent is removed, which is almost never what an
operator wants.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from core.database import engine, DATABASE_URL


# Always-cascade parent tables — referenced via non-``org_id`` FKs that
# still need to vanish when the org goes (users own audit rows, scans
# own findings/assets/inventories, etc.). Discovered tenant tables
# (any table with an ``org_id`` column) are added to this set at
# runtime; this constant lists the structural roots that the
# auto-discovery can't infer.
_ALWAYS_CASCADE = {
    "organizations",
    "users",
    "scans",
    "assets",
    "findings",
    "agents",
    "agent_runs",
    "workflows",
    "campaigns",
    "integrations",
    "custom_roles",
}


def _is_pg() -> bool:
    return DATABASE_URL.startswith("postgresql")


def _tenant_target_tables(conn) -> set[str]:
    """Every public-schema table that holds tenant data — i.e. has an
    ``org_id`` column. Their child FKs must cascade so the org delete
    can prune the whole tree."""
    rows = conn.execute(
        text(
            """
            SELECT DISTINCT table_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND column_name = 'org_id'
            """
        )
    ).fetchall()
    return {r[0] for r in rows}


def upgrade():
    if not _is_pg():
        # SQLite doesn't support ALTER TABLE ... DROP CONSTRAINT and is
        # only used by tests with fresh schemas; the model-level
        # ondelete="CASCADE" will be honoured there.
        print("[=] skipping (non-postgres)")
        return

    with engine.begin() as conn:
        targets = sorted(_tenant_target_tables(conn) | _ALWAYS_CASCADE)
        print(f"[+] cascading FKs into {len(targets)} parent tables")
        rows = conn.execute(
            text(
                """
                SELECT
                  con.conname AS conname,
                  cl.relname AS table_name,
                  cr.relname AS ref_table,
                  pg_get_constraintdef(con.oid) AS constraintdef
                FROM pg_constraint con
                JOIN pg_class cl ON cl.oid = con.conrelid
                JOIN pg_class cr ON cr.oid = con.confrelid
                JOIN pg_namespace ns ON ns.oid = cl.relnamespace
                WHERE con.contype = 'f'
                  AND ns.nspname = 'public'
                  AND cr.relname = ANY(:targets)
                  AND cl.oid <> cr.oid
                  AND con.confdeltype IN ('a', 'r')
                ORDER BY cl.relname, con.conname
                """
            ),
            {"targets": targets},
        ).fetchall()

        if not rows:
            print("[=] all FKs already CASCADE/SET NULL — nothing to do")
            return

        print(f"[+] rewriting {len(rows)} FK constraints to ON DELETE CASCADE")
        for r in rows:
            # pg_get_constraintdef returns e.g.
            #   FOREIGN KEY (org_id) REFERENCES organizations(id)
            # Just append the action.
            new_def = f"{r.constraintdef} ON DELETE CASCADE"
            conn.execute(
                text(
                    f'ALTER TABLE "{r.table_name}" '
                    f'DROP CONSTRAINT "{r.conname}"'
                )
            )
            conn.execute(
                text(
                    f'ALTER TABLE "{r.table_name}" '
                    f'ADD CONSTRAINT "{r.conname}" {new_def}'
                )
            )
            print(f"    {r.table_name}.{r.conname} -> {r.ref_table} (CASCADE)")


def downgrade():
    """Revert every FK pointing at the target tables back to NO ACTION.

    Downgrade is best-effort — we can't tell which FKs *originally* were
    NO ACTION vs CASCADE before upgrade(). We restore the safe default
    (NO ACTION) for every target-table FK; if specific FKs were already
    CASCADE before this migration, they'll lose that and need to be
    re-set by a later migration.
    """
    if not _is_pg():
        return

    with engine.begin() as conn:
        targets = sorted(_tenant_target_tables(conn) | _ALWAYS_CASCADE)
        rows = conn.execute(
            text(
                """
                SELECT
                  con.conname AS conname,
                  cl.relname AS table_name,
                  pg_get_constraintdef(con.oid) AS constraintdef
                FROM pg_constraint con
                JOIN pg_class cl ON cl.oid = con.conrelid
                JOIN pg_class cr ON cr.oid = con.confrelid
                JOIN pg_namespace ns ON ns.oid = cl.relnamespace
                WHERE con.contype = 'f'
                  AND ns.nspname = 'public'
                  AND cr.relname = ANY(:targets)
                  AND cl.oid <> cr.oid
                  AND con.confdeltype = 'c'
                ORDER BY cl.relname, con.conname
                """
            ),
            {"targets": targets},
        ).fetchall()

        for r in rows:
            # Strip ON DELETE CASCADE from the definition.
            base = r.constraintdef.replace(" ON DELETE CASCADE", "")
            conn.execute(
                text(
                    f'ALTER TABLE "{r.table_name}" '
                    f'DROP CONSTRAINT "{r.conname}"'
                )
            )
            conn.execute(
                text(
                    f'ALTER TABLE "{r.table_name}" '
                    f'ADD CONSTRAINT "{r.conname}" {base}'
                )
            )
            print(f"    {r.table_name}.{r.conname} -> NO ACTION")


if __name__ == "__main__":
    print("Running migration: 073_cascade_org_delete")
    upgrade()
    print("Done.")
