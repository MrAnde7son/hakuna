"""Add `validated_chain_finding_id` to `attack_paths`.

Phase 3 of the Cross-Scan Chain Coordinator (see
`docs/cross-scan-chain-coordinator-plan.md`). When the Coordinator closes
a chain end-to-end (internet → crown-jewel) it emits a single
`ValidatedChain` Finding row that summarises the path. This column links
the AttackPath to that summary Finding so the UI can render a "Chain"
badge and join straight to the validated finding.

Nullable — the field is only set for paths the Coordinator validated;
correlator-generated paths leave it NULL.
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
        if not _column_exists(conn, "attack_paths", "validated_chain_finding_id"):
            conn.execute(text(
                "ALTER TABLE attack_paths "
                "ADD COLUMN validated_chain_finding_id INTEGER"
            ))
            print("[+] attack_paths.validated_chain_finding_id added")
        if not _index_exists(conn, "ix_attack_paths_validated_chain"):
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_attack_paths_validated_chain "
                "ON attack_paths (validated_chain_finding_id)"
            ))
            print("[+] ix_attack_paths_validated_chain created")


def downgrade():
    with engine.begin() as conn:
        if _is_pg:
            conn.execute(text("DROP INDEX IF EXISTS ix_attack_paths_validated_chain"))
            conn.execute(text(
                "ALTER TABLE attack_paths DROP COLUMN IF EXISTS validated_chain_finding_id"
            ))
        print("Migration 055: reverted.")


if __name__ == "__main__":
    print("Running migration: 055_add_attack_path_chain_link")
    upgrade()
    print("Done.")
