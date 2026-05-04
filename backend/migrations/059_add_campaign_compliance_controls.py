"""Link campaigns to compliance controls.

Creates ``campaign_compliance_controls`` — a junction table associating a
remediation Campaign with one or more ComplianceControl rows. This powers the
"Create campaign from compliance control" flow: clicking a failing control
spins up a campaign whose finding set is materialised from the control's
mapping rules (or from `compliance_finding_status.verdict='failing'`),
and the linkage is recorded here so the campaign UI can show which controls
each campaign helps remediate.

A single FK on Campaign was rejected in favour of a junction because auditors
typically bundle controls (e.g. all HIPAA §164.312 technical safeguards into
one campaign).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from core.database import engine, DATABASE_URL


_is_pg = DATABASE_URL.startswith("postgresql")


def _table_exists(conn, table: str) -> bool:
    return table in inspect(conn).get_table_names()


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
        if not _table_exists(conn, "campaign_compliance_controls"):
            conn.execute(text("""
                CREATE TABLE campaign_compliance_controls (
                    id SERIAL PRIMARY KEY,
                    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                    control_id INTEGER NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
                    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_campaign_compliance_control UNIQUE (campaign_id, control_id)
                )
            """) if _is_pg else text("""
                CREATE TABLE campaign_compliance_controls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                    control_id INTEGER NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
                    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_campaign_compliance_control UNIQUE (campaign_id, control_id)
                )
            """))
            print("[+] campaign_compliance_controls table created")

        for col, idx in [
            ("campaign_id", "ix_campaign_compliance_controls_campaign_id"),
            ("control_id", "ix_campaign_compliance_controls_control_id"),
            ("org_id", "ix_campaign_compliance_controls_org_id"),
        ]:
            if not _index_exists(conn, idx):
                conn.execute(text(
                    f"CREATE INDEX {idx} ON campaign_compliance_controls ({col})"
                ))
                print(f"[+] {idx} created")

        if not _index_exists(conn, "ix_campaign_compliance_control_org"):
            conn.execute(text(
                "CREATE INDEX ix_campaign_compliance_control_org "
                "ON campaign_compliance_controls (org_id)"
            ))
            print("[+] ix_campaign_compliance_control_org created")


def downgrade():
    with engine.begin() as conn:
        for idx in [
            "ix_campaign_compliance_control_org",
            "ix_campaign_compliance_controls_org_id",
            "ix_campaign_compliance_controls_control_id",
            "ix_campaign_compliance_controls_campaign_id",
        ]:
            conn.execute(text(f"DROP INDEX IF EXISTS {idx}"))
        conn.execute(text("DROP TABLE IF EXISTS campaign_compliance_controls"))
        print("Migration 059: reverted.")


if __name__ == "__main__":
    print("Running migration: 059_add_campaign_compliance_controls")
    upgrade()
    print("Done.")
