"""Add endpoint-agent tables and model-derived threat intelligence.

Three tables back the vulnerability-detection-and-response demo:

* `endpoint_agents`        — host-resident agents for live detection
* `endpoint_agent_actions` — response actions queued back to an agent
* `ai_threat_signals`      — model-synthesized ('mythos') threat intel that
                             augments the classic feeds (NVD, KEV, EPSS, MITRE)

Postgres-first; SQLite branches are kept so the pytest in-memory suite runs.
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
    json_type = "JSONB" if _is_pg else "JSON"
    pk_int = "SERIAL PRIMARY KEY" if _is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"

    with engine.begin() as conn:
        if not _table_exists(conn, "endpoint_agents"):
            conn.execute(text(f"""
                CREATE TABLE endpoint_agents (
                    id VARCHAR PRIMARY KEY,
                    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    name VARCHAR NOT NULL,
                    token_hash VARCHAR NOT NULL,
                    token_prefix VARCHAR,
                    status VARCHAR DEFAULT 'pending',
                    hostname VARCHAR,
                    platform VARCHAR,
                    os_version VARCHAR,
                    ip_address VARCHAR,
                    agent_version VARCHAR,
                    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
                    auto_respond BOOLEAN DEFAULT FALSE,
                    last_checkin_at TIMESTAMP,
                    checkin_interval INTEGER DEFAULT 300,
                    labels {json_type} DEFAULT '{{}}',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_by VARCHAR
                )
            """))
            print("[+] endpoint_agents table created")

        if not _table_exists(conn, "endpoint_agent_actions"):
            conn.execute(text(f"""
                CREATE TABLE endpoint_agent_actions (
                    id VARCHAR PRIMARY KEY,
                    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    agent_id VARCHAR NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
                    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
                    action_type VARCHAR NOT NULL,
                    params {json_type} DEFAULT '{{}}',
                    status VARCHAR DEFAULT 'pending',
                    result {json_type} DEFAULT '{{}}',
                    reason TEXT,
                    origin VARCHAR DEFAULT 'manual',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    dispatched_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    created_by VARCHAR
                )
            """))
            print("[+] endpoint_agent_actions table created")

        if not _table_exists(conn, "ai_threat_signals"):
            conn.execute(text(f"""
                CREATE TABLE ai_threat_signals (
                    id {pk_int},
                    cve_id VARCHAR NOT NULL,
                    source VARCHAR DEFAULT 'mythos',
                    signal_type VARCHAR NOT NULL,
                    title VARCHAR,
                    summary TEXT,
                    reasoning TEXT,
                    confidence FLOAT DEFAULT 0,
                    predicted_score FLOAT,
                    predicted_exploitation BOOLEAN DEFAULT FALSE,
                    horizon_days INTEGER,
                    generated_by_model VARCHAR,
                    indicators {json_type} DEFAULT '[]',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_ai_threat_signal UNIQUE (cve_id, source, signal_type)
                )
            """))
            print("[+] ai_threat_signals table created")

        for idx, table, cols in [
            ("ix_endpoint_agents_org_id", "endpoint_agents", "org_id"),
            ("ix_endpoint_agents_asset_id", "endpoint_agents", "asset_id"),
            ("ix_endpoint_agent_actions_org_id", "endpoint_agent_actions", "org_id"),
            ("ix_endpoint_agent_actions_agent_id", "endpoint_agent_actions", "agent_id"),
            ("ix_endpoint_agent_actions_finding_id", "endpoint_agent_actions", "finding_id"),
            ("ix_ai_threat_signals_cve", "ai_threat_signals", "cve_id"),
        ]:
            if not _index_exists(conn, idx):
                conn.execute(text(f"CREATE INDEX {idx} ON {table} ({cols})"))
                print(f"[+] {idx} created")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS endpoint_agent_actions"))
        conn.execute(text("DROP TABLE IF EXISTS endpoint_agents"))
        conn.execute(text("DROP TABLE IF EXISTS ai_threat_signals"))
        print("Migration 074: reverted.")


if __name__ == "__main__":
    print("Running migration: 074_add_endpoint_agents")
    upgrade()
    print("Done.")
