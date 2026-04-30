"""Add `background_jobs` — durable job registry shared across Cloud Run replicas.

The previous registry lived in `_jobs: dict` inside `services.job_manager`
(in-memory, per-process). With Cloud Run scaled to multiple replicas the
`POST /run`-then-`GET /jobs/{id}/status` flow could land on different
instances; the second instance had never heard of the job and returned
404. Production users hit this on attack-paths correlation polling.

Moving job state into Postgres keeps the dispatch/get_job/list_jobs API
identical to all 27 callers and removes the cross-instance 404.
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
        if not _table_exists(conn, "background_jobs"):
            json_type = "JSONB" if _is_pg else "JSON"
            conn.execute(text(f"""
                CREATE TABLE background_jobs (
                    id VARCHAR(64) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'pending',
                    progress INTEGER,
                    result {json_type},
                    error TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP
                )
            """))
            print("[+] background_jobs table created")

        if not _index_exists(conn, "ix_background_jobs_status"):
            conn.execute(text(
                "CREATE INDEX ix_background_jobs_status "
                "ON background_jobs (status)"
            ))
            print("[+] ix_background_jobs_status created")

        if not _index_exists(conn, "ix_background_jobs_created_at"):
            conn.execute(text(
                "CREATE INDEX ix_background_jobs_created_at "
                "ON background_jobs (created_at)"
            ))
            print("[+] ix_background_jobs_created_at created")

        if not _index_exists(conn, "ix_background_jobs_name_created_at"):
            conn.execute(text(
                "CREATE INDEX ix_background_jobs_name_created_at "
                "ON background_jobs (name, created_at)"
            ))
            print("[+] ix_background_jobs_name_created_at created")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_background_jobs_name_created_at"))
        conn.execute(text("DROP INDEX IF EXISTS ix_background_jobs_created_at"))
        conn.execute(text("DROP INDEX IF EXISTS ix_background_jobs_status"))
        conn.execute(text("DROP TABLE IF EXISTS background_jobs"))
        print("Migration 058: reverted.")


if __name__ == "__main__":
    print("Running migration: 058_add_background_jobs")
    upgrade()
    print("Done.")
