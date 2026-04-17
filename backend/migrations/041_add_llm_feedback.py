"""Add LLM interaction logging + outcome-linking tables.

Every LLM call (agent runs and one-shot services.llm_provider.call_llm) is
logged to `llm_interactions`. An async linker job populates
`llm_interaction_outcomes` by joining against AgentRun status, AgentApproval
decisions, Finding status transitions, AuditLog, etc.

The paired outcome score is used to rank tenant-scoped few-shot exemplars
that get injected into future prompts — a lightweight feedback loop that
personalizes the LLM to each org without fine-tuning.

On Postgres we add a pgvector `embedding` column for cosine retrieval.
On SQLite (dev) we skip pgvector; retrieval is a Postgres-only feature.
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
            try:
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
                _pgvector = True
            except Exception as exc:
                print(f"Migration 041: pgvector extension unavailable ({exc}) — skipping vector column.")
                _pgvector = False

            embedding_col = "embedding vector(1024)," if _pgvector else ""

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS llm_interactions (
                    id BIGSERIAL PRIMARY KEY,
                    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    surface VARCHAR NOT NULL,
                    surface_ref_type VARCHAR,
                    surface_ref_id VARCHAR,
                    agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
                    agent_run_id INTEGER REFERENCES agent_runs(id) ON DELETE CASCADE,
                    provider VARCHAR,
                    model VARCHAR,
                    system_prompt_hash VARCHAR,
                    system_prompt TEXT,
                    messages JSONB DEFAULT '[]'::jsonb,
                    response_text TEXT,
                    tool_calls JSONB DEFAULT '[]'::jsonb,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    latency_ms INTEGER,
                    error TEXT,
                    status VARCHAR DEFAULT 'ok',
                    redacted BOOLEAN DEFAULT FALSE,
                    {embedding_col}
                    embedding_model VARCHAR,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_int_org_surface_created ON llm_interactions (org_id, surface, created_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_int_agent_run ON llm_interactions (agent_run_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_int_surface_ref ON llm_interactions (surface, surface_ref_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_int_sph ON llm_interactions (system_prompt_hash)"))
            if _pgvector:
                # IVFFlat index for cosine distance — adjust lists once data accumulates.
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_llm_int_embedding "
                    "ON llm_interactions USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
                ))

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS llm_interaction_outcomes (
                    id BIGSERIAL PRIMARY KEY,
                    interaction_id BIGINT NOT NULL REFERENCES llm_interactions(id) ON DELETE CASCADE,
                    org_id INTEGER NOT NULL,
                    user_rating INTEGER,
                    user_edit_distance FLOAT,
                    accepted BOOLEAN,
                    finding_outcome VARCHAR,
                    ticket_outcome VARCHAR,
                    approval_outcome VARCHAR,
                    workflow_outcome VARCHAR,
                    outcome_score FLOAT,
                    computed_at TIMESTAMP DEFAULT NOW()
                )
            """))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_llm_outcome_interaction ON llm_interaction_outcomes (interaction_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_outcome_org_score ON llm_interaction_outcomes (org_id, outcome_score DESC)"))
        else:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS llm_interactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER NOT NULL,
                    user_id INTEGER,
                    surface VARCHAR NOT NULL,
                    surface_ref_type VARCHAR,
                    surface_ref_id VARCHAR,
                    agent_id INTEGER,
                    agent_run_id INTEGER,
                    provider VARCHAR,
                    model VARCHAR,
                    system_prompt_hash VARCHAR,
                    system_prompt TEXT,
                    messages JSON DEFAULT '[]',
                    response_text TEXT,
                    tool_calls JSON DEFAULT '[]',
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    latency_ms INTEGER,
                    error TEXT,
                    status VARCHAR DEFAULT 'ok',
                    redacted BOOLEAN DEFAULT 0,
                    embedding_model VARCHAR,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_int_org_surface_created ON llm_interactions (org_id, surface, created_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_int_agent_run ON llm_interactions (agent_run_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_int_surface_ref ON llm_interactions (surface, surface_ref_id)"))

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS llm_interaction_outcomes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    interaction_id INTEGER NOT NULL,
                    org_id INTEGER NOT NULL,
                    user_rating INTEGER,
                    user_edit_distance FLOAT,
                    accepted BOOLEAN,
                    finding_outcome VARCHAR,
                    ticket_outcome VARCHAR,
                    approval_outcome VARCHAR,
                    workflow_outcome VARCHAR,
                    outcome_score FLOAT,
                    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_llm_outcome_interaction ON llm_interaction_outcomes (interaction_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_llm_outcome_org_score ON llm_interaction_outcomes (org_id, outcome_score)"))

    print("Migration 041: llm_interactions + llm_interaction_outcomes created.")


def downgrade():
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS llm_interaction_outcomes"))
        conn.execute(text("DROP TABLE IF EXISTS llm_interactions"))
    print("Migration 041: llm_interactions + outcomes dropped.")


if __name__ == "__main__":
    upgrade()
