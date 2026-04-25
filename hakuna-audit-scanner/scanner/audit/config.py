"""Audit Scanner configuration — env vars only.

Mirrors hakuna-vm-scanner/scanner/vm/config.py so the two services
configure identically: same DSN normalisation, same env-var precedence,
same graceful defaults for OSS/standalone use.
"""

import os


# ── Database ─────────────────────────────────────────────────────
# Shared with the backend. asyncpg consumes it directly — no SQLAlchemy
# driver prefix is needed, and one is stripped at the db.py layer if the
# operator pasted a SQLAlchemy URL by accident.
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://hakuna:hakuna@postgres:5432/hakuna",
)

# ── Celery ───────────────────────────────────────────────────────
# /2 keeps the audit queue separate from the VM scanner (/1) and the
# backend's own celery (/0). Same Redis broker, different logical DB.
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/2")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/2")

# ── Relay transport ──────────────────────────────────────────────
# OSS users get the HTTP relay by default — the WebSocket-broker path
# only works inside Hakuna's deployment. The HTTP path posts a single
# JSON envelope per task to a relay node that runs hakuna-relay-agent
# with the http-server entrypoint. Token is a shared secret.
RELAY_TRANSPORT = os.environ.get("RELAY_TRANSPORT", "http").lower()
HAKUNA_RELAY_URL = os.environ.get("HAKUNA_RELAY_URL", "")
HAKUNA_RELAY_TOKEN = os.environ.get("HAKUNA_RELAY_TOKEN", "")
RELAY_TIMEOUT_SECONDS = int(os.environ.get("RELAY_TIMEOUT_SECONDS", "120"))

# ── Audit engine defaults ────────────────────────────────────────
# Per-run overrides come in via the API/Celery payload. These are the
# fallback values the worker uses when nothing else is specified.
AUDIT_DEFAULT_MODEL = os.environ.get("AUDIT_DEFAULT_MODEL", "claude-sonnet-4-6")
AUDIT_DEFAULT_MAX_STEPS = int(os.environ.get("AUDIT_DEFAULT_MAX_STEPS", "20"))
AUDIT_DEFAULT_WALLCLOCK_S = int(os.environ.get("AUDIT_DEFAULT_WALLCLOCK_S", "600"))
AUDIT_MAX_TOKENS_PER_TURN = int(os.environ.get("AUDIT_MAX_TOKENS_PER_TURN", "4096"))

# ── Templates ────────────────────────────────────────────────────
# YAML mission registration is loaded at engine startup. Keeps the
# 3.7k-line agent_prompts.py monolith out of OSS — missions are data,
# not Python.
TEMPLATES_DIR = os.environ.get(
    "TEMPLATES_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates"),
)
MISSIONS_DIR = os.path.join(TEMPLATES_DIR, "missions")
CUSTOM_MISSIONS_DIR = os.path.join(TEMPLATES_DIR, "custom", "missions")

# ── Streaming (Redis pub-sub) ────────────────────────────────────
# When set, the engine publishes per-iteration events (thinking,
# tool_call, tool_result, finding, run_end) to ``audit:run:{run_id}``.
# Backend's SSE endpoint subscribes and forwards to the agent-run
# viewer. Unset → engine uses NullPublisher; transcript still arrives
# in the Celery result payload, just without live updates.
#
# Default falls through to the Celery broker URL — same Redis is fine
# for almost every deployment. Set to a different DSN only when you
# want pub-sub on a dedicated Redis.
REDIS_PUBSUB_URL = os.environ.get("REDIS_PUBSUB_URL", CELERY_BROKER_URL)

# ── Scratchpad persistence ───────────────────────────────────────
# File-based per-agent state. In OSS mode this is a local volume; in
# Hakuna deployment it lives on the worker's persistent disk. Path is
# overridable so multi-replica workers can point at a shared volume.
SCRATCHPAD_DIR = os.environ.get(
    "SCRATCHPAD_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scratchpads"),
)
