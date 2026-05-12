"""Single-process migration runner.

CI used to invoke each ``NNN_*.py`` script as its own Python process. With
80+ migrations the cumulative Python+SQLAlchemy import overhead pushed the
Cloud Run job past its 300s task timeout, even though every individual
migration is idempotent and fast against the actual DB.

This runner does two things:

1. Loads each migration module once in a single Python process so SQLAlchemy,
   ``core.database``, and the connection pool are paid for exactly once.
2. Records applied migrations in a ``schema_migrations`` table so subsequent
   deploys only execute the new ones.

Existing prod DBs are already at head. The first run after this lands will
re-apply every migration (cheap — they all short-circuit via
``_column_exists`` / ``CREATE TABLE IF NOT EXISTS`` style checks) and then
record them as applied; every deploy after that touches only new files.
"""

import importlib.util
import os
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import text

from core.database import engine

MIGRATIONS_DIR = Path(__file__).resolve().parent


def _ensure_tracking_table() -> None:
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "  name VARCHAR(255) PRIMARY KEY,"
            "  applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ")"
        ))


def _applied_set() -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT name FROM schema_migrations")).fetchall()
    return {r[0] for r in rows}


def _record_applied(name: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO schema_migrations (name) VALUES (:n) "
                "ON CONFLICT (name) DO NOTHING"
            ),
            {"n": name},
        )


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    _ensure_tracking_table()
    applied = _applied_set()

    files = sorted(p for p in MIGRATIONS_DIR.glob("[0-9]*.py"))
    pending = [p for p in files if p.stem not in applied]

    if not pending:
        print(f"No pending migrations ({len(applied)} already applied).")
        return 0

    print(f"Applying {len(pending)} migration(s); {len(applied)} already recorded.")
    for path in pending:
        name = path.stem
        print(f"-> {name}")
        try:
            module = _load_module(path)
        except Exception:
            traceback.print_exc()
            print(f"FAILED to import {name}")
            return 1

        upgrade = getattr(module, "upgrade", None)
        if upgrade is None:
            print(f"   (skip: no upgrade() in {name})")
            _record_applied(name)
            continue

        try:
            upgrade()
        except Exception:
            traceback.print_exc()
            print(f"FAILED in {name}.upgrade()")
            return 1

        _record_applied(name)

    print("All migrations applied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
