"""
Query complexity guards — prevent runaway aggregation queries from
exhausting DB resources or timing out in production.
"""
import logging
from functools import wraps

from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from core.database import _IS_SQLITE

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────

MAX_AGGREGATION_ROWS = 10_000
MAX_PAGE_SIZE = 500
STATEMENT_TIMEOUT_SECONDS = 30


# ── Page size guard ──────────────────────────────────────────────────────

def clamp_page_size(page_size: int, maximum: int = MAX_PAGE_SIZE) -> int:
    """Clamp page_size to [1, maximum]. Use in paginated endpoints."""
    return max(1, min(page_size, maximum))


# ── Statement timeout (Postgres only) ───────────────────────────────────

def set_statement_timeout(db: Session, seconds: int = STATEMENT_TIMEOUT_SECONDS) -> None:
    """Set a per-transaction statement timeout. No-op under the SQLite test DB."""
    if _IS_SQLITE:
        return
    db.execute(text(f"SET LOCAL statement_timeout = '{seconds}s'"))


def disable_statement_timeout(db: Session) -> None:
    """Lift the per-session statement timeout for long-running jobs.

    Scan ingest, report exports, and bulk migrations can exceed the default
    30s budget. The checkout hook in core.database resets the session
    timeout when the connection returns to the pool, so this override is
    contained to the current session.
    """
    if _IS_SQLITE:
        return
    db.execute(text("SET statement_timeout = 0"))


# ── Row count guard for aggregation endpoints ────────────────────────────

def check_row_count(db: Session, query, limit: int = MAX_AGGREGATION_ROWS) -> int:
    """Count rows the query would process. Raises HTTP 422 if over limit.

    Returns the count so callers can include it in responses.
    """
    row_count = query.count()
    if row_count > limit:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Query would process {row_count:,} rows, which exceeds the "
                f"limit of {limit:,}. Apply filters (scan_id, severity, tags) "
                f"to reduce scope."
            ),
        )
    return row_count


def guarded_aggregation(max_rows: int = MAX_AGGREGATION_ROWS, timeout: int = STATEMENT_TIMEOUT_SECONDS):
    """Decorator for aggregation-heavy endpoints.

    Usage:
        @app.get("/api/reports/summary")
        @guarded_aggregation(max_rows=10_000, timeout=30)
        def get_summary(db: Session = Depends(get_db), ...):
            ...

    The decorator sets a statement timeout on the DB session before the
    handler runs. Row-count checks should be done explicitly inside the
    handler using check_row_count() where the base query is available.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Extract db session from kwargs (FastAPI injects it)
            db = kwargs.get("db")
            if db:
                set_statement_timeout(db, timeout)
            return fn(*args, **kwargs)
        return wrapper
    return decorator
