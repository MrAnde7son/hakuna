"""asyncpg connection pool for the VM scanner service."""

import asyncpg

from scanner.vm.config import DATABASE_URL

_pool: asyncpg.Pool | None = None


def _normalize_dsn(url: str) -> str:
    """Strip SQLAlchemy driver prefixes so asyncpg gets a plain postgres:// DSN."""
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg2://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix):]
    return url


async def get_pool(min_size: int = 2, max_size: int = 10) -> asyncpg.Pool:
    global _pool
    if _pool is None or _pool._closed:
        dsn = _normalize_dsn(DATABASE_URL)
        _pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None and not _pool._closed:
        await _pool.close()
        _pool = None
