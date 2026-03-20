from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.config import settings

# Engine for FastAPI (long-lived, single event loop)
engine = create_async_engine(settings.database_url, pool_size=20, max_overflow=10)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session


def get_task_session() -> async_sessionmaker[AsyncSession]:
    """Create a session factory for Celery tasks using NullPool.

    NullPool disables connection pooling so connections are returned to
    PostgreSQL immediately after use. This prevents connection accumulation
    when get_task_session() is called many times across concurrent tasks.
    """
    task_engine = create_async_engine(
        settings.database_url, poolclass=NullPool
    )
    return async_sessionmaker(task_engine, class_=AsyncSession, expire_on_commit=False)
