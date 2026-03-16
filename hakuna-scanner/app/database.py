from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

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
    """Create a fresh engine + session factory for Celery tasks.

    Each Celery task runs in a new event loop, so we need a fresh
    engine that isn't bound to a previous loop's connection pool.
    """
    task_engine = create_async_engine(
        settings.database_url, pool_size=5, max_overflow=5
    )
    return async_sessionmaker(task_engine, class_=AsyncSession, expire_on_commit=False)
