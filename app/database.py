from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


def _pool_kwargs(database_url: str) -> dict:
    """Connection-pool kwargs for ``create_async_engine``.

    Empty for SQLite (dev/test), which SQLAlchemy backs with a ``StaticPool``
    that rejects ``pool_size``/``max_overflow``. For the production
    ``postgresql+asyncpg`` engine these bound the per-instance pool and add
    liveness checks (``pool_pre_ping``) plus periodic recycling, so Cloud
    SQL dropping an idle connection surfaces as a transparent reconnect
    rather than a request error.
    """
    if database_url.startswith("sqlite"):
        return {}
    return {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_timeout": settings.db_pool_timeout,
        "pool_recycle": settings.db_pool_recycle,
        "pool_pre_ping": settings.db_pool_pre_ping,
    }


engine = create_async_engine(
    settings.database_url,
    echo=settings.is_development,
    **_pool_kwargs(settings.database_url),
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides an async database session."""
    async with async_session_maker() as session:
        yield session
