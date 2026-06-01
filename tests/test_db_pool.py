"""Tests for the database connection-pool configuration (follow-up to #47).

On Cloud Run, total DB connections ≈ (pool_size + max_overflow) × instances,
so the per-instance pool is bounded and configurable, sized against Cloud
SQL's max_connections. SQLite (dev/test) uses a StaticPool that rejects these
args, so they must be applied to Postgres only.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import create_async_engine

from app.config import settings
from app.database import _pool_kwargs

POSTGRES_URL = "postgresql+asyncpg://u:p@h/db"


def test_pool_kwargs_empty_for_sqlite() -> None:
    """SQLite's StaticPool rejects pool_size/max_overflow — must pass none."""
    assert _pool_kwargs("sqlite+aiosqlite:///:memory:") == {}
    assert _pool_kwargs("sqlite:///./local.db") == {}


def test_pool_kwargs_set_for_postgres() -> None:
    assert _pool_kwargs(POSTGRES_URL) == {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_timeout": settings.db_pool_timeout,
        "pool_recycle": settings.db_pool_recycle,
        "pool_pre_ping": settings.db_pool_pre_ping,
    }


def test_postgres_engine_applies_configured_pool_size() -> None:
    """asyncpg never connects at construction, so building a throwaway engine
    is safe and confirms the kwargs actually bound the pool."""
    eng = create_async_engine(POSTGRES_URL, **_pool_kwargs(POSTGRES_URL))
    assert eng.pool.size() == settings.db_pool_size


def test_defaults_stay_conservative() -> None:
    """Tripwire: keep the per-instance footprint modest so (pool × instances)
    stays under Cloud SQL's ceiling. If you raise these intentionally, update
    the formula in .env.example and --max-instances in deploy.yml too."""
    assert settings.db_pool_size + settings.db_max_overflow <= 10
    assert settings.db_pool_pre_ping is True
