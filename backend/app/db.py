"""Async database session management.

Provides the SQLAlchemy async engine, session provider, and a
FastAPI dependency yielding ``AsyncSession`` instances with
connection pooling for production resilience.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

_db_url = settings.database_url
_is_sqlite = _db_url.startswith("sqlite")

engine = create_async_engine(
    _db_url,
    echo=(settings.app_env == "dev"),
    **(
        {}
        if _is_sqlite
        else {
            "pool_size": 20,
            "max_overflow": 10,
            "pool_pre_ping": True,
            "pool_recycle": 3600,
        }
    ),
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an async database session.

    The session is automatically closed when the generator exits,
    ensuring no connection leaks even on endpoint exceptions.

    Yields:
        An ``AsyncSession`` instance bound to the application engine.
    """
    async with AsyncSessionLocal() as session:
        yield session
