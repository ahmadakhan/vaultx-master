"""Shared SQLAlchemy base and database infrastructure.

This module centralizes the declarative base, async engine factory,
and session management with proper connection pooling for production
workloads.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger("vaultx.models")


def utcnow() -> datetime:
    """Return the current timezone-aware UTC timestamp.

    Used as the default for every timestamp column so persisted instants are
    independent of the host and database timezone. Naive local timestamps on a
    ``timezone=True`` column get reinterpreted by PostgreSQL, which previously
    made audit-chain ordering (and therefore verification) unreliable.
    """
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base with ``repr`` and dict utilities for all models."""

    def __repr__(self) -> str:
        # Model repr is frequently included in exception/log messages. Do not
        # expose password hashes, key bundles, MFA secrets, or stored ciphertext.
        return f"<{self.__class__.__name__}>"

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict representation of the model's columns."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


def create_engine(url: str, echo: bool = False) -> AsyncEngine:
    """Create an async SQLAlchemy engine with connection pooling.

    Args:
        url: The database connection URL.
        echo: Whether to log SQL statements.

    Returns:
        A configured ``AsyncEngine`` with pool sizing appropriate
        for concurrent async workloads.
    """
    return create_async_engine(
        url,
        echo=echo,
        hide_parameters=True,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
