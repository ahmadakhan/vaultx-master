"""VaultX backend application factory.

Creates and configures the FastAPI application with:
- Production-safe CORS configuration (no wildcard origins).
- Security response headers middleware.
- Rate limiting middleware.
- Structured JSON logging.
- Global exception handlers for all custom exception types.
- Database initialization during startup.

Usage::

    from app.main import create_app
    app = create_app()
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware

from app.api import router as api_router
from app.config import settings
from app.core.exceptions import VaultXError, get_exception_handler
from app.core.logging import get_logger, setup_logging
from app.db import AsyncSessionLocal, engine
from app.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from app.models import Base, Role

logger = get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs each incoming request and its duration."""

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Request completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(elapsed_ms, 2),
            },
        )
        return response


def _register_exception_handlers(app: FastAPI) -> None:
    """Register handlers for all custom exception types."""
    handler = get_exception_handler()
    app.add_exception_handler(VaultXError, handler)

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "Unhandled exception",
            extra={
                "method": request.method,
                "path": request.url.path,
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error. Please try again later."},
        )


def _ensure_schema_columns(sync_conn: Any) -> None:
    """Lightweight forward migration for columns added after first release.

    ``create_all`` only creates missing *tables*; it never alters existing
    ones, so columns introduced later (e.g. ``files.deleted_at`` for the
    trash retention window) must be added explicitly.

    Args:
        sync_conn: Synchronous SQLAlchemy connection used by ``run_sync``.
    """
    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(sync_conn)
    if "files" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("files")}
        if "deleted_at" not in columns:
            sync_conn.execute(text("ALTER TABLE files ADD COLUMN deleted_at TIMESTAMP"))
            logger.info("Applied schema migration: files.deleted_at")


async def _trash_reaper_loop() -> None:
    """Permanently purge soft-deleted files once the retention window elapses.

    Runs every 6 hours inside the app process (H1): rows with
    ``deleted = TRUE`` whose ``deleted_at`` is older than
    ``TRASH_RETENTION_DAYS`` lose their ciphertext blob and their row.
    """
    interval_seconds = 6 * 60 * 60
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            from sqlalchemy import select as sa_select

            from app.models import File as _File
            from app.storage import get_storage as _get_storage

            cutoff = datetime.now(UTC) - timedelta(days=settings.trash_retention_days)
            async with AsyncSessionLocal() as session:
                rows = (
                    (
                        await session.execute(
                            sa_select(_File).where(
                                _File.deleted.is_(True),
                                _File.deleted_at.is_not(None),
                                _File.deleted_at <= cutoff,
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                if not rows:
                    continue
                storage = _get_storage()
                purged = 0
                for f in rows:
                    try:
                        if f.storage_path:
                            storage.delete_blob(str(f.id))
                        await session.delete(f)
                        purged += 1
                    except Exception:
                        logger.exception("Failed to purge expired file", extra={"file_id": str(f.id)})
                await session.commit()
                logger.info("Trash reaper purged expired files", extra={"count": purged})
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Trash reaper iteration failed")


def _create_lifespan() -> Any:
    """Create the lifespan context manager for startup/shutdown."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(_ensure_schema_columns)
            logger.info("Database tables checked/created")

        # Seed default roles if they don't exist
        from sqlalchemy import select as _select
        from sqlalchemy.ext.asyncio import async_sessionmaker
        async_session = async_sessionmaker(engine, expire_on_commit=False)
        async with async_session() as session:
            for role_name in ("admin", "user"):
                result = await session.execute(_select(Role).where(Role.name == role_name))
                if result.scalar_one_or_none() is None:
                    session.add(Role(name=role_name))
            await session.commit()
            logger.info("Default roles seeded")

        logger.info(
            "VaultX backend started",
            extra={
                "environment": settings.app_env,
                "database": settings.db_name,
            },
        )

        reaper_task = asyncio.create_task(_trash_reaper_loop())

        yield

        reaper_task.cancel()
        try:
            await reaper_task
        except asyncio.CancelledError:
            pass
        await engine.dispose()
        logger.info("Database connection closed")

    return lifespan


def create_app() -> FastAPI:
    """Create and configure the VaultX FastAPI application.

    Returns:
        A fully configured ``FastAPI`` instance with middleware,
        exception handlers, and all routes registered.
    """
    setup_logging()

    lifespan = _create_lifespan()

    app = FastAPI(
        title="VaultX Backend",
        version="1.0.0",
        description=(
            "VaultX is a secure, encrypted cloud storage platform with "
            "AES-256-GCM encryption, encrypted search, and tamper-evident "
            "audit logging."
        ),
        lifespan=lifespan,
        docs_url="/docs" if settings.app_env != "prod" else None,
        redoc_url="/redoc" if settings.app_env != "prod" else None,
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        rate=settings.rate_limit_rate,
        capacity=settings.rate_limit_capacity,
    )
    app.add_middleware(RequestLoggingMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["X-Total-Count"],
        max_age=3600,
    )

    _register_exception_handlers(app)
    app.include_router(api_router)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        """Health check endpoint.

        Returns the application status, database connectivity, and
        environment without exposing sensitive configuration.
        """
        db_status = "ok"
        try:
            async with AsyncSessionLocal() as session:
                await session.execute(text("SELECT 1"))
        except Exception as exc:
            logger.error("Database health check failed", extra={"error": str(exc)})
            db_status = "unreachable"

        return {
            "status": "ok" if db_status == "ok" else "degraded",
            "database": db_status,
            "environment": settings.app_env,
        }

    return app


app = create_app()
