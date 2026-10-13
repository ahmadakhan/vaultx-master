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
import base64
import secrets
import time
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware

from app.api import router as api_router
from app.config import settings
from app.core.exceptions import VaultXError, get_exception_handler
from app.core.logging import get_logger, setup_logging
from app.core.security import hash_password
from app.db import AsyncSessionLocal, engine
from app.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from app.models import Base, Role, User, UserRole, email_matches, normalize_email

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
                "path": getattr(request.scope.get("route"), "path", "<unmatched>"),
                "status_code": response.status_code,
                "duration_ms": round(elapsed_ms, 2),
            },
        )
        return response


def _register_exception_handlers(app: FastAPI) -> None:
    """Register handlers for all custom exception types."""
    handler = get_exception_handler()
    app.add_exception_handler(VaultXError, handler)

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Pydantic's input/context may include passwords, tokens, or exception
        # objects that cannot be JSON encoded. Return only safe field metadata.
        errors = [
            {key: error[key] for key in ("type", "loc", "msg") if key in error}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "Unhandled exception",
            extra={
                "method": request.method,
                "path": getattr(request.scope.get("route"), "path", "<unmatched>"),
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
                            ).with_for_update(skip_locked=True).limit(100)
                        )
                    )
                    .scalars()
                    .all()
                )
                if not rows:
                    continue
                storage = _get_storage()
                blob_ids = []
                for f in rows:
                    if f.storage_path:
                        blob_ids.append(str(f.id))
                    await session.delete(f)
                # A failed transaction must never destroy a restorable blob.
                # Restores acquire the same row lock before changing state.
                await session.commit()
                for file_id in blob_ids:
                    try:
                        storage.delete_blob(file_id)
                    except Exception:
                        logger.exception(
                            "Failed to remove orphaned ciphertext", extra={"file_id": file_id}
                        )
                logger.info("Trash reaper purged expired files", extra={"count": len(rows)})
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Trash reaper iteration failed")


async def seed_bootstrap_admin(
    session: Any,
    *,
    email: str | None = None,
    password: str | None = None,
) -> bool:
    """Create or update an optional bootstrap admin account.

    This is intentionally disabled unless one of the supported admin bootstrap
    environment variables is configured, so ordinary public registration still
    remains non-admin by default.
    """
    admin_email = normalize_email((email or settings.bootstrap_admin_email or "").strip())
    admin_password = (password if password is not None else settings.bootstrap_admin_password or "").strip()
    if not admin_email or not admin_password:
        return False

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from sqlalchemy import select as _select

    def _b64(value: bytes) -> bytes:
        return base64.b64encode(value)

    def _bundle_aad(role: str) -> bytes:
        return f"vaultx:key-bundle:v2:{role}".encode()

    def _derive_password_key(password: str, salt: bytes, *, iterations: int = 600_000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    def _encrypt_bundle_value(value: bytes, *, role: str, password: str, salt: bytes) -> tuple[bytes, bytes]:
        iv = secrets.token_bytes(12)
        key = _derive_password_key(password, salt)
        ciphertext = AESGCM(key).encrypt(iv, value, _bundle_aad(role))
        return _b64(ciphertext), _b64(iv)

    result = await session.execute(_select(User).where(email_matches(User.email, admin_email)))
    user = result.scalar_one_or_none()
    roles = {"user", "admin"}
    if user is None:
        user = User(
            email=admin_email,
            password_hash=hash_password(admin_password),
            is_active=True,
        )
        session.add(user)
        await session.flush()
        roles = {"user", "admin"}
    else:
        user.is_active = True
        user.password_hash = hash_password(admin_password)

    salt = secrets.token_bytes(16)
    password_key = _derive_password_key(admin_password, salt)
    key_pair = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    master_key = secrets.token_bytes(32)
    search_key = secrets.token_bytes(32)
    private_key = key_pair.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_b64 = _b64(
        key_pair.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    enc_master_key_b64, enc_master_key_iv = _encrypt_bundle_value(
        master_key, role="master", password=admin_password, salt=salt
    )
    enc_search_key_b64, enc_search_key_iv = _encrypt_bundle_value(
        search_key, role="search", password=admin_password, salt=salt
    )
    enc_private_key_b64, enc_private_key_iv = _encrypt_bundle_value(
        private_key, role="private", password=admin_password, salt=salt
    )

    user.password_salt_b64 = _b64(salt)
    user.enc_master_key_b64 = enc_master_key_b64
    user.enc_master_key_iv = enc_master_key_iv
    user.enc_search_key_b64 = enc_search_key_b64
    user.enc_search_key_iv = enc_search_key_iv
    user.enc_private_key_b64 = enc_private_key_b64
    user.enc_private_key_iv = enc_private_key_iv
    user.public_key_b64 = public_key_b64
    user.key_bundle_version = 2
    user.password_kdf_iterations = 600000

    for role_name in sorted(roles):
        existing = await session.execute(
            _select(UserRole).where(UserRole.user_id == user.id, UserRole.role == role_name)
        )
        if existing.scalar_one_or_none() is None:
            session.add(UserRole(user_id=user.id, role=role_name))

    await session.commit()
    logger.warning(
        "Bootstrap admin account ensured",
        extra={"email": admin_email},
    )
    return True


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

            await seed_bootstrap_admin(session)

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
        with suppress(asyncio.CancelledError):
            await reaper_task
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
        except Exception:
            logger.error("Database health check failed")
            db_status = "unreachable"

        return {
            "status": "ok" if db_status == "ok" else "degraded",
            "database": db_status,
            "environment": settings.app_env,
        }

    return app


app = create_app()
