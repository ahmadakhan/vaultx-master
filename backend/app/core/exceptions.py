"""Custom exception hierarchy for the VaultX backend.

This module defines a structured exception hierarchy that maps application
errors to appropriate HTTP status codes, enabling consistent and
meaningful error responses across all API endpoints.

Exceptions are organized into three tiers:
    1. ``VaultXError`` - base class for all application exceptions.
    2. Domain-specific exceptions (e.g., ``AuthenticationError``,
       ``ValidationError``).
    3. Specific leaf exceptions for individual failure modes.

Each exception carries a ``status_code`` attribute so the global
exception handler can translate it directly into an HTTP response
without leaking internal details.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request, status
from fastapi.responses import JSONResponse


class VaultXError(Exception):
    """Base exception for all VaultX application errors.

    Attributes:
        message: A human-readable error message safe to expose to clients.
        status_code: The HTTP status code to return.
        details: Optional structured details for debugging (not exposed
            to clients by default).
    """

    def __init__(
        self,
        message: str = "An error occurred",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.headers: dict[str, str] = {}


class ValidationError(VaultXError):
    """Raised when input validation fails (e.g., malformed payload)."""

    def __init__(
        self, message: str = "Validation failed", details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(
            message, status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, details=details
        )


class DatabaseError(VaultXError):
    """Raised when a database operation fails."""

    def __init__(self, message: str = "Database operation failed") -> None:
        super().__init__(message, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConflictError(VaultXError):
    """Raised when a resource conflict occurs (e.g., duplicate email)."""

    def __init__(self, message: str = "Resource conflict") -> None:
        super().__init__(message, status_code=status.HTTP_409_CONFLICT)


class AuthenticationError(VaultXError):
    """Raised when authentication fails (invalid credentials, expired token).

    Always carries a ``WWW-Authenticate`` challenge so clients (and proxies)
    can tell an authentication failure from a generic 401.
    """

    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message, status_code=status.HTTP_401_UNAUTHORIZED)
        self.headers: dict[str, str] = {"WWW-Authenticate": "Bearer"}


class AuthorizationError(VaultXError):
    """Raised when a user lacks permission for an action."""

    def __init__(self, message: str = "Access denied") -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)
        self.headers: dict[str, str] = {}


class NotFoundError(VaultXError):
    """Raised when a requested resource is not found."""

    def __init__(self, message: str = "Resource not found") -> None:
        super().__init__(message, status_code=status.HTTP_404_NOT_FOUND)


class RateLimitError(VaultXError):
    """Raised when a rate limit is exceeded."""

    def __init__(
        self, message: str = "Rate limit exceeded", headers: dict[str, str] | None = None
    ) -> None:
        super().__init__(message, status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        self.headers = headers or {}


class CryptoError(VaultXError):
    """Raised when a cryptographic operation fails."""

    def __init__(self, message: str = "Cryptographic operation failed") -> None:
        super().__init__(message, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


def get_exception_handler() -> Any:
    """Return the FastAPI exception handler for VaultXError.

    This handler translates ``VaultXError`` instances into structured JSON
    responses without leaking internal stack traces or database details.

    Returns:
        A callable suitable as a FastAPI exception handler.
    """

    async def handler(request: Request, exc: VaultXError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.message, "details": exc.details or {}},
            headers=getattr(exc, "headers", None) or None,
        )

    return handler
