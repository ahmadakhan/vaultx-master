"""Authentication dependencies for FastAPI endpoints.

Provides ``get_current_user``, a FastAPI dependency that extracts,
decodes, and validates JWT access tokens, then fetches the
corresponding user from the database.

Also provides ``get_current_admin`` which checks that the authenticated
user has the "admin" role.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.security import ACCESS_TOKEN_TYPE, decode_token
from app.db import get_db
from app.models import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# In-memory MFA verification cache (token jti -> expiry).
# In production, use Redis with a TTL matching the access token lifetime.
_mfa_verified_cache: dict[str, float] = {}


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Resolve the authenticated user from a JWT bearer token.

    Extracts the token from the ``Authorization`` header, decodes it,
    validates that it is an *access* token and that it has not expired, then
    looks up the user by the ``sub`` claim and confirms the account is active.

    Args:
        token: The bearer token extracted by ``OAuth2PasswordBearer``.
        db: Active database session.

    Returns:
        The authenticated ``User`` model instance.

    Raises:
        AuthenticationError: If the token is invalid, expired, of the wrong
            type, or the user no longer exists or is deactivated.
    """
    try:
        payload = decode_token(token, expected_type=ACCESS_TOKEN_TYPE)
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Token missing subject claim")
        user_uuid = uuid.UUID(user_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise AuthenticationError("Invalid or expired token") from exc

    # Belt-and-braces alongside the type check above: never accept a token
    # that still carries an unverified MFA claim (C3).
    if payload.get("mfa") is not None:
        raise AuthenticationError("MFA challenge token is not a valid session token")

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise AuthenticationError("Invalid or expired token")

    return user


async def get_current_admin(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Return the current user if they have the admin role.

    Wraps :func:`get_current_user` and additionally checks the
    ``user_roles`` table for an ``admin`` entry.

    Raises:
        AuthorizationError: If the user is not an admin.
    """
    result = await db.execute(select(UserRole).where(UserRole.user_id == current_user.id))
    roles = result.scalars().all()
    if not any(r.role == "admin" for r in roles):
        raise AuthorizationError("Admin access required")
    return current_user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentAdmin = Annotated[User, Depends(get_current_admin)]


async def get_current_user_mfa_verified(
    current_user: Annotated[User, Depends(get_current_user)],
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User:
    """Return the current user if they have recently verified MFA.

    For users with MFA enabled, this dependency requires that MFA was
    re-verified within the last 30 minutes (e.g., via ``POST /auth/mfa/verify``
    during login). This should be used for sensitive operations such as
    file deletion, user deactivation, or audit log access.

    The verification state is tracked in an in-memory cache keyed by the
    token's ``jti`` (JWT ID). In a multi-worker deployment, replace this
    with Redis.

    Raises:
        AuthenticationError: If MFA is enabled but not recently verified.
    """
    if not current_user.mfa_enabled:
        return current_user

    try:
        payload = decode_token(token, expected_type=ACCESS_TOKEN_TYPE)
    except Exception as exc:  # noqa: BLE001 — fail CLOSED on any decode error
        raise AuthenticationError("MFA verification required for this action") from exc
    jti = payload.get("jti")

    import time

    now = time.monotonic()
    # Opportunistic pruning so the cache cannot grow without bound for the
    # lifetime of a worker process.
    for key in [k for k, exp in _mfa_verified_cache.items() if exp <= now]:
        del _mfa_verified_cache[key]

    if jti and _mfa_verified_cache.get(jti, 0) > now:
        return current_user

    raise AuthenticationError("MFA verification required for this action")
