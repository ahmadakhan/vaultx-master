"""Security utilities for password hashing and JWT token management.

Provides:
- Password hashing/verification via bcrypt with constant-time comparison.
- JWT access and refresh token creation with proper expiry and
  type claims.
- Token decoding with signature and expiry validation.
- Password strength enforcement.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from passlib.context import CryptContext

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"
# Challenge token issued by POST /auth/login when MFA is pending. It is only
# accepted by POST /auth/mfa/verify and is rejected everywhere else.
MFA_CHALLENGE_TOKEN_TYPE = "mfa"

# bcrypt only considers the first 72 bytes of input; longer passwords are
# truncated silently by the algorithm.
BCRYPT_MAX_PASSWORD_BYTES = 72

# Client-side key-bundle parameters. These must stay in sync with
# ``frontend/lib/crypto/keys.ts``; the stored values let old bundles keep
# deriving with the parameters they were created with.
LEGACY_KEY_BUNDLE_VERSION = 1
CURRENT_KEY_BUNDLE_VERSION = 2
LEGACY_KDF_ITERATIONS = 150_000
CURRENT_KDF_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: The plaintext password to hash.

    Returns:
        A bcrypt hash string.

    Raises:
        ValueError: If the password exceeds bcrypt's 72-byte input limit,
            which would otherwise be truncated silently.
    """
    if len(password.encode("utf-8")) > BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError(f"Password exceeds bcrypt's {BCRYPT_MAX_PASSWORD_BYTES}-byte input limit")
    result: str = pwd_context.hash(password)
    return result


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash.

    Uses ``secrets.compare_digest`` internally via passlib to prevent
    timing-based attacks.

    Args:
        password: The plaintext password to check.
        hashed: The stored bcrypt hash.

    Returns:
        ``True`` if the password matches, ``False`` otherwise.
    """
    try:
        result: bool = pwd_context.verify(password, hashed)
        return result
    except (ValueError, TypeError) as exc:
        logger.warning("Password verification failed: %s", exc)
        return False


def _create_token(
    data: dict[str, Any],
    expires_delta: timedelta,
    token_type: str,
    *,
    jti: str | None = None,
) -> str:
    """Internal helper to encode a JWT with issued-at, expiry and type claims.

    Args:
        data: Payload claims to include.
        expires_delta: Token lifetime.
        token_type: ``"access"`` or ``"refresh"``.
        jti: Optional unique token identifier (required for revocation).

    Returns:
        A signed JWT string.
    """
    now = datetime.now(UTC)
    to_encode = data.copy()
    to_encode.update({"exp": now + expires_delta, "iat": now, "type": token_type})
    if jti is not None:
        to_encode["jti"] = jti
    token: str = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token


def create_access_token(
    data: dict[str, Any], *, expires_delta: timedelta | None = None, jti: str | None = None
) -> str:
    """Create a short-lived JWT access token.

    Args:
        data: Claims to embed (typically ``{"sub": user_id}``).
        expires_delta: Optional override for token lifetime.
        jti: Optional unique token identifier for tracking.

    Returns:
        A signed JWT string valid for ``jwt_expire_minutes`` minutes
        (or the provided ``expires_delta``).
    """
    delta = expires_delta or timedelta(minutes=settings.jwt_expire_minutes)
    if jti is not None:
        data = data.copy()
        data["jti"] = jti
    return _create_token(data, delta, ACCESS_TOKEN_TYPE)


def create_mfa_challenge_token(
    data: dict[str, Any], *, expires_delta: timedelta | None = None, jti: str | None = None
) -> str:
    """Create a short-lived MFA *challenge* token (``type="mfa"``).

    This token proves only that the password factor succeeded. It is
    deliberately a distinct token type so that ``get_current_user`` — which
    accepts ``type="access"`` only — refuses it for every API route until the
    second factor has been verified (C3).

    Args:
        data: Claims to embed (typically ``{"sub": user_id, "mfa": "pending"}``).
        expires_delta: Optional override; defaults to 10 minutes.
        jti: Optional unique token identifier.

    Returns:
        A signed JWT string valid only for ``POST /auth/mfa/verify``.
    """
    delta = expires_delta or timedelta(minutes=10)
    if jti is not None:
        data = data.copy()
        data["jti"] = jti
    return _create_token(data, delta, MFA_CHALLENGE_TOKEN_TYPE)


def create_refresh_token(data: dict[str, Any], *, jti: str | None = None) -> str:
    """Create a long-lived JWT refresh token carrying a unique ``jti``.

    The ``jti`` is what makes server-side rotation and revocation possible: the
    auth layer persists its hash and invalidates it on first use.

    Args:
        data: Claims to embed (typically ``{"sub": user_id}``).
        jti: Explicit token identifier; a random one is generated when omitted.

    Returns:
        A signed JWT string valid for ``jwt_refresh_expire_days`` days.
    """
    return _create_token(
        data,
        timedelta(days=settings.jwt_refresh_expire_days),
        REFRESH_TOKEN_TYPE,
        jti=jti or uuid.uuid4().hex,
    )


def hash_token_identifier(jti: str) -> str:
    """Return the at-rest representation of a refresh token's ``jti``.

    Only the hash is persisted, so a database disclosure does not hand an
    attacker a set of reusable token identifiers.
    """
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


def decode_token(
    token: str,
    *,
    expected_type: str | None = None,
    required_claims: tuple[str, ...] = ("sub", "type"),
) -> dict[str, Any]:
    """Decode and validate a JWT token.

    Verifies the signature and expiration, then enforces the expected token
    type and the presence of every required claim.

    Args:
        token: The JWT string to decode.
        expected_type: When set, the ``type`` claim must match exactly.
        required_claims: Claims that must be present and non-empty.

    Returns:
        The decoded token payload as a dict.

    Raises:
        ValueError: If the token is expired, signed with the wrong key, has an
            invalid structure, or fails the type/claim checks.
    """
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ValueError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise ValueError(f"Invalid token: {exc}") from exc

    if expected_type is not None and payload.get("type") != expected_type:
        raise ValueError(f"Expected a {expected_type} token")

    missing = [claim for claim in required_claims if not payload.get(claim)]
    if missing:
        raise ValueError(f"Token missing required claims: {', '.join(missing)}")

    return payload
