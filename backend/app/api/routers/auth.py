"""Authentication and key provisioning endpoints.

Handles user registration, login, JWT refresh, and public key
retrieval for file sharing.

All sensitive key material (master key, search key, RSA private key)
is encrypted client-side before being sent to the server. The server
stores ciphertext only and never has access to plaintext keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.audit_decorator import audit_event
from app.core.audit_log import record_audit_log
from app.core.deps import get_current_user
from app.core.exceptions import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.login_throttle import login_throttle, throttle_key
from app.core.mfa import EncryptedSecret, decrypt_totp_secret, encrypt_totp_secret
from app.core.security import (
    ACCESS_TOKEN_TYPE,
    LEGACY_KDF_ITERATIONS,
    LEGACY_KEY_BUNDLE_VERSION,
    MFA_CHALLENGE_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    create_access_token,
    create_mfa_challenge_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token_identifier,
    verify_password,
)
from app.db import get_db
from app.models import RefreshToken, User, UserRole, email_matches, normalize_email
from app.schemas import (
    AuthResponse,
    LogoutRequest,
    MFADisableRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    PublicKeyResponse,
    RegisterPayload,
    TokenResponse,
    UserKeysResponse,
    UserLogin,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_dummy_password_hash: str | None = None


def _dummy_hash() -> str:
    """Return a bcrypt hash used to equalise timing for unknown accounts.

    Verified against when the address does not exist so that "no such user" and
    "wrong password" take the same time, removing the account-existence oracle.
    Computed lazily so importing this module does not pay the bcrypt cost.
    """
    global _dummy_password_hash
    if _dummy_password_hash is None:
        _dummy_password_hash = hash_password("vaultx-timing-equalizer")
    return _dummy_password_hash


def _keys_response(user: User) -> UserKeysResponse:
    """Serialise the stored (still encrypted) key bundle for the client.

    Legacy bundles report the parameters they were created with so the client
    keeps deriving exactly as before.
    """
    return UserKeysResponse(
        password_salt_b64=user.password_salt_b64.decode(),
        enc_master_key_b64=user.enc_master_key_b64.decode(),
        enc_master_key_iv=user.enc_master_key_iv.decode(),
        enc_search_key_b64=user.enc_search_key_b64.decode(),
        enc_search_key_iv=user.enc_search_key_iv.decode(),
        enc_private_key_b64=user.enc_private_key_b64.decode(),
        enc_private_key_iv=user.enc_private_key_iv.decode(),
        public_key_b64=user.public_key_b64.decode(),
        kdf_iterations=user.password_kdf_iterations or LEGACY_KDF_ITERATIONS,
        key_bundle_version=user.key_bundle_version or LEGACY_KEY_BUNDLE_VERSION,
    )


async def _issue_tokens(db: AsyncSession, user: User) -> tuple[str, str]:
    """Create an access/refresh token pair and register the refresh token.

    The refresh token carries a unique ``jti`` whose hash is persisted, which is
    what makes rotation and revocation possible.

    Returns:
        A ``(access_token, refresh_token)`` tuple.
    """
    jti = uuid.uuid4().hex
    access = create_access_token({"sub": str(user.id)}, jti=jti)
    refresh = create_refresh_token({"sub": str(user.id)}, jti=jti)
    db.add(
        RefreshToken(
            user_id=user.id,
            jti_hash=hash_token_identifier(jti),
            expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_expire_days),
        )
    )
    await db.commit()
    return access, refresh


async def _revoke_all_refresh_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Invalidate every outstanding refresh token for a user."""
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )


async def _record_login_failure(
    db: AsyncSession, request: Request, user: User | None, email: str
) -> None:
    """Record a failed-login audit event tied to the request's IP."""
    await record_audit_log(
        db=db,
        request=request,
        user_id=user.id if user else None,
        action="login_failed",
        resource={"email": email},
    )


@router.post("/register", response_model=AuthResponse)
async def register_user(
    payload: RegisterPayload,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Register a new user with encrypted vault keys.

    The client sends an encrypted key bundle (master key, search key,
    RSA private key) all encrypted under a PBKDF2-derived password
    key. The server hashes the password with bcrypt and stores the
    encrypted blobs as-is.

    Args:
        payload: Registration data including email, password, encrypted key
            material, and the KDF parameters the bundle was produced with.
        db: Database session.

    Returns:
        Access/refresh tokens and the stored key bundle for client
        session initialization.

    Raises:
        ConflictError: If the email is already registered.
    """
    email = normalize_email(str(payload.email))

    existing = await db.execute(select(User.id).where(email_matches(User.email, email)))
    if existing.scalar_one_or_none():
        raise ConflictError("Email already registered")

    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    user = User(
        email=email,
        password_hash=password_hash,
        password_salt_b64=payload.password_salt_b64.encode(),
        enc_master_key_b64=payload.enc_master_key_b64.encode(),
        enc_master_key_iv=payload.enc_master_key_iv.encode(),
        enc_search_key_b64=payload.enc_search_key_b64.encode(),
        enc_search_key_iv=payload.enc_search_key_iv.encode(),
        enc_private_key_b64=payload.enc_private_key_b64.encode(),
        enc_private_key_iv=payload.enc_private_key_iv.encode(),
        public_key_b64=payload.public_key_b64.encode(),
        key_bundle_version=payload.key_bundle_version,
        password_kdf_iterations=payload.kdf_iterations,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError as exc:
        # Unique constraint on users.email: lost the race against a concurrent
        # registration for the same address.
        await db.rollback()
        raise ConflictError("Email already registered") from exc
    await db.refresh(user)

    # Assign roles: if no admin exists yet, this first user becomes admin.
    # Otherwise the user gets the "user" role.
    from sqlalchemy import func as _func
    admin_count = await db.scalar(
        select(_func.count()).select_from(UserRole).where(UserRole.role == "admin")
    )
    role_name = "admin" if (admin_count or 0) == 0 else "user"
    db.add(UserRole(user_id=user.id, role=role_name))

    access_token, refresh_token = await _issue_tokens(db, user)

    logger.info("User registered", extra={"user_id": str(user.id)})

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        keys=_keys_response(user),
    )


@router.post("/login", response_model=AuthResponse)
@audit_event("login")
async def login_user(
    user_in: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Authenticate a user and return tokens plus encrypted key material.

    Applies per-account throttling, verifies the password in constant time
    (including for unknown accounts) and refuses deactivated users. Nothing
    distinguishes a wrong password from a non-existent or disabled account.

    If the user has MFA enabled but does not supply a valid TOTP ``code``,
    the response includes ``mfa_required: true`` and no tokens are issued.
    The client must call ``POST /auth/mfa-verify`` with the TOTP code (and
    the temporary ``mfa_token``) to receive the final access/refresh tokens.

    Args:
        user_in: Login credentials (email + password, optional ``code``).
        request: The incoming request (for audit logging).
        db: Database session.

    Returns:
        Access/refresh tokens and the stored key bundle (if MFA passes),
        or ``mfa_required`` placeholder (if MFA code is needed).

    Raises:
        AuthenticationError: If credentials are invalid.
        RateLimitError: If the account is temporarily locked.
    """
    email = normalize_email(str(user_in.email))
    key = throttle_key(email)

    retry_after = login_throttle.check(key)
    if retry_after:
        logger.warning(
            "Login rejected: account temporarily locked",
            extra={"email": email, "retry_after": retry_after},
        )
        raise RateLimitError(
            "Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    result = await db.execute(select(User).where(email_matches(User.email, email)))
    user = result.scalar_one_or_none()

    # Verify against a dummy hash when the account is unknown so that response
    # time does not reveal whether the address exists.
    candidate_hash = str(user.password_hash) if user else _dummy_hash()
    password_ok = verify_password(user_in.password, candidate_hash)

    if user is None or not user.is_active or not password_ok:
        locked_for = login_throttle.record_failure(key)
        logger.warning(
            "Failed login attempt",
            extra={
                "email": email,
                "account_exists": user is not None,
                "locked_for_seconds": locked_for,
            },
        )
        await _record_login_failure(db, request, user, email)
        if locked_for:
            raise RateLimitError(
                "Too many failed login attempts. Please try again later.",
                headers={"Retry-After": str(locked_for)},
            )
        raise AuthenticationError("Invalid credentials")

    login_throttle.reset(key)

    # --- MFA check ---
    if user.mfa_enabled:
        code = getattr(user_in, "code", None)
        if code:
            enc = EncryptedSecret(
                ciphertext_b64=user.mfa_secret_encrypted.decode() if user.mfa_secret_encrypted else "",
                iv_b64=user.mfa_secret_iv.decode() if user.mfa_secret_iv else "",
                salt_b64=user.mfa_secret_salt.decode() if user.mfa_secret_salt else "",
            )
            try:
                secret = decrypt_totp_secret(enc)
            except Exception as err:
                raise AuthenticationError("MFA encryption error") from err
            import pyotp
            totp = pyotp.TOTP(secret)

            # Try TOTP first
            totp_valid = totp.verify(code, valid_window=1)
            if totp_valid:
                pass  # TOTP verified, proceed with login
            else:
                # Try backup code
                used_backup = False
                if user.mfa_backup_codes_hash:
                    hashes = json.loads(user.mfa_backup_codes_hash.decode())
                    used_raw = json.loads(user.mfa_backup_codes_used.decode()) if user.mfa_backup_codes_used else [False] * len(hashes)
                    code_hash = hashlib.sha256(code.encode()).hexdigest()
                    for i, h in enumerate(hashes):
                        if h == code_hash and not used_raw[i]:
                            used_raw[i] = True
                            used_backup = True
                            break
                    if used_backup:
                        user.mfa_backup_codes_used = json.dumps(used_raw).encode()
                        await db.commit()
                    else:
                        await _record_login_failure(db, request, user, email)
                        raise AuthenticationError("Invalid MFA code")
                else:
                    await _record_login_failure(db, request, user, email)
                    raise AuthenticationError("Invalid MFA code")
        else:
            # MFA required but no code provided: issue a *challenge* token of
            # a distinct type that get_current_user rejects, and withhold the
            # key bundle until the second factor is proven (C3).
            mfa_token = create_mfa_challenge_token(
                {"sub": str(user.id), "mfa": "pending"},
                expires_delta=timedelta(minutes=10),
                jti=uuid.uuid4().hex,
            )

            logger.info("MFA challenge issued", extra={"user_id": str(user.id)})
            return {
                "access_token": mfa_token,
                "refresh_token": "",
                "token_type": "bearer",
                "mfa_required": True,
                "keys": None,
            }

    access_token, refresh_token = await _issue_tokens(db, user)

    logger.info("User logged in", extra={"user_id": str(user.id)})

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        keys=_keys_response(user),
    )


@router.post("/mfa/setup", response_model=MFASetupResponse)
@audit_event("mfa_setup")
async def mfa_setup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MFASetupResponse:
    """Generate a TOTP secret and QR code for MFA enrollment.

    The secret is encrypted server-side and temporarily stored on
    the user record (NOT yet activated). The client must scan the
    QR code and call ``POST /auth/mfa/enable`` with a verification
    code to activate MFA.

    Args:
        current_user: Authenticated user.

     Returns:
        QR code URL, the plaintext secret, and 10 backup recovery codes.
    """
    import io

    import pyotp
    import qrcode

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    # Temporarily store the encrypted secret (mfa_enabled stays False)
    enc = encrypt_totp_secret(secret)
    current_user.mfa_secret_encrypted = base64.b64decode(enc.ciphertext_b64)
    current_user.mfa_secret_iv = base64.b64decode(enc.iv_b64)
    current_user.mfa_secret_salt = base64.b64decode(enc.salt_b64)

    # Generate 10 backup codes (20-char hex each)
    backup_codes = [secrets.token_hex(10) for _ in range(10)]
    backup_codes_hash = json.dumps([hashlib.sha256(c.encode()).hexdigest() for c in backup_codes]).encode()
    current_user.mfa_backup_codes_hash = backup_codes_hash
    current_user.mfa_backup_codes_used = json.dumps([False] * 10).encode()

    await db.commit()

    # Build QR code (otpauth:// URI)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name="VaultX")
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode()
    qr_code_url = f"data:image/png;base64,{img_b64}"

    logger.info("MFA setup initiated", extra={"user_id": str(current_user.id)})
    return MFASetupResponse(qr_code_url=qr_code_url, secret=secret, backup_codes=backup_codes)


@router.post("/mfa/enable", response_model=dict[str, str])
@audit_event("mfa_enable")
async def mfa_enable(
    request: Request,
    payload: MFAVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Verify a TOTP code and activate MFA for the user.

    Uses the secret generated by :meth:`mfa_setup`. If the code is valid,
    ``mfa_enabled`` is set to ``True``.

    Args:
        payload: Email + TOTP verification code.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A confirmation message.

    Raises:
        AuthenticationError: If the code is invalid or no setup secret exists.
    """
    import pyotp

    if not current_user.mfa_secret_encrypted:
        raise AuthenticationError("No MFA secret found. Call /mfa/setup first.")

    enc = EncryptedSecret(
        ciphertext_b64=current_user.mfa_secret_encrypted.decode(),
        iv_b64=current_user.mfa_secret_iv.decode() if current_user.mfa_secret_iv else "",
        salt_b64=current_user.mfa_secret_salt.decode() if current_user.mfa_secret_salt else "",
    )
    try:
        secret = decrypt_totp_secret(enc)
    except Exception as err:
        raise AuthenticationError("MFA secret decryption failed") from err

    totp = pyotp.TOTP(secret)
    if not totp.verify(payload.code, valid_window=1):
        raise AuthenticationError("Invalid MFA code")

    current_user.mfa_enabled = True
    await db.commit()

    logger.info("MFA enabled", extra={"user_id": str(current_user.id)})
    return {"message": "MFA has been enabled"}


@router.get("/mfa/status", response_model=dict[str, Any])
@audit_event("mfa_status")
async def mfa_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Check whether MFA is enabled for the current user.

    Args:
        current_user: Authenticated user.

    Returns:
        A dict with ``mfa_enabled`` boolean and ``backup_codes_remaining`` count.
    """
    backup_remaining = 0
    if current_user.mfa_backup_codes_hash:
        used_raw = json.loads(current_user.mfa_backup_codes_used.decode()) if current_user.mfa_backup_codes_used else []
        backup_remaining = sum(1 for u in used_raw if not u) if used_raw else 10
    return {"mfa_enabled": bool(current_user.mfa_enabled), "backup_codes_remaining": backup_remaining}


@router.post("/mfa/verify", response_model=AuthResponse)
@audit_event("mfa_verify")
async def mfa_verify(
    payload: MFAVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Verify a TOTP code and issue tokens during MFA login.

    The caller must have authenticated with ``POST /auth/login`` and received
    an MFA challenge token (access token with ``mfa: "pending"`` claim).

    Args:
        payload: Email + TOTP verification code.
        request: The incoming request (for audit logging).
        db: Database session.

    Returns:
        Access/refresh token pair plus the encrypted key bundle.

    Raises:
        AuthenticationError: If the challenge token or the TOTP code is invalid.
    """
    # Verify the token carries the MFA-pending claim
    auth_header = request.headers.get("authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    try:
        mfa_payload = decode_token(token, expected_type=MFA_CHALLENGE_TOKEN_TYPE)
    except ValueError as err:
        raise AuthenticationError("MFA challenge token missing or invalid") from err

    if mfa_payload.get("mfa") != "pending":
        raise AuthenticationError("MFA challenge token required")

    # Resolve the user directly from the challenge token: such tokens are
    # deliberately rejected by get_current_user (C3).
    sub = mfa_payload.get("sub")
    try:
        user_uuid = uuid.UUID(str(sub))
    except (ValueError, TypeError, AttributeError) as err:
        raise AuthenticationError("MFA challenge token missing or invalid") from err

    result = await db.execute(select(User).where(User.id == user_uuid))
    current_user = result.scalar_one_or_none()
    if not current_user or not current_user.is_active:
        raise AuthenticationError("Invalid or expired token")

    if not current_user.mfa_enabled:
        raise AuthenticationError("MFA is not enabled for this user")

    enc = EncryptedSecret(
        ciphertext_b64=current_user.mfa_secret_encrypted.decode() if current_user.mfa_secret_encrypted else "",
        iv_b64=current_user.mfa_secret_iv.decode() if current_user.mfa_secret_iv else "",
        salt_b64=current_user.mfa_secret_salt.decode() if current_user.mfa_secret_salt else "",
    )
    import pyotp

    try:
        secret = decrypt_totp_secret(enc)
    except Exception as err:
        raise AuthenticationError("MFA encryption error") from err

    totp = pyotp.TOTP(secret)
    is_totp_valid = totp.verify(payload.code, valid_window=1)

    used_backup = False
    if not is_totp_valid and current_user.mfa_backup_codes_hash:
        hashes = json.loads(current_user.mfa_backup_codes_hash.decode())
        used_raw = json.loads(current_user.mfa_backup_codes_used.decode()) if current_user.mfa_backup_codes_used else [False] * len(hashes)
        code_hash = hashlib.sha256(payload.code.encode()).hexdigest()
        for i, h in enumerate(hashes):
            if h == code_hash and not used_raw[i]:
                used_raw[i] = True
                used_backup = True
                break
        if used_backup:
            current_user.mfa_backup_codes_used = json.dumps(used_raw).encode()

    if not is_totp_valid and not used_backup:
        raise AuthenticationError("Invalid MFA code or backup code")

    access_token, refresh_token = await _issue_tokens(db, current_user)

    # Record MFA verification in the cache so MFA-verified dependency checks
    # pass for sensitive operations (30 minute window).
    import time as _time_mod

    from app.core.deps import _mfa_verified_cache
    try:
        new_payload = decode_token(access_token, expected_type=ACCESS_TOKEN_TYPE)
        new_jti = new_payload.get("jti")
        if new_jti:
            _mfa_verified_cache[new_jti] = _time_mod.monotonic() + 1800
    except Exception:
        pass

    logger.info("MFA verified, tokens issued", extra={"user_id": str(current_user.id)})

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        keys=_keys_response(current_user),
    )


@router.post("/mfa/disable", response_model=dict[str, str])
@audit_event("mfa_disable")
async def mfa_disable(
    request: Request,
    payload: MFADisableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Disable MFA after re-verification.

    Args:
        payload: Email + current TOTP verification code.
        db: Database session.
        current_user: Authenticated user with MFA enabled.

    Returns:
        A confirmation message.

     Raises:
        AuthenticationError: If the verification code is invalid.
    """
    import pyotp

    if not current_user.mfa_enabled:
        raise AuthenticationError("MFA is not enabled for this user")

    enc = EncryptedSecret(
        ciphertext_b64=current_user.mfa_secret_encrypted.decode() if current_user.mfa_secret_encrypted else "",
        iv_b64=current_user.mfa_secret_iv.decode() if current_user.mfa_secret_iv else "",
        salt_b64=current_user.mfa_secret_salt.decode() if current_user.mfa_secret_salt else "",
    )
    try:
        secret = decrypt_totp_secret(enc)
    except Exception as err:
        raise AuthenticationError("MFA encryption error") from err

    totp = pyotp.TOTP(secret)
    is_totp_valid = totp.verify(payload.code, valid_window=1)

    used_backup = False
    if not is_totp_valid and current_user.mfa_backup_codes_hash:
        hashes = json.loads(current_user.mfa_backup_codes_hash.decode())
        used_raw = json.loads(current_user.mfa_backup_codes_used.decode()) if current_user.mfa_backup_codes_used else [False] * len(hashes)
        code_hash = hashlib.sha256(payload.code.encode()).hexdigest()
        for i, h in enumerate(hashes):
            if h == code_hash and not used_raw[i]:
                used_raw[i] = True
                used_backup = True
                break
        if used_backup:
            current_user.mfa_backup_codes_used = json.dumps(used_raw).encode()

    if not is_totp_valid and not used_backup:
        raise AuthenticationError("Invalid MFA code or backup code")

    current_user.mfa_enabled = False
    current_user.mfa_secret_encrypted = None
    current_user.mfa_secret_iv = None
    current_user.mfa_secret_salt = None
    current_user.mfa_backup_codes_hash = None
    current_user.mfa_backup_codes_used = None
    await db.commit()

    logger.info("MFA disabled", extra={"user_id": str(current_user.id)})
    return {"message": "MFA has been disabled"}


@router.post("/refresh", response_model=TokenResponse)
@audit_event("token_refresh", resource_fields=("refresh_token",))
async def refresh_token(
    request: Request,
    refresh_token: str = Body(..., embed=True),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Exchange a refresh token for a new access token pair.

    The presented refresh token is validated against the persisted
    ``RefreshToken`` row: it must exist, be active, not yet revoked, and not
    expired. On success the old token is revoked and a new one issued
    (rotation), so a single leaked token can only be used once. Replaying a
    revoked token is treated as evidence of theft and revokes the entire
    token family.

    Args:
        refresh_token: A valid refresh JWT.
        db: Database session.

    Returns:
        A new access/refresh token pair.

    Raises:
        AuthenticationError: If the refresh token is invalid, expired,
            revoked, or the user no longer exists.
    """
    try:
        payload = decode_token(refresh_token, expected_type=REFRESH_TOKEN_TYPE)
    except ValueError as exc:
        raise AuthenticationError("Invalid or expired refresh token") from exc

    jti = payload.get("jti")
    user_id = payload.get("sub")
    if not jti or not user_id:
        raise AuthenticationError("Invalid refresh token: missing claims")

    jti_hash = hash_token_identifier(jti)

    try:
        uuid.UUID(user_id)
    except (ValueError, AttributeError):
        raise AuthenticationError("Invalid refresh token") from None

    # Look up the token row and the user in one go.
    async with db.begin():
        stmt = (
            select(RefreshToken, User)
            .join(User, RefreshToken.user_id == User.id)
            .where(RefreshToken.jti_hash == jti_hash)
            .with_for_update()
        )
        result = await db.execute(stmt)
        row = result.first()

        if row is None:
            # The token was never issued, or it was revoked and the row
            # replaced. Treat replay of a revoked token as theft.
            raise AuthenticationError("Invalid or expired refresh token")

        token_row, user = row

        if token_row.revoked_at is not None:
            # Reuse of a rotated token: invalidate the whole family.
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.user_id == user.id,
                    RefreshToken.revoked_at.is_(None),
                )
                .values(revoked_at=datetime.now(UTC))
            )
            logger.warning(
                "Refresh token reuse detected — revoking all tokens for user",
                extra={"user_id": str(user.id)},
            )
            raise AuthenticationError("Refresh token reuse detected; re-authenticate")

        if user is None or not user.is_active:
            raise AuthenticationError("Invalid or expired refresh token")

        if token_row.expires_at.tzinfo is None:
            expires_at = token_row.expires_at.replace(tzinfo=UTC)
        else:
            expires_at = token_row.expires_at
        if expires_at <= datetime.now(UTC):
            raise AuthenticationError("Refresh token has expired")

        # Revoke the used token and issue a fresh one.
        token_row.revoked_at = datetime.now(UTC)

        new_jti = uuid.uuid4().hex
        new_jti_hash = hash_token_identifier(new_jti)
        token_row.replaced_by_hash = new_jti_hash
        new_refresh = create_refresh_token({"sub": str(user.id)}, jti=new_jti)
        db.add(
            RefreshToken(
                user_id=user.id,
                jti_hash=new_jti_hash,
                expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_expire_days),
            )
        )

    # Refreshed access tokens must carry a jti like every other access token —
    # it is what get_current_user_mfa_verified keys its cache on (H7).
    access = create_access_token({"sub": str(user.id)}, jti=uuid.uuid4().hex)
    logger.info("Token refreshed", extra={"user_id": str(user.id)})
    return TokenResponse(access_token=access, refresh_token=new_refresh)


@router.post("/logout", response_model=dict[str, str])
@audit_event("logout")
async def logout(
    request: Request,
    payload: LogoutRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Revoke a refresh token, ending the session that issued it.

    The access token is short-lived and stateless, so it cannot be revoked
    synchronously; logout's security value is in invalidating the refresh
    token so it cannot mint new access tokens.

    Args:
        request: The incoming request (for audit logging).
        payload: Contains the refresh token to revoke.
        db: Database session.

    Returns:
        A confirmation message.
    """
    try:
        decoded = decode_token(payload.refresh_token, expected_type=REFRESH_TOKEN_TYPE)
    except ValueError:
        raise AuthenticationError("Invalid or expired refresh token") from None

    jti = decoded.get("jti")
    if jti:
        jti_hash = hash_token_identifier(jti)
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.jti_hash == jti_hash)
            .values(revoked_at=datetime.now(UTC))
        )
        await db.commit()

    return {"message": "Logged out"}


@router.get("/public-key/{email}", response_model=PublicKeyResponse)
async def get_public_key(
    email: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PublicKeyResponse:
    """Retrieve a user's RSA public key in PEM format.

    Used by senders to wrap (encrypt) file keys for secure sharing.

    Args:
        email: The recipient user's email address.
        db: Database session.
        current_user: Authenticated user (access is gated to stop
            email-enumeration).

    Returns:
        The user's public key as a PEM-encoded string.

    Raises:
        NotFoundError: If no user exists with the given email.
    """
    result = await db.execute(select(User.public_key_b64).where(User.email == email))
    key_b64 = result.scalar_one_or_none()
    if not key_b64:
        raise NotFoundError("User not found")

    try:
        key_bytes = base64.b64decode(key_b64)
        public_key = serialization.load_der_public_key(key_bytes)
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as exc:
        logger.error(
            "Failed to parse public key",
            extra={"email": email, "error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve public key",
        ) from exc

    return PublicKeyResponse(public_key_pem=pem.decode("utf-8"))
