"""Authentication, revocable sessions, and database-coordinated MFA."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp
import qrcode
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Body, Depends, Request
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.audit_decorator import audit_event
from app.core.audit_log import record_audit_log
from app.core.auth_budget import reserve_attempt, reset_attempts
from app.core.deps import get_current_user, valid_mfa_claim
from app.core.exceptions import AuthenticationError, ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.mfa import EncryptedSecret, decrypt_totp_secret, encrypt_totp_secret
from app.core.security import (
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
from app.core.tenant import set_tenant_context
from app.db import get_db
from app.models import (
    RefreshToken,
    Tenant,
    TenantQuota,
    User,
    UserRole,
    email_matches,
    normalize_email,
)
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
    global _dummy_password_hash
    if _dummy_password_hash is None:
        _dummy_password_hash = hash_password("vaultx-timing-equalizer")
    return _dummy_password_hash


def _keys_response(user: User) -> UserKeysResponse:
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


async def _issue_tokens(
    db: AsyncSession, user: User, *, mfa_at: float | None = None, commit: bool = True
) -> tuple[str, str]:
    jti = uuid.uuid4().hex
    claims: dict[str, Any] = {"sub": str(user.id)}
    if mfa_at is not None:
        claims["mfa_at"] = mfa_at
        claims["type"] = "access"
    access = create_access_token(claims, jti=jti)
    refresh = create_refresh_token(claims, jti=jti)
    db.add(
        RefreshToken(
            user_id=user.id,
            jti_hash=hash_token_identifier(jti),
            expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_expire_days),
        )
    )
    if commit:
        await db.commit()
    return access, refresh


async def _revoke_all_refresh_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )


async def _locked_user(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = await db.scalar(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if user is None or not user.is_active:
        raise AuthenticationError("Invalid or expired token")
    return user


def _totp_secret(user: User) -> str:
    # Enrollment has always stored raw bytes, not UTF-8 base64 text.
    try:
        enc = EncryptedSecret(
            *(
                base64.b64encode(value or b"").decode()
                for value in (user.mfa_secret_encrypted, user.mfa_secret_iv, user.mfa_secret_salt)
            )
        )
        return decrypt_totp_secret(enc)
    except Exception as exc:
        raise AuthenticationError("MFA verification unavailable") from exc


async def _verify_factor(db: AsyncSession, user: User, code: str, *, backup: bool = True) -> None:
    """Verify while holding the user lock; reserve TOTP steps/backup codes once."""
    secret = _totp_secret(user)
    totp = pyotp.TOTP(secret)
    now = datetime.now(UTC)
    step = int(now.timestamp()) // totp.interval
    matched = next(
        (
            n
            for n in (step - 1, step, step + 1)
            if secrets.compare_digest(totp.generate_otp(n), code)
        ),
        None,
    )
    if matched is not None:
        # A uniqueness constraint also prevents concurrent consumption on SQLite,
        # whose SELECT FOR UPDATE is a no-op. Never persist the secret or OTP.
        marker = hash_token_identifier(
            f"totp:{user.id}:{hashlib.sha256(secret.encode()).hexdigest()}:{matched}"
        )
        db.add(
            RefreshToken(
                user_id=user.id,
                jti_hash=marker,
                revoked_at=now,
                expires_at=now + timedelta(minutes=2),
            )
        )
        try:
            await db.flush()
        except IntegrityError as exc:
            await db.rollback()
            raise AuthenticationError("MFA code has already been used") from exc
        return
    if backup and user.mfa_backup_codes_hash:
        hashes = json.loads(user.mfa_backup_codes_hash)
        used = json.loads(user.mfa_backup_codes_used or b"[]")
        digest = hashlib.sha256(code.encode()).hexdigest()
        for index, stored in enumerate(hashes):
            if index < len(used) and not used[index] and secrets.compare_digest(stored, digest):
                marker = hash_token_identifier(f"backup:{user.id}:{stored}")
                db.add(
                    RefreshToken(
                        user_id=user.id,
                        jti_hash=marker,
                        revoked_at=now,
                        expires_at=now + timedelta(days=365),
                    )
                )
                used[index] = True
                user.mfa_backup_codes_used = json.dumps(used).encode()
                try:
                    await db.flush()
                except IntegrityError as exc:
                    await db.rollback()
                    raise AuthenticationError("MFA code has already been used") from exc
                return
    raise AuthenticationError("Invalid MFA code or backup code")


@router.post("/register", response_model=AuthResponse)
async def register_user(
    payload: RegisterPayload, db: AsyncSession = Depends(get_db)
) -> AuthResponse:
    if settings.password_auth_mode == "opaque-required":
        raise AuthenticationError("PAKE/OPAQUE authentication is required but not configured")
    email = normalize_email(str(payload.email))
    if await db.scalar(select(User.id).where(email_matches(User.email, email))):
        raise ConflictError("Email already registered")
    fields = {
        name: getattr(payload, name).encode()
        for name in (
            "password_salt_b64",
            "enc_master_key_b64",
            "enc_master_key_iv",
            "enc_search_key_b64",
            "enc_search_key_iv",
            "enc_private_key_b64",
            "enc_private_key_iv",
            "public_key_b64",
        )
    }
    # Every account owns an isolated tenant from its first transaction.  Do
    # not create tenantless users: RLS intentionally denies rows without a
    # tenant context and such accounts could not be safely served.
    tenant = Tenant(
        tenant_id=str(uuid.uuid4()),
        name=f"{email}'s Vault",
    )
    db.add(tenant)
    await db.flush()
    await set_tenant_context(db, tenant.id)
    db.add(TenantQuota(tenant_id=tenant.id, storage_quota_bytes=tenant.storage_quota_bytes))
    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        tenant_id=tenant.id,
        **fields,
        key_bundle_version=payload.key_bundle_version,
        password_kdf_iterations=payload.kdf_iterations,
    )
    db.add(user)
    try:
        await db.flush()
        # Public registration never grants administrator privileges. Bootstrap
        # an administrator explicitly through trusted deployment tooling.
        db.add(UserRole(user_id=user.id, role="user"))
        access, refresh = await _issue_tokens(db, user)
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictError("Email already registered") from exc
    return AuthResponse(access_token=access, refresh_token=refresh, keys=_keys_response(user))


@router.post("/login", response_model=AuthResponse)
@audit_event("login")
async def login_user(
    user_in: UserLogin, request: Request, db: AsyncSession = Depends(get_db)
) -> AuthResponse:
    if settings.password_auth_mode == "opaque-required":
        raise AuthenticationError("PAKE/OPAQUE authentication is required but not configured")
    email = normalize_email(str(user_in.email))
    await reserve_attempt(db, "password", email)
    user = await db.scalar(select(User).where(email_matches(User.email, email)))
    password_ok = verify_password(
        user_in.password, str(user.password_hash) if user else _dummy_hash()
    )
    if user is None or not user.is_active or not password_ok:
        await record_audit_log(db, request, user.id if user else None, "login_failed")
        raise AuthenticationError("Invalid credentials")
    mfa_at = None
    if user.mfa_enabled:
        if user_in.code:
            await reserve_attempt(db, "mfa", str(user.id))
            user = await _locked_user(db, user.id)
            await _verify_factor(db, user, user_in.code)
            mfa_at = datetime.now(UTC).timestamp()
        else:
            jti = uuid.uuid4().hex
            challenge = create_mfa_challenge_token({"sub": str(user.id), "mfa": "pending"}, jti=jti)
            db.add(
                RefreshToken(
                    user_id=user.id,
                    jti_hash=hash_token_identifier(jti),
                    expires_at=datetime.now(UTC) + timedelta(minutes=10),
                )
            )
            await db.commit()
            return AuthResponse(access_token=challenge, refresh_token="", mfa_required=True)
    await reset_attempts(db, "password", email)
    access, refresh = await _issue_tokens(db, user, mfa_at=mfa_at)
    return AuthResponse(access_token=access, refresh_token=refresh, keys=_keys_response(user))


@router.post("/mfa/setup", response_model=MFASetupResponse)
@audit_event("mfa_setup")
async def mfa_setup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MFASetupResponse:
    current_user = await _locked_user(db, current_user.id)
    if current_user.mfa_enabled:
        raise ConflictError("Disable MFA before starting a new enrollment")
    secret = pyotp.random_base32()
    enc = encrypt_totp_secret(secret)
    current_user.mfa_secret_encrypted = base64.b64decode(enc.ciphertext_b64)
    current_user.mfa_secret_iv = base64.b64decode(enc.iv_b64)
    current_user.mfa_secret_salt = base64.b64decode(enc.salt_b64)
    codes = [secrets.token_hex(10) for _ in range(10)]
    current_user.mfa_backup_codes_hash = json.dumps(
        [hashlib.sha256(c.encode()).hexdigest() for c in codes]
    ).encode()
    current_user.mfa_backup_codes_used = json.dumps([False] * len(codes)).encode()
    await db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="VaultX")
    image = qrcode.make(uri)
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return MFASetupResponse(
        qr_code_url="data:image/png;base64," + base64.b64encode(buf.getvalue()).decode(),
        secret=secret,
        backup_codes=codes,
    )


@router.post("/mfa/enable", response_model=dict[str, str])
@audit_event("mfa_enable")
async def mfa_enable(
    request: Request,
    payload: MFAVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    await reserve_attempt(db, "mfa", str(current_user.id))
    current_user = await _locked_user(db, current_user.id)
    if current_user.mfa_enabled:
        raise ConflictError("MFA is already enabled")
    await _verify_factor(db, current_user, payload.code, backup=False)
    current_user.mfa_enabled = True
    await _revoke_all_refresh_tokens(db, current_user.id)
    await db.commit()
    return {"message": "MFA has been enabled. Sign in again."}


@router.get("/mfa/status", response_model=dict[str, Any])
async def mfa_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    used = json.loads(current_user.mfa_backup_codes_used or b"[]")
    return {
        "mfa_enabled": bool(current_user.mfa_enabled),
        "backup_codes_remaining": sum(not value for value in used),
    }


@router.post("/mfa/verify", response_model=AuthResponse)
@audit_event("mfa_verify")
async def mfa_verify(
    payload: MFAVerifyRequest, request: Request, db: AsyncSession = Depends(get_db)
) -> AuthResponse:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    try:
        if scheme.lower() != "bearer":
            raise ValueError("Missing bearer token")
        claims = decode_token(token, expected_type=MFA_CHALLENGE_TOKEN_TYPE)
        user_id = uuid.UUID(claims["sub"])
        if claims.get("mfa") != "pending":
            raise ValueError("Invalid challenge")
    except (ValueError, TypeError) as exc:
        raise AuthenticationError("MFA challenge token missing or invalid") from exc
    await reserve_attempt(db, "mfa", str(user_id))
    user = await _locked_user(db, user_id)
    if not user.mfa_enabled:
        raise AuthenticationError("MFA is not enabled")
    challenge = await db.scalar(
        select(RefreshToken)
        .where(
            RefreshToken.jti_hash == hash_token_identifier(claims["jti"]),
            RefreshToken.user_id == user.id,
        )
        .with_for_update()
    )
    if challenge is None or not challenge.is_active:
        raise AuthenticationError("MFA challenge has expired or been used")
    await _verify_factor(db, user, payload.code)
    challenge.revoked_at = datetime.now(UTC)
    await reset_attempts(db, "password", user.email)
    access, refresh = await _issue_tokens(db, user, mfa_at=datetime.now(UTC).timestamp())
    return AuthResponse(access_token=access, refresh_token=refresh, keys=_keys_response(user))


@router.post("/mfa/disable", response_model=dict[str, str])
@audit_event("mfa_disable")
async def mfa_disable(
    request: Request,
    payload: MFADisableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    await reserve_attempt(db, "mfa", str(current_user.id))
    current_user = await _locked_user(db, current_user.id)
    if not current_user.mfa_enabled:
        raise AuthenticationError("MFA is not enabled")
    await _verify_factor(db, current_user, payload.code)
    current_user.mfa_enabled = False
    current_user.mfa_secret_encrypted = None
    current_user.mfa_secret_iv = None
    current_user.mfa_secret_salt = None
    current_user.mfa_backup_codes_hash = None
    current_user.mfa_backup_codes_used = None
    await _revoke_all_refresh_tokens(db, current_user.id)
    await db.commit()
    return {"message": "MFA has been disabled. Sign in again."}


@router.post("/refresh", response_model=TokenResponse)
@audit_event("token_refresh")
async def refresh_token(
    request: Request,
    refresh_token: str = Body(..., embed=True, min_length=1, max_length=4096),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        payload = decode_token(refresh_token, expected_type=REFRESH_TOKEN_TYPE)
        user_id = uuid.UUID(payload["sub"])
    except (ValueError, TypeError) as exc:
        raise AuthenticationError("Invalid or expired refresh token") from exc
    # Lock ordering is consistently user -> session, including MFA/logout.
    user = await _locked_user(db, user_id)
    row = await db.scalar(
        select(RefreshToken)
        .where(
            RefreshToken.jti_hash == hash_token_identifier(payload["jti"]),
            RefreshToken.user_id == user.id,
        )
        .with_for_update()
    )
    if row is None:
        raise AuthenticationError("Invalid or expired refresh token")
    if row.revoked_at is not None:
        await _revoke_all_refresh_tokens(db, user.id)
        # Commit before raising: a transaction context would roll back this
        # security-critical revocation when AuthenticationError escapes.
        await db.commit()
        raise AuthenticationError("Refresh token reuse detected; re-authenticate")
    if not row.is_active or (user.mfa_enabled and not valid_mfa_claim(payload)):
        raise AuthenticationError("Invalid or expired refresh token")
    row.revoked_at = datetime.now(UTC)
    access, refresh = await _issue_tokens(db, user, mfa_at=payload.get("mfa_at"), commit=False)
    row.replaced_by_hash = hash_token_identifier(decode_token(refresh)["jti"])
    await db.commit()
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/logout", response_model=dict[str, str])
@audit_event("logout")
async def logout(
    request: Request, payload: LogoutRequest, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    try:
        claims = decode_token(payload.refresh_token, expected_type=REFRESH_TOKEN_TYPE)
        user_id = uuid.UUID(claims["sub"])
    except (ValueError, TypeError) as exc:
        raise AuthenticationError("Invalid or expired refresh token") from exc
    await _locked_user(db, user_id)
    await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.jti_hash == hash_token_identifier(claims["jti"]),
            RefreshToken.user_id == user_id,
        )
        .values(revoked_at=datetime.now(UTC))
    )
    await db.commit()
    return {"message": "Logged out"}


@router.get("/public-key/{email}", response_model=PublicKeyResponse)
async def get_public_key(
    email: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> PublicKeyResponse:
    key = await db.scalar(
        select(User.public_key_b64).where(
            email_matches(User.email, email), User.is_active.is_(True)
        )
    )
    if not key:
        raise NotFoundError("User not found")
    try:
        public_key = serialization.load_der_public_key(base64.b64decode(key, validate=True))
        pem = public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except (ValueError, TypeError) as exc:
        raise NotFoundError("Public key unavailable") from exc
    return PublicKeyResponse(public_key_pem=pem.decode())
