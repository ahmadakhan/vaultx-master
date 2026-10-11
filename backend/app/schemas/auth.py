"""Authentication-related Pydantic schemas.

Defines request and response models for user registration, login,
token management, key provisioning, and logout.
"""

from __future__ import annotations

import base64
import binascii

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, EmailStr, Field, ValidationInfo, field_validator, model_validator

from app.core.security import (
    BCRYPT_MAX_PASSWORD_BYTES,
    CURRENT_KDF_ITERATIONS,
    CURRENT_KEY_BUNDLE_VERSION,
    LEGACY_KDF_ITERATIONS,
    LEGACY_KEY_BUNDLE_VERSION,
)

MIN_PASSWORD_LENGTH = 12
MAX_KDF_ITERATIONS = 10_000_000


class UserKeysResponse(BaseModel):
    """Encrypted key material returned after registration or login.

    All fields are base64-encoded ciphertext or IVs produced client-side.
    The backend stores these as-is without decryption.

    ``kdf_iterations`` and ``key_bundle_version`` tell the client how the
    bundle was produced. They are always concrete values: bundles created
    before these fields existed are reported as the legacy parameters so the
    client keeps deriving exactly as it originally did.
    """

    password_salt_b64: str
    enc_master_key_b64: str
    enc_master_key_iv: str
    enc_search_key_b64: str
    enc_search_key_iv: str
    enc_private_key_b64: str
    enc_private_key_iv: str
    public_key_b64: str
    kdf_iterations: int = LEGACY_KDF_ITERATIONS
    key_bundle_version: int = LEGACY_KEY_BUNDLE_VERSION


class RegisterPayload(BaseModel):
    """Client request body for user registration.

    The client generates a salt, derives a password-based key via PBKDF2, and
    encrypts the master/search/RSA-private keys under it. All encrypted blobs
    are sent as base64 strings.

    ``kdf_iterations``/``key_bundle_version`` are optional so clients predating
    the versioned bundle continue to work; omitting them is treated as the
    legacy 150k-iteration, unauthenticated-AD bundle.
    """

    email: EmailStr
    password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=128)

    password_salt_b64: str
    enc_master_key_b64: str
    enc_master_key_iv: str
    enc_search_key_b64: str
    enc_search_key_iv: str
    enc_private_key_b64: str
    enc_private_key_iv: str
    public_key_b64: str

    kdf_iterations: int | None = None
    key_bundle_version: int | None = None

    @field_validator(
        "password_salt_b64",
        "enc_master_key_b64",
        "enc_master_key_iv",
        "enc_search_key_b64",
        "enc_search_key_iv",
        "enc_private_key_b64",
        "enc_private_key_iv",
        "public_key_b64",
    )
    @classmethod
    def _validate_key_material(cls, value: str, info: ValidationInfo) -> str:
        if len(value) > 16384:
            raise ValueError("Encoded key material is too large")
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Key material must be valid base64") from exc
        name = info.field_name or ""
        if name.endswith("_iv"):
            valid = len(raw) == 12
        elif name == "password_salt_b64":
            valid = 16 <= len(raw) <= 64
        elif name in ("enc_master_key_b64", "enc_search_key_b64"):
            valid = len(raw) == 48  # AES-256 key + GCM tag
        elif name == "public_key_b64":
            try:
                key = serialization.load_der_public_key(raw)
                valid = isinstance(key, rsa.RSAPublicKey) and 2048 <= key.key_size <= 8192
            except (ValueError, TypeError):
                valid = False
        else:
            valid = 16 < len(raw) <= 12288
        if not valid:
            raise ValueError("Invalid key material size or format")
        return value

    @model_validator(mode="after")
    def _paired_bundle_metadata(self) -> RegisterPayload:
        if (self.key_bundle_version is None) != (self.kdf_iterations is None):
            raise ValueError("key_bundle_version and kdf_iterations must be supplied together")
        return self

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        """Store addresses in one canonical form."""
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def _validate_password_strength(cls, v: str) -> str:
        """Enforce minimum password complexity and bcrypt-safe length."""
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if len(v.encode("utf-8")) > BCRYPT_MAX_PASSWORD_BYTES:
            raise ValueError(
                f"Password must be at most {BCRYPT_MAX_PASSWORD_BYTES} bytes; "
                "bcrypt silently ignores anything beyond that"
            )
        return v

    @field_validator("kdf_iterations")
    @classmethod
    def _validate_kdf_iterations(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v < CURRENT_KDF_ITERATIONS:
            raise ValueError(f"kdf_iterations must be at least {CURRENT_KDF_ITERATIONS}")
        if v > MAX_KDF_ITERATIONS:
            raise ValueError(f"kdf_iterations must be at most {MAX_KDF_ITERATIONS}")
        return v

    @field_validator("key_bundle_version")
    @classmethod
    def _validate_bundle_version(cls, v: int | None) -> int | None:
        """Only the current bundle version may be requested explicitly."""
        if v is None:
            return None
        if v != CURRENT_KEY_BUNDLE_VERSION:
            raise ValueError(
                f"key_bundle_version must be {CURRENT_KEY_BUNDLE_VERSION}; "
                "omit the field to keep a legacy bundle"
            )
        return v


class UserLogin(BaseModel):
    """Client request body for login."""

    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)
    code: str | None = Field(default=None, pattern=r"^(?:[0-9]{6}|[a-f0-9]{20})$", max_length=20)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class AuthResponse(BaseModel):
    """Combined response for register/login containing tokens and keys."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    mfa_required: bool = False
    # Absent while MFA is pending: the bundle is only released by
    # POST /auth/mfa/verify once the second factor passes.
    keys: UserKeysResponse | None = None


class TokenResponse(BaseModel):
    """Response for token refresh endpoint."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """Request body for exchanging a refresh token."""

    refresh_token: str = Field(..., min_length=1, max_length=4096)


class LogoutRequest(BaseModel):
    """Request body for revoking a refresh token."""

    refresh_token: str = Field(..., min_length=1, max_length=4096)


class PublicKeyResponse(BaseModel):
    """Response containing a user's RSA public key in PEM format."""

    public_key_pem: str


class MFASetupResponse(BaseModel):
    """Response after MFA setup — includes QR code URL and backup codes."""

    qr_code_url: str
    secret: str
    backup_codes: list[str]  # 10 single-use codes for recovery


class MFAVerifyRequest(BaseModel):
    """Request body for verifying a TOTP code during login or MFA enable/disable."""

    code: str = Field(..., pattern=r"^(?:[0-9]{6}|[a-f0-9]{20})$", max_length=20)


class MFADisableRequest(BaseModel):
    """Request body for disabling MFA — requires a current TOTP or backup code."""

    code: str = Field(..., pattern=r"^(?:[0-9]{6}|[a-f0-9]{20})$", max_length=20)
    use_backup: bool = Field(default=False, description="Use a backup code instead of TOTP")


class TokenPayload(BaseModel):
    """Decoded JWT token payload schema."""

    sub: str | None = None
    exp: int | None = None
    type: str | None = None
