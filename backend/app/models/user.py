"""User and role models.

Defines the ``User`` entity along with role-based access control
(RBAC) support via ``Role`` and ``UserRole`` association tables.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    UUID,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow

if TYPE_CHECKING:
    from app.models.file import File, FileShare


def normalize_email(email: str) -> str:
    """Return the canonical form of an email address used for storage/lookup."""
    return email.strip().lower()


def email_matches(column: Any, email: str) -> Any:
    """Build a case-insensitive equality predicate for an email column.

    Addresses are normalised on write, but rows created before normalisation
    existed may be mixed-case, so lookups must not rely on exact equality.
    """
    return func.lower(column) == normalize_email(email)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    password_salt_b64: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enc_master_key_b64: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enc_master_key_iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enc_search_key_b64: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enc_search_key_iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enc_private_key_b64: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enc_private_key_iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_key_b64: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    index_state_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    index_state_iv: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # --- MFA (TOTP) ---
    # The TOTP secret is encrypted with the user's password-derived key before
    # being stored, so the server never sees the plaintext secret.
    mfa_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_secret_iv: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_secret_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # --- MFA Backup Codes ---
    # SHA-256 hashes of 10 single-use backup codes (20-char hex each).
    # The plaintext codes are returned only once at creation time.
    mfa_backup_codes_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_backup_codes_used: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True, comment="JSON array of booleans tracking used codes"
    )

    # --- Client-side key bundle metadata ---
    # ``None`` marks a pre-existing bundle, so legacy rows keep deriving keys
    # with their original parameters instead of becoming undecryptable.
    key_bundle_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    password_kdf_iterations: Mapped[int | None] = mapped_column(Integer, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    files: Mapped[list[File]] = relationship(
        "File", back_populates="owner", cascade="all, delete-orphan"
    )
    backups: Mapped[list[Backup]] = relationship(
        "Backup", back_populates="user", cascade="all, delete-orphan"
    )
    shares: Mapped[list[FileShare]] = relationship(
        "FileShare",
        back_populates="recipient",
        foreign_keys="FileShare.recipient_user_id",
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class Role(Base):
    """Role definition for RBAC access control."""

    __tablename__ = "roles"
    name: Mapped[str] = mapped_column(String, primary_key=True)


class UserRole(Base):
    """Association between a user and a role. Enforced via get_current_admin."""

    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role: Mapped[str] = mapped_column(
        String, ForeignKey("roles.name", ondelete="CASCADE"), primary_key=True
    )


class Backup(Base):
    __tablename__ = "backups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    user: Mapped[User] = relationship("User", back_populates="backups")


class RefreshToken(Base):
    """Server-side record of an issued refresh token.

    Only the SHA-256 hash of the token's ``jti`` claim is stored, so a database
    disclosure does not yield usable identifiers. Rows make refresh tokens
    single-use (rotation) and revocable: deleting or marking every row for a
    user invalidates all of that user's outstanding sessions.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    jti_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replaced_by_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[User] = relationship("User", back_populates="refresh_tokens")

    @property
    def is_active(self) -> bool:
        """Whether the token is still usable (not revoked and not expired)."""
        expires = self.expires_at
        if expires.tzinfo is None:  # SQLite returns naive datetimes
            expires = expires.replace(tzinfo=UTC)
        return self.revoked_at is None and expires > utcnow()
