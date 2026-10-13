"""File and sharing models.

Defines the ``File`` entity representing an encrypted file stored
in the vault, along with ``FileShare`` for secure file sharing
between users via RSA-OAEP wrapped key encryption.

File ciphertext is stored on the filesystem (not in the database)
to support large uploads up to 10 GB. The ``ciphertext`` column is
retained for backward compatibility but new uploads use the
``storage_path`` column to locate the blob.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    UUID,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow

if TYPE_CHECKING:
    from app.models.user import User


class File(Base):
    """Encrypted file stored in the vault.

    The file content (``ciphertext``), metadata, and file key
    (``encrypted_kf``) are all encrypted before persistence. The
    file key (Kf) is itself encrypted under the owner's master key.

    For large files (>1 GB) the ciphertext is stored on the
    filesystem and ``storage_path`` points to the blob location.
    """

    __tablename__ = "files"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    storage_path: Mapped[str | None] = mapped_column(String, nullable=True)
    file_size: Mapped[int | None] = mapped_column(nullable=True)
    file_iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    metadata_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    metadata_iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_kf: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    encrypted_kf_iv: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Set when the file enters the trash; the reaper purges blob + row once
    # the retention window elapses. NULL while the file is live.
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    owner: Mapped[User] = relationship("User", back_populates="files")
    shares: Mapped[list[FileShare]] = relationship(
        "FileShare", back_populates="file", cascade="all, delete-orphan"
    )
    shared_links: Mapped[list[SharedLink]] = relationship(
        "SharedLink", back_populates="file", cascade="all, delete-orphan"
    )


class FileShare(Base):
    """Share entry for granting access to a file.

    The file key (Kf) is wrapped (encrypted) using the recipient's
    RSA-OAEP public key and stored as ``wrapped_key``. Only the
    recipient can unwrap it with their private key.
    """

    __tablename__ = "file_shares"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("files.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    recipient_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    permissions: Mapped[str] = mapped_column(String, default="read", nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    file: Mapped[File] = relationship("File", back_populates="shares", foreign_keys=[file_id])
    recipient: Mapped[User] = relationship(
        "User", back_populates="shares", foreign_keys=[recipient_user_id]
    )


class SharedLink(Base):
    """Publicly shareable link for a file (no recipient account required).

    A shareable link uses a cryptographically random ``token`` (UUID) that
    acts as a bearer credential. Optionally an ``access_code`` can be required
    so the link alone is insufficient to download the file.
    """

    __tablename__ = "shared_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("files.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    access_code_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    encrypted_kf: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    encrypted_kf_iv: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    kf_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_downloads: Mapped[int | None] = mapped_column(Integer, nullable=True)
    download_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    file: Mapped[File] = relationship("File", back_populates="shared_links")

    attempt_guard: Mapped[SharedLinkAttempt | None] = relationship(
        "SharedLinkAttempt", back_populates="link", cascade="all, delete-orphan", uselist=False
    )


class SharedLinkAttempt(Base):
    """Per-link access-code attempt guard for public share links (H4).

    Tracks failed access-code guesses so that a short code cannot be
    brute-forced online: after ``max_attempts`` failures the link is locked
    for a cool-off period. The table is created automatically by
    ``Base.metadata.create_all``.
    """

    __tablename__ = "share_link_attempts"

    link_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("shared_links.id", ondelete="CASCADE"),
        primary_key=True,
    )
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    link: Mapped[SharedLink] = relationship("SharedLink", back_populates="attempt_guard")
