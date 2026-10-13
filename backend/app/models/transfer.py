"""Durable transfer and write-only guest dropbox state."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import UUID, BigInteger, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow


class UploadSession(Base):
    """Server-side checkpoint for a resumable encrypted upload."""

    __tablename__ = "upload_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    file_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True, index=True)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    offset: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    chunk_size: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_path: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="active", nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class GuestDropbox(Base):
    """Write-only, expiring capability owned by an authenticated user."""

    __tablename__ = "guest_dropboxes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    capability_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    used_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    max_uploads: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    upload_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class GuestDropboxUpload(Base):
    """Opaque staged object accepted by a dropbox; never guest-readable."""

    __tablename__ = "guest_dropbox_uploads"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dropbox_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("guest_dropboxes.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    storage_path: Mapped[str] = mapped_column(String, nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    finalized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending", nullable=False, index=True)
    file_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reconciliation_state: Mapped[str] = mapped_column(String, default="staged", nullable=False)

    dropbox: Mapped[GuestDropbox] = relationship("GuestDropbox")
