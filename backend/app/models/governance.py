"""Durable recovery and governance records.

These records deliberately contain metadata and hashes only.  Blob delivery is
provided by a pluggable adapter; VaultX never claims that an external archive
has been configured.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, UUID, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class RecoveryPolicy(Base):
    __tablename__ = "recovery_policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rpo_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)
    rto_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=240)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    residency_region: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class BackupManifest(Base):
    __tablename__ = "backup_manifests"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    object_count: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditOutbox(Base):
    __tablename__ = "audit_outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class LegalHold(Base):
    __tablename__ = "legal_holds"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
