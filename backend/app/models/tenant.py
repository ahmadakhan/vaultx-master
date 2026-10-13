from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    BIGINT,
    UUID,
    Boolean,
    DateTime,
    ForeignKey,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow
from app.models.user import User


class Tenant(Base):
    """Enterprise tenant entity with storage allocation control.

    Each tenant has a dedicated storage quota allocated by administrators.
    The quota is enforced at upload time through database row locking.
    All access is via foreign key constraints for inherent RLS.
    """

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        comment="External tenant identifier for integrations",
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False, comment="Tenant display name for admin dashboards"
    )
    storage_quota_bytes: Mapped[int] = mapped_column(
        BIGINT,
        default=10737418240,
        nullable=False,  # 10GB default
        comment="Hard quota for this tenant's storage in bytes",
    )
    allocated_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True,
        comment="Administrator who allocated this quota",
    )
    quota_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        comment="Tenant active status for soft disable",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # Relationships
    users: Mapped[list[User]] = relationship(
        "User", back_populates="tenant", foreign_keys="User.tenant_id"
    )
    quota: Mapped[TenantQuota | None] = relationship(
        "TenantQuota", back_populates="tenant", uselist=False, lazy="select"
    )
    storage_allocations: Mapped[list[AdminStorageAllocation]] = relationship(
        "AdminStorageAllocation",
        back_populates="tenant",
        foreign_keys="AdminStorageAllocation.tenant_id",
    )

    @property
    def is_quota_exceeded(self) -> bool:
        """Check if tenant has exceeded its storage quota."""
        return self.quota is not None and self.quota.storage_used_bytes >= self.storage_quota_bytes

    @property
    def quota_utilization_percent(self) -> float:
        """Calculate quota utilization percentage."""
        if not self.quota or self.storage_quota_bytes == 0:
            return 0.0
        return min(100.0, (self.quota.storage_used_bytes / self.storage_quota_bytes) * 100)


class TenantQuota(Base):
    """Real-time storage quota tracking with usage metrics.

    Tracks actual storage usage against allocated quota. All quota changes
    are logged through AdminStorageAllocation for audit trail completeness.
    """

    __tablename__ = "tenant_quotas"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
        comment="Reference to parent tenant",
    )
    storage_quota_bytes: Mapped[int] = mapped_column(
        BIGINT,
        default=10737418240,
        nullable=False,
        comment="The allocated storage quota in bytes",
    )
    storage_used_bytes: Mapped[int] = mapped_column(
        BIGINT,
        default=0,
        nullable=False,
        index=True,
        comment="Current storage consumption in bytes",
    )
    pending_upload_bytes: Mapped[int] = mapped_column(
        BIGINT, default=0, nullable=False, index=True,
        comment="Bytes held by staged uploads awaiting publication",
    )
    allocated_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True,
        comment="Administrator who last updated the quota",
    )
    quota_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    last_accessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # Relationships
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="quota")
    admin: Mapped[User | None] = relationship("User", foreign_keys=[allocated_by_admin_id])

    def update_quota(
        self, new_quota_bytes: int, admin_user_id: uuid.UUID, reason: str | None = None
    ) -> None:
        """Update tenant quota with audit trail preparation.

        Args:
            new_quota_bytes: New quota in bytes (must be >= 0)
            admin_user_id: ID of administrator making the change
            reason: Optional reason for audit logging

        Raises:
            ValueError: If new_quota_bytes is negative
        """
        if new_quota_bytes < 0:
            raise ValueError("Quota cannot be negative")

        self.storage_quota_bytes = new_quota_bytes
        self.allocated_by_admin_id = admin_user_id
        self.quota_updated_at = datetime.now(UTC)
        self.last_accessed_at = datetime.now(UTC)

    def increment_usage(self, bytes_to_add: int) -> None:
        """Increment storage usage by specified bytes.

        Args:
            bytes_to_add: Number of bytes to add (must be non-negative)

        Raises:
            ValueError: If bytes_to_add is negative or would exceed quota
        """
        if bytes_to_add < 0:
            raise ValueError("Cannot increment storage usage with negative value")

        if self.storage_used_bytes + bytes_to_add > self.storage_quota_bytes:
            raise ValueError(
                f"Would exceed quota: {self.storage_used_bytes} + {bytes_to_add} > "
                f"{self.storage_quota_bytes}"
            )

        self.storage_used_bytes += bytes_to_add
        self.last_accessed_at = datetime.now(UTC)

    def reserve(self, bytes_to_add: int) -> None:
        """Apply a validated reservation to an already locked quota row."""
        self.increment_usage(bytes_to_add)

    def decrement_usage(self, bytes_to_remove: int) -> None:
        """Decrement storage usage by specified bytes.

        Args:
            bytes_to_remove: Number of bytes to remove (must be non-negative)

        Raises:
            ValueError: If bytes_to_remove is negative
        """
        if bytes_to_remove < 0:
            raise ValueError("Cannot decrement storage usage with negative value")

        if bytes_to_remove > self.storage_used_bytes:
            raise ValueError(
                f"Cannot remove more than used: {bytes_to_remove} > {self.storage_used_bytes}"
            )

        self.storage_used_bytes -= bytes_to_remove
        self.last_accessed_at = datetime.now(UTC)

    @property
    def remaining_bytes(self) -> int:
        """Get remaining storage quota in bytes."""
        return max(0, self.storage_quota_bytes - self.storage_used_bytes)

    @property
    def utilization_percent(self) -> float:
        """Calculate quota utilization percentage."""
        if self.storage_quota_bytes == 0:
            return 0.0
        return min(100.0, (self.storage_used_bytes / self.storage_quota_bytes) * 100)


class AdminStorageAllocation(Base):
    """Administrative audit trail for tenant storage quota modifications.

    Every quota change is logged here with previous and new values for
    compliance auditing. This table enables complete reconstruction of
    resource allocation history.
    """

    __tablename__ = "admin_storage_allocations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    admin_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_quota_bytes: Mapped[int] = mapped_column(
        BIGINT, nullable=False, comment="Quota before the change"
    )
    new_quota_bytes: Mapped[int] = mapped_column(
        BIGINT, nullable=False, comment="Quota after the change"
    )
    allocation_reason: Mapped[str | None] = mapped_column(
        String(500), nullable=True, comment="Reason for quota modification"
    )
    action_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="quota_update",
        index=True,
        comment="Type of storage allocation action",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # Relationships
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="storage_allocations")
    admin: Mapped[User] = relationship("User", foreign_keys=[admin_user_id])

    def __init__(
        self,
        tenant_id: uuid.UUID,
        admin_user_id: uuid.UUID,
        previous_quota_bytes: int,
        new_quota_bytes: int,
        allocation_reason: str | None = None,
        action_type: str = "quota_update",
    ):
        self.tenant_id = tenant_id
        self.admin_user_id = admin_user_id
        self.previous_quota_bytes = previous_quota_bytes
        self.new_quota_bytes = new_quota_bytes
        self.allocation_reason = allocation_reason
        self.action_type = action_type
        self.created_at = datetime.now(UTC)
