"""Admin-related Pydantic schemas.

Defines request and response models for user management and audit
log inspection endpoints accessible only to users with the admin role.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


class UserRead(BaseModel):
    """Public representation of a user for admin views."""

    id: str
    email: str
    mfa_enabled: bool
    is_active: bool
    created_at: datetime
    roles: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    """Request body for creating a user via admin endpoint."""

    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    role: Literal["admin", "user"] | None = None


class AdminAuditLogRead(BaseModel):
    """Read-only representation of an audit log entry for admin views."""

    id: int
    user_id: str | None = None
    seq: int
    entry_json: dict[str, Any]
    entry_hash: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AdminAuditLogList(BaseModel):
    """Paginated response of admin audit log entries."""

    count: int
    logs: list[AdminAuditLogRead]


class AdminAuditVerifyResponse(BaseModel):
    """Response from the admin audit-chain verification endpoint."""

    valid: bool
    errors: list[str]
    user_id: str


class TenantQuotaRead(BaseModel):
    """Read representation of tenant storage quota for admin views."""

    id: str
    tenant_id: str
    storage_quota_bytes: int
    storage_used_bytes: int
    allocated_by_admin_id: str | None = None
    quota_updated_at: datetime
    last_accessed_at: datetime
    utilization_percent: float = Field(default=0.0, ge=0.0, le=100.0)

    model_config = {"from_attributes": True}


class TenantRead(BaseModel):
    """Read representation of tenant for admin views."""

    id: str
    tenant_id: str
    name: str
    storage_quota_bytes: int
    allocated_by_admin_id: str | None = None
    quota_updated_at: datetime
    is_active: bool
    created_at: datetime
    utilization_percent: float = Field(default=0.0, ge=0.0, le=100.0)

    model_config = {"from_attributes": True}


class TenantUpdate(BaseModel):
    """Request body for updating tenant configuration."""

    tenant_id: str | None = None
    name: str | None = None
    storage_quota_bytes: int | None = Field(None, ge=1048576)  # Minimum 1MB
    is_active: bool | None = None


class AdminStorageAllocationRead(BaseModel):
    """Read representation of admin storage allocation for audit purposes."""

    id: str
    tenant_id: str
    admin_user_id: str
    previous_quota_bytes: int
    new_quota_bytes: int
    allocation_reason: str | None = None
    action_type: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AdminStats(BaseModel):
    """Dashboard statistics for admin views."""

    total_tenants: int
    active_tenants: int
    total_storage_allocated_bytes: int
    total_storage_used_bytes: int
    total_users: int
    admin_users: int
    quota_violations: int

    model_config = {"from_attributes": True}
