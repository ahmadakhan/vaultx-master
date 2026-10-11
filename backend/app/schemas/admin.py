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
