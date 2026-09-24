"""Audit log Pydantic schemas.

Defines response models for retrieving tamper-evident audit logs
and verifying the integrity of the audit chain.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class TamperLogRead(BaseModel):
    """Read-only representation of a single audit log entry."""

    id: int
    user_id: UUID | None = None
    entry_json: dict[str, Any]
    entry_hash: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogList(BaseModel):
    """Paginated response of audit log entries."""

    count: int
    logs: list[TamperLogRead]


class AuditVerifyResponse(BaseModel):
    """Response from the audit chain verification endpoint."""

    valid: bool
    errors: list[str]
