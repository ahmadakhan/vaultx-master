"""File sharing-related Pydantic schemas.

Defines request and response models for creating, reading, and
revoking file shares between users and via shareable public links.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator


def _normalize_email(value: str) -> str:
    """Canonicalise an address so lookups and storage agree."""
    return value.strip().lower()


class FileShareCreate(BaseModel):
    """Request body for creating a new file share.

    The ``wrapped_key_b64`` is the file key (Kf) encrypted with the
    recipient's RSA-OAEP public key.
    """

    file_id: UUID
    recipient_email: EmailStr
    wrapped_key_b64: str = Field(..., min_length=1, max_length=4096)
    permissions: str = Field(default="read", pattern="^(read|write|admin)$")

    @field_validator("recipient_email")
    @classmethod
    def _normalize_recipient(cls, v: str) -> str:
        return _normalize_email(v)


class FileShareRead(BaseModel):
    """Read-only representation of a file share."""

    id: UUID
    file_id: UUID
    recipient_user_id: UUID
    permissions: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FileShareRevoke(BaseModel):
    """Request body for revoking a file share."""

    file_id: UUID
    recipient_email: EmailStr

    @field_validator("recipient_email")
    @classmethod
    def _normalize_recipient(cls, v: str) -> str:
        return _normalize_email(v)


class SharedLinkCreate(BaseModel):
    """Request body for creating a shareable public link.

    If an ``access_code`` is provided, the client SHOULD also provide
    ``encrypted_kf_b64`` and ``encrypted_kf_iv_b64`` — the file key (Kf)
    encrypted with the access code so that guests can decrypt the file
    without a VaultX account.
    """

    file_id: UUID
    access_code: str | None = Field(default=None, min_length=4, max_length=12)
    expires_at: datetime | None = None
    max_downloads: int | None = Field(default=None, ge=1)
    encrypted_kf_b64: str | None = Field(default=None)
    encrypted_kf_iv_b64: str | None = Field(default=None)
    kf_salt_b64: str | None = Field(default=None)


class SharedLinkRead(BaseModel):
    """Read-only representation of a shared link."""

    id: UUID
    file_id: UUID
    token: str
    has_access_code: bool
    expires_at: datetime | None
    max_downloads: int | None
    download_count: int
    created_at: datetime
    link_url: str | None = None

    model_config = {"from_attributes": True}


class SharedLinkRevoke(BaseModel):
    """Request body for revoking a shared link."""

    file_id: UUID
