"""Schemas for resumable transfers and guest write-only dropboxes."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.file import SearchTokenEntry


class UploadSessionCreate(BaseModel):
    file_id: UUID
    total_bytes: int = Field(..., gt=0, le=11_000_000_000)
    chunk_size: int = Field(4 * 1024 * 1024, ge=64 * 1024, le=16 * 1024 * 1024)


class UploadSessionRead(BaseModel):
    id: UUID
    file_id: UUID
    total_bytes: int
    offset: int
    chunk_size: int
    status: str
    expires_at: datetime

    model_config = {"from_attributes": True}


class UploadSessionFinalize(BaseModel):
    """Encrypted file metadata published with a completed upload session."""

    metadata_ciphertext_b64: str = Field(..., min_length=1, max_length=8192)
    metadata_iv_b64: str = Field(..., min_length=1, max_length=256)
    encrypted_kf_b64: str = Field(..., min_length=1, max_length=8192)
    encrypted_kf_iv_b64: str = Field(..., min_length=1, max_length=256)
    file_iv_b64: str = Field(..., min_length=1, max_length=256)
    tokens: list[SearchTokenEntry] = Field(default_factory=list, max_length=500)

class DropboxCreate(BaseModel):
    ttl_seconds: int = Field(86_400, ge=60, le=2_592_000)
    max_bytes: int = Field(..., gt=0, le=11_000_000_000)
    max_uploads: int = Field(1, ge=1, le=100)


class DropboxRead(BaseModel):
    id: UUID
    expires_at: datetime
    max_bytes: int
    max_uploads: int
    active: bool
    capability: str


class DropboxUploadRead(BaseModel):
    id: UUID
    size: int
    finalized: bool
    status: str = "pending"
    file_id: UUID | None = None

    model_config = {"from_attributes": True}
