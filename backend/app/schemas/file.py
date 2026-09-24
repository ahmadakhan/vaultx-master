"""File-related Pydantic schemas.

Defines request and response models for file upload, listing,
batch retrieval, download, and lifecycle operations (delete/restore).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, Field, TypeAdapter

# Upper bounds keep a malicious client from forcing large allocations or
# thousands of index inserts in one request.
MAX_TOKENS_PER_UPLOAD = 500
MAX_TOKEN_B64_LENGTH = 256
MAX_TOKEN_VALUE_B64_LENGTH = 8192


class FileUploadResponse(BaseModel):
    """Response after a successful file upload."""

    id: UUID
    created_at: datetime


class TokenValue(BaseModel):
    """Encrypted file reference stored against a search token."""

    ciphertext_b64: str = Field(..., min_length=1, max_length=MAX_TOKEN_VALUE_B64_LENGTH)
    iv_b64: str = Field(..., min_length=1, max_length=MAX_TOKEN_B64_LENGTH)


class SearchTokenEntry(BaseModel):
    """A single encrypted search-index entry supplied during upload."""

    token: str = Field(..., min_length=1, max_length=MAX_TOKEN_B64_LENGTH)
    value: TokenValue
    prev_token: str | None = Field(default=None, max_length=MAX_TOKEN_B64_LENGTH)


_token_list_adapter: TypeAdapter[list[SearchTokenEntry]] = TypeAdapter(
    Annotated[list[SearchTokenEntry], Field(max_length=MAX_TOKENS_PER_UPLOAD)]
)


def parse_token_entries(tokens_json: str) -> list[SearchTokenEntry]:
    """Validate the ``tokens_json`` form field.

    Raises:
        ValueError: If the payload is not valid JSON or does not match the
            expected shape (surfaced to clients as a 422 by the caller).
    """
    raw = json.loads(tokens_json)
    return _token_list_adapter.validate_python(raw)


class FileListItem(BaseModel):
    """A single file in a paginated list response.

    ``shared_with`` is a list of recipient email addresses (a flat list, which
    is what the API has always returned and what the UI consumes). It is typed
    as ``list[str]`` rather than a nested model so response construction cannot
    fail validation.
    """

    id: UUID
    owner_email: str
    metadata_ciphertext: str
    metadata_iv: str
    created_at: datetime
    deleted: bool
    shared_with: list[str] = Field(default_factory=list)
    wrapped_key_b64: str | None = None
    encrypted_kf_b64: str | None = None
    encrypted_kf_iv: str | None = None
    is_shared_file: bool = False

    model_config = {"from_attributes": True}


class FileListPage(BaseModel):
    """Paginated response of file list items."""

    total: int
    count: int
    limit: int
    offset: int
    files: list[FileListItem]


class FileBatchList(BaseModel):
    """Request body for batch file retrieval."""

    ids: list[UUID] = Field(..., min_length=1, max_length=200)


class FileDownloadResponse(BaseModel):
    """Response for single-file download endpoint."""

    id: UUID
    ciphertext: str
    file_iv: str
    metadata_ciphertext: str
    metadata_iv: str
    encrypted_kf_b64: str | None = None
    encrypted_kf_iv: str | None = None
    wrapped_key_b64: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
