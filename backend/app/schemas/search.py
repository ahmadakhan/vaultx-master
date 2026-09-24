"""Search-related Pydantic schemas.

Defines request and response models for encrypted keyword search.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# A search token is a base64-encoded 16-byte value; the bound stops a client
# from forcing huge allocations during base64 decoding.
MAX_SEARCH_TOKEN_LENGTH = 256


class SearchToken(BaseModel):
    """Request body for submitting a search token.

    The token is a base64-encoded hashed keyword digest that the
    backend uses to traverse the encrypted search index.
    """

    token: str = Field(..., min_length=1, max_length=MAX_SEARCH_TOKEN_LENGTH)


class SearchResult(BaseModel):
    """A single search index value (encrypted file reference)."""

    ciphertext_b64: str
    iv_b64: str


class SearchResponse(BaseModel):
    """Response from the search endpoint: list of encrypted values."""

    values: list[str]
    count: int
