"""User-specific Pydantic schemas.

Defines request and response models for managing user-indexed
search chain state (encrypted keyword chains persisted server-side).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class IndexStateUpdate(BaseModel):
    """Request body for updating the user's encrypted index state."""

    index_state_ciphertext: str = Field(..., min_length=1)
    index_state_iv: str = Field(..., min_length=1)


class IndexStateResponse(BaseModel):
    """Response containing the user's encrypted index state."""

    index_state_ciphertext: str | None = None
    index_state_iv: str | None = None
