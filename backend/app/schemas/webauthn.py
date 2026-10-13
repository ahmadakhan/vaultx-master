from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class WebAuthnResponse(BaseModel):
    """The browser's PublicKeyCredential JSON representation."""

    id: str = Field(min_length=1, max_length=1024)
    raw_id: str = Field(alias="rawId", min_length=1, max_length=2048)
    type: str = Field(default="public-key", pattern="^public-key$")
    response: dict[str, Any]

    model_config = {"extra": "ignore", "populate_by_name": True}
