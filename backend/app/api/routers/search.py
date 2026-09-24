"""Encrypted keyword search endpoints.

Search operates over hashed keyword tokens. Each keyword is hashed
with SHA-256 client-side and used to traverse a forward-chained
index of encrypted file references. The server never sees plaintext
keywords or file names.

The search follows a linked-list structure: the client provides the
latest token for a keyword, and the server walks backward through
``prev_token`` links, returning all matching encrypted values.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.exceptions import ValidationError
from app.core.logging import get_logger
from app.db import get_db
from app.models import IndexEntry
from app.schemas import SearchToken

logger = get_logger(__name__)

router = APIRouter(prefix="/search", tags=["search"])


@router.post("")
async def search(
    payload: SearchToken,
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(get_current_user),
) -> dict[str, Any]:
    """Traverse the encrypted search index for a given keyword token.

    The client sends the latest token (SHA-256 hash of the keyword)
    for a search term. The server follows the ``prev_token`` chain
    backward, collecting all matching encrypted file references.

    Args:
        payload: Contains the base64-decoded token string.
        db: Database session.
        current_user: Authenticated user (search is scoped to their index).

    Returns:
        A dict with ``values`` (list of encrypted JSON strings) and
        ``count``.

    Raises:
        ValidationError: If the token is empty or invalid.
    """
    token = payload.token
    if not token:
        raise ValidationError("Missing search token")

    import base64

    try:
        current_token = base64.b64decode(token, validate=True)
    except Exception as exc:
        raise ValidationError("Invalid token encoding") from exc

    visited: set[bytes] = set()
    values: list[str] = []

    while bool(current_token) and current_token not in visited:
        visited.add(current_token)
        result: Any = await db.execute(
            select(IndexEntry).where(
                IndexEntry.token == current_token,
                IndexEntry.owner_id == current_user.id,
            )
        )
        entry = result.scalar_one_or_none()
        if not entry:
            break
        value_json = entry.value.decode()
        values.append(value_json)
        current_token = entry.prev_token or b""

    logger.info(
        "Search executed",
        extra={"user_id": str(current_user.id), "results": len(values)},
    )

    return {"values": values, "count": len(values)}
