"""User profile and index state endpoints.

Manages encrypted user index state (the keyword chain) that enables
the client-side encrypted search functionality. The index state is
encrypted under the user's master key before storage.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.logging import get_logger
from app.db import get_db
from app.models import User
from app.schemas.user import IndexStateResponse, IndexStateUpdate

logger = get_logger(__name__)

router = APIRouter(prefix="/user", tags=["user"])


@router.post("/index_state", response_model=dict[str, Any])
async def update_index_state(
    payload: IndexStateUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Update the user's encrypted search index state.

    The index state is a JSON document encrypted under the user's
    master key, containing the keyword-to-token chain mapping that
    enables encrypted search.

    Args:
        payload: Contains the encrypted index state ciphertext and IV.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A dict confirming the update.
    """
    current_user.index_state_ciphertext = payload.index_state_ciphertext.encode()
    current_user.index_state_iv = payload.index_state_iv.encode()

    await db.commit()

    logger.info("Index state updated", extra={"user_id": str(current_user.id)})

    return {"updated": True}


@router.get("/index_state", response_model=IndexStateResponse)
async def get_index_state(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IndexStateResponse:
    """Retrieve the user's encrypted search index state.

    Args:
        db: Database session.
        current_user: Authenticated user.

    Returns:
        The encrypted index state ciphertext and IV, or ``null``
        fields if no state has been stored.
    """
    return IndexStateResponse(
        index_state_ciphertext=(
            current_user.index_state_ciphertext.decode()
            if current_user.index_state_ciphertext
            else None
        ),
        index_state_iv=(
            current_user.index_state_iv.decode() if current_user.index_state_iv else None
        ),
    )
