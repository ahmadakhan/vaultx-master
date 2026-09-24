"""Audit log retrieval and verification endpoints.

Allows authenticated users to:
- List their audit log entries (paginated).
- Verify the integrity of their audit chain, detecting any
  tampering, deletion, or insertion of log entries.

All audit entries are signed with the server's RSA private key and
chained via SHA-256 hashes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_verify import verify_audit_chain
from app.core.deps import get_current_user
from app.core.logging import get_logger
from app.db import get_db
from app.models import TamperLog, User
from app.schemas.audit import AuditLogList, AuditVerifyResponse, TamperLogRead

logger = get_logger(__name__)

router = APIRouter(prefix="/audit", tags=["audit"])


async def get_user_audit_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AuditLogList:
    """Retrieve a paginated list of the user's audit log entries.

    Args:
        db: Database session.
        current_user: Authenticated user.
        limit: Maximum entries to return (1-200).
        offset: Pagination offset.

    Returns:
        Paginated audit log entries for the current user.
    """
    result = await db.execute(
        select(TamperLog)
        .where(TamperLog.user_id == current_user.id)
        .order_by(TamperLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    logs = result.scalars().all()

    return AuditLogList(
        count=len(logs),
        logs=[
            TamperLogRead(
                id=log.id,
                user_id=log.user_id,
                entry_json=log.entry_json,
                entry_hash=log.entry_hash,
                created_at=log.created_at,
            )
            for log in logs
        ],
    )


@router.get("/logs", response_model=AuditLogList)
async def get_audit_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AuditLogList:
    """Retrieve a paginated list of the user's audit log entries.

    Args:
        db: Database session.
        current_user: Authenticated user.
        limit: Maximum entries to return (1-200).
        offset: Pagination offset.

    Returns:
        Paginated audit log entries for the current user.
    """
    return await get_user_audit_logs(db=db, current_user=current_user, limit=limit, offset=offset)


@router.get("/verify", response_model=AuditVerifyResponse)
async def verify_my_audit_chain(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditVerifyResponse:
    """Verify the integrity of the user's audit log chain.

    Checks each entry's hash, RSA signature, and chain linkage
    to detect tampering, deletion, or insertion.

    Args:
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A response with ``valid`` (bool) and ``errors`` (list of
        descriptions if the chain is compromised).
    """
    ok, errors = await verify_audit_chain(db, current_user.id)
    return AuditVerifyResponse(valid=ok, errors=errors)
