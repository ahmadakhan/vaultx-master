"""Admin endpoints for user management and tamper-proof audit logs.

All endpoints in this router require an authenticated user with the
``"admin"`` role. Provides:

- ``GET /admin/users`` — list all users (with roles, MFA status, activity).
- ``POST /admin/users`` — create a new user (admin-specified password).
- ``DELETE /admin/users/{user_id}`` — deactivate / delete a user.
- ``GET /admin/users/me/roles`` — list roles for the current admin.
- ``GET /admin/audit/logs`` — paginated tamper log across all users.
- ``GET /admin/audit/verify`` — verify the chain for a specific user.

Requires the ``admin`` role via ``get_current_admin``.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_decorator import audit_event
from app.core.deps import get_current_admin, get_current_user_mfa_verified
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db import get_db
from app.models import TamperLog, User, UserRole
from app.schemas.admin import (
    AdminAuditLogList,
    AdminAuditLogRead,
    AdminAuditVerifyResponse,
    UserCreate,
    UserRead,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/admin", tags=["admin"], dependencies=[Depends(get_current_user_mfa_verified)]
)


@router.get("/users", response_model=list[UserRead])
async def list_users(
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[UserRead]:
    """List all users in the system.

    Only accessible to users with the ``admin`` role.
    """
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    )
    users = result.scalars().all()

    user_reads: list[UserRead] = []
    for u in users:
        role_result = await db.execute(select(UserRole.role).where(UserRole.user_id == u.id))
        roles = [row[0] for row in role_result.fetchall()]
        user_reads.append(
            UserRead(
                id=str(u.id),
                email=u.email,
                mfa_enabled=u.mfa_enabled,
                is_active=u.is_active,
                created_at=u.created_at,
                roles=roles,
            )
        )
    return user_reads


@router.post("/users", response_model=UserRead)
async def create_user(
    payload: UserCreate,
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    """Reject password-only provisioning: it cannot create a usable vault."""
    raise ConflictError("Users must register with a client-generated encrypted key bundle")


@router.delete("/users/{user_id}")
@audit_event("user_deactivated", resource_fields=("user_id",))
async def delete_user(
    user_id: UUID,
    request: Request,
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Deactivate a user (admin-only).

    Prevents the user from authenticating again without removing their
    data, preserving audit trail integrity.
    """
    if user_id == current_admin.id:
        raise AuthorizationError("Administrators cannot deactivate themselves")
    # Serialise administrator changes on the role row, preventing two admins
    # concurrently deactivating each other after their dependency checks.
    from app.models import Role

    await db.execute(select(Role).where(Role.name == "admin").with_for_update())
    await db.refresh(current_admin)
    if not current_admin.is_active:
        raise AuthorizationError("Admin access required")
    result = await db.execute(select(User).where(User.id == user_id).with_for_update())
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("User not found")

    user.is_active = False
    from app.api.routers.auth import _revoke_all_refresh_tokens

    await _revoke_all_refresh_tokens(db, user.id)
    await db.commit()

    logger.info(
        "Admin deactivated user",
        extra={"admin_id": str(current_admin.id), "user_id": str(user_id)},
    )
    return {"deleted": True, "user_id": str(user_id)}


@router.get("/users/me/roles", response_model=list[str])
async def get_my_roles(
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
) -> list[str]:
    """List the roles assigned to the current admin user."""
    result = await db.execute(select(UserRole.role).where(UserRole.user_id == current_admin.id))
    return [row[0] for row in result.fetchall()]


@router.get("/audit/logs", response_model=AdminAuditLogList)
async def list_all_audit_logs(
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user_filter: UUID | None = Query(default=None, description="Filter by user_id"),
) -> AdminAuditLogList:
    """Retrieve a paginated list of audit log entries across all users.

    Admin-only. Supports an optional ``user_filter`` query parameter
    to narrow results to a single user.
    """
    query = select(TamperLog).order_by(TamperLog.created_at.desc()).limit(limit).offset(offset)
    if user_filter:
        query = query.where(TamperLog.user_id == user_filter)

    result = await db.execute(query)
    logs = result.scalars().all()

    return AdminAuditLogList(
        count=len(logs),
        logs=[
            AdminAuditLogRead(
                id=log.id,
                user_id=str(log.user_id) if log.user_id else None,
                seq=log.seq,
                entry_json=log.entry_json,
                entry_hash=log.entry_hash,
                created_at=log.created_at,
            )
            for log in logs
        ],
    )


@router.get("/audit/verify", response_model=AdminAuditVerifyResponse)
async def verify_user_audit_chain(
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
    user_id: UUID = Query(..., description="User ID to verify audit chain for"),
) -> AdminAuditVerifyResponse:
    """Verify the audit chain for a specific user (admin-only).

    Runs the full tamper-detection verification and returns the result.
    """
    from app.core.audit_verify import verify_audit_chain

    ok, errors = await verify_audit_chain(db, user_id)
    return AdminAuditVerifyResponse(valid=ok, errors=errors, user_id=str(user_id))
