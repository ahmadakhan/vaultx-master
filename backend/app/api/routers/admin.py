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

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_admin
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.security import hash_password
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

router = APIRouter(prefix="/admin", tags=["admin"])


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
        role_result = await db.execute(
            select(UserRole.role).where(UserRole.user_id == u.id)
        )
        roles = [row[0] for row in role_result.fetchall()]
        user_reads.append(UserRead(
            id=str(u.id),
            email=u.email,
            mfa_enabled=u.mfa_enabled,
            is_active=u.is_active,
            created_at=u.created_at,
            roles=roles,
        ))
    return user_reads


@router.post("/users", response_model=UserRead)
async def create_user(
    payload: UserCreate,
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    """Create a new user (admin-only).

    Unlike self-service registration, this endpoint allows an admin to
    specify a password directly. The user is created with encrypted key
    fields left empty — the admin-set password must be changed by the
    user on first login.
    """
    from app.models import email_matches, normalize_email
    email = normalize_email(payload.email)

    existing = await db.execute(select(User.id).where(email_matches(User.email, email)))
    if existing.scalar_one_or_none():
        raise ConflictError("User already exists")

    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise AuthorizationError(str(exc)) from exc

    user = User(
        email=email,
        password_hash=password_hash,
        password_salt_b64=b"",
        enc_master_key_b64=b"",
        enc_master_key_iv=b"",
        enc_search_key_b64=b"",
        enc_search_key_iv=b"",
        enc_private_key_b64=b"",
        enc_private_key_iv=b"",
        public_key_b64=b"",
        key_bundle_version=1,
        password_kdf_iterations=150_000,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    if payload.role:
        db.add(UserRole(user_id=user.id, role=payload.role))
        await db.commit()

    logger.info("Admin created user", extra={"admin_id": str(current_admin.id), "user_id": str(user.id)})

    return UserRead(
        id=str(user.id),
        email=user.email,
        mfa_enabled=user.mfa_enabled,
        is_active=user.is_active,
        created_at=user.created_at,
        roles=[payload.role] if payload.role else [],
    )


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: UUID,
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Deactivate a user (admin-only).

    Prevents the user from authenticating again without removing their
    data, preserving audit trail integrity.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("User not found")

    user.is_active = False
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
