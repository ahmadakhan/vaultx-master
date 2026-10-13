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

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_decorator import audit_event
from app.core.deps import get_current_admin, get_current_user_mfa_verified
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db import get_db
from app.models import TamperLog, TenantQuota, User, UserRole
from app.schemas.admin import (
    AdminAuditLogList,
    AdminAuditLogRead,
    AdminAuditVerifyResponse,
    TenantQuotaRead,
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
    This endpoint allows administrators to verify any user's audit integrity.

    Args:
        current_admin: Administrator performing the verification.
        db: Database session.
        user_id: User ID to verify audit chain for.

    Returns:
        Admin audit verification result with status and any errors found.

    Example:
        GET /admin/audit/verify?user_id=550e8400-e29b-41d4-a716-446655440000

        Success Response (200):
        {
            "valid": true,
            "errors": [],
            "user_id": "550e8400-e29b-41d4-a716-446655440000"
        }

        Verification Failed Response (200 with errors):
        {
            "valid": false,
            "errors": [
                "Hash mismatch at entry 1: expected abc123..., got def456...",
                "Signature verification failed at entry 2",
                "Broken chain at entry 3: prev_hash mismatch"
            ],
            "user_id": "550e8400-e29b-41d4-a716-446655440000"
        }

    Raises:
        HTTPException: If audit verification fails (404 if user not found,
            500 for internal errors).
    """
    from app.core.audit_verify import verify_audit_chain

    try:
        ok, errors = await verify_audit_chain(db, user_id)

        if not ok:
            logger.warning(
                "Admin audit chain verification failed",
                extra={
                    "admin_id": str(current_admin.id),
                    "target_user_id": str(user_id),
                    "error_count": len(errors),
                    "sample_error": errors[0] if errors else None,
                },
            )
            # Return 200 with validation errors for admin visibility
            return AdminAuditVerifyResponse(valid=ok, errors=errors, user_id=str(user_id))

        logger.info(
            "Admin audit chain verification successful",
            extra={
                "admin_id": str(current_admin.id),
                "target_user_id": str(user_id),
            },
        )

        return AdminAuditVerifyResponse(valid=ok, errors=errors, user_id=str(user_id))

    except Exception as e:
        logger.error(
            "Unexpected error during admin audit chain verification",
            extra={
                "admin_id": str(current_admin.id),
                "target_user_id": str(user_id),
                "error": str(e),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error during audit chain verification",
        ) from e


@router.get("/tenants/quotas", response_model=list[TenantQuotaRead])
@audit_event("tenant_quotas_viewed")
async def list_tenant_quotas(
    request: Request,
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[TenantQuotaRead]:
    """List all tenant storage quotas (admin-only).

    Provides visibility into storage allocation across all tenants.
    """
    result = await db.execute(
        select(TenantQuota)
        .order_by(TenantQuota.storage_used_bytes.desc())
        .limit(limit)
        .offset(offset)
    )
    quotas = result.scalars().all()

    return [
        TenantQuotaRead(
            id=str(q.id),
            tenant_id=str(q.tenant_id),
            storage_quota_bytes=q.storage_quota_bytes,
            storage_used_bytes=q.storage_used_bytes,
            allocated_by_admin_id=str(q.allocated_by_admin_id) if q.allocated_by_admin_id else None,
            quota_updated_at=q.quota_updated_at,
            last_accessed_at=q.last_accessed_at,
            utilization_percent=(q.storage_used_bytes / q.storage_quota_bytes * 100)
            if q.storage_quota_bytes > 0
            else 0,
        )
        for q in quotas
    ]


@router.post("/tenants/{tenant_id}/quota", response_model=TenantQuotaRead)
@audit_event("tenant_quota_updated")
async def update_tenant_quota(
    request: Request,
    tenant_id: UUID,
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
    new_quota_bytes: int = Query(
        ..., ge=1048576, description="New storage quota in bytes (minimum 1MB)"
    ),
    reason: str | None = Query(default=None, description="Reason for quota change"),
) -> TenantQuotaRead:
    """Update storage quota for a tenant (admin-only).

    Administrators can increase or decrease storage quotas for tenants.
    Quota decreases are enforced immediately and existing uploads are preserved.
    """
    # Verify tenant exists
    result = await db.execute(
        select(TenantQuota).where(TenantQuota.tenant_id == tenant_id).with_for_update()
    )
    quota = result.scalar_one_or_none()

    if not quota:
        raise NotFoundError("Tenant quota not found")

    # Record allocation change
    previous_quota = quota.storage_quota_bytes
    quota.storage_quota_bytes = new_quota_bytes
    quota.allocated_by_admin_id = current_admin.id
    quota.quota_updated_at = datetime.now(UTC)
    quota.last_accessed_at = datetime.now(UTC)

    # Validate against current usage
    if new_quota_bytes < quota.storage_used_bytes:
        logger.warning(
            "Tenant quota reduced below current usage",
            extra={
                "tenant_id": str(tenant_id),
                "admin_id": str(current_admin.id),
                "previous_quota": previous_quota,
                "new_quota": new_quota_bytes,
                "current_usage": quota.storage_used_bytes,
            },
        )

    await db.commit()
    await db.refresh(quota)

    logger.info(
        "Tenant quota updated",
        extra={
            "tenant_id": str(tenant_id),
            "admin_id": str(current_admin.id),
            "previous_quota": previous_quota,
            "new_quota": new_quota_bytes,
            "reason": reason or "No reason provided",
        },
    )

    return TenantQuotaRead(
        id=str(quota.id),
        tenant_id=str(quota.tenant_id),
        storage_quota_bytes=quota.storage_quota_bytes,
        storage_used_bytes=quota.storage_used_bytes,
        allocated_by_admin_id=str(quota.allocated_by_admin_id)
        if quota.allocated_by_admin_id
        else None,
        quota_updated_at=quota.quota_updated_at,
        last_accessed_at=quota.last_accessed_at,
        utilization_percent=(quota.storage_used_bytes / quota.storage_quota_bytes * 100)
        if quota.storage_quota_bytes > 0
        else 0,
    )


@router.post("/tenants/{tenant_id}/provision", response_model=TenantQuotaRead)
@audit_event("tenant_provisioned")
async def provision_tenant(
    request: Request,
    tenant_id: UUID,
    current_admin: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
    initial_quota_bytes: int = Query(
        10737418240, ge=1048576, description="Initial storage quota (10GB default)"
    ),
) -> TenantQuotaRead:
    """Provision a new tenant with storage quota (admin-only).

    Creates a new tenant with specified storage allocation.
    Use this endpoint to onboard new organizations.
    """
    # Check if tenant already has a quota
    result = await db.execute(select(TenantQuota).where(TenantQuota.tenant_id == tenant_id))
    existing = result.scalar_one_or_none()

    if existing:
        raise ConflictError("Tenant already has a quota allocated")

    # Create new tenant quota
    new_quota = TenantQuota(
        tenant_id=tenant_id,
        storage_quota_bytes=initial_quota_bytes,
        storage_used_bytes=0,
        allocated_by_admin_id=current_admin.id,
        quota_updated_at=datetime.now(UTC),
        last_accessed_at=datetime.now(UTC),
    )
    db.add(new_quota)
    await db.commit()
    await db.refresh(new_quota)

    logger.info(
        "Tenant provisioned with storage quota",
        extra={
            "tenant_id": str(tenant_id),
            "admin_id": str(current_admin.id),
            "initial_quota_bytes": initial_quota_bytes,
        },
    )

    return TenantQuotaRead(
        id=str(new_quota.id),
        tenant_id=str(new_quota.tenant_id),
        storage_quota_bytes=new_quota.storage_quota_bytes,
        storage_used_bytes=new_quota.storage_used_bytes,
        allocated_by_admin_id=str(new_quota.allocated_by_admin_id),
        quota_updated_at=new_quota.quota_updated_at,
        last_accessed_at=new_quota.last_accessed_at,
        utilization_percent=0.0,
    )
