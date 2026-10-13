"""Audit log retrieval and verification endpoints.

Allows authenticated users to:
- List their audit log entries (paginated).
- Verify the integrity of their audit chain, detecting any
  tampering, deletion, or insertion of log entries.

All audit entries are signed with the server's RSA private key and
chained via SHA-256 hashes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_verify import verify_audit_chain
from app.core.deps import get_current_user_mfa_verified as get_current_user
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

    Raises:
        HTTPException: If the user has no audit logs.
    """
    result = await db.execute(
        select(TamperLog)
        .where(TamperLog.user_id == current_user.id)
        .order_by(TamperLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    logs = result.scalars().all()

    if not logs:
        logger.info(
            "No audit logs found for user",
            extra={
                "user_id": str(current_user.id),
            },
        )
        return AuditLogList(count=0, logs=[])

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

    This endpoint provides the same functionality as the default route
    for consistency with other API patterns.

    Args:
        db: Database session.
        current_user: Authenticated user.
        limit: Maximum entries to return (1-200).
        offset: Pagination offset.

    Returns:
        Paginated audit log entries for the current user.

    Example:
        GET /audit/logs?limit=10&offset=0

        Response:
        {
            "count": 2,
            "logs": [
                {
                    "id": 1,
                    "user_id": "550e8400-e29b-41d4-a716-446655440000",
                    "entry_json": {"action": "file_upload", "timestamp": "2024-01-15T10:30:00Z"},
                    "entry_hash": "a1b2c3d4e5f6...",
                    "created_at": "2024-01-15T10:30:00Z"
                }
            ]
        }
    """
    return await get_user_audit_logs(db=db, current_user=current_user, limit=limit, offset=offset)


@router.get("/verify", response_model=AuditVerifyResponse)
async def verify_my_audit_chain(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditVerifyResponse:
    """Verify the integrity of the user's audit log chain.

    Performs comprehensive verification of the audit trail by:
    1. Recomputing each entry's SHA-256 hash
    2. Validating RSA-PSS signatures
    3. Checking hash chain continuity
    4. Verifying anchor consistency

    Detects any tampering, deletion, or insertion of audit log entries.

    Args:
        db: Database session.
        current_user: Authenticated user.

    Returns:
        Audit verification result with status and any errors found.

    Example:
        GET /audit/verify

        Success Response (200):
        {
            "valid": true,
            "errors": []
        }

        Verification Failed Response (200 with errors):
        {
            "valid": false,
            "errors": [
                "Hash mismatch at entry 1: expected abc123..., got def456...",
                "Signature verification failed at entry 2",
                "Broken chain at entry 3: prev_hash mismatch"
            ]
        }

    Raises:
        HTTPException: If audit verification fails (401 for unauthorized,
            500 for internal errors).
    """
    try:
        ok, errors = await verify_audit_chain(db, current_user.id)

        if not ok:
            logger.warning(
                "Audit chain verification failed",
                extra={
                    "user_id": str(current_user.id),
                    "error_count": len(errors),
                    "sample_error": errors[0] if errors else None,
                },
            )

        else:
            logger.info(
                "Audit chain verification successful",
                extra={
                    "user_id": str(current_user.id),
                },
            )

        return AuditVerifyResponse(valid=ok, errors=errors)

    except Exception as e:
        logger.error(
            "Unexpected error during audit chain verification",
            extra={
                "user_id": str(current_user.id),
                "error": str(e),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error during audit chain verification",
        ) from e


@router.get("/security-summary", response_model=dict)
async def get_security_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Get a comprehensive security-focused summary of the user's audit state.

    This endpoint provides detailed security metrics and actionable insights
    for UI dashboards and monitoring interfaces.

    Args:
        db: Database session.
        current_user: Authenticated user.

    Returns:
        Comprehensive security summary with verification status and recommendations.

    Example:
        GET /audit/security-summary

        Response:
        {
            "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "audit_status": "verified",
            "entry_count": 5,
            "last_verification": "2024-01-15T10:30:00Z",
            "security_score": 100,
            "security_metrics": {
                "total_entries": 5,
                "valid_entries": 5,
                "invalid_entries": 0,
                "hash_errors": 0,
                "signature_errors": 0,
                "chain_errors": 0
            },
            "recommendations": [],
            "time_metrics": {
                "oldest_entry": "2024-01-10T09:00:00Z",
                "newest_entry": "2024-01-15T10:30:00Z",
                "days_of_records": 5
            },
            "needs_attention": false,
            "error_details": [],
            "ui_priority_actions": [
                "Enable multi-factor authentication"
            ] if not current_user.mfa_enabled else []
        }
    """
    ok, errors = await verify_audit_chain(db, current_user.id)

    all_entries = await db.execute(
        select(TamperLog).where(TamperLog.user_id == current_user.id)
    ).scalars().all()

    hash_errors = sum(1 for e in errors if "hash mismatch" in e.lower())
    signature_errors = sum(1 for e in errors if "signature" in e.lower())
    chain_errors = sum(1 for e in errors if "chain" in e.lower())
    sequence_errors = sum(1 for e in errors if "sequence" in e.lower())

    summary = {
        "user_id": str(current_user.id),
        "audit_status": "verified" if ok else "compromised",
        "entry_count": len(all_entries),
        "last_verification": all_entries[-1].created_at.isoformat() if all_entries else None,
        "security_score": max(0, 100 - (len(errors) * 10)),
        "security_metrics": {
            "total_entries": len(all_entries),
            "valid_entries": len(all_entries) - len(errors),
            "invalid_entries": len(errors),
            "hash_errors": hash_errors,
            "signature_errors": signature_errors,
            "chain_errors": chain_errors,
            "sequence_errors": sequence_errors,
            "verification_success_rate": (len(all_entries) - len(errors)) / max(len(all_entries), 1) * 100
        },
        "time_metrics": {
            "oldest_entry": all_entries[0].created_at.isoformat() if all_entries else None,
            "newest_entry": all_entries[-1].created_at.isoformat() if all_entries else None,
            "days_of_records": ((all_entries[-1].created_at - all_entries[0].created_at).days
                             if all_entries and len(all_entries) > 1 else 0) + 1
        },
        "recommendations": [
            "Enable multi-factor authentication" if not current_user.mfa_enabled else "",
            "Review recent access patterns" if len(errors) > 0 else "",
            "Consider rotating access codes periodically"
        ] if errors else [
            "Security audit completed successfully",
            "Maintain current security controls",
            "Schedule regular security reviews"
        ],
        "needs_attention": not ok,
        "error_details": errors if not ok else [],
        "ui_priority_actions": [
            "Enable multi-factor authentication" if not current_user.mfa_enabled else "",
            "Review failed verification attempts" if len(errors) > 0 else "",
            "Update access credentials if compromise suspected"
        ],
        "last_successful_verification": all_entries[-1].created_at.isoformat() if all_entries and ok else None,
        "next_recommended_verification": "30 days"
    }

    summary["recommendations"] = [r for r in summary["recommendations"] if r]

    logger.info(
        "Security summary provided",
        extra={
            "user_id": str(current_user.id),
            "status": summary["audit_status"],
            "entry_count": summary["entry_count"],
            "security_score": summary["security_score"],
        },
    )

    return summary
