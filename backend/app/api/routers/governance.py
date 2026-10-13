"""Admin-controlled recovery and data-governance endpoints."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.audit_decorator import audit_event
from app.core.deps import get_current_admin
from app.core.governance import erase_subject, release_hold
from app.core.recovery import build_manifest, export_manifest, verify_manifest
from app.db import get_db
from app.models import AuditOutbox, LegalHold, RecoveryPolicy, User

router = APIRouter(prefix="/admin/governance", tags=["governance"])
Admin = Annotated[User, Depends(get_current_admin)]


@router.get("/recovery")
async def recovery_policy(current_admin: Admin, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    policy = await db.scalar(select(RecoveryPolicy).order_by(RecoveryPolicy.id).limit(1))
    return {"rpo_minutes": policy.rpo_minutes if policy else settings.recovery_rpo_minutes,
            "rto_minutes": policy.rto_minutes if policy else settings.recovery_rto_minutes,
            "evidence": policy.evidence if policy else {"source": "configuration", "verified": False},
            "residency_region": policy.residency_region if policy else settings.data_residency_region}


@router.put("/recovery")
@audit_event("recovery_policy_updated")
async def update_recovery_policy(rpo_minutes: int, rto_minutes: int, request: Request,
                                 current_admin: Admin, db: AsyncSession = Depends(get_db),
                                 evidence: str | None = None, residency_region: str | None = None) -> dict[str, Any]:
    if rpo_minutes < 1 or rto_minutes < 1:
        raise HTTPException(422, "RPO and RTO must be positive minutes")
    policy = await db.scalar(select(RecoveryPolicy).order_by(RecoveryPolicy.id).limit(1))
    if policy is None:
        policy = RecoveryPolicy(rpo_minutes=rpo_minutes, rto_minutes=rto_minutes)
        db.add(policy)
    policy.rpo_minutes, policy.rto_minutes = rpo_minutes, rto_minutes
    policy.evidence = {"statement": evidence or "", "verified": False, "updated_by": str(current_admin.id)}
    policy.residency_region = residency_region
    policy.updated_at = datetime.now(UTC)
    await db.commit()
    return await recovery_policy(current_admin=current_admin, db=db)


@router.post("/recovery/manifest")
@audit_event("backup_manifest_created")
async def create_manifest(request: Request, current_admin: Admin, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    manifest = await build_manifest(db, created_by=current_admin.id)
    return {"id": str(manifest.id), "object_count": manifest.object_count,
            "manifest_sha256": manifest.manifest_sha256, "delivery": "local-only"}


@router.get("/recovery/manifests/{manifest_id}/verify")
async def verify_backup(manifest_id: UUID, current_admin: Admin, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    from app.models import BackupManifest
    manifest = await db.get(BackupManifest, manifest_id)
    if manifest is None:
        raise HTTPException(404, "manifest not found")
    valid, actual = verify_manifest(manifest)
    return {"valid": valid, "manifest_sha256": manifest.manifest_sha256, "computed_sha256": actual}


@router.get("/recovery/manifests/{manifest_id}/export")
async def export_backup(manifest_id: UUID, current_admin: Admin, db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    from app.models import BackupManifest
    manifest = await db.get(BackupManifest, manifest_id)
    if manifest is None:
        raise HTTPException(404, "manifest not found")
    return {"content_type": "application/json", "manifest": export_manifest(manifest).decode()}


@router.get("/audit/outbox")
async def audit_outbox(current_admin: Admin, db: AsyncSession = Depends(get_db), limit: int = 100) -> list[dict[str, Any]]:
    rows = (await db.execute(select(AuditOutbox).where(AuditOutbox.delivered_at.is_(None)).order_by(AuditOutbox.id).limit(min(limit, 500)))).scalars()
    return [{"id": row.id, "event_hash": row.event_hash, "event": row.event_json, "created_at": row.created_at} for row in rows]


@router.post("/holds")
@audit_event("legal_hold_created", resource_fields=("subject",))
async def create_hold(subject: str, reason: str, request: Request, current_admin: Admin, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    hold = LegalHold(subject=subject, reason=reason, created_by=current_admin.id)
    db.add(hold)
    await db.commit()
    await db.refresh(hold)
    return {"id": str(hold.id), "subject": hold.subject, "active": hold.active}


@router.delete("/holds/{hold_id}")
@audit_event("legal_hold_released", resource_fields=("hold_id",))
async def release_legal_hold(hold_id: UUID, request: Request, current_admin: Admin, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    hold = await db.get(LegalHold, hold_id)
    if hold is None:
        raise HTTPException(404, "legal hold not found")
    release_hold(hold)
    await db.commit()
    return {"id": str(hold.id), "active": False}


@router.post("/erasure")
@audit_event("subject_erasure_requested", resource_fields=("subject",))
async def erase_data(subject: str, request: Request, current_admin: Admin, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Permanently erase owned metadata; an active legal hold always wins."""
    try:
        count = await erase_subject(db, subject)
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"subject": subject, "erased_records": count, "completed_at": datetime.now(UTC)}


@router.get("/residency")
async def residency(current_admin: Admin, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    return {"region": settings.data_residency_region, "declared": settings.data_residency_region is not None,
            "enforcement": "metadata-only; storage adapter policy required"}
