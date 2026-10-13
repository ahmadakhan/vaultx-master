"""Tenant context and database-backed resource reservations.

The PostgreSQL migration installs deny-by-default RLS policies keyed by the
transaction-local ``app.tenant_id`` setting.  These helpers keep application
queries explicit as well; RLS is a backstop, not a substitute for predicates.
"""

from __future__ import annotations

import uuid

from sqlalchemy import and_, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ValidationError
from app.models import File, IndexEntry, TenantQuota


async def set_tenant_context(db: AsyncSession, tenant_id: uuid.UUID | None) -> None:
    """Set the transaction-local tenant used by PostgreSQL RLS.

    SQLite has no custom GUCs, so this is deliberately a no-op there.  A null
    context is represented by an empty string and is rejected by policies.
    """
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(
            text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id) if tenant_id else ""},
        )


async def set_public_capability_context(
    db: AsyncSession, *, link_token: str | None = None, dropbox_hash: bytes | None = None
) -> None:
    """Scope RLS to one presented public capability, never a whole tenant."""
    if db.get_bind().dialect.name != "postgresql":
        return
    await db.execute(text("SELECT set_config('app.public_link_token', :token, true)"), {"token": link_token or ""})
    await db.execute(text("SELECT set_config('app.dropbox_capability_hash', :capability, true)"), {"capability": dropbox_hash.hex() if dropbox_hash else ""})


def tenant_predicate(column: object, tenant_id: uuid.UUID):
    """Return the standard tenant equality predicate for a model column."""
    return column == tenant_id  # type: ignore[operator]


def scope_file_query(statement, tenant_id: uuid.UUID):
    """Add an explicit tenant predicate to a File select/update/delete."""
    return statement.where(tenant_predicate(File.tenant_id, tenant_id))


def scope_index_query(statement, tenant_id: uuid.UUID):
    """Add an explicit tenant predicate to an encrypted index query."""
    return statement.where(tenant_predicate(IndexEntry.tenant_id, tenant_id))


async def reserve_storage(db: AsyncSession, tenant_id: uuid.UUID, amount: int) -> None:
    """Atomically reserve storage, failing without changing usage.

    The conditional UPDATE is the correctness boundary: concurrent uploads
    serialize on the quota row and only one can consume the remaining bytes.
    The caller owns the surrounding transaction and can roll it back if blob
    publication or file metadata persistence fails.
    """
    if amount < 0:
        raise ValidationError("Storage reservation cannot be negative")
    result = await db.execute(
        update(TenantQuota)
        .where(
            and_(
                TenantQuota.tenant_id == tenant_id,
                TenantQuota.storage_used_bytes + amount <= TenantQuota.storage_quota_bytes,
            )
        )
        .values(storage_used_bytes=TenantQuota.storage_used_bytes + amount)
    )
    if result.rowcount != 1:
        raise ValidationError("Upload would exceed the tenant storage quota")


async def release_storage(db: AsyncSession, tenant_id: uuid.UUID, amount: int) -> None:
    """Release a reservation after an upload is discarded."""
    if amount < 0:
        raise ValidationError("Storage release cannot be negative")
    result = await db.execute(
        update(TenantQuota)
        .where(
            TenantQuota.tenant_id == tenant_id,
            TenantQuota.storage_used_bytes >= amount,
        )
        .values(storage_used_bytes=TenantQuota.storage_used_bytes - amount)
    )
    if result.rowcount != 1:
        raise ValidationError("Storage release exceeds the tenant's recorded usage")


async def reserve_pending_storage(db: AsyncSession, tenant_id: uuid.UUID, amount: int) -> None:
    """Hold staged bytes against quota until publication or cleanup."""
    if amount < 0:
        raise ValidationError("Pending storage reservation cannot be negative")
    result = await db.execute(
        update(TenantQuota).where(
            TenantQuota.tenant_id == tenant_id,
            TenantQuota.storage_used_bytes + TenantQuota.pending_upload_bytes + amount
            <= TenantQuota.storage_quota_bytes,
        ).values(pending_upload_bytes=TenantQuota.pending_upload_bytes + amount)
    )
    if result.rowcount != 1:
        raise ValidationError("Upload would exceed the tenant storage quota")


async def publish_pending_storage(db: AsyncSession, tenant_id: uuid.UUID, amount: int) -> None:
    """Atomically convert a pending hold into committed storage usage."""
    if amount < 0:
        raise ValidationError("Pending storage publication cannot be negative")
    result = await db.execute(update(TenantQuota).where(
        TenantQuota.tenant_id == tenant_id,
        TenantQuota.pending_upload_bytes >= amount,
    ).values(
        pending_upload_bytes=TenantQuota.pending_upload_bytes - amount,
        storage_used_bytes=TenantQuota.storage_used_bytes + amount,
    ))
    if result.rowcount != 1:
        raise ValidationError("Pending upload reservation is missing")


async def release_pending_storage(db: AsyncSession, tenant_id: uuid.UUID, amount: int) -> None:
    if amount < 0:
        raise ValidationError("Pending storage release cannot be negative")
    result = await db.execute(update(TenantQuota).where(
        TenantQuota.tenant_id == tenant_id,
        TenantQuota.pending_upload_bytes >= amount,
    ).values(pending_upload_bytes=TenantQuota.pending_upload_bytes - amount))
    if result.rowcount != 1:
        raise ValidationError("Pending upload release exceeds recorded reservations")
