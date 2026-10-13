"""Scheduled MinIO backup and immutable audit-outbox delivery worker."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlalchemy import select

from app.config import settings
from app.core.backup import MinioBackupAdapter, run_backup
from app.core.logging import get_logger
from app.db import AsyncSessionLocal
from app.models import AuditOutbox

logger = get_logger(__name__)


async def deliver_audit_outbox(adapter: MinioBackupAdapter) -> int:
    """Mark events delivered only after immutable object-store upload succeeds."""
    delivered = 0
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(AuditOutbox).where(AuditOutbox.delivered_at.is_(None))
            .order_by(AuditOutbox.id).limit(500)
        )).scalars().all()
        for row in rows:
            key = await asyncio.to_thread(adapter.deliver_audit_outbox, row.id, row.event_json)
            row.delivered_at = datetime.now(UTC)
            delivered += 1
            logger.info("Audit event delivered", extra={"event_id": row.id, "object_key": key})
        if delivered:
            await db.commit()
    return delivered


async def run() -> None:
    if not settings.backup_enabled:
        raise RuntimeError("BACKUP_ENABLED must be true for the backup worker")
    adapter = MinioBackupAdapter.from_settings()
    adapter.bootstrap_bucket()
    next_backup = 0.0
    while True:
        try:
            now = asyncio.get_running_loop().time()
            if now >= next_backup:
                result = await asyncio.to_thread(run_backup, adapter=adapter)
                logger.info("Immutable backup completed", extra={"backup_id": result.backup_id, "manifest_sha256": result.manifest_sha256})
                next_backup = now + settings.backup_interval_minutes * 60
            await deliver_audit_outbox(adapter)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scheduled backup or audit delivery failed")
        await asyncio.sleep(settings.audit_delivery_interval_seconds)


if __name__ == "__main__":
    asyncio.run(run())
