"""Retention, legal-hold, export and erasure policy helpers."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import File, LegalHold


async def subject_on_hold(db: AsyncSession, subject: str) -> bool:
    return (await db.scalar(select(LegalHold.id).where(LegalHold.subject == subject, LegalHold.active.is_(True)))) is not None


async def erase_subject(db: AsyncSession, subject: str) -> int:
    """Erase metadata for a subject unless a matching legal hold is active."""
    if await subject_on_hold(db, subject):
        raise PermissionError("active legal hold prevents erasure")
    result = await db.execute(delete(File).where(File.owner_id == subject))
    await db.commit()
    return int(result.rowcount or 0)


def release_hold(hold: LegalHold) -> None:
    hold.active = False
    hold.released_at = datetime.now(UTC)
