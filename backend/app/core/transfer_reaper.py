"""Durable cleanup for staged transfer receipts and abandoned payloads."""

from datetime import UTC, datetime

from sqlalchemy import select

from app.core.tenant import release_pending_storage
from app.models import GuestDropbox, GuestDropboxUpload, UploadSession
from app.storage import get_storage


async def reap_transfer_staging(db, *, limit: int = 200) -> int:
    """Expire receipts before deleting bytes, keeping quota accounting balanced.

    Rows are marked first and the storage deletion is performed while the row is
    locked. A subsequent run is safe when a process is interrupted.
    """
    now = datetime.now(UTC)
    storage = get_storage()
    count = 0
    sessions = (await db.scalars(select(UploadSession).where(
        UploadSession.status.in_(("active", "complete")),
        UploadSession.expires_at <= now,
    ).with_for_update(skip_locked=True).limit(limit))).all()
    for session in sessions:
        storage.cancel_upload(str(session.id))
        if session.tenant_id:
            await release_pending_storage(db, session.tenant_id, session.total_bytes)
        session.status = "expired"
        count += 1

    uploads = (await db.scalars(select(GuestDropboxUpload).join(
        GuestDropbox, GuestDropbox.id == GuestDropboxUpload.dropbox_id
    ).where(
        GuestDropbox.expires_at <= now,
        GuestDropboxUpload.status == "pending",
    ).with_for_update(skip_locked=True).limit(limit))).all()
    for upload in uploads:
        storage.cancel_upload(str(upload.id))
        if upload.tenant_id:
            await release_pending_storage(db, upload.tenant_id, upload.size)
        upload.status = "expired"
        upload.reconciliation_state = "discarded"
        count += 1
    if count:
        await db.commit()
    return count
