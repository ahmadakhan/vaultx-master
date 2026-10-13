"""Bounded resumable uploads and write-only guest dropboxes."""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.deps import get_current_user
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError, ValidationError
from app.core.tenant import (  # noqa: F401 - compatibility instrumentation alias
    publish_pending_storage,
    release_pending_storage,
    reserve_pending_storage,
    reserve_storage,
    set_public_capability_context,
)
from app.db import get_db
from app.models import File, GuestDropbox, GuestDropboxUpload, IndexEntry, UploadSession, User
from app.schemas.file import FileUploadResponse
from app.schemas.transfer import (
    DropboxCreate,
    DropboxRead,
    DropboxUploadRead,
    UploadSessionCreate,
    UploadSessionFinalize,
    UploadSessionRead,
)
from app.storage import get_storage

router = APIRouter(tags=["transfers"])
MAX_REQUEST_CHUNK = 16 * 1024 * 1024


def _hash_capability(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii")).digest()


def _expired(value: datetime) -> bool:
    return value.replace(tzinfo=UTC) <= datetime.now(UTC) if value.tzinfo is None else value <= datetime.now(UTC)


def _decode_b64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValidationError(f"Invalid base64 encoding for {label}") from exc


def _check_tenant(session: UploadSession, current_user: User) -> None:
    if session.owner_id != current_user.id:
        raise NotFoundError("Upload session not found")
    if session.tenant_id != getattr(current_user, "tenant_id", None):
        raise AuthorizationError("Upload session is not in the current tenant")


def _check_dropbox(dropbox: GuestDropbox, current_user: User) -> None:
    if dropbox.owner_id != current_user.id:
        raise NotFoundError("Dropbox not found")
    if dropbox.tenant_id != getattr(current_user, "tenant_id", None):
        raise AuthorizationError("Dropbox is not in the current tenant")


@router.post("/upload-sessions", response_model=UploadSessionRead)
async def create_upload_session(payload: UploadSessionCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> UploadSession:
    tenant_id = getattr(current_user, "tenant_id", None)
    existing = await db.scalar(select(UploadSession).where(UploadSession.file_id == payload.file_id).with_for_update())
    if existing:
        _check_tenant(existing, current_user)
        if existing.total_bytes != payload.total_bytes or existing.chunk_size != payload.chunk_size:
            raise ConflictError("An upload session already exists for this file")
        return existing
    if await db.get(File, payload.file_id):
        raise ConflictError("File ID already exists")
    session = UploadSession(owner_id=current_user.id, tenant_id=tenant_id, file_id=payload.file_id, total_bytes=payload.total_bytes, chunk_size=payload.chunk_size, expires_at=datetime.now(UTC) + timedelta(days=2))
    db.add(session)
    if tenant_id:
        await reserve_pending_storage(db, tenant_id, payload.total_bytes)
    await db.commit()
    await db.refresh(session)
    return session


@router.get("/upload-sessions/{session_id}", response_model=UploadSessionRead)
async def get_upload_session(session_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> UploadSession:
    session = await db.get(UploadSession, session_id)
    if not session:
        raise NotFoundError("Upload session not found")
    _check_tenant(session, current_user)
    if _expired(session.expires_at) and session.status == "active":
        session.status = "expired"
        await db.commit()
    return session


@router.patch("/upload-sessions/{session_id}", response_model=UploadSessionRead)
async def append_upload(session_id: uuid.UUID, request: Request, upload_offset: int = Header(..., alias="Upload-Offset", ge=0), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> UploadSession:
    session = await db.scalar(select(UploadSession).where(UploadSession.id == session_id).with_for_update())
    if not session:
        raise NotFoundError("Upload session not found")
    _check_tenant(session, current_user)
    if session.status != "active" or _expired(session.expires_at):
        raise ConflictError("Upload session is not active")
    if upload_offset != session.offset:
        raise ConflictError(f"Upload offset mismatch; expected {session.offset}")
    if request.headers.get("content-length") and int(request.headers["content-length"]) == 0:
        raise ValidationError("Upload chunk cannot be empty")
    if request.headers.get("content-length") and int(request.headers["content-length"]) > min(session.chunk_size, MAX_REQUEST_CHUNK):
        raise ValidationError("Upload chunk is too large")
    staging = get_storage()
    # Stream into a bounded temporary file through the same 1 MiB backpressure loop.
    temp = staging._safe(staging._staging_dir(str(session.id)) / "request")
    temp.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    received = 0
    with open(temp, "wb") as output:
        async for block in request.stream():
            received += len(block)
            if received > min(session.chunk_size, MAX_REQUEST_CHUNK) or session.offset + received > session.total_bytes:
                temp.unlink(missing_ok=True)
                raise ValidationError("Upload chunk exceeds configured bound")
            output.write(block)
    with open(temp, "rb") as source:
        await run_in_threadpool(staging.append_stream, str(session.id), session.offset, source, max_bytes=session.total_bytes, max_chunk_bytes=min(session.chunk_size, MAX_REQUEST_CHUNK))
    temp.unlink(missing_ok=True)
    session.offset += received
    if session.offset == session.total_bytes:
        session.status = "complete"
        session.storage_path = str(staging.staged_path(str(session.id)))
    await db.commit()
    await db.refresh(session)
    return session


@router.delete("/upload-sessions/{session_id}", status_code=204)
async def cancel_upload_session(session_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> None:
    session = await db.scalar(select(UploadSession).where(UploadSession.id == session_id).with_for_update())
    if not session:
        raise NotFoundError("Upload session not found")
    _check_tenant(session, current_user)
    if session.status in {"complete", "finalized"}:
        raise ConflictError("Completed upload sessions cannot be cancelled")
    get_storage().cancel_upload(str(session.id))
    if session.tenant_id:
        await release_pending_storage(db, session.tenant_id, session.total_bytes)
    session.status = "cancelled"
    await db.commit()


@router.post("/upload-sessions/{session_id}/finalize", response_model=FileUploadResponse)
async def finalize_upload_session(
    session_id: uuid.UUID,
    payload: UploadSessionFinalize,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FileUploadResponse:
    """Publish a complete resumable ciphertext as an owned ``File``.

    Chunk receipt only advances the staged session. This transaction creates
    the file row, encrypted search index entries, and quota reservation. A
    retry after success returns the existing file without reserving quota
    again.
    """
    session = await db.scalar(select(UploadSession).where(UploadSession.id == session_id).with_for_update())
    if not session:
        raise NotFoundError("Upload session not found")
    _check_tenant(session, current_user)
    existing = await db.scalar(select(File).where(File.id == session.file_id).with_for_update())
    if session.status == "finalized":
        if not existing or existing.owner_id != current_user.id or existing.tenant_id != session.tenant_id:
            raise ConflictError("Upload session finalization is incomplete")
        return FileUploadResponse(id=existing.id, created_at=existing.created_at)
    if existing:
        raise ConflictError("File ID already exists")
    if session.status != "complete" or session.offset != session.total_bytes:
        raise ConflictError("Upload session is not complete")

    storage = get_storage()
    try:
        staged = storage.staged_path(str(session.id))
        blob_size = staged.stat().st_size
    except (FileNotFoundError, NotFoundError) as exc:
        raise ConflictError("Completed upload payload is missing") from exc
    if blob_size != session.total_bytes:
        raise ConflictError("Completed upload size does not match its session")

    decoded = [
        _decode_b64(payload.metadata_ciphertext_b64, "metadata ciphertext"),
        _decode_b64(payload.metadata_iv_b64, "metadata IV"),
        _decode_b64(payload.encrypted_kf_b64, "encrypted file key"),
        _decode_b64(payload.encrypted_kf_iv_b64, "encrypted file key IV"),
        _decode_b64(payload.file_iv_b64, "file IV"),
    ]
    if len(decoded[1]) != 12 or len(decoded[3]) != 12 or len(decoded[4]) != 12:
        raise ValidationError("AES-GCM IVs must be 12 bytes")
    if not decoded[0] or not decoded[2]:
        raise ValidationError("Encrypted metadata and file key are required")

    seen_tokens: set[bytes] = set()
    for token in payload.tokens:
        token_b = _decode_b64(token.token, "search token")
        if len(token_b) != 32 or token_b in seen_tokens:
            raise ValidationError("Invalid or duplicate search token")
        seen_tokens.add(token_b)
        if token.prev_token and len(_decode_b64(token.prev_token, "previous search token")) != 32:
            raise ValidationError("Invalid previous search token")
        _decode_b64(token.value.ciphertext_b64, "search token value")
        if len(_decode_b64(token.value.iv_b64, "search token IV")) != 12:
            raise ValidationError("Invalid token IV")
    existing_tokens = await db.execute(
        select(IndexEntry.token).where(
            IndexEntry.owner_id == current_user.id,
            IndexEntry.token.in_(seen_tokens),
        )
    )
    if existing_tokens.first():
        raise ConflictError("Search token already exists")

    final_path = storage._final_path(str(session.file_id))
    file = File(
        id=session.file_id, owner_id=current_user.id, tenant_id=session.tenant_id,
        storage_path=str(final_path), file_size=blob_size, ciphertext=None,
        metadata_ciphertext=decoded[0], metadata_iv=decoded[1], encrypted_kf=decoded[2],
        encrypted_kf_iv=decoded[3], file_iv=decoded[4],
    )
    db.add(file)
    for token in payload.tokens:
        db.add(IndexEntry(
            token=_decode_b64(token.token, "search token"),
            owner_id=current_user.id,
            tenant_id=session.tenant_id,
            value=token.value.model_dump_json().encode(),
            prev_token=_decode_b64(token.prev_token, "previous search token") if token.prev_token else None,
        ))
    session.status = "finalized"
    published = False
    commit_ambiguous = False
    try:
        if session.tenant_id:
            await publish_pending_storage(db, session.tenant_id, blob_size)
        await db.flush()
        with storage.upload_lock(str(session.id)):
            await run_in_threadpool(storage.finalize_staged_upload, str(session.id), str(session.file_id))
            published = True
        session.storage_path = str(final_path)
        try:
            await db.commit()
        except Exception:
            # A failed COMMIT is ambiguous: PostgreSQL may have committed
            # before the connection dropped. Keep the blob for recovery.
            await db.rollback()
            commit_ambiguous = True
            raise
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictError("File or search token already exists") from exc
    except Exception:
        await db.rollback()
        # Publication and the receipt commit are one logical operation. If the
        # database commit fails after the hard-link succeeds, remove the blob
        # so a later retry cannot inherit an unaccounted-for object.
        if published and not commit_ambiguous:
            storage.delete_blob(str(session.file_id))
        raise
    await db.refresh(file)
    return FileUploadResponse(id=file.id, created_at=file.created_at)


@router.post("/dropboxes", response_model=DropboxRead)
async def create_dropbox(payload: DropboxCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> DropboxRead:
    capability = secrets.token_urlsafe(32)
    dropbox = GuestDropbox(owner_id=current_user.id, tenant_id=getattr(current_user, "tenant_id", None), capability_hash=_hash_capability(capability), expires_at=datetime.now(UTC) + timedelta(seconds=payload.ttl_seconds), max_bytes=payload.max_bytes, max_uploads=payload.max_uploads)
    db.add(dropbox)
    await db.commit()
    await db.refresh(dropbox)
    return DropboxRead(id=dropbox.id, expires_at=dropbox.expires_at, max_bytes=dropbox.max_bytes, max_uploads=dropbox.max_uploads, active=True, capability=capability)


@router.post("/dropboxes/{capability}/uploads", response_model=DropboxUploadRead, status_code=201)
async def receive_dropbox_upload(capability: str, request: Request, db: AsyncSession = Depends(get_db)) -> GuestDropboxUpload:
    if len(capability) < 32 or len(capability) > 128:
        raise NotFoundError("Dropbox not found")
    capability_hash = _hash_capability(capability)
    await set_public_capability_context(db, dropbox_hash=capability_hash)
    dropbox = await db.scalar(select(GuestDropbox).where(GuestDropbox.capability_hash == capability_hash).with_for_update())
    if not dropbox or not dropbox.active or _expired(dropbox.expires_at) or dropbox.upload_count >= dropbox.max_uploads:
        raise NotFoundError("Dropbox not found")
    declared = request.headers.get("content-length")
    if declared and int(declared) > dropbox.max_bytes - dropbox.used_bytes:
        raise ValidationError("Dropbox byte limit exceeded")
    upload_id = uuid.uuid4()
    storage = get_storage()
    received = 0
    staging = storage._safe(storage._staging_dir(str(upload_id)) / "payload")
    staging.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(staging, "wb") as output:
        async for block in request.stream():
            received += len(block)
            if received > dropbox.max_bytes - dropbox.used_bytes:
                staging.unlink(missing_ok=True)
                raise ValidationError("Dropbox byte limit exceeded")
            output.write(block)
    upload = GuestDropboxUpload(id=upload_id, dropbox_id=dropbox.id, tenant_id=dropbox.tenant_id, storage_path=str(staging), size=received, finalized=False, status="pending")
    if dropbox.tenant_id:
        try:
            await reserve_pending_storage(db, dropbox.tenant_id, received)
        except Exception:
            staging.unlink(missing_ok=True)
            raise
    dropbox.used_bytes += received
    dropbox.upload_count += 1
    db.add(upload)
    await db.commit()
    return upload


async def _owned_dropbox_upload(dropbox_id: uuid.UUID, upload_id: uuid.UUID, db: AsyncSession, current_user: User) -> tuple[GuestDropbox, GuestDropboxUpload]:
    dropbox = await db.get(GuestDropbox, dropbox_id)
    if not dropbox:
        raise NotFoundError("Dropbox not found")
    _check_dropbox(dropbox, current_user)
    upload = await db.scalar(select(GuestDropboxUpload).where(
        GuestDropboxUpload.id == upload_id,
        GuestDropboxUpload.dropbox_id == dropbox_id,
        GuestDropboxUpload.tenant_id == getattr(current_user, "tenant_id", None),
    ).with_for_update())
    if not upload:
        raise NotFoundError("Dropbox upload not found")
    return dropbox, upload


@router.get("/dropboxes/{dropbox_id}/uploads", response_model=list[DropboxUploadRead])
async def list_dropbox_uploads(dropbox_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> list[GuestDropboxUpload]:
    dropbox = await db.get(GuestDropbox, dropbox_id)
    if not dropbox:
        raise NotFoundError("Dropbox not found")
    _check_dropbox(dropbox, current_user)
    result = await db.scalars(select(GuestDropboxUpload).where(
        GuestDropboxUpload.dropbox_id == dropbox_id,
        GuestDropboxUpload.tenant_id == getattr(current_user, "tenant_id", None),
    ).order_by(GuestDropboxUpload.created_at.desc()))
    return list(result)


@router.get("/dropboxes/{dropbox_id}/uploads/{upload_id}", response_model=DropboxUploadRead)
async def get_dropbox_upload(dropbox_id: uuid.UUID, upload_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> GuestDropboxUpload:
    return (await _owned_dropbox_upload(dropbox_id, upload_id, db, current_user))[1]


@router.post("/dropboxes/{dropbox_id}/uploads/{upload_id}/accept", response_model=FileUploadResponse)
async def accept_dropbox_upload(dropbox_id: uuid.UUID, upload_id: uuid.UUID, payload: UploadSessionFinalize, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> FileUploadResponse:
    """Accept a staged guest object and publish it as an owned File."""
    _dropbox, upload = await _owned_dropbox_upload(dropbox_id, upload_id, db, current_user)
    if upload.status == "accepted" and upload.file_id:
        file = await db.get(File, upload.file_id)
        if file and file.owner_id == current_user.id and file.tenant_id == upload.tenant_id:
            return FileUploadResponse(id=file.id, created_at=file.created_at)
        raise ConflictError("Dropbox upload acceptance is incomplete")
    if upload.status == "rejected":
        raise ConflictError("Rejected uploads cannot be accepted")
    storage = get_storage()
    try:
        staged = storage.staged_path(str(upload.id))
        if staged.stat().st_size != upload.size:
            raise ConflictError("Staged upload size does not match its receipt")
    except (FileNotFoundError, NotFoundError) as exc:
        raise ConflictError("Staged upload payload is missing") from exc
    decoded = [_decode_b64(value, label) for value, label in (
        (payload.metadata_ciphertext_b64, "metadata ciphertext"), (payload.metadata_iv_b64, "metadata IV"),
        (payload.encrypted_kf_b64, "encrypted file key"), (payload.encrypted_kf_iv_b64, "encrypted file key IV"),
        (payload.file_iv_b64, "file IV"),)]
    if any(len(decoded[index]) != 12 for index in (1, 3, 4)) or not decoded[0] or not decoded[2]:
        raise ValidationError("Invalid encrypted file metadata")
    file_id = upload.id
    file = File(id=file_id, owner_id=current_user.id, tenant_id=upload.tenant_id, storage_path=str(storage._final_path(str(file_id))), file_size=upload.size, ciphertext=None, metadata_ciphertext=decoded[0], metadata_iv=decoded[1], encrypted_kf=decoded[2], encrypted_kf_iv=decoded[3], file_iv=decoded[4])
    db.add(file)
    if upload.tenant_id:
        await publish_pending_storage(db, upload.tenant_id, upload.size)
    upload.status = "accepted"
    upload.finalized = True
    upload.file_id = file_id
    upload.published_at = datetime.now(UTC)
    upload.reconciliation_state = "published"
    await db.flush()
    published = False
    commit_ambiguous = False
    try:
        with storage.upload_lock(str(upload.id)):
            await run_in_threadpool(storage.finalize_staged_upload, str(upload.id), str(file_id))
            published = True
        try:
            await db.commit()
        except Exception:
            # Never delete a blob when commit outcome cannot be known.
            await db.rollback()
            commit_ambiguous = True
            raise
    except Exception:
        await db.rollback()
        if published and not commit_ambiguous:
            storage.delete_blob(str(file_id))
        raise
    await db.refresh(file)
    return FileUploadResponse(id=file.id, created_at=file.created_at)


@router.post("/dropboxes/{dropbox_id}/uploads/{upload_id}/reject", response_model=DropboxUploadRead)
async def reject_dropbox_upload(dropbox_id: uuid.UUID, upload_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> GuestDropboxUpload:
    _dropbox, upload = await _owned_dropbox_upload(dropbox_id, upload_id, db, current_user)
    if upload.status == "accepted":
        raise ConflictError("Accepted uploads cannot be rejected")
    if upload.status == "rejected":
        return upload
    get_storage().cancel_upload(str(upload.id))
    if upload.tenant_id:
        await release_pending_storage(db, upload.tenant_id, upload.size)
    upload.status = "rejected"
    upload.finalized = False
    upload.reconciliation_state = "discarded"
    await db.commit()
    return upload
