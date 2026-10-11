"""File management endpoints.

Handles encrypted file upload, listing, batch retrieval, download,
soft-delete, and restore. All file content and metadata are encrypted
client-side before reaching the server; the server only stores
ciphertext blobs.

Access control ensures users can only access their own files or
files explicitly shared with them.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from fastapi import (
    APIRouter,
    Depends,
    Form,
    Query,
    Request,
    UploadFile,
)
from fastapi import (
    File as FastAPIFile,
)
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.audit_decorator import audit_event
from app.core.deps import get_current_user, get_current_user_mfa_verified
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db import get_db
from app.models import File, FileShare, IndexEntry, User
from app.schemas.file import (
    FileBatchList,
    FileListPage,
    FileUploadResponse,
    parse_token_entries,
)
from app.storage import get_storage

logger = get_logger(__name__)

router = APIRouter(prefix="/files", tags=["files"])


def _decode_b64(value: str) -> bytes:
    """Decode a base64 string, raising ``ValidationError`` on failure.

    Args:
        value: Base64-encoded string.

    Returns:
        Decoded bytes.

    Raises:
        ValidationError: If the input is not valid base64.
    """
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValidationError("Invalid base64 encoding in request payload") from exc


def _get_current_time() -> datetime:
    """Return current UTC time for placeholder timestamps on chunk uploads."""
    from app.models.base import utcnow
    return utcnow()


def _build_file_dict(
    f: File,
    owner_email: str,
    share: FileShare | None = None,
    include_kf: bool = False,
) -> dict[str, Any]:
    """Serialize a File model to a response dict.

    Args:
        f: The File model instance.
        owner_email: The owner's email address.
        share: Optional FileShare if the user is a recipient.
        include_kf: Whether to include encrypted key-folder data
            (only for the file owner).

    Returns:
        A dict suitable for JSON response.
    """
    encrypted_kf_b64 = base64.b64encode(f.encrypted_kf or b"").decode() if include_kf else None
    encrypted_kf_iv = base64.b64encode(f.encrypted_kf_iv or b"").decode() if include_kf else None
    wrapped_key_b64 = base64.b64encode(share.wrapped_key or b"").decode() if share else None

    return {
        "id": str(f.id),
        "owner_email": owner_email,
        "metadata_ciphertext": base64.b64encode(f.metadata_ciphertext or b"").decode(),
        "metadata_iv": base64.b64encode(f.metadata_iv or b"").decode(),
        "encrypted_kf_b64": encrypted_kf_b64,
        "encrypted_kf_iv": encrypted_kf_iv,
        "wrapped_key_b64": wrapped_key_b64,
        "created_at": f.created_at,
        "deleted": bool(f.deleted),
        "shared_with": [],
        "is_shared_file": share is not None,
    }


@router.post("/upload", response_model=FileUploadResponse)
@audit_event("file_upload")
async def upload_file(
    request: Request,
    file_id: str = Form(..., description="Client-generated UUID for the file"),
    metadata_ciphertext: str = Form(..., description="Base64-encoded encrypted metadata"),
    metadata_iv: str = Form(..., description="Base64-encoded metadata IV"),
    tokens_json: str = Form(..., description="JSON array of encrypted search index entries"),
    encrypted_kf_b64: str = Form(
        ..., description="Base64-encoded file key encrypted under master key"
    ),
    encrypted_kf_iv: str = Form(..., description="Base64-encoded file key IV"),
    file_iv: str = Form(..., description="Base64-encoded file content IV"),
    file: UploadFile = FastAPIFile(...),
    chunk_index: int = Form(0, description="Zero-based chunk index for chunked uploads"),
    total_chunks: int = Form(1, description="Total number of chunks (1 for non-chunked)"),
    is_last_chunk: bool = Form(False, description="Whether this is the final chunk"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FileUploadResponse:
    """Upload an encrypted file with metadata and search index entries.

    The client encrypts the file content, metadata, and file key
    (Kf) before sending. Search tokens are encrypted references
    linking keyword hashes to the file ID.

    For large files (up to 10 GB), the client should send the file
    in chunks using multipart form fields ``chunk_index``,
    ``total_chunks``, and ``is_last_chunk``. Each chunk is streamed
    directly to the filesystem; on the last chunk the blob is
    assembled and the DB record is created. Metadata and tokens are
    submitted only on the first chunk.

    Args:
        file_id: Client-generated UUID string.
        metadata_ciphertext: Base64 encrypted file metadata (name, size, type, keywords).
        metadata_iv: Base64 IV for metadata encryption.
        tokens_json: JSON array of search token objects (first chunk only).
        encrypted_kf_b64: Base64 file key encrypted under the user's master key.
        encrypted_kf_iv: Base64 IV for file key encryption.
        file_iv: Base64 IV for file content encryption.
        file: The encrypted file (or chunk).
        chunk_index: Zero-based chunk index.
        total_chunks: Total number of chunks in the upload.
        is_last_chunk: Whether this is the final chunk.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        The file UUID and creation timestamp (on the final chunk).

    Raises:
        ValidationError: If ``file_id`` is not a valid UUID, any base64
            field is malformed, or the chunk sequence is invalid.
        ConflictError: If a file with the given ID already exists.
    """
    from app.config import settings as _settings

    try:
        file_uuid = uuid.UUID(file_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid file_id format") from exc

    if not 1 <= total_chunks <= 10000 or not 0 <= chunk_index < total_chunks:
        raise ValidationError("Invalid chunk sequence")
    if is_last_chunk and chunk_index != total_chunks - 1:
        raise ValidationError("Invalid final chunk")
    is_chunked = total_chunks > 1

    # --- Decode form fields (required on first chunk, optional on subsequent) ---
    if chunk_index == 0 or not is_chunked:
        if any(len(value) > 8192 for value in (
            metadata_ciphertext, metadata_iv, encrypted_kf_b64, encrypted_kf_iv, file_iv
        )) or len(tokens_json) > 5_000_000:
            raise ValidationError("Upload metadata is too large")
        metadata_bytes = _decode_b64(metadata_ciphertext)
        metadata_iv_b = _decode_b64(metadata_iv)
        encrypted_kf = _decode_b64(encrypted_kf_b64)
        encrypted_kf_iv_b = _decode_b64(encrypted_kf_iv)
        file_iv_b = _decode_b64(file_iv)
        if any(len(iv) != 12 for iv in (metadata_iv_b, encrypted_kf_iv_b, file_iv_b)):
            raise ValidationError("AES-GCM IVs must be 12 bytes")
        if not metadata_bytes or not encrypted_kf:
            raise ValidationError("Encrypted metadata and file key are required")
        try:
            tokens = parse_token_entries(tokens_json or "[]")
            seen = set()
            for entry in tokens:
                token = _decode_b64(entry.token)
                if len(token) != 32 or token in seen:
                    raise ValueError("Invalid or duplicate search token")
                seen.add(token)
                if entry.prev_token and len(_decode_b64(entry.prev_token)) != 32:
                    raise ValueError("Invalid previous token")
                _decode_b64(entry.value.ciphertext_b64)
                if len(_decode_b64(entry.value.iv_b64)) != 12:
                    raise ValueError("Invalid token IV")
        except ValueError as exc:
            raise ValidationError("Invalid search tokens") from exc
    else:
        metadata_bytes = b""
        metadata_iv_b = b""
        encrypted_kf_b64 = ""
        encrypted_kf_iv = ""
        file_iv = ""
        encrypted_kf = b""
        encrypted_kf_iv_b = b""
        file_iv_b = b""

    existing = await db.get(File, file_uuid)
    if existing:
        raise ConflictError("File ID already exists")

    storage = get_storage()

    # Namespacing prevents another account from continuing/cancelling a session.
    upload_id = str(uuid.uuid5(current_user.id, str(file_uuid)))
    metadata = None
    if chunk_index == 0:
        metadata = {
            "metadata_ciphertext": metadata_ciphertext, "metadata_iv": metadata_iv,
            "encrypted_kf_b64": encrypted_kf_b64, "encrypted_kf_iv": encrypted_kf_iv,
            "file_iv": file_iv, "tokens": [entry.model_dump() for entry in tokens],
        }
    try:
        with storage.upload_lock(upload_id):
            upload_complete = await run_in_threadpool(storage.write_chunk,
                upload_id, chunk_index, total_chunks, file.file, is_last_chunk,
                max_bytes=_settings.max_upload_bytes, metadata=metadata,
            )
            if not upload_complete:
                return FileUploadResponse(id=file_uuid, created_at=_get_current_time())
            saved = storage.upload_metadata(upload_id)
            metadata_bytes = _decode_b64(saved["metadata_ciphertext"])
            metadata_iv_b = _decode_b64(saved["metadata_iv"])
            encrypted_kf = _decode_b64(saved["encrypted_kf_b64"])
            encrypted_kf_iv_b = _decode_b64(saved["encrypted_kf_iv"])
            file_iv_b = _decode_b64(saved["file_iv"])
            tokens = saved["tokens"]
            if tokens:
                existing_tokens = await db.execute(select(IndexEntry.token).where(
                    IndexEntry.owner_id == current_user.id,
                    IndexEntry.token.in_([_decode_b64(entry["token"]) for entry in tokens]),
                ))
                if existing_tokens.first():
                    raise ConflictError("Search token already exists")
            blob_path = storage._final_path(str(file_uuid))
            blob_size = storage.upload_size(upload_id)
    finally:
        await file.close()

    new_file = File(
        id=file_uuid,
        owner_id=current_user.id,
        ciphertext=None,
        storage_path=str(blob_path),
        file_size=blob_size,
        metadata_ciphertext=metadata_bytes,
        metadata_iv=metadata_iv_b,
        encrypted_kf=encrypted_kf,
        encrypted_kf_iv=encrypted_kf_iv_b,
        file_iv=file_iv_b,
    )
    db.add(new_file)

    for t in tokens:
        token_b = _decode_b64(t["token"])

        value_obj = t.get("value")
        if (
            not isinstance(value_obj, dict)
            or "ciphertext_b64" not in value_obj
            or "iv_b64" not in value_obj
        ):
            raise ValidationError("Invalid token value format")

        value_json = json.dumps(value_obj).encode()
        prev_b = _decode_b64(t["prev_token"]) if t.get("prev_token") else None

        db.add(
            IndexEntry(
                token=token_b,
                owner_id=current_user.id,
                value=value_json,
                prev_token=prev_b,
            )
        )

    try:
        # Check all DB constraints before publishing a blob. The unique file ID
        # also serializes competing owners attempting to publish the same ID.
        await db.flush()
        with storage.upload_lock(upload_id):
            await run_in_threadpool(storage.finalize_upload, upload_id, str(file_uuid))
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictError("File or search token already exists") from exc
    await db.refresh(new_file)

    logger.info(
        "File uploaded",
        extra={
            "file_id": str(file_uuid),
            "user_id": str(current_user.id),
            "size": blob_size,
        },
    )

    return FileUploadResponse(
        id=new_file.id,
        created_at=new_file.created_at,
    )


@router.get("", response_model=FileListPage)
async def list_files(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> FileListPage:
    """List all files owned by or shared with the current user.

    Uses a single joined query to fetch shared emails, eliminating
    the N+1 query pattern present in the original implementation.

    Args:
        db: Database session.
        current_user: Authenticated user.
        limit: Maximum results per page (1-100).
        offset: Pagination offset.

    Returns:
        Paginated file list with owner info and sharing status.
    """
    owned_q: Any = await db.execute(
        select(File, User.email)
        .join(User, File.owner_id == User.id)
        .where(File.owner_id == current_user.id, File.deleted.is_(False))
    )
    owned_files = owned_q.all()

    shared_q = await db.execute(
        select(File, User.email, FileShare)
        .join(User, File.owner_id == User.id)
        .join(FileShare, FileShare.file_id == File.id)
        .where(FileShare.recipient_user_id == current_user.id, File.deleted.is_(False))
    )
    shared_files = shared_q.all()

    combined: list[dict[str, Any]] = []

    all_file_ids = [f.id for f, _ in owned_files]
    if all_file_ids:
        shared_emails_q = await db.execute(
            select(FileShare.file_id, User.email)
            .join(User, FileShare.recipient_user_id == User.id)
            .where(FileShare.file_id.in_(all_file_ids))
        )
        email_map: dict[str, list[str]] = {}
        for fid, email in shared_emails_q.all():
            email_map.setdefault(str(fid), []).append(email)

        for f, owner_email in owned_files:
            combined.append(
                {
                    **_build_file_dict(f, owner_email, include_kf=True),
                    "shared_with": email_map.get(str(f.id), []),
                    "is_shared_file": False,
                }
            )

    for f, owner_email, share in shared_files:
        combined.append(_build_file_dict(f, owner_email, share=share))

    combined.sort(key=lambda x: x["created_at"], reverse=True)
    paginated = combined[offset : offset + limit]

    return FileListPage(
        total=len(combined),
        count=len(paginated),
        limit=limit,
        offset=offset,
        files=cast(list[Any], paginated),
    )


@router.post("/batch", response_model=dict[str, Any])
async def list_files_by_ids(
    payload: FileBatchList,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve multiple files by ID in a single request.

    Args:
        payload: Request body containing a list of file UUIDs.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A dict with ``count`` and ``files`` keys.
    """
    ids = payload.ids
    result: Any = await db.execute(
        select(File, User.email, FileShare)
        .outerjoin(User, File.owner_id == User.id)
        .outerjoin(
            FileShare,
            and_(
                FileShare.file_id == File.id,
                FileShare.recipient_user_id == current_user.id,
            ),
        )
        .where(
            File.id.in_(ids),
            File.deleted.is_(False),
            or_(
                File.owner_id == current_user.id,
                FileShare.id.is_not(None),
            ),
        )
    )
    files = result.all()

    out: list[dict[str, Any]] = []
    for f, owner_email, share in files:
        item = _build_file_dict(f, owner_email, include_kf=bool(f.owner_id == current_user.id))

        if share is not None and f.owner_id != current_user.id:
            item["wrapped_key_b64"] = base64.b64encode(share.wrapped_key or b"").decode()

        out.append(item)

    return {"count": len(out), "files": out}


@router.get("/deleted", response_model=dict[str, Any])
async def list_deleted_files(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """List soft-deleted files owned by the current user.

    Args:
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A dict with ``count`` and ``files`` keys.
    """
    result: Any = await db.execute(
        select(File, User.email)
        .join(User, File.owner_id == User.id)
        .where(File.owner_id == current_user.id, File.deleted.is_(True))
    )
    files = result.all()

    out = [_build_file_dict(f, email, include_kf=True) for f, email in files]

    return {"count": len(out), "files": out}


@router.get("/{file_id}", response_model=dict[str, Any])
async def get_file(
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve metadata for a single file (owned or shared).

    Args:
        file_id: The file's UUID.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A dict with file metadata and key material (owner gets
        encrypted_kf; recipient gets wrapped_key).

    Raises:
        NotFoundError: If the file does not exist.
        HTTPException: 403 if the user is neither owner nor recipient.
    """
    try:
        file_uuid = uuid.UUID(file_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid file_id format") from exc

    result: Any = await db.execute(
        select(File, User.email).join(User, File.owner_id == User.id).where(File.id == file_uuid)
    )
    entry = result.first()
    if not entry:
        raise NotFoundError("File not found")

    f, owner_email = entry
    if f.deleted and f.owner_id != current_user.id:
        raise NotFoundError("File not found")
    item = _build_file_dict(f, owner_email, include_kf=bool(f.owner_id == current_user.id))

    if f.owner_id != current_user.id:
        share_check: Any = await db.execute(
            select(FileShare).where(
                FileShare.file_id == f.id,
                FileShare.recipient_user_id == current_user.id,
            )
        )
        share = share_check.scalar_one_or_none()
        if not share:
            raise AuthorizationError("Access denied")
        item["wrapped_key_b64"] = base64.b64encode(share.wrapped_key).decode()

    shared_emails: list[str] = []
    if f.owner_id == current_user.id:
        shared_entries: Any = await db.execute(
            select(User.email)
            .join(FileShare, FileShare.recipient_user_id == User.id)
            .where(FileShare.file_id == f.id)
        )
        shared_emails = [r[0] for r in shared_entries.all()]

    item["shared_with"] = shared_emails
    item["is_shared_file"] = f.owner_id != current_user.id

    return item


@router.get("/{file_id}/download", response_model=dict[str, Any])
@audit_event("file_download")
async def download_file(
    request: Request,
    file_id: str,
    range: str | None = Query(default=None, description="HTTP Range header value: bytes=start-end"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Download a file's encrypted content and metadata.

    The endpoint returns all key material needed by the client to
    decrypt the file: the file ciphertext + IV, the metadata
    ciphertext + IV, and either the encrypted file key (for owner)
    or the RSA-wrapped file key (for shared recipient).

    For large files the ciphertext is streamed from the filesystem
    rather than held in memory. A ``Range`` query parameter
    (``bytes=start-end``) enables HTTP range requests so the client
    can download in chunks and resume interrupted transfers.

    Args:
        request: The incoming request (for audit logging).
        file_id: The file's UUID.
        range: Optional HTTP Range value for partial content.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A JSON response with metadata and key-wrapping material, and
        the ciphertext either inline (small files / no range) or as a
        streaming response (when ``range`` is provided or the blob
        exceeds the inline threshold).

    Raises:
        NotFoundError: If the file does not exist.
        HTTPException: 403 if the user is neither owner nor recipient.
    """
    from fastapi.responses import JSONResponse, StreamingResponse

    try:
        file_uuid = uuid.UUID(file_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid file_id format") from exc

    result: Any = await db.execute(select(File).where(File.id == file_uuid))
    f = result.scalar_one_or_none()
    if not f:
        raise NotFoundError("File not found")

    if f.deleted:
        if f.owner_id == current_user.id:
            raise NotFoundError("File is in the trash; restore it before downloading")
        raise AuthorizationError("File has been deleted by its owner")

    encrypted_kf_b64 = None
    encrypted_kf_iv = None
    wrapped_key_b64 = None

    if f.owner_id == current_user.id:
        encrypted_kf_b64 = base64.b64encode(f.encrypted_kf or b"").decode()
        encrypted_kf_iv = base64.b64encode(f.encrypted_kf_iv or b"").decode()
    else:
        share_check: Any = await db.execute(
            select(FileShare).where(
                FileShare.file_id == f.id,
                FileShare.recipient_user_id == current_user.id,
            )
        )
        share = share_check.scalar_one_or_none()
        if not share:
            raise AuthorizationError("Access denied")
        wrapped_key_b64 = base64.b64encode(share.wrapped_key).decode()

    file_iv_b64 = base64.b64encode(f.file_iv or b"").decode()
    metadata_ct_b64 = base64.b64encode(f.metadata_ciphertext or b"").decode()
    metadata_iv_b64 = base64.b64encode(f.metadata_iv or b"").decode()

    # Determine content source: filesystem (large) or DB (small / legacy)
    blob_size: int | None = f.file_size

    # Handle range requests
    range_start = 0
    range_end: int | None = None
    total_size = 0
    blob_path: Path | None = None

    if f.storage_path:
        blob_path = get_storage().validated_path(str(f.id), f.storage_path)
        total_size = blob_path.stat().st_size
        blob_size = total_size

    if range:
        # Parse Range header: "bytes=start-end"
        try:
            if range.startswith("bytes="):
                spec = range[6:]  # strip "bytes="
                parts = spec.split("-", 1)
                range_start = int(parts[0])
                if len(parts) > 1 and parts[1]:
                    range_end = int(parts[1])
            else:
                raise ValueError("Invalid range prefix")
        except (ValueError, IndexError) as exc:
            raise ValidationError("Invalid Range header format") from exc

        if not blob_path or not blob_path.exists():
            raise NotFoundError("File blob not found on disk")

        assert blob_path is not None  # for type checker; checked above

        range_end = total_size - 1 if range_end is None else min(range_end, total_size - 1)

        if range_start < 0 or range_start > total_size - 1 or range_start > range_end:
            range_not_satisfiable = JSONResponse(
                status_code=416,
                content={"detail": "Range not satisfiable"},
                headers={"Content-Range": f"bytes */{total_size}"},
            )
            return range_not_satisfiable

        # Stream the range from the file
        def _range_generator() -> Any:
            remaining = range_end - range_start + 1
            read_size = min(remaining, 16 * 1024 * 1024)
            with open(blob_path, "rb") as bf:
                bf.seek(range_start)
                while remaining > 0:
                    to_read = min(remaining, read_size)
                    data = bf.read(to_read)
                    if not data:
                        break
                    yield data
                    remaining -= len(data)

        range_response = StreamingResponse(_range_generator(), media_type="application/octet-stream")
        range_response.headers["Content-Range"] = f"bytes {range_start}-{range_end}/{total_size}"
        range_response.headers["Content-Length"] = str(range_end - range_start + 1)
        range_response.headers["Accept-Ranges"] = "bytes"
        # Include metadata as response headers
        range_response.headers["X-File-Id"] = str(f.id)
        range_response.headers["X-File-Iv"] = file_iv_b64
        range_response.headers["X-Metadata-Ciphertext"] = metadata_ct_b64
        range_response.headers["X-Metadata-Iv"] = metadata_iv_b64
        if encrypted_kf_b64:
            range_response.headers["X-Encrypted-Kf"] = encrypted_kf_b64
            range_response.headers["X-Encrypted-Kf-Iv"] = base64.b64encode(f.encrypted_kf_iv or b"").decode()
        if wrapped_key_b64:
            range_response.headers["X-Wrapped-Key"] = wrapped_key_b64
        range_response.headers["X-Created-At"] = (
            f.created_at.isoformat() if f.created_at else ""
        )
        range_response.status_code = 206
        return range_response

    # Non-range: return metadata as JSON with inline ciphertext (for small files)
    # or a streaming response (for large files on filesystem)
    if blob_path and blob_path.exists() and blob_size and blob_size > 1_048_576:
        # Large file — stream as octet-stream with metadata headers
        def _stream_generator() -> Any:
            with open(blob_path, "rb") as bf:
                while True:
                    chunk = bf.read(16 * 1024 * 1024)
                    if not chunk:
                        break
                    yield chunk

        stream_response = StreamingResponse(_stream_generator(), media_type="application/octet-stream")
        stream_response.headers["Content-Length"] = str(blob_size)
        stream_response.headers["Accept-Ranges"] = "bytes"
        stream_response.headers["X-File-Id"] = str(f.id)
        stream_response.headers["X-File-Iv"] = file_iv_b64
        stream_response.headers["X-Metadata-Ciphertext"] = metadata_ct_b64
        stream_response.headers["X-Metadata-Iv"] = metadata_iv_b64
        if encrypted_kf_b64:
            stream_response.headers["X-Encrypted-Kf"] = encrypted_kf_b64
            stream_response.headers["X-Encrypted-Kf-Iv"] = base64.b64encode(f.encrypted_kf_iv or b"").decode()
        if wrapped_key_b64:
            stream_response.headers["X-Wrapped-Key"] = wrapped_key_b64
        stream_response.headers["X-Created-At"] = (
            f.created_at.isoformat() if f.created_at else ""
        )
        return stream_response

    # Small file or legacy DB-stored ciphertext — inline response
    return {
        "id": str(f.id),
        "ciphertext": base64.b64encode(blob_path.read_bytes() if blob_path else (f.ciphertext or b"")).decode(),
        "file_iv": file_iv_b64,
        "metadata_ciphertext": metadata_ct_b64,
        "metadata_iv": metadata_iv_b64,
        "encrypted_kf_b64": encrypted_kf_b64,
        "encrypted_kf_iv": encrypted_kf_iv,
        "wrapped_key_b64": wrapped_key_b64,
        "created_at": f.created_at,
    }


@router.delete("/{file_id}", response_model=dict[str, Any])
@audit_event("file_delete")
async def delete_file(
    request: Request,
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_mfa_verified),
) -> dict[str, Any]:
    """Soft-delete a file (owner only).

    The file is marked as deleted rather than physically removed,
    allowing restoration via the restore endpoint.

    Args:
        request: The incoming request (for audit logging).
        file_id: The file's UUID.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A success message.

    Raises:
        NotFoundError: If the file does not exist.
        HTTPException: 403 if the user is not the owner.
    """
    try:
        file_uuid = uuid.UUID(file_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid file_id format") from exc

    file = await db.get(File, file_uuid, with_for_update=True)
    if not file:
        raise NotFoundError("File not found")

    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can delete file")

    # Metadata-only soft delete: the blob stays on disk so restore keeps
    # working. Permanent removal happens via DELETE /files/{id}/purge or the
    # reaper after the retention window (H1).
    file.deleted = True
    file.deleted_at = datetime.now(UTC)
    await db.commit()

    return {"message": "File deleted successfully"}


@router.post("/{file_id}/restore", response_model=dict[str, Any])
@audit_event("file_restore")
async def restore_file(
    request: Request,
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Restore a soft-deleted file (owner only).

    Args:
        request: The incoming request (for audit logging).
        file_id: The file's UUID.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A success message.

    Raises:
        NotFoundError: If the file does not exist.
        HTTPException: 403 if the user is not the owner.
    """
    try:
        file_uuid = uuid.UUID(file_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid file_id format") from exc

    file = await db.get(File, file_uuid, with_for_update=True)
    if not file:
        raise NotFoundError("File not found")

    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can restore file")

    file.deleted = False
    file.deleted_at = None
    await db.commit()

    return {"message": "File restored successfully"}


@router.delete("/{file_id}/purge", response_model=dict[str, Any])
@audit_event("file_purge")
async def purge_file(
    request: Request,
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_mfa_verified),
) -> dict[str, Any]:
    """Permanently delete a soft-deleted file (owner only, MFA-verified).

    Removes the ciphertext blob and the database row. Only files already in
    the trash (``deleted = True``) can be purged, so every permanent deletion
    passes through the restorable soft-delete step first. Files left in the
    trash past ``TRASH_RETENTION_DAYS`` are purged by the background reaper.

    Args:
        request: The incoming request (for audit logging).
        file_id: The file's UUID.
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A success message.

    Raises:
        NotFoundError: If the file does not exist.
        ValidationError: If the file is not in the trash.
        AuthorizationError: If the user is not the owner.
    """
    try:
        file_uuid = uuid.UUID(file_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid file_id format") from exc

    file = await db.get(File, file_uuid, with_for_update=True)
    if not file:
        raise NotFoundError("File not found")

    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can purge file")

    if not file.deleted:
        raise ValidationError("File must be in the trash before it can be purged")

    file_id_str = str(file.id)
    has_blob = bool(file.storage_path)
    await db.delete(file)
    await db.commit()
    if has_blob:
        get_storage().delete_blob(file_id_str)

    logger.info("File purged", extra={"file_id": file_id_str, "user_id": str(current_user.id)})
    return {"message": "File permanently deleted"}
