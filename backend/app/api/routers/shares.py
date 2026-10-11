"""File sharing endpoints.

Implements secure file sharing using RSA-OAEP key wrapping. When a
user shares a file, the file key (Kf) is encrypted with the
recipient's RSA public key. Only the recipient can decrypt the
wrapped key using their private RSA key.

Additionally supports publicly shareable links (guest access) that
do not require a recipient account. Links can be protected with an
optional access code and have expiration/download limits.

All operations enforce ownership verification: only the file owner
can share or revoke access to their files.
"""

from __future__ import annotations

import base64
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.audit_decorator import audit_event
from app.core.deps import get_current_user
from app.core.exceptions import AuthorizationError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db import get_db
from app.models import File, FileShare, SharedLink, User
from app.models.file import SharedLinkAttempt
from app.schemas import (
    FileShareCreate,
    FileShareRead,
    FileShareRevoke,
    SharedLinkCreate,
    SharedLinkRead,
)
from app.schemas.share import SharedLinkRevoke
from app.storage import get_storage
from app.storage.share_security import hash_access_code, verify_access_code

logger = get_logger(__name__)

router = APIRouter(prefix="/shares", tags=["shares"])


async def _check_access_code(db: AsyncSession, link: SharedLink, code: str | None) -> None:
    """Caller holds the link row lock, serializing guards across workers."""
    if not link.access_code_hash:
        return
    if not code:
        raise AuthorizationError("Access code required")
    guard = await db.get(SharedLinkAttempt, link.id)
    now = datetime.now(UTC)
    if guard and guard.locked_until:
        locked_until = guard.locked_until.replace(tzinfo=UTC) if guard.locked_until.tzinfo is None else guard.locked_until
        if locked_until > now:
            raise HTTPException(429, "Too many access-code attempts", headers={"Retry-After": "900"})
        guard.failed_attempts = 0
        guard.locked_until = None
    valid = await run_in_threadpool(verify_access_code, code, link.access_code_hash)
    if not valid:
        if guard is None:
            guard = SharedLinkAttempt(link_id=link.id, failed_attempts=0)
            db.add(guard)
        guard.failed_attempts += 1
        guard.updated_at = now
        if guard.failed_attempts >= 5:
            guard.locked_until = now + timedelta(minutes=15)
        await db.commit()  # Persist failures even though the request is rejected.
        raise AuthorizationError("Invalid access code")
    if guard:
        guard.failed_attempts = 0
        guard.locked_until = None
    if not link.access_code_hash.startswith("pbkdf2_sha256$"):
        link.access_code_hash = await run_in_threadpool(hash_access_code, code)


def _decode_b64(value: str) -> bytes:
    """Decode a base64 string, raising ``HTTPException`` on failure."""
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail="Invalid wrapped_key (not valid base64)"
        ) from exc


def _build_share_read(share: FileShare) -> FileShareRead:
    """Convert a FileShare model to a FileShareRead schema."""
    return FileShareRead(
        id=share.id,
        file_id=share.file_id,
        recipient_user_id=share.recipient_user_id,
        permissions=share.permissions,
        created_at=share.created_at,
    )


def _link_read(link: SharedLink) -> SharedLinkRead:
    return SharedLinkRead(
        id=link.id, file_id=link.file_id, token=link.token,
        has_access_code=bool(link.access_code_hash), expires_at=link.expires_at,
        max_downloads=link.max_downloads, download_count=link.download_count,
        created_at=link.created_at, link_url=f"/shared/{link.token}",
    )


@router.post("", response_model=FileShareRead)
@audit_event("file_shared")
async def share_file(
    request: Request,
    payload: FileShareCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FileShareRead:
    """Share a file with another user.

    The file key (Kf) must be encrypted (wrapped) under the recipient's
    RSA-OAEP public key client-side before being sent.

    Args:
        request: The incoming request (for audit logging).
        payload: Share creation request containing file ID, recipient
            email, wrapped key, and permissions.
        db: Database session.
        current_user: Authenticated user (must be the file owner).

    Returns:
        The created or updated share record.

    Raises:
        NotFoundError: If the file or recipient user does not exist.
        HTTPException: 403 if the current user is not the file owner.
    """
    result = await db.execute(select(File).where(File.id == payload.file_id))
    file = result.scalar_one_or_none()
    if not file:
        raise NotFoundError("File not found")
    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can share the file")
    if file.deleted:
        raise ValidationError("Restore the file before sharing")

    res = await db.execute(select(User).where(User.email == payload.recipient_email))
    recipient = res.scalar_one_or_none()
    if not recipient:
        raise NotFoundError("Recipient not found")

    wrapped_key = _decode_b64(payload.wrapped_key_b64)

    q = await db.execute(
        select(FileShare).where(
            FileShare.file_id == payload.file_id,
            FileShare.recipient_user_id == recipient.id,
        )
    )
    existing = q.scalar_one_or_none()

    if existing:
        existing.wrapped_key = wrapped_key
        existing.permissions = payload.permissions
        await db.commit()
        await db.refresh(existing)
        logger.info(
            "Share updated",
            extra={"file_id": str(payload.file_id), "recipient": payload.recipient_email},
        )
        return _build_share_read(existing)

    share = FileShare(
        file_id=payload.file_id,
        owner_user_id=current_user.id,
        recipient_user_id=recipient.id,
        wrapped_key=wrapped_key,
        permissions=payload.permissions,
    )
    db.add(share)
    await db.commit()
    await db.refresh(share)

    logger.info(
        "File shared",
        extra={
            "file_id": str(payload.file_id),
            "owner_id": str(current_user.id),
            "recipient_id": str(recipient.id),
        },
    )

    return _build_share_read(share)


@router.post("/revoke", response_model=dict[str, Any])
@audit_event("file_share_revoked")
async def revoke_share(
    request: Request,
    payload: FileShareRevoke,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Revoke a file share from a recipient.

    Args:
        payload: Request containing the file ID and recipient email.
        db: Database session.
        current_user: Authenticated user (must be the file owner).

    Returns:
        A dict confirming the revocation.

    Raises:
        NotFoundError: If the file, recipient, or share does not exist.
        HTTPException: 403 if the current user is not the file owner.
    """
    result = await db.execute(select(File).where(File.id == payload.file_id))
    file = result.scalar_one_or_none()
    if not file:
        raise NotFoundError("File not found")
    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can revoke sharing")

    r = await db.execute(select(User).where(User.email == payload.recipient_email))
    recipient = r.scalar_one_or_none()
    if not recipient:
        raise NotFoundError("Recipient not found")

    q = await db.execute(
        select(FileShare).where(
            FileShare.file_id == payload.file_id,
            FileShare.recipient_user_id == recipient.id,
        )
    )
    share = q.scalar_one_or_none()
    if not share:
        raise NotFoundError("Share not found")

    await db.execute(delete(FileShare).where(FileShare.id == share.id))
    await db.commit()

    logger.info(
        "Share revoked",
        extra={"file_id": str(payload.file_id), "recipient": payload.recipient_email},
    )

    return {
        "revoked": True,
        "file_id": str(payload.file_id),
        "recipient_email": payload.recipient_email,
    }


@router.get("/file/{file_id}", response_model=list[FileShareRead])
async def list_shares_for_file(
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[FileShareRead]:
    """List all shares for a specific file (owner only).

    Args:
        file_id: The file's UUID.
        db: Database session.
        current_user: Authenticated user (must be the file owner).

    Returns:
        A list of share records.

    Raises:
        NotFoundError: If the file does not exist.
        HTTPException: 403 if the current user is not the owner.
    """
    try:
        file_uuid = uuid.UUID(file_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid file_id format") from exc

    result = await db.execute(select(File).where(File.id == file_uuid))
    file = result.scalar_one_or_none()
    if not file:
        raise NotFoundError("File not found")

    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can view shares")

    q = await db.execute(select(FileShare).where(FileShare.file_id == file_uuid))
    rows = q.scalars().all()
    return [_build_share_read(s) for s in rows]


@router.get("/me", response_model=list[FileShareRead])
async def list_shares_for_recipient(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[FileShareRead]:
    """List all files shared with the current user (as recipient).

    Args:
        db: Database session.
        current_user: Authenticated user.

    Returns:
        A list of share records where the current user is the recipient.
    """
    q = await db.execute(select(FileShare).where(FileShare.recipient_user_id == current_user.id))
    rows = q.scalars().all()
    return [_build_share_read(s) for s in rows]


@router.post("/link", response_model=SharedLinkRead)
@audit_event("link_created")
async def create_shared_link(
    request: Request,
    payload: SharedLinkCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SharedLinkRead:
    """Create a publicly shareable link for a file.

    Only the file owner can create a shareable link. The link uses a
    cryptographically random token that acts as a bearer credential.
    An optional access code can be required so the link alone is
    insufficient to download the file.

    Args:
        request: The incoming request (for audit logging).
        payload: Link creation parameters (file_id, optional access code,
            optional expiration, optional download limit).
        db: Database session.
        current_user: Authenticated user (must be the file owner).

    Returns:
        The created SharedLink with a ``link_url`` field containing the
        full URL path.

    Raises:
        NotFoundError: If the file does not exist.
        AuthorizationError: If the user is not the file owner.
    """
    result = await db.execute(select(File).where(File.id == payload.file_id))
    file = result.scalar_one_or_none()
    if not file:
        raise NotFoundError("File not found")
    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can create a shareable link")
    if file.deleted:
        raise ValidationError("Restore the file before sharing")

    token = secrets.token_urlsafe(32)
    access_code_hash = None
    if payload.access_code:
        access_code_hash = await run_in_threadpool(hash_access_code, payload.access_code)

    link = SharedLink(
        file_id=payload.file_id,
        token=token,
        access_code_hash=access_code_hash,
        encrypted_kf=_decode_b64(payload.encrypted_kf_b64),
        encrypted_kf_iv=_decode_b64(payload.encrypted_kf_iv_b64),
        kf_salt=_decode_b64(payload.kf_salt_b64),
        expires_at=payload.expires_at,
        max_downloads=payload.max_downloads,
    )
    db.add(link)
    await db.commit()
    await db.refresh(link)

    link_url = f"/shared/{token}"

    logger.info(
        "Shared link created",
        extra={"file_id": str(payload.file_id), "user_id": str(current_user.id)},
    )

    read = _link_read(link)
    read.link_url = link_url
    return read


@router.get("/links/{file_id}", response_model=list[SharedLinkRead])
@audit_event("links_listed")
async def list_shared_links(
    file_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SharedLinkRead]:
    """List all active shareable links for a file (owner only).

    Args:
        file_id: The file's UUID.
        db: Database session.
        current_user: Authenticated user (must be the file owner).

    Returns:
        A list of SharedLinkRead without the ``link_url`` field filled in.
    """
    try:
        file_uuid = uuid.UUID(file_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid file_id format") from exc

    result = await db.execute(select(File).where(File.id == file_uuid))
    file = result.scalar_one_or_none()
    if not file:
        raise NotFoundError("File not found")
    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can view shareable links")

    q = await db.execute(select(SharedLink).where(SharedLink.file_id == file_uuid))
    rows = q.scalars().all()
    return [_link_read(row) for row in rows]


@router.delete("/link/{link_id}", response_model=dict[str, Any])
@audit_event("link_revoked")
async def revoke_shared_link(
    request: Request,
    link_id: str,
    payload: SharedLinkRevoke,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Revoke a shareable link (owner only).

    Args:
        request: The incoming request (for audit logging).
        link_id: The link's UUID.
        payload: Contains the file_id for ownership verification.
        db: Database session.
        current_user: Authenticated user (must be the file owner).

    Returns:
        A confirmation message.
    """
    try:
        link_uuid = uuid.UUID(link_id)
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Invalid link_id format") from exc

    result = await db.execute(select(SharedLink).where(SharedLink.id == link_uuid))
    link = result.scalar_one_or_none()
    if not link:
        raise NotFoundError("Link not found")

    file_result = await db.execute(select(File).where(File.id == link.file_id))
    file = file_result.scalar_one_or_none()
    if not file:
        raise NotFoundError("File not found")
    if file.owner_id != current_user.id:
        raise AuthorizationError("Only owner can revoke this link")

    await db.execute(delete(SharedLink).where(SharedLink.id == link_uuid))
    await db.commit()

    logger.info(
        "Shared link revoked",
        extra={"link_id": link_id, "file_id": str(link.file_id)},
    )

    return {"revoked": True, "link_id": link_id}


@router.get("/link/{token}", response_model=dict[str, Any])
async def get_shared_link_file(
    token: str,
    response: Response,
    access_code: str | None = Header(default=None, alias="X-Access-Code", max_length=128),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve file metadata via a public shareable link.

    No authentication is required. If the link has an access code, it must
    be provided in the X-Access-Code header. Metadata does not consume a download.

    **Security note**: This endpoint does NOT return the file ciphertext.
    It returns only metadata (IVs, encrypted key material) so that the
    client can fetch the ciphertext from the streaming download endpoint.

    Args:
        token: The shareable link token.
        access_code: The access code if one was set.
        db: Database session.

    Returns:
        A dict with file metadata, IVs, and key-wrapping material.

    Raises:
        NotFoundError: If the link or file does not exist.
        AuthorizationError: If the access code is missing or incorrect,
            or the link has expired / exceeded its download limit.
    """
    response.headers["Cache-Control"] = "no-store"
    result = await db.execute(select(SharedLink).where(SharedLink.token == token).with_for_update())
    link = result.scalar_one_or_none()
    if not link:
        raise NotFoundError("Link not found")

    # Check expiration
    if link.expires_at:
        if link.expires_at.tzinfo is None:
            expires = link.expires_at.replace(tzinfo=UTC)
        else:
            expires = link.expires_at
        if expires <= datetime.now(UTC):
            raise NotFoundError("Link has expired")

    # Check access code
    await _check_access_code(db, link, access_code)

    # Check download limit
    if link.max_downloads is not None and link.download_count >= link.max_downloads:
        raise NotFoundError("Link has reached maximum downloads")

    # Fetch the file
    file_result = await db.execute(select(File).where(File.id == link.file_id))
    f = file_result.scalar_one_or_none()
    if not f or f.deleted:
        raise NotFoundError("File not found")

    await db.commit()
    # Return file metadata (no ciphertext — client fetches via streaming download)
    return {
        "id": str(f.id),
        "file_iv": base64.b64encode(f.file_iv or b"").decode(),
        "metadata_ciphertext": base64.b64encode(f.metadata_ciphertext or b"").decode(),
        "metadata_iv": base64.b64encode(f.metadata_iv or b"").decode(),
        "encrypted_kf_b64": base64.b64encode(link.encrypted_kf).decode() if link.encrypted_kf else None,
        "encrypted_kf_iv": base64.b64encode(link.encrypted_kf_iv).decode() if link.encrypted_kf_iv else None,
        "kf_salt": base64.b64encode(link.kf_salt).decode() if link.kf_salt else None,
        "has_access_code": link.access_code_hash is not None,
        "file_size": f.file_size,
    }


@router.get("/link/{token}/download")
async def download_shared_link_file(
    token: str,
    access_code: str | None = Header(default=None, alias="X-Access-Code", max_length=128),
    range: str | None = Query(default=None, description="HTTP Range value: bytes=start-end"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Stream a file's ciphertext to a guest via a public shareable link.

    No authentication is required. Supports Range requests for chunked
    downloads and resume support. Increments the download counter on
    each successful request.

    Args:
        token: The shareable link token.
        access_code: The access code if one was set.
        range: Optional HTTP Range value for partial content.
        db: Database session.

    Returns:
        A StreamingResponse with the ciphertext, with metadata in headers.

    Raises:
        NotFoundError: If the link or file does not exist, or is expired/depleted.
        AuthorizationError: If the access code is missing or incorrect.
    """
    from fastapi.responses import StreamingResponse

    result = await db.execute(select(SharedLink).where(SharedLink.token == token).with_for_update())
    link = result.scalar_one_or_none()
    if not link:
        raise NotFoundError("Link not found")

    # Check expiration
    if link.expires_at:
        if link.expires_at.tzinfo is None:
            expires = link.expires_at.replace(tzinfo=UTC)
        else:
            expires = link.expires_at
        if expires <= datetime.now(UTC):
            raise NotFoundError("Link has expired")

    # Check access code
    await _check_access_code(db, link, access_code)

    # Check download limit
    if link.max_downloads is not None and link.download_count >= link.max_downloads:
        raise NotFoundError("Link has reached maximum downloads")

    # Fetch the file
    file_result = await db.execute(select(File).where(File.id == link.file_id))
    f = file_result.scalar_one_or_none()
    if not f or f.deleted:
        raise NotFoundError("File not found")

    blob_path = get_storage().validated_path(str(f.id), f.storage_path) if f.storage_path else None
    total_size = blob_path.stat().st_size if blob_path else len(f.ciphertext or b"")
    start, end = 0, total_size - 1
    if range:
        try:
            unit, spec = range.split("=", 1)
            first, last = spec.split("-", 1)
            if unit != "bytes" or not first.isdigit() or (last and not last.isdigit()):
                raise ValueError
            start = int(first)
            end = min(int(last), total_size - 1) if last else total_size - 1
            if start > end:
                raise ValueError
        except ValueError as exc:
            raise HTTPException(416, "Range not satisfiable", headers={"Content-Range": f"bytes */{total_size}"}) from exc
    # Conditional update is an additional guard against lost updates.
    result = await db.execute(update(SharedLink).where(
        SharedLink.id == link.id,
        or_(SharedLink.max_downloads.is_(None), SharedLink.download_count < SharedLink.max_downloads),
    ).values(download_count=SharedLink.download_count + 1).returning(SharedLink.id))
    if result.scalar_one_or_none() is None:
        raise NotFoundError("Link has reached maximum downloads")
    await db.commit()

    # Stream from filesystem if available
    def _stream_generator() -> Any:
        if blob_path:
            with open(blob_path, "rb") as bf:
                bf.seek(start)
                remaining = end - start + 1
                while remaining > 0:
                    chunk = bf.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    yield chunk
                    remaining -= len(chunk)
        else:
            data = f.ciphertext or b""
            yield data[start:end + 1]

    file_iv_b64 = base64.b64encode(f.file_iv or b"").decode()
    metadata_ct_b64 = base64.b64encode(f.metadata_ciphertext or b"").decode()
    metadata_iv_b64 = base64.b64encode(f.metadata_iv or b"").decode()

    response = StreamingResponse(_stream_generator(), media_type="application/octet-stream")
    response.headers["Content-Length"] = str(end - start + 1)
    response.headers["Cache-Control"] = "no-store"
    if range:
        response.status_code = 206
        response.headers["Content-Range"] = f"bytes {start}-{end}/{total_size}"
    response.headers["Accept-Ranges"] = "bytes"
    response.headers["X-File-Id"] = str(f.id)
    response.headers["X-File-Iv"] = file_iv_b64
    response.headers["X-Metadata-Ciphertext"] = metadata_ct_b64
    response.headers["X-Metadata-Iv"] = metadata_iv_b64
    if link.encrypted_kf:
        response.headers["X-Encrypted-Kf"] = base64.b64encode(link.encrypted_kf).decode()
    if link.encrypted_kf_iv:
        response.headers["X-Encrypted-Kf-Iv"] = base64.b64encode(link.encrypted_kf_iv).decode()
    if link.kf_salt:
        response.headers["X-Kf-Salt"] = base64.b64encode(link.kf_salt).decode()
    return response
