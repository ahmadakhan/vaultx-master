"""Tamper-evident audit logging.

Implements a hash-chained, RSA-signed audit trail. Each log entry
includes a SHA-256 hash of the entry payload concatenated with the
previous entry's hash, and an RSA-PSS signature over the hash.

This ensures:
- **Integrity**: Any modification to an entry is detected by hash
  mismatch.
- **Non-repudiation**: The RSA signature proves the server signed
  the entry.
- **Chain integrity**: Entries form a forward hash chain; inserting
  or deleting an entry breaks the chain.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import DatabaseError
from app.core.logging import get_logger
from app.core.net import client_ip_from_scope
from app.core.server_keys import SERVER_PRIVATE_KEY
from app.models import AuditChainAnchor, TamperLog, User

logger = get_logger(__name__)

# Bounded retries when a concurrent append invalidates our chain head.
_MAX_CHAIN_ATTEMPTS = 3


def _sign(value: str) -> bytes:
    """RSA-PSS sign a UTF-8 string with the server's signing key."""
    return SERVER_PRIVATE_KEY.sign(
        value.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def _chain_hash(entry_json: dict[str, Any], prev_hash: str | None) -> str:
    """Compute the chained hash of an audit entry.

    The serialized entry (which includes ``seq``) is concatenated with the
    previous entry's hash, so each entry authenticates both its own content and
    its position in the chain.
    """
    payload = json.dumps(entry_json, sort_keys=True).encode()
    if prev_hash:
        payload += prev_hash.encode()
    return hashlib.sha256(payload).hexdigest()


def anchor_payload(user_id: uuid.UUID | str, entry_count: int, head_hash: str) -> str:
    """Build the signed payload describing a chain head."""
    return f"{user_id}:{entry_count}:{head_hash}"


async def _lock_user_chain(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Serialise chain extension for a single user.

    Without this, two concurrent requests from the same user read the same
    ``prev_hash`` and both append a child of it, forking the chain (which later
    reads as tampering). The row lock makes appends strictly sequential.
    """
    await db.execute(select(User.id).where(User.id == user_id).with_for_update())


async def _upsert_anchor(
    db: AsyncSession, user_id: uuid.UUID, entry_count: int, head_hash: str
) -> None:
    """Record the signed chain head so later truncation is detectable."""
    anchor = await db.get(AuditChainAnchor, user_id)
    signature = _sign(anchor_payload(user_id, entry_count, head_hash))
    if anchor is None:
        db.add(
            AuditChainAnchor(
                user_id=user_id,
                seq=entry_count,
                entry_count=entry_count,
                head_hash=head_hash,
                signature=signature,
            )
        )
        return
    anchor.seq = entry_count
    anchor.entry_count = entry_count
    anchor.head_hash = head_hash
    anchor.signature = signature
    anchor.updated_at = datetime.now(UTC)


async def record_audit_log(
    db: AsyncSession,
    request: Request,
    user_id: uuid.UUID | None,
    action: str,
    *,
    resource: dict[str, Any] | None = None,
) -> TamperLog:
    """Record a single audit log entry.

    Appends exactly one entry to the requesting user's hash chain. The user row
    is locked for the duration so concurrent requests cannot fork the chain,
    and the signed chain head is refreshed in the same transaction so later
    truncation is detectable.

    Args:
        db: Active database session.
        request: The incoming FastAPI request (for IP, path, method).
        user_id: UUID of the user performing the action, or ``None``
            for system-level events (which are not anchored).
        action: A short label describing the action (e.g.,
            ``"file_upload"``, ``"login"``).
        resource: Optional identifiers of the affected object (e.g.
            ``{"file_id": ...}``) recorded inside the signed payload.

    Returns:
        The persisted ``TamperLog`` model instance.

    Raises:
        DatabaseError: If the chain head could not be advanced after repeated
            conflicts with concurrent writers.
    """
    client_ip = client_ip_from_scope(request.scope, settings.trusted_proxy_networks) or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")[:512]

    for attempt in range(1, _MAX_CHAIN_ATTEMPTS + 1):
        if user_id is not None:
            await _lock_user_chain(db, user_id)

        # ``id`` is a monotonic primary key, so it orders entries even when
        # legacy rows predate the ``seq`` column (and regardless of clock
        # skew, which ``created_at`` was vulnerable to).
        head = (
            await db.execute(
                select(TamperLog.seq, TamperLog.entry_hash)
                .where(TamperLog.user_id == user_id)
                .order_by(TamperLog.id.desc())
                .limit(1)
            )
        ).first()
        prev_seq = int(head[0]) if head and head[0] is not None else 0
        prev_hash = str(head[1]) if head and head[1] else None
        seq = prev_seq + 1

        entry_json: dict[str, Any] = {
            "action": action,
            "seq": seq,
            "timestamp": datetime.now(UTC).isoformat(),
            "ip": client_ip,
            "user_agent": user_agent,
            "path": getattr(request.scope.get("route"), "path", "<unmatched>"),
            "method": request.method,
        }
        if user_id is not None:
            entry_json["user_id"] = str(user_id)
        if resource:
            entry_json["resource"] = resource

        entry_hash = _chain_hash(entry_json, prev_hash)

        entry = TamperLog(
            user_id=user_id,
            seq=seq,
            entry_json=entry_json,
            entry_hash=entry_hash,
            prev_hash=prev_hash,
            signature=_sign(entry_hash),
        )
        db.add(entry)

        if user_id is not None:
            await _upsert_anchor(db, user_id, seq, entry_hash)

        try:
            await db.commit()
        except IntegrityError:
            # Another writer advanced the chain between our read and commit;
            # roll back and retry against the new head instead of forking.
            await db.rollback()
            logger.warning(
                "Audit chain append conflicted; retrying",
                extra={"user_id": str(user_id) if user_id else None, "attempt": attempt},
            )
            continue

        await db.refresh(entry)

        logger.info(
            "Audit log recorded",
            extra={"user_id": str(user_id) if user_id else None, "action": action, "seq": seq},
        )

        return entry

    raise DatabaseError("Could not append audit log entry after repeated chain conflicts")
