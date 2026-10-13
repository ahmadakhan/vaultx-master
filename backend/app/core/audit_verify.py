"""Audit chain verification for tamper detection.

Verifies the integrity of a user's audit log by:
1. Recomputing each entry's SHA-256 hash and comparing it to the
   stored ``entry_hash``.
2. Verifying the RSA-PSS signature against the stored hash.
3. Checking that the hash chain (via ``prev_hash``) is unbroken.

Any discrepancy indicates tampering, deletion, or insertion of
entries in the audit trail.
"""

from __future__ import annotations

import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_log import _chain_hash, anchor_payload
from app.core.logging import get_logger
from app.core.server_keys import SERVER_PUBLIC_KEY
from app.models import AuditChainAnchor, TamperLog

logger = get_logger(__name__)


def _verify_signature(entry_hash: str, signature: bytes | None) -> bool:
    """Return whether ``signature`` is a valid server signature over ``entry_hash``."""
    if not isinstance(SERVER_PUBLIC_KEY, rsa.RSAPublicKey):
        return False
    try:
        SERVER_PUBLIC_KEY.verify(
            signature or b"",
            entry_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception:
        return False
    return True


def _anchor_is_valid(anchor: AuditChainAnchor, user_id: uuid.UUID | str) -> bool:
    """Return whether the stored anchor signature is authentic."""
    if not isinstance(SERVER_PUBLIC_KEY, rsa.RSAPublicKey):
        return False
    try:
        SERVER_PUBLIC_KEY.verify(
            anchor.signature,
            anchor_payload(user_id, anchor.entry_count, anchor.head_hash).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception:
        return False
    return True


async def verify_audit_chain(
    db: AsyncSession,
    user_id: uuid.UUID | str,
) -> tuple[bool, list[str]]:
    """Verify the integrity of a user's audit log chain.

    Performs comprehensive verification of the audit trail by:
    1. Recomputing each entry's SHA-256 hash and comparing with stored ``entry_hash``
    2. Validating RSA-PSS signatures against stored hashes
    3. Checking hash chain continuity via ``prev_hash`` links
    4. Ensuring sequence numbers are sequential and non-repeating
    5. Comparing final chain against signed audit anchor to detect truncation

    This verification detects any tampering, deletion, or insertion of audit
    log entries, providing detailed error messages for each failure.

    Args:
        db: Active database session.
        user_id: The user whose audit trail to verify (UUID or string).

    Returns:
        A tuple of ``(is_valid, errors)`` where ``is_valid`` is ``True`` if no
        issues were found, and ``errors`` is a list of human-readable defects.

    Example:
        >>> ok, errors = await verify_audit_chain(db, "550e8400-e29b-41d4-a716-446655440000")
        >>> if ok:
        ...     print("Audit chain is valid")
        ... else:
        ...     for error in errors:
        ...         print(f"Validation error: {error}")

    Note:
        - Verification includes cryptographic signature validation
        - Sequence numbers must be sequential and non-repeating
        - Chain anchor verification prevents truncation attacks
        - Returns early on first error for performance
    """
    result = await db.execute(
        select(TamperLog).where(TamperLog.user_id == user_id).order_by(TamperLog.id.asc())
    )
    entries = result.scalars().all()

    anchor: AuditChainAnchor | None = None
    if user_id is not None:
        anchor = await db.get(AuditChainAnchor, user_id)

    # Empty chain check with anchor validation
    if not entries:
        if anchor is not None and anchor.entry_count > 0:
            return False, [
                f"Audit chain is empty but the signed anchor expects "
                f"{anchor.entry_count} entries (entries were removed or corrupted)"
            ]
        return True, []

    # Initialize verification state
    errors: list[str] = []
    prev_hash: str | None = None
    last_seq: int | None = None

    # Verify each entry in sequence
    for entry in entries:
        entry_data: dict[str, Any] = entry.entry_json or {}
        entry_hash_val = str(entry.entry_hash)
        prev_hash_val = str(entry.prev_hash) if entry.prev_hash else None

        # Hash verification
        computed_hash = _chain_hash(entry_data, prev_hash)
        if computed_hash != entry_hash_val:
            errors.append(
                f"Hash mismatch at entry {entry.id}: expected {computed_hash}, got {entry_hash_val}"
            )

        # Signature verification
        if not _verify_signature(entry_hash_val, entry.signature):
            errors.append(f"Signature verification failed at entry {entry.id}")

        # Chain linkage verification
        if prev_hash_val != prev_hash:
            errors.append(
                f"Broken chain at entry {entry.id}: prev_hash mismatch "
                f"(expected {prev_hash}, got {prev_hash_val})"
            )

        # Sequence number verification
        seq = entry_data.get("seq")
        if isinstance(seq, int):
            if last_seq is not None and seq != last_seq + 1:
                errors.append(
                    f"Sequence gap at entry {entry.id}: previous seq {last_seq}, "
                    f"got {seq} (expected {last_seq + 1})"
                )
            last_seq = seq

        prev_hash = entry_hash_val

    # Tail-truncation detection using anchor
    if not errors:  # Only check anchor if all entries are valid
        head = entries[-1]
        if anchor is None:
            errors.append(
                "No signed chain anchor found for this user, so removal of the most "
                "recent entries cannot be definitively detected"
            )
        else:
            if not _anchor_is_valid(anchor, user_id):
                errors.append("Anchor signature verification failed - chain may be compromised")

            if len(entries) < anchor.entry_count:
                errors.append(
                    f"Truncated audit chain: {len(entries)} entries remain but the "
                    f"signed anchor expects {anchor.entry_count} (missing {anchor.entry_count - len(entries)} entries)"
                )
            elif len(entries) > anchor.entry_count:
                errors.append(
                    f"Audit chain has {len(entries)} entries but the signed anchor "
                    f"expects {anchor.entry_count} (extra {len(entries) - anchor.entry_count} entries)"
                )

            if str(anchor.head_hash) != str(head.entry_hash):
                errors.append(
                    "Chain head does not match the signed anchor (recent entries were "
                    "removed or replaced, compromising integrity)"
                )

    # Log verification results
    logger.info(
        "Audit chain verification completed",
        extra={
            "user_id": str(user_id),
            "valid": len(errors) == 0,
            "total_entries": len(entries),
            "error_count": len(errors),
            "has_anchor": anchor is not None,
        },
    )

    return len(errors) == 0, errors
    result = await db.execute(
        select(TamperLog).where(TamperLog.user_id == user_id).order_by(TamperLog.id.asc())
    )
    entries = result.scalars().all()

    anchor: AuditChainAnchor | None = None
    if user_id is not None:
        anchor = await db.get(AuditChainAnchor, user_id)

    if not entries:
        if anchor is not None and anchor.entry_count > 0:
            return False, [
                f"Audit chain is empty but the signed anchor expects "
                f"{anchor.entry_count} entries (entries were removed)"
            ]
        return True, []

    errors: list[str] = []
    prev_hash: str | None = None
    last_seq: int | None = None

    for entry in entries:
        entry_data: dict[str, Any] = entry.entry_json or {}
        entry_hash_val = str(entry.entry_hash)
        prev_hash_val = str(entry.prev_hash) if entry.prev_hash else None

        computed_hash = _chain_hash(entry_data, prev_hash)
        if computed_hash != entry_hash_val:
            errors.append(
                f"Hash mismatch at entry {entry.id}: expected {computed_hash}, got {entry_hash_val}"
            )

        if not _verify_signature(entry_hash_val, entry.signature):
            errors.append(f"Signature verification failed at entry {entry.id}")

        if prev_hash_val != prev_hash:
            errors.append(
                f"Broken chain at entry {entry.id}: prev_hash mismatch "
                f"(expected {prev_hash}, got {prev_hash_val})"
            )

        seq = entry_data.get("seq")
        if isinstance(seq, int):
            if last_seq is not None and seq != last_seq + 1:
                errors.append(
                    f"Sequence gap at entry {entry.id}: previous seq {last_seq}, got {seq}"
                )
            last_seq = seq

        prev_hash = entry_hash_val

    # Tail-truncation and rollback detection: without an anchor, deleting the
    # newest entries leaves a prefix that verifies perfectly.
    head = entries[-1]
    if anchor is None:
        errors.append(
            "No signed chain anchor found for this user, so removal of the most "
            "recent entries cannot be ruled out"
        )
    else:
        if not _anchor_is_valid(anchor, user_id):
            errors.append("Anchor signature verification failed")
        if len(entries) < anchor.entry_count:
            errors.append(
                f"Truncated audit chain: {len(entries)} entries remain but the "
                f"signed anchor expects {anchor.entry_count}"
            )
        elif len(entries) > anchor.entry_count:
            errors.append(
                f"Audit chain has {len(entries)} entries but the signed anchor "
                f"expects {anchor.entry_count}"
            )
        if str(anchor.head_hash) != str(head.entry_hash):
            errors.append(
                "Chain head does not match the signed anchor (recent entries were "
                "removed or replaced)"
            )

    logger.info(
        "Audit chain verified",
        extra={
            "user_id": str(user_id),
            "valid": len(errors) == 0,
            "entries": len(entries),
            "anchored": anchor is not None,
        },
    )

    return len(errors) == 0, errors
