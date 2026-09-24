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

    Iterates over the user's entries in insertion order, checking hash
    consistency, signature validity, chain linkage and sequence continuity, then
    compares the surviving head against the signed anchor to detect truncation
    of the most recent entries.

    Args:
        db: Active database session.
        user_id: The user whose audit trail to verify.

    Returns:
        A tuple of ``(is_valid, errors)`` where ``is_valid`` is ``True`` if no
        issues were found, and ``errors`` is a list of human-readable defects.
    """
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
