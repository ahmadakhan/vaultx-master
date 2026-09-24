"""Tamper-evident audit log model.

Defines the ``TamperLog`` model which implements a hash-chained,
cryptographically signed audit trail. Each entry's hash incorporates
the previous entry's hash, and each entry is signed with the server's
RSA private key, enabling detection of any modification or deletion.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    UUID,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class TamperLog(Base):
    """Cryptographically signed audit log entry.

    Each entry forms a hash chain via ``prev_hash`` (the hash of the
    preceding entry for the same user). ``seq`` is the entry's position
    within that user's chain and is what verification orders by, so a
    clock change can never reorder or invalidate a chain. The ``signature``
    is an RSA-PSS signature over the entry hash, enabling offline
    verification of log integrity.
    """

    __tablename__ = "tamper_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    entry_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    entry_hash: Mapped[str] = mapped_column(String, nullable=False, index=True)
    prev_hash: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_tamper_user_created", "user_id", "created_at"),
        Index("idx_tamper_user_seq", "user_id", "seq"),
        # Chain links are unique per user: two entries can never claim the same
        # parent, so a concurrent append fails loudly instead of silently
        # forking the chain.
        UniqueConstraint("user_id", "prev_hash", name="uq_tamper_user_prev_hash"),
    )


class AuditChainAnchor(Base):
    """Signed snapshot of a user's audit chain head.

    Without an anchor, deleting the newest entries of a chain is undetectable:
    the surviving prefix still verifies correctly. The anchor records the
    expected entry count and head hash, letting :func:`verify_audit_chain`
    detect truncation.

    Limitation: an attacker with write access to the database could roll the
    anchor back to an older consistent state together with the chain. Detecting
    that requires exporting anchors to storage the application cannot rewrite
    (WORM bucket, append-only log, or signature published out-of-band).
    """

    __tablename__ = "audit_chain_anchors"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    head_hash: Mapped[str] = mapped_column(String, nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
