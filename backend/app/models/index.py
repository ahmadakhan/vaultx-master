"""Search index entry model.

Defines the ``IndexEntry`` model that supports encrypted, searchable
keyword indexing. Each entry stores a hashed keyword token linked
to encrypted file metadata via a forward-chained hash structure
enabling traversal without revealing plaintext keywords.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import UUID, DateTime, ForeignKey, Index, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class IndexEntry(Base):
    """Encrypted search index entry for a single keyword.

    The ``token`` is a SHA-256 digest of the keyword. The ``value``
    field stores the encrypted file identifier (encrypted under the
    user's search key). The ``prev_token`` creates a linked-list
    structure per keyword, enabling incremental search result
    traversal.
    """

    __tablename__ = "index_entries"

    token: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    prev_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (Index("idx_index_entries_owner_created", "owner_id", "created_at"),)
