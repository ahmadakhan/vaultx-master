"""SQLAlchemy model package.

All database models are organized by domain for maintainability:

- :mod:`app.models.base` — DeclarativeBase, engine factory, SharedMixin
- :mod:`app.models.user` — User, Role, UserRole, Backup
- :mod:`app.models.file` — File, FileShare
- :mod:`app.models.index` — IndexEntry
- :mod:`app.models.audit` — TamperLog

Models are automatically registered with the shared ``Base`` via
import. Use ``Base.metadata.create_all`` for table creation.
"""

from app.models.audit import AuditChainAnchor, TamperLog
from app.models.base import Base, create_engine, utcnow
from app.models.file import File, FileShare, SharedLink
from app.models.index import IndexEntry
from app.models.user import (
    Backup,
    RefreshToken,
    Role,
    User,
    UserRole,
    email_matches,
    normalize_email,
)

__all__ = [
    "AuditChainAnchor",
    "Backup",
    "Base",
    "File",
    "FileShare",
    "IndexEntry",
    "RefreshToken",
    "Role",
    "SharedLink",
    "TamperLog",
    "User",
    "UserRole",
    "create_engine",
    "email_matches",
    "normalize_email",
    "utcnow",
]
