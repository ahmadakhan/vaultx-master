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
from app.models.file import File, FileShare, SharedLink, SharedLinkAttempt
from app.models.index import IndexEntry
from app.models.tenant import AdminStorageAllocation, Tenant, TenantQuota
from app.models.transfer import GuestDropbox, GuestDropboxUpload, UploadSession
from app.models.user import (
    Backup,
    RefreshToken,
    Role,
    User,
    UserRole,
    WebAuthnChallenge,
    WebAuthnCredential,
    email_matches,
    normalize_email,
)

__all__ = [
    "AdminStorageAllocation",
    "AuditChainAnchor",
    "Backup",
    "Base",
    "File",
    "FileShare",
    "GuestDropbox",
    "GuestDropboxUpload",
    "IndexEntry",
    "RefreshToken",
    "Role",
    "SharedLink",
    "SharedLinkAttempt",
    "TamperLog",
    "Tenant",
    "TenantQuota",
    "UploadSession",
    "User",
    "UserRole",
    "WebAuthnChallenge",
    "WebAuthnCredential",
    "create_engine",
    "email_matches",
    "normalize_email",
    "utcnow",
]
