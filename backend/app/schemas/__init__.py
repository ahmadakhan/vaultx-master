"""Re-export all Pydantic schemas for convenient access.

Importing from ``app.schemas`` gives access to every schema
without needing to know the internal module organization.
"""

from app.schemas.admin import (
    AdminAuditLogList,
    AdminAuditLogRead,
    AdminAuditVerifyResponse,
    UserCreate,
    UserRead,
)
from app.schemas.audit import AuditLogList, AuditVerifyResponse, TamperLogRead
from app.schemas.auth import (
    AuthResponse,
    LogoutRequest,
    MFADisableRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    PublicKeyResponse,
    RefreshRequest,
    RegisterPayload,
    TokenPayload,
    TokenResponse,
    UserKeysResponse,
    UserLogin,
)
from app.schemas.file import (
    FileBatchList,
    FileDownloadResponse,
    FileListItem,
    FileListPage,
    FileUploadResponse,
    SearchTokenEntry,
    parse_token_entries,
)
from app.schemas.search import SearchResponse, SearchToken
from app.schemas.share import (
    FileShareCreate,
    FileShareRead,
    FileShareRevoke,
    SharedLinkCreate,
    SharedLinkRead,
)
from app.schemas.transfer import (
    DropboxCreate,
    DropboxRead,
    DropboxUploadRead,
    UploadSessionCreate,
    UploadSessionFinalize,
    UploadSessionRead,
)
from app.schemas.user import IndexStateResponse, IndexStateUpdate

__all__ = [
    # Admin
    "AdminAuditLogList",
    "AdminAuditLogRead",
    "AdminAuditVerifyResponse",
    # Audit
    "AuditLogList",
    "AuditVerifyResponse",
    # Auth
    "AuthResponse",
    "DropboxCreate",
    "DropboxRead",
    "DropboxUploadRead",
    # File
    "FileBatchList",
    "FileDownloadResponse",
    "FileListItem",
    "FileListPage",
    # Share
    "FileShareCreate",
    "FileShareRead",
    "FileShareRevoke",
    "FileUploadResponse",
    # User
    "IndexStateResponse",
    "IndexStateUpdate",
    "LogoutRequest",
    "MFADisableRequest",
    "MFASetupResponse",
    "MFAVerifyRequest",
    "PublicKeyResponse",
    "RefreshRequest",
    "RegisterPayload",
    # Search
    "SearchResponse",
    "SearchToken",
    "SearchTokenEntry",
    "SharedLinkCreate",
    "SharedLinkRead",
    "TamperLogRead",
    "TokenPayload",
    "TokenResponse",
    "UploadSessionCreate",
    "UploadSessionFinalize",
    "UploadSessionRead",
    "UserCreate",
    "UserKeysResponse",
    "UserLogin",
    "UserRead",
    "parse_token_entries",
]
