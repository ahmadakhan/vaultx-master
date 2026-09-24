"""API router package for VaultX backend.

All endpoint routers are registered here and aggregated into a single
``router`` instance that is mounted by the FastAPI application factory.

Organized by domain:
- :mod:`app.api.routers.auth` — authentication and key provisioning
- :mod:`app.api.routers.files` — file upload, list, download, delete
- :mod:`app.api.routers.shares` — file sharing via RSA-OAEP key wrapping
- :mod:`app.api.routers.search` — encrypted keyword search
- :mod:`app.api.routers.user` — user profile and index state
- :mod:`app.api.routers.audit` — audit log retrieval and verification
"""

from fastapi import APIRouter

from app.api.routers.admin import router as admin_router
from app.api.routers.audit import router as audit_router
from app.api.routers.auth import router as auth_router
from app.api.routers.files import router as files_router
from app.api.routers.search import router as search_router
from app.api.routers.shares import router as shares_router
from app.api.routers.user import router as user_router

router = APIRouter()

router.include_router(auth_router)
router.include_router(files_router)
router.include_router(shares_router)
router.include_router(search_router)
router.include_router(user_router)
router.include_router(audit_router)
router.include_router(admin_router)

__all__ = [
    "admin_router",
    "audit_router",
    "auth_router",
    "files_router",
    "router",
    "search_router",
    "shares_router",
    "user_router",
]
