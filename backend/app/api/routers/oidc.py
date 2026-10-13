"""Keycloak OIDC token validation endpoint.

The endpoint deliberately returns claims only; account/session provisioning and
local authorization remain explicit application operations.
"""

import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routers.auth import _issue_tokens, _keys_response
from app.core.audit_log import record_audit_log
from app.core.oidc import verify_oidc_token
from app.core.security import hash_password
from app.db import get_db
from app.models import Tenant, TenantQuota, User, UserRole, email_matches, normalize_email
from app.schemas.auth import AuthResponse, UserKeysResponse

router = APIRouter(prefix="/auth/oidc", tags=["OIDC"])


class OIDCVerifyRequest(BaseModel):
    token: str


class OIDCSessionRequest(BaseModel):
    """Verified IdP assertion plus the client-generated VaultX key bundle.

    VaultX never derives or receives a password for OIDC users.  The browser
    creates the same encrypted bundle used by local registration, allowing the
    resulting response to be consumed by the normal session flow.
    """

    token: str = Field(min_length=1)
    keys: UserKeysResponse


@router.post("/verify")
async def verify(request: OIDCVerifyRequest) -> dict[str, object]:
    try:
        return {"claims": await verify_oidc_token(request.token)}
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid OIDC token") from exc


@router.post("/session", response_model=AuthResponse)
async def oidc_session(
    payload: OIDCSessionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Exchange a verified Keycloak token for a normal VaultX session.

    Existing users are matched by the verified email claim. New users are
    provisioned into an isolated tenant and receive the ordinary access and
    refresh tokens. No password protocol is consulted or weakened.
    """
    try:
        claims = await verify_oidc_token(payload.token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid OIDC token") from exc
    email = normalize_email(str(claims.get("email") or claims.get("preferred_username") or ""))
    if not email or "@" not in email or claims.get("email_verified") is not True:
        raise HTTPException(status_code=403, detail="OIDC token has no verified email")

    user = await db.scalar(select(User).where(email_matches(User.email, email)))
    if user is not None:
        if not user.is_active:
            raise HTTPException(status_code=403, detail="User is deprovisioned")
        access, refresh = await _issue_tokens(db, user)
        await record_audit_log(db, request, user.id, "oidc_login", resource={"subject": str(claims["sub"])})
        return AuthResponse(access_token=access, refresh_token=refresh, keys=_keys_response(user))

    tenant = Tenant(tenant_id=str(uuid.uuid4()), name=f"{email}'s Vault")
    db.add(tenant)
    await db.flush()
    db.add(TenantQuota(tenant_id=tenant.id, storage_quota_bytes=tenant.storage_quota_bytes))
    user = User(
        email=email,
        password_hash=hash_password(secrets.token_urlsafe(48)),
        tenant_id=tenant.id,
        password_salt_b64=__import__("base64").b64decode(payload.keys.password_salt_b64),
        enc_master_key_b64=__import__("base64").b64decode(payload.keys.enc_master_key_b64),
        enc_master_key_iv=__import__("base64").b64decode(payload.keys.enc_master_key_iv),
        enc_search_key_b64=__import__("base64").b64decode(payload.keys.enc_search_key_b64),
        enc_search_key_iv=__import__("base64").b64decode(payload.keys.enc_search_key_iv),
        enc_private_key_b64=__import__("base64").b64decode(payload.keys.enc_private_key_b64),
        enc_private_key_iv=__import__("base64").b64decode(payload.keys.enc_private_key_iv),
        public_key_b64=__import__("base64").b64decode(payload.keys.public_key_b64),
        key_bundle_version=payload.keys.key_bundle_version,
        password_kdf_iterations=payload.keys.kdf_iterations,
    )
    db.add(user)
    await db.flush()
    db.add(UserRole(user_id=user.id, role="user"))
    access, refresh = await _issue_tokens(db, user, commit=False)
    await record_audit_log(db, request, user.id, "oidc_provision", resource={"subject": str(claims["sub"])})
    return AuthResponse(access_token=access, refresh_token=refresh, keys=payload.keys)
