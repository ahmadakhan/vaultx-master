"""Standards-oriented SCIM 2.0 user provisioning for Keycloak."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.audit_log import record_audit_log
from app.core.security import hash_password
from app.db import get_db
from app.models import (
    RefreshToken,
    Role,
    Tenant,
    TenantQuota,
    User,
    UserRole,
    email_matches,
    normalize_email,
)

router = APIRouter(prefix="/scim/v2", tags=["SCIM 2.0"])


@router.get("/ServiceProviderConfig")
async def service_provider_config(authorization: str | None = Header(None)):
    _auth(authorization)
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False},
        "filter": {"supported": True, "maxResults": 100},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer"}],
    }


def _auth(authorization: str | None) -> None:
    if not settings.scim_bearer_token:
        raise HTTPException(status_code=404, detail="SCIM is disabled")
    expected = "Bearer " + settings.scim_bearer_token
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid SCIM credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _resource(user: User, tenant: Tenant | None) -> dict[str, Any]:
    version = hashlib.sha256(
        f"{user.id}:{user.is_active}:{user.email}:{user.created_at.timestamp()}".encode()
    ).hexdigest()
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(user.id),
        "userName": user.email,
        "active": user.is_active,
        "name": {"formatted": user.email},
        "meta": {"resourceType": "User", "version": version},
        **({"tenant": tenant.tenant_id} if tenant else {}),
    }


def _etag(resource: dict[str, Any]) -> str:
    return '"' + hashlib.sha256(json.dumps(resource, sort_keys=True).encode()).hexdigest() + '"'


def _reply(resource: dict[str, Any], response: Response, status_code: int | None = None) -> dict[str, Any]:
    response.headers["ETag"] = _etag(resource)
    response.headers["Content-Type"] = "application/scim+json"
    if status_code is not None:
        response.status_code = status_code
    return resource


def _filter_email(expression: str | None) -> str | None:
    if not expression:
        return None
    import re

    match = re.fullmatch(r'\s*userName\s+eq\s+"([^"]+)"\s*', expression, re.I)
    if not match:
        raise HTTPException(status_code=400, detail="Only userName eq filters are supported")
    return normalize_email(match.group(1))


async def _tenant(db: AsyncSession) -> Tenant:
    assert settings.scim_tenant_id
    tenant = await db.scalar(select(Tenant).where(Tenant.tenant_id == settings.scim_tenant_id))
    if tenant is None:
        tenant = Tenant(tenant_id=settings.scim_tenant_id, name=settings.scim_tenant_id)
        db.add(tenant)
        await db.flush()
        db.add(TenantQuota(tenant_id=tenant.id))
    return tenant


def _user_fields(payload: dict[str, Any]) -> tuple[str, bool, list[str]]:
    email = normalize_email(
        str(payload.get("userName") or payload.get("emails", [{}])[0].get("value", ""))
    )
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="SCIM userName must be an email address")
    groups = [
        str(g.get("display", g.get("value", "")))
        for g in payload.get("groups", [])
        if isinstance(g, dict)
    ]
    return email, bool(payload.get("active", True)), groups


@router.post("/Users", status_code=201)
async def create_user(
    payload: dict[str, Any],
    response: Response,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    _auth(authorization)
    tenant = await _tenant(db)
    email, active, groups = _user_fields(payload)
    if await db.scalar(select(User).where(email_matches(User.email, email))):
        raise HTTPException(status_code=409, detail="User already exists")
    user = User(
        email=email,
        password_hash=hash_password(secrets.token_urlsafe(32)),
        tenant_id=tenant.id,
        password_salt_b64=b"scim",
        enc_master_key_b64=b"scim",
        enc_master_key_iv=b"scim",
        enc_search_key_b64=b"scim",
        enc_search_key_iv=b"scim",
        enc_private_key_b64=b"scim",
        enc_private_key_iv=b"scim",
        public_key_b64=b"scim",
        is_active=active,
    )
    db.add(user)
    await db.flush()
    for role in {"user", *({g.lower() for g in groups} & {"admin"})}:
        if await db.scalar(select(Role).where(Role.name == role)) is None:
            db.add(Role(name=role))
        db.add(UserRole(user_id=user.id, role=role))
    await db.commit()
    await db.refresh(user)
    return _reply(_resource(user, tenant), response, 201)


@router.get("/Users")
async def list_users(
    authorization: str | None = Header(None),
    filter: str | None = Query(None),
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=0, le=100),
    db: AsyncSession = Depends(get_db),
):
    _auth(authorization)
    email = _filter_email(filter)
    query = select(User).order_by(User.created_at, User.id)
    if email:
        query = query.where(email_matches(User.email, email))
    users = list((await db.scalars(query)).all())
    page = users[startIndex - 1 : startIndex - 1 + count]
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(users),
        "startIndex": startIndex,
        "itemsPerPage": len(page),
        "Resources": [_resource(user, None) for user in page],
    }


@router.delete("/Users/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    request: Request,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    _auth(authorization)
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(revoked_at=datetime.now(UTC)))
    await db.commit()
    await record_audit_log(db, request, user.id, "scim_deprovision", resource={"user_id": str(user.id)})
    return Response(status_code=204)


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: uuid.UUID,
    payload: dict[str, Any],
    request: Request,
    response: Response,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    _auth(authorization)
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    was_active = user.is_active
    for operation in payload.get("Operations", []):
        if str(operation.get("op", "")).lower() not in {"replace", "add"}:
            raise HTTPException(status_code=400, detail="Unsupported SCIM operation")
        path = str(operation.get("path", "")).lower()
        value = operation.get("value")
        if path == "active" and isinstance(value, bool):
            user.is_active = value
        elif (
            path in {"", "active"}
            and isinstance(value, dict)
            and isinstance(value.get("active"), bool)
        ):
            user.is_active = value["active"]
        else:
            raise HTTPException(status_code=400, detail="Only active replacement is supported")
    await db.commit()
    if was_active and not user.is_active:
        await record_audit_log(db, request, user.id, "scim_deprovision", resource={"user_id": str(user.id)})
        await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(revoked_at=datetime.now(UTC)))
        await db.commit()
    return _reply(_resource(user, None), response)


@router.get("/Users/{user_id}")
async def get_user(
    user_id: uuid.UUID,
    response: Response,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    _auth(authorization)
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _reply(_resource(user, None), response)
