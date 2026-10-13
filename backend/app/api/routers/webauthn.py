"""WebAuthn registration and platform-authenticator MFA ceremonies."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.deps import get_current_user
from app.core.exceptions import AuthenticationError
from app.core.security import MFA_CHALLENGE_TOKEN_TYPE, decode_token, hash_token_identifier
from app.core.webauthn import (
    WebAuthnUnavailable,
    verify_authentication,
    verify_registration,
)
from app.core.webauthn import (
    authentication_options as make_authentication_options,
)
from app.core.webauthn import (
    registration_options as make_registration_options,
)
from app.db import get_db
from app.models import RefreshToken, User, WebAuthnChallenge, WebAuthnCredential
from app.schemas.webauthn import WebAuthnResponse

router = APIRouter(prefix="/auth/webauthn", tags=["webauthn"])


def _decode_id(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid WebAuthn credential id") from exc


def _bad_verification() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="WebAuthn verification failed"
    )


async def _pending_mfa_user(request, db: AsyncSession) -> tuple[User, RefreshToken]:
    """Resolve the password-authenticated, single-use MFA continuation token."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    try:
        if scheme.lower() != "bearer":
            raise ValueError("missing bearer token")
        claims = decode_token(token, expected_type=MFA_CHALLENGE_TOKEN_TYPE)
        if claims.get("mfa") != "pending":
            raise ValueError("not a pending MFA token")
        import uuid

        user = await db.scalar(
            select(User).where(User.id == uuid.UUID(claims["sub"])).with_for_update()
        )
        pending = await db.scalar(
            select(RefreshToken)
            .where(
                RefreshToken.user_id == user.id if user else False,
                RefreshToken.jti_hash == hash_token_identifier(claims["jti"]),
            )
            .with_for_update()
        )
        if user is None or not user.is_active or not user.mfa_enabled or pending is None:
            raise ValueError("invalid pending MFA token")
        if not pending.is_active:
            raise ValueError("expired pending MFA token")
        return user, pending
    except (ValueError, TypeError, KeyError, AuthenticationError) as exc:
        raise HTTPException(status_code=401, detail="MFA challenge token missing or invalid") from exc


async def _challenge(db: AsyncSession, user: User, ceremony: str, value: bytes) -> None:
    db.add(
        WebAuthnChallenge(
            user_id=user.id,
            ceremony=ceremony,
            challenge=value,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=settings.webauthn_challenge_ttl_seconds),
        )
    )
    await db.commit()


async def _consume_challenge(
    db: AsyncSession, user: User, ceremony: str, value: bytes
) -> WebAuthnChallenge:
    row = await db.scalar(
        select(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.user_id == user.id,
            WebAuthnChallenge.ceremony == ceremony,
            WebAuthnChallenge.challenge == value,
            WebAuthnChallenge.used_at.is_(None),
        )
        .with_for_update()
    )
    if row is None or row.expires_at.replace(tzinfo=UTC) <= datetime.now(UTC):
        raise _bad_verification()
    return row


@router.post("/registration/options")
async def registration_options(
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    try:
        ids = list(
            (
                await db.scalars(
                    select(WebAuthnCredential.credential_id).where(
                        WebAuthnCredential.user_id == current_user.id
                    )
                )
            ).all()
        )
        options, challenge = make_registration_options(
            user_id=str(current_user.id), email=current_user.email, exclude_ids=ids
        )
        await _challenge(db, current_user, "registration", challenge)
        return options
    except WebAuthnUnavailable as exc:
        raise HTTPException(status_code=503, detail="WebAuthn verifier is not installed") from exc


@router.post("/registration/verify")
async def registration_verify(
    payload: WebAuthnResponse,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, bool]:
    try:
        client_data = payload.response.get("clientDataJSON")
        if not isinstance(client_data, str):
            raise _bad_verification()
        raw = base64.urlsafe_b64decode(client_data + "=" * (-len(client_data) % 4))
        challenge = json.loads(raw).get("challenge")
        if not isinstance(challenge, str):
            raise _bad_verification()
        row = await _consume_challenge(db, current_user, "registration", _decode_id(challenge))
        # Reserve the challenge before crypto verification so a concurrent
        # request cannot replay it (the transaction rolls back on failure).
        row.used_at = datetime.now(UTC)
        await db.flush()
        verified = verify_registration(
            response=payload.model_dump(by_alias=True), expected_challenge=row.challenge
        )
        db.add(
            WebAuthnCredential(
                user_id=current_user.id,
                credential_id=verified.credential_id,
                public_key=verified.credential_public_key,
                sign_count=verified.sign_count,
            )
        )
        await db.commit()
        return {"verified": True}
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        raise _bad_verification() from exc


@router.post("/authentication/options")
async def authentication_options(
    request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    try:
        current_user, _ = await _pending_mfa_user(request, db)
        ids = list(
            (
                await db.scalars(
                    select(WebAuthnCredential.credential_id).where(
                        WebAuthnCredential.user_id == current_user.id
                    )
                )
            ).all()
        )
        if not ids:
            raise HTTPException(status_code=404, detail="No WebAuthn credentials registered")
        options, challenge = make_authentication_options(credential_ids=ids)
        await _challenge(db, current_user, "authentication", challenge)
        return options
    except WebAuthnUnavailable as exc:
        raise HTTPException(status_code=503, detail="WebAuthn verifier is not installed") from exc


@router.post("/authentication/verify")
async def authentication_verify(
    payload: WebAuthnResponse,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        current_user, pending = await _pending_mfa_user(request, db)
        credential_id = _decode_id(payload.id)
        credential = await db.scalar(
            select(WebAuthnCredential).where(
                WebAuthnCredential.user_id == current_user.id,
                WebAuthnCredential.credential_id == credential_id,
            )
        )
        if credential is None:
            raise _bad_verification()
        client_data = payload.response.get("clientDataJSON")
        if not isinstance(client_data, str):
            raise _bad_verification()
        challenge = json.loads(
            base64.urlsafe_b64decode(client_data + "=" * (-len(client_data) % 4))
        ).get("challenge")
        row = await _consume_challenge(db, current_user, "authentication", _decode_id(challenge))
        # Reserve both one-time values before verification; rollback restores
        # them only when this attempt fails, while concurrent attempts block.
        row.used_at = datetime.now(UTC)
        pending.revoked_at = datetime.now(UTC)
        await db.flush()
        verified = verify_authentication(
            response=payload.model_dump(by_alias=True),
            expected_challenge=row.challenge,
            public_key=credential.public_key,
            sign_count=credential.sign_count,
        )
        credential.sign_count = verified.new_sign_count
        # Issue a fresh signed session carrying the same MFA assurance claim
        # used by password/TOTP login.  The timestamp is therefore enforced by
        # get_current_user_mfa_verified rather than trusted from the response.
        from app.api.routers.auth import _issue_tokens, _keys_response

        verified_at = datetime.now(UTC).timestamp()
        access_token, refresh_token = await _issue_tokens(
            db, current_user, mfa_at=verified_at, commit=False
        )
        await db.commit()
        return {
            "verified": True,
            "mfa_verified_at": verified_at,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "keys": _keys_response(current_user),
        }
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        raise _bad_verification() from exc
