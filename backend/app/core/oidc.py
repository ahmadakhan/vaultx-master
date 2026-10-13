"""Fail-closed OIDC JWT verification for self-hosted Keycloak."""

from __future__ import annotations

import asyncio
from typing import Any

import jwt
from jwt import PyJWKClient

from app.config import settings


def oidc_enabled() -> bool:
    return all((settings.oidc_issuer_url, settings.oidc_jwks_url, settings.oidc_audience))


def _verify(token: str) -> dict[str, Any]:
    if not oidc_enabled():
        raise ValueError("OIDC integration is not configured")
    assert settings.oidc_jwks_url and settings.oidc_issuer_url and settings.oidc_audience
    key = PyJWKClient(settings.oidc_jwks_url).get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key=key,
        algorithms=["RS256", "RS384", "RS512"],
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer_url,
        options={"require": ["exp", "iat", "sub", "iss", "aud"]},
    )


async def verify_oidc_token(token: str) -> dict[str, Any]:
    """Verify signature, issuer, audience and required time claims."""
    return await asyncio.to_thread(_verify, token)
