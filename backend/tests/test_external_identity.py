"""Focused fail-closed checks for Keycloak and SCIM configuration."""

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.routers.scim import _filter_email
from app.config import Settings


def test_oidc_partial_configuration_is_rejected(monkeypatch):
    with pytest.raises(ValidationError):
        Settings(OIDC_ISSUER_URL="https://id.example", OIDC_AUDIENCE="vaultx")


def test_scim_requires_tenant_and_long_secret(monkeypatch):
    with pytest.raises(ValidationError):
        Settings(SCIM_BEARER_TOKEN="too-short")


def test_scim_basic_filter_is_normalized_and_fail_closed():
    assert _filter_email('userName eq "Person@Example.COM"') == "person@example.com"
    with pytest.raises(HTTPException):
        _filter_email('active eq true')


def test_password_auth_mode_accepts_explicit_pake_fail_closed_mode():
    settings = Settings(PASSWORD_AUTH_MODE="opaque-required")
    assert settings.password_auth_mode == "opaque-required"
    with pytest.raises(ValidationError):
        Settings(PASSWORD_AUTH_MODE="invented-pake")
