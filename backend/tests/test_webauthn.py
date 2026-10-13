"""Focused WebAuthn policy and persistence-boundary tests."""

from __future__ import annotations

import pytest

pytest.importorskip("webauthn")

from app.core.webauthn import authentication_options, registration_options
from app.models import Base


def test_options_require_platform_user_verification() -> None:
    registration, registration_challenge = registration_options(
        user_id="user-id", email="user@example.com", exclude_ids=[]
    )
    authentication, authentication_challenge = authentication_options(credential_ids=[b"cred-id"])

    assert registration["authenticatorSelection"] == {
        "authenticatorAttachment": "platform",
        "requireResidentKey": False,
        "userVerification": "required",
    }
    assert authentication["userVerification"] == "required"
    assert len(registration_challenge) == 32
    assert len(authentication_challenge) == 32


def test_web_authn_tables_are_registered_with_metadata() -> None:
    assert "webauthn_challenges" in Base.metadata.tables
    assert "webauthn_credentials" in Base.metadata.tables
