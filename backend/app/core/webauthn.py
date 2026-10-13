"""WebAuthn adapter backed by the vetted ``webauthn`` package.

The adapter deliberately contains no cryptographic verification of its own:
the package parses clientData/authenticatorData, validates RP/origin, checks
the signature and enforces user presence/verification.
"""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from app.config import settings

try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers.structs import (
        AuthenticatorAttachment,
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    )
except ImportError:  # pragma: no cover - protects diagnostics before dependency installation
    generate_authentication_options = None


_MIN_WEBAUTHN_VERSION = (2, 8, 0)


class WebAuthnUnavailable(RuntimeError):
    """Raised when the WebAuthn verifier dependency is unavailable."""


def _require_library() -> None:
    verify_dependency()


def verify_dependency() -> None:
    """Verify the runtime WebAuthn dependency and expose an actionable error.

    The dependency is deliberately checked at runtime as well as declared in
    the lock/requirements files. This catches incomplete production images and
    accidental upgrades before an authentication request reaches crypto code.
    """
    if generate_authentication_options is None:
        raise WebAuthnUnavailable(
            "WebAuthn is unavailable: install the pinned dependency with "
            "'pip install webauthn>=2.8.0,<3' and restart VaultX"
        )
    try:
        installed = version("webauthn")
    except PackageNotFoundError as exc:  # pragma: no cover - import metadata edge case
        raise WebAuthnUnavailable(
            "WebAuthn cannot be verified: the 'webauthn' package metadata is missing; "
            "rebuild the production image from backend/requirements.txt"
        ) from exc
    parsed = tuple(int(part) for part in installed.split(".")[:3] if part.isdigit())
    if parsed < _MIN_WEBAUTHN_VERSION or parsed[0] >= 3:
        raise WebAuthnUnavailable(
            f"Unsupported webauthn version {installed}; VaultX requires >=2.8.0,<3"
        )


def registration_options(
    *, user_id: str, email: str, exclude_ids: list[bytes]
) -> tuple[dict[str, Any], bytes]:
    _require_library()
    import secrets

    challenge = secrets.token_bytes(32)
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=user_id.encode(),
        user_name=email,
        user_display_name=email,
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=value) for value in exclude_ids],
    )
    return json.loads(options_to_json(options)), challenge


def authentication_options(*, credential_ids: list[bytes]) -> tuple[dict[str, Any], bytes]:
    _require_library()
    import secrets

    challenge = secrets.token_bytes(32)
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=value) for value in credential_ids],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options)), challenge


def verify_registration(*, response: dict[str, Any], expected_challenge: bytes) -> Any:
    _require_library()
    return verify_registration_response(
        credential=response,
        expected_challenge=expected_challenge,
        expected_rp_id=settings.webauthn_rp_id,
        expected_origin=settings.webauthn_origin,
        require_user_presence=True,
        require_user_verification=True,
    )


def verify_authentication(
    *, response: dict[str, Any], expected_challenge: bytes, public_key: bytes, sign_count: int
) -> Any:
    _require_library()
    return verify_authentication_response(
        credential=response,
        expected_challenge=expected_challenge,
        expected_rp_id=settings.webauthn_rp_id,
        expected_origin=settings.webauthn_origin,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
        require_user_verification=True,
    )
