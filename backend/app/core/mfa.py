"""Server-side TOTP secret encryption/decryption.

The MFA TOTP secret is encrypted with a key derived from the application
secret so that the server never stores the plaintext secret at rest.
"""

from __future__ import annotations

import base64
import os
from typing import NamedTuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings


class EncryptedSecret(NamedTuple):
    """Container for encrypted TOTP secret fields."""

    ciphertext_b64: str
    iv_b64: str
    salt_b64: str


def _derive_key(salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the app secret and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key_material = (settings.app_secret_key + "mfa-salt-context").encode()
    return kdf.derive(key_material)


def encrypt_totp_secret(secret: str) -> EncryptedSecret:
    """Encrypt a TOTP secret for at-rest storage.

    Args:
        secret: The plaintext TOTP secret (base32).

    Returns:
        EncryptedSecret with base64 ciphertext, IV, and salt.
    """
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = _derive_key(salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, secret.encode(), None)

    return EncryptedSecret(
        ciphertext_b64=base64.b64encode(ciphertext).decode(),
        iv_b64=base64.b64encode(iv).decode(),
        salt_b64=base64.b64encode(salt).decode(),
    )


def decrypt_totp_secret(enc: EncryptedSecret) -> str:
    """Decrypt a TOTP secret for verification.

    Args:
        enc: The encrypted secret fields.

    Returns:
        The plaintext TOTP secret.
    """
    salt = base64.b64decode(enc.salt_b64)
    iv = base64.b64decode(enc.iv_b64)
    ciphertext = base64.b64decode(enc.ciphertext_b64)
    key = _derive_key(salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode()
