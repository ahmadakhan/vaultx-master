"""
Secure Access Code Hashing with Per-Link Salts

Implements strong, secure hashing of access codes using PBKDF2 with
per-link salts and high iteration counts to prevent brute force attacks.
"""

from __future__ import annotations

import hashlib
import secrets
import time

ITERATIONS = 600_000  # OWASP-recommended minimum for PBKDF2-SHA256
SALT_LENGTH = 16  # bytes
MAX_ATTEMPTS_PER_MINUTE = 5
COOLDOWN_SECONDS = 900  # 15 minutes
ACCESS_CODE_MIN_LENGTH = 6
ACCESS_CODE_MAX_LENGTH = 128
MAX_CODE_LENGTH = 128


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(SALT_LENGTH)


def hash_access_code(code: str, salt: bytes | None = None) -> str:
    """Hash an access code with strong PBKDF2-HMAC-SHA256.

    Args:
        code: The access code to hash.
        salt: Optional salt to use for key derivation.

    Returns:
        A formatted string containing the iteration count, salt, and hash.

    Raises:
        ValueError: If the access code is too short or too long.
    """
    if not code or len(code) < ACCESS_CODE_MIN_LENGTH:
        raise ValueError(f"Access code must be at least {ACCESS_CODE_MIN_LENGTH} characters")

    if len(code) > ACCESS_CODE_MAX_LENGTH:
        raise ValueError(f"Access code must be at most {ACCESS_CODE_MAX_LENGTH} characters")

    if salt is None:
        salt = generate_salt()

    if len(salt) != SALT_LENGTH:
        raise ValueError(f"Salt must be exactly {SALT_LENGTH} bytes")

    digest = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, ITERATIONS)

    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_access_code(code: str, encoded: str) -> bool:
    """Verify an access code against a stored hash with rate limiting.

    Args:
        code: The access code to verify.
        encoded: The stored hash (format: pbkdf2_sha256$iterations$salt$hash).

    Returns:
        ``True`` only when the supplied code matches.
    """
    if not code or len(code) > MAX_CODE_LENGTH:
        return False

    cooldown_remaining = check_rate_limit(encoded)
    if cooldown_remaining > 0:
        return False

    try:
        if encoded.startswith("pbkdf2_sha256$"):
            parts = encoded.split("$")
            if len(parts) != 4:
                return False

            _, iterations_str, salt_hex, expected_hash = parts

            try:
                iterations = int(iterations_str)
                salt = bytes.fromhex(salt_hex)
            except ValueError:
                return False

            actual_hash = hashlib.pbkdf2_hmac(
                "sha256", code.encode("utf-8"), salt, iterations
            ).hex()
        else:
            expected_hash = encoded
            actual_hash = hashlib.sha256(code.encode()).hexdigest()

        valid = constant_time_compare(actual_hash, expected_hash)

        if valid:
            reset_rate_limit(encoded)

            return valid

    except Exception:
        record_failed_attempt(encoded)
        return False


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.

    Args:
        a: First string to compare.
        b: Second string to compare.

    Returns:
        True if strings are equal, False otherwise.
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a.encode(), b.encode(), strict=False):
        result |= x ^ y

    return result == 0


_attempt_store: dict[str, list[float]] = {}


def check_rate_limit(encoded: str) -> int:
    """Check if access code verification is rate-limited.

    Args:
        encoded: The stored hash identifier.

    Returns:
        Remaining cooldown time in seconds, or 0 if not rate-limited.
    """
    key = f"attempt_{encoded}"

    if key not in _attempt_store:
        return 0

    attempts = _attempt_store[key]
    current_time = time.time()

    attempts[:] = [t for t in attempts if current_time - t < 60]

    if len(attempts) >= MAX_ATTEMPTS_PER_MINUTE:
        cooldown_remaining = 60 - (current_time - attempts[0])
        return int(cooldown_remaining)

    return 0


def record_failed_attempt(encoded: str) -> None:
    """Record a failed access code verification attempt.

    Args:
        encoded: The stored hash identifier.
    """
    key = f"attempt_{encoded}"

    if key not in _attempt_store:
        _attempt_store[key] = []

    _attempt_store[key].append(time.time())


def reset_rate_limit(encoded: str) -> None:
    """Reset rate limiting for a successful verification.

    Args:
        encoded: The stored hash identifier.
    """
    key = f"attempt_{encoded}"
    _attempt_store.pop(key, None)


def migrate_legacy_hash(code: str, legacy_hash: str) -> str:
    """Migrate a legacy single-hash to the modern PBKDF2 format.

    Args:
        code: The plaintext access code.
        legacy_hash: The legacy SHA-256 hash.

    Returns:
        The new PBKDF2 hash format.
    """
    return hash_access_code(code)


def generate_secure_access_code(length: int = 12) -> str:
    """Generate a cryptographically secure access code.

    Args:
        length: The desired length of the access code.

    Returns:
        A secure, random access code string.
    """
    if length < ACCESS_CODE_MIN_LENGTH or length > ACCESS_CODE_MAX_LENGTH:
        raise ValueError(
            f"Access code length must be between {ACCESS_CODE_MIN_LENGTH} and {ACCESS_CODE_MAX_LENGTH}"
        )

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def cleanup_expired_attempts() -> int:
    """Clean up expired rate limit attempts.

    Returns:
        Number of cleaned entries.
    """
    current_time = time.time()
    cleaned = 0

    for key in list(_attempt_store.keys()):
        attempts = _attempt_store[key]
        recent = [t for t in attempts if current_time - t < 3600]
        if recent:
            _attempt_store[key] = recent
        else:
            del _attempt_store[key]
            cleaned += 1

    return cleaned
