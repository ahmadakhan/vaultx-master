"""Versioned access-code hashes, with verification of existing link records."""
import hashlib
import secrets

ITERATIONS = 600_000


def hash_access_code(code: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(salt), ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt}${digest.hex()}"


def verify_access_code(code: str, encoded: str) -> bool:
    if len(code) > 128:
        return False
    if encoded.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt, expected = encoded.split("$")
            if int(iterations) != ITERATIONS:
                return False
            actual = hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(salt), ITERATIONS).hex()
        except (ValueError, TypeError):
            return False
    else:
        expected = encoded
        actual = hashlib.sha256(code.encode()).hexdigest()
    return secrets.compare_digest(actual, expected)
