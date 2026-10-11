"""RSA key-pair management for audit log signing.

Generates or loads an RSA-3072 key pair used to sign and verify
tamper-evident audit log entries. Keys are stored on disk with
restrictive file permissions (0o600 for private, 0o644 for public).

The key pair is loaded once at module import time as module-level
singletons (``SERVER_PRIVATE_KEY``, ``SERVER_PUBLIC_KEY``).
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings
from app.core.exceptions import CryptoError
from app.core.logging import get_logger

logger = get_logger(__name__)

PRIVATE_KEY_FILENAME = "server_signing_key.pem"
PUBLIC_KEY_FILENAME = "server_signing_key.pub"


def _restrict(path: Path, mode: int) -> None:
    """Best-effort permission tightening.

    ``os.chmod`` is a no-op for most modes on Windows and may fail on
    filesystems without POSIX permissions, so failures are logged only.
    """
    try:
        os.chmod(path, mode)
    except OSError as exc:  # pragma: no cover - platform dependent
        logger.warning("Could not set permissions", extra={"path": str(path), "error": str(exc)})


def _ensure_writable_dir(primary: Path) -> Path:
    """Create and return a usable key directory.

    Tries the primary directory first and falls back to
    ``FALLBACK_KEYS_DIR``; unlike the previous implementation the chosen
    directory is returned so callers do not keep writing to an unwritable
    path.

    Args:
        primary: Preferred key directory.

    Returns:
        The directory that should be used.

    Raises:
        CryptoError: If neither directory can be created or written to.
    """
    for candidate, label in ((primary, "primary"), (Path(settings.fallback_keys_dir), "fallback")):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # A fixed probe filename races across workers: one worker unlinks
            # another's probe and may incorrectly fall back to a different key.
            with tempfile.TemporaryFile(dir=candidate):
                pass
        except OSError as exc:
            logger.warning(
                "Key directory unusable",
                extra={"directory": str(candidate), "which": label, "error": str(exc)},
            )
            continue

        _restrict(candidate, 0o700)
        if label == "fallback":
            logger.warning(
                "Falling back to alternate keys directory", extra={"path": str(candidate)}
            )
        return candidate

    raise CryptoError("No writable directory available for server signing keys")


def _generate_rsa() -> tuple[rsa.RSAPrivateKey, bytes, bytes]:
    """Generate a new RSA-3072 key pair.

    Returns:
        A tuple of ``(private_key, private_pem, public_pem)``.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, priv_pem, pub_pem


def _write_new(path: Path, data: bytes, mode: int = 0o600) -> bool:
    """Atomically create a file with restrictive permissions.

    Uses ``O_CREAT | O_EXCL`` so the permission mode is applied at creation
    time (no window where the key is world-readable) and an existing file is
    never overwritten.

    Args:
        path: Destination file path.
        data: File content bytes.
        mode: File permission mode (default 0o600).

    Returns:
        ``True`` if this process created the file, ``False`` if it already
        existed.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    _restrict(path, mode)
    return True


def _wait_for_file(path: Path, timeout: float = 10.0) -> None:
    """Wait until ``path`` exists and is non-empty.

    Used when another worker wins the key-generation race: the winner creates
    the private key first and the public key immediately after, so a loser can
    briefly observe only half of the pair.

    Raises:
        CryptoError: If the file does not appear before ``timeout``.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if path.exists() and path.stat().st_size > 0:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise CryptoError(f"Timed out waiting for key file: {path}")


def _load_pair(priv_path: Path, pub_path: Path) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Load and cross-validate a signing key pair from disk.

    Raises:
        CryptoError: If either file is unreadable, not RSA, or the public key
            does not belong to the private key.
    """
    try:
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        pub = serialization.load_pem_public_key(pub_path.read_bytes())
    except Exception as exc:
        logger.error("Failed to load existing keys: %s", exc)
        raise CryptoError("Failed to load server signing keys") from exc

    if not isinstance(priv, rsa.RSAPrivateKey):
        raise CryptoError("Loaded private key is not an RSA key")
    if not isinstance(pub, rsa.RSAPublicKey):
        raise CryptoError("Loaded public key is not an RSA key")

    if priv.public_key().public_numbers() != pub.public_numbers():
        raise CryptoError(
            "Server signing key pair on disk is inconsistent: the public key "
            "does not match the private key. Audit signatures cannot be "
            "verified until this is corrected."
        )

    return priv, pub


def load_server_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Load the RSA signing key pair, generating it exactly once if absent.

    The pair is created with ``O_EXCL`` so that concurrent workers cannot each
    produce their own key, and an existing pair is never overwritten. A partial
    or mismatched pair raises instead of silently rotating the key, because
    silent rotation would invalidate every previously signed audit entry.

    Returns:
        A tuple of ``(private_key, public_key)``.

    Raises:
        CryptoError: If the key material is unusable or only half of the pair
            exists on disk.
    """
    key_dir = _ensure_writable_dir(Path(settings.keys_dir))
    # Serialize the complete check/create/load sequence. O_EXCL alone leaves a
    # window where another worker observes only the private half of a new pair.
    # Production runs on Linux; flock is released automatically on process exit.
    import fcntl

    fd = os.open(key_dir / ".signing-key.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return _load_keys_in_directory(key_dir)
    finally:
        os.close(fd)


def _load_keys_in_directory(key_dir: Path) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv_path = key_dir / PRIVATE_KEY_FILENAME
    pub_path = key_dir / PUBLIC_KEY_FILENAME

    priv_exists = priv_path.exists()
    pub_exists = pub_path.exists()

    if priv_exists != pub_exists:
        missing = pub_path if priv_exists else priv_path
        raise CryptoError(
            f"Refusing to start: {missing.name} is missing while the other half of "
            "the signing key pair exists. Restore the key file rather than letting "
            "the service regenerate it, or all existing audit signatures become "
            "unverifiable."
        )

    if priv_exists and pub_exists:
        return _load_pair(priv_path, pub_path)

    key, priv_pem, pub_pem = _generate_rsa()
    try:
        created = _write_new(priv_path, priv_pem, 0o600)
    except OSError as exc:
        raise CryptoError(f"Failed to write server signing key: {exc}") from exc

    if created:
        try:
            _write_new(pub_path, pub_pem, 0o644)
        except OSError as exc:
            raise CryptoError(f"Failed to write server public key: {exc}") from exc
        logger.info("New RSA signing key pair generated", extra={"directory": str(key_dir)})
        return key, key.public_key()

    # Another worker created the key while we were generating ours; discard the
    # local copy and adopt the persisted pair so every worker signs alike.
    logger.info("Adopting signing key pair created by another worker")
    _wait_for_file(pub_path)
    return _load_pair(priv_path, pub_path)


def _load_or_create_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Backwards-compatible alias for :func:`load_server_keys`."""
    return load_server_keys()


# Loaded (or created) once per process. ``load_server_keys`` is race-safe and
# never overwrites an existing pair, so importing this module from several
# gunicorn workers cannot fork the signing key.
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = load_server_keys()
