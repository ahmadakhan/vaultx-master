"""Per-account authentication throttling.

The global IP rate limit alone cannot stop credential stuffing: an attacker can
spread attempts across many source addresses while a single account absorbs the
whole attack. This module tracks consecutive failures per account and applies a
temporary lockout.

State is process-local. A multi-worker deployment should replace the store with
a shared one (e.g. Redis) behind the same interface, otherwise the effective
attempt budget is multiplied by the worker count.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

from app.config import settings

_MAX_TRACKED_ACCOUNTS = 10_000


def throttle_key(email: str) -> str:
    """Derive the throttle key for an account.

    The address is hashed so counters in memory never hold raw addresses and
    two spellings of the same address cannot be locked independently.
    """
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:32]


@dataclass
class _AttemptRecord:
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class LoginThrottle:
    """Consecutive-failure tracker with temporary lockouts.

    Args:
        max_attempts: Failures allowed before an account is locked.
        lockout_seconds: How long an account stays locked after too many
            failures.
        max_entries: Upper bound on tracked accounts, preventing unbounded
            memory growth under a distributed attack.
    """

    max_attempts: int = 5
    lockout_seconds: int = 900
    max_entries: int = _MAX_TRACKED_ACCOUNTS
    _records: dict[str, _AttemptRecord] = field(default_factory=dict)

    def check(self, key: str) -> int:
        """Return the remaining lockout in seconds (``0`` when not locked)."""
        record = self._records.get(key)
        if record is None:
            return 0
        remaining = record.locked_until - time.monotonic()
        if remaining <= 0:
            if record.failures == 0:
                self._records.pop(key, None)
            return 0
        return max(1, int(remaining) + 1)

    def record_failure(self, key: str) -> int:
        """Register a failed attempt.

        Returns:
            The lockout duration in seconds now in force (``0`` if not locked).
        """
        if len(self._records) >= self.max_entries and key not in self._records:
            self._evict_expired()
            if len(self._records) >= self.max_entries:
                self._records.clear()

        record = self._records.setdefault(key, _AttemptRecord())
        record.failures += 1
        if record.failures >= self.max_attempts:
            record.locked_until = time.monotonic() + self.lockout_seconds
            record.failures = 0
            return self.lockout_seconds
        return 0

    def reset(self, key: str) -> None:
        """Clear the counters for an account after a successful login."""
        self._records.pop(key, None)

    def _evict_expired(self) -> None:
        now = time.monotonic()
        for key in [
            k for k, v in self._records.items() if v.locked_until < now and v.failures == 0
        ]:
            del self._records[key]


login_throttle = LoginThrottle(
    max_attempts=settings.login_max_attempts,
    lockout_seconds=settings.login_lockout_seconds,
)
