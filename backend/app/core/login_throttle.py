"""Stable identifiers for the shared database authentication budget.

Attempt state lives in ``auth_budget``; it must never be process-local because
production serves requests from multiple workers.
"""

import hashlib


def throttle_key(identity: str) -> str:
    """Canonicalise and hash an identity without retaining raw account names."""
    return hashlib.sha256(identity.strip().lower().encode("utf-8")).hexdigest()
