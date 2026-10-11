"""Audit event decorator for automatic log recording.

Wraps endpoint handlers to record an audit entry after the handler
completes successfully. Failures in log recording are logged but do
not interrupt the user-facing response.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Callable
from functools import wraps
from typing import Any

from app.core.audit_log import record_audit_log
from app.core.logging import get_logger
from app.core.security import ACCESS_TOKEN_TYPE, decode_token

logger = get_logger(__name__)


def _resolve_user_id(response: Any) -> uuid.UUID | None:
    """Best-effort extraction of the acting user from a login-style response.

    Login has no ``current_user`` dependency, so the subject is taken from the
    access token that was just issued.
    """
    access_token = (
        response.get("access_token")
        if isinstance(response, dict)
        else getattr(response, "access_token", None)
    )
    if not access_token:
        return None
    try:
        payload = decode_token(access_token, expected_type=ACCESS_TOKEN_TYPE)
        sub = payload.get("sub")
        return uuid.UUID(sub) if sub else None
    except (ValueError, AttributeError, TypeError):
        return None


def audit_event(
    action: str,
    resource_fields: tuple[str, ...] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that records an audit event after endpoint execution.

    The wrapped endpoint **must** declare ``request: Request`` and
    ``db: AsyncSession`` parameters; this is validated at import time so a
    mismatch fails loudly instead of at request time. FastAPI resolves both via
    the endpoint's own signature (``functools.wraps`` exposes it through
    ``__wrapped__``), so the values injected into the handler are reused here.

    Args:
        action: A short label for the audit event (e.g., ``"file_upload"``).
        resource_fields: Names of handler parameters whose values identify the
            affected object; they are embedded in the signed audit payload so
            entries are forensically useful (which file, which recipient).

    Returns:
        A decorator function.

    Raises:
        TypeError: If the decorated endpoint does not accept ``request`` and
            ``db`` parameters.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(func, eval_str=True)
        params = signature.parameters
        missing = [name for name in ("request", "db") if name not in params]
        if missing:
            raise TypeError(
                f"@audit_event({action!r}) requires '{func.__qualname__}' to accept "
                f"the parameter(s): {', '.join(missing)}"
            )

        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            response = await func(*args, **kwargs)

            user_id = getattr(kwargs.get("current_user") or kwargs.get("current_admin"), "id", None)
            if user_id is None:
                user_id = _resolve_user_id(response)

            resource = {
                field: str(kwargs[field])
                for field in resource_fields
                if kwargs.get(field) is not None
                and not any(
                    secret in field.lower()
                    for secret in ("token", "password", "secret", "code", "key")
                )
            }

            try:
                await record_audit_log(
                    db=kwargs["db"],
                    request=kwargs["request"],
                    user_id=user_id,
                    action=action,
                    resource=resource or None,
                )
            except Exception:
                await kwargs["db"].rollback()
                logger.error(
                    "Failed to record audit log",
                    extra={"action": action},
                )
            return response

        # FastAPI otherwise resolves postponed annotations in this wrapper's
        # globals, misclassifying Request as a required query parameter and
        # leaving endpoint-local model/UUID references unresolved.
        wrapper.__signature__ = signature  # type: ignore[attr-defined]
        return wrapper

    return decorator
