"""Atomic database-backed attempt reservations; failures survive request rollback."""

import math
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import RateLimitError
from app.core.login_throttle import throttle_key
from app.models.user import AuthenticationAttempt


async def reserve_attempt(db: AsyncSession, scope: str, identity: str) -> None:
    """Charge before verification using an atomic upsert, then commit.

    Call before business mutations. A correct password alone must never reset
    the independent MFA budget. Expired rows are pruned on each reservation.
    """
    now = datetime.now(UTC)
    deadline = now + timedelta(seconds=settings.login_lockout_seconds)
    table = AuthenticationAttempt
    key = throttle_key(f"{scope}:{identity}")
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    await db.execute(delete(table).where(table.expires_at <= now))
    stmt = insert(table).values(key=key, attempts=1, expires_at=deadline)
    stmt = stmt.on_conflict_do_update(
        index_elements=[table.key],
        set_={
            "attempts": case(
                (table.attempts <= settings.login_max_attempts, table.attempts + 1),
                else_=table.attempts,
            )
        },
    ).returning(table.attempts, table.expires_at)
    attempts, expiry = (await db.execute(stmt)).one()
    await db.commit()
    if attempts > settings.login_max_attempts:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        retry = max(1, math.ceil((expiry - now).total_seconds()))
        raise RateLimitError(
            "Too many authentication attempts. Please try again later.",
            headers={"Retry-After": str(retry)},
        )


async def reset_attempts(db: AsyncSession, scope: str, identity: str) -> None:
    await db.execute(
        delete(AuthenticationAttempt).where(
            AuthenticationAttempt.key == throttle_key(f"{scope}:{identity}")
        )
    )
