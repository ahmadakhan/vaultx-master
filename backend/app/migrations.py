"""Small, idempotent SQL migration runner used by deployment startup."""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.core.logging import get_logger

logger = get_logger(__name__)
MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def _split_sql(script: str) -> list[str]:
    """Split PostgreSQL statements while preserving dollar-quoted PL/pgSQL."""
    statements: list[str] = []
    start = 0
    dollar_tag: str | None = None
    index = 0
    while index < len(script):
        if script[index] == "$":
            end = script.find("$", index + 1)
            if end != -1:
                tag = script[index : end + 1]
                if tag.count("$") == 2:
                    if dollar_tag is None:
                        dollar_tag = tag
                        index = end + 1
                        continue
                    if tag == dollar_tag:
                        dollar_tag = None
                        index = end + 1
                        continue
        if script[index] == ";" and dollar_tag is None:
            statement = script[start:index].strip()
            statement = re.sub(r"\A(?:\s*--[^\n]*(?:\n|$))+", "", statement).strip()
            if statement:
                statements.append(statement)
            start = index + 1
        index += 1
    remainder = re.sub(r"\A(?:\s*--[^\n]*(?:\n|$))+", "", script[start:]).strip()
    if remainder:
        statements.append(remainder)
    return statements


async def apply_migrations(conn: AsyncConnection) -> None:
    """Apply checked-in PostgreSQL migrations exactly once."""
    if conn.dialect.name != "postgresql":
        return
    await conn.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)"))
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = path.name
        if await conn.scalar(text("SELECT 1 FROM schema_migrations WHERE version = :version"), {"version": version}):
            continue
        logger.info("Applying database migration", extra={"version": version})
        for statement in _split_sql(path.read_text(encoding="utf-8")):
            await conn.exec_driver_sql(statement)
        await conn.execute(text("INSERT INTO schema_migrations (version) VALUES (:version)"), {"version": version})


async def migrate_database() -> None:
    """Create the model baseline and apply all deployment migrations."""
    from app.db import engine
    from app.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await apply_migrations(conn)
