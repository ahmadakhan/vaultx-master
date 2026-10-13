"""PostgreSQL integration coverage for the phase 3/4 tenant policies.

This suite is opt-in locally, but CI sets ``REQUIRE_PG_RLS_TESTS=1`` so a
missing or unavailable PostgreSQL test database fails the job instead of
silently removing RLS evidence. SQLite cannot exercise PostgreSQL RLS.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import create_async_engine

from app.models import Base


def _database_url() -> str:
    # Never point this test at the application database.  The harness creates
    # tables, policies, and seed rows; callers must explicitly provide a
    # disposable PostgreSQL URL.
    value = os.environ.get("PG_RLS_TEST_DATABASE_URL", "").strip()
    if not value:
        _configuration_error("PG_RLS_TEST_DATABASE_URL is not set")
    if not value.startswith(("postgresql://", "postgresql+asyncpg://")):
        _configuration_error(
            "PG_RLS_TEST_DATABASE_URL must use PostgreSQL (SQLite cannot enforce RLS)"
        )
    return value.replace("postgresql://", "postgresql+asyncpg://", 1)


def _configuration_error(reason: str) -> None:
    message = f"PostgreSQL RLS integration test unavailable: {reason}"
    if os.environ.get("REQUIRE_PG_RLS_TESTS") == "1":
        pytest.fail(message)
    pytest.skip(message)


@pytest.mark.asyncio
async def test_phase3_4_rls_denies_cross_tenant_reads_and_writes() -> None:
    """Apply the real migration and prove tenant A cannot access tenant B."""
    engine = create_async_engine(_database_url(), pool_pre_ping=True)
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()
    file_a = uuid.uuid4()
    file_b = uuid.uuid4()
    migration = Path(__file__).parents[1] / "migrations" / "phase3_4_rls.sql"

    schema = f"rls_test_{uuid.uuid4().hex}"
    try:
        async with engine.connect() as conn:
            transaction = await conn.begin()
            await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
            await conn.execute(text(f'SET LOCAL search_path TO "{schema}"'))
            await conn.run_sync(Base.metadata.create_all)
            # Seed both tenants and rows before RLS is enabled. The IDs are
            # unique, so this harness is safe to run against a shared test DB.
            await conn.execute(
                text(
                        "INSERT INTO tenants (id, tenant_id, name, storage_quota_bytes, quota_updated_at, created_at, is_active) "
                        "VALUES (:a, :aid, 'RLS A', 1000000, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, true), "
                        "(:b, :bid, 'RLS B', 1000000, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, true)"
                ),
                {"a": tenant_a, "aid": str(tenant_a), "b": tenant_b, "bid": str(tenant_b)},
            )
            user_values = {
                "password_hash": "integration-test",
                "empty": b"",
            }
            for user_id, tenant_id, email in (
                (user_a, tenant_a, f"rls-a-{user_a}@example.test"),
                (user_b, tenant_b, f"rls-b-{user_b}@example.test"),
            ):
                await conn.execute(
                    text(
                        "INSERT INTO users (id, tenant_id, email, password_hash, "
                        "password_salt_b64, enc_master_key_b64, enc_master_key_iv, "
                        "enc_search_key_b64, enc_search_key_iv, enc_private_key_b64, "
                        "enc_private_key_iv, public_key_b64, mfa_enabled, is_active, created_at) "
                        "VALUES (:id, :tenant, :email, :password_hash, :empty, :empty, :empty, "
                        ":empty, :empty, :empty, :empty, :empty, false, true, CURRENT_TIMESTAMP)"
                    ),
                    {**user_values, "id": user_id, "tenant": tenant_id, "email": email},
                )
            for file_id, owner_id, tenant_id in ((file_a, user_a, tenant_a), (file_b, user_b, tenant_b)):
                await conn.execute(
                    text(
                        "INSERT INTO files (id, owner_id, tenant_id, file_iv, metadata_ciphertext, "
                            "metadata_iv, deleted, created_at) VALUES "
                            "(:id, :owner, :tenant, :iv, :metadata, :iv, false, CURRENT_TIMESTAMP)"
                    ),
                    {"id": file_id, "owner": owner_id, "tenant": tenant_id, "iv": b"x", "metadata": b"m"},
                )
            raw = await conn.get_raw_connection()
            await raw.driver_connection.execute(migration.read_text())
            role = await conn.execute(
                text(
                    "SELECT rolsuper, rolbypassrls FROM pg_roles "
                    "WHERE rolname = current_user"
                )
            )
            assert role.one() == (False, False)
            await transaction.commit()

            async with conn.begin():
                await conn.execute(text(f'SET LOCAL search_path TO "{schema}"'))
                await conn.execute(
                    text("SELECT set_config('app.tenant_id', :tenant, true)"),
                    {"tenant": str(tenant_a)},
                )
                visible = await conn.execute(text("SELECT id FROM files ORDER BY id"))
                assert [row[0] for row in visible] == [file_a]
                with pytest.raises(Exception, match=r"row-level security|policy"):
                    await conn.execute(
                        text(
                            "INSERT INTO files (id, owner_id, tenant_id, file_iv, metadata_ciphertext, "
                            "metadata_iv, deleted) VALUES (:id, :owner, :tenant, :iv, :metadata, :iv, false)"
                        ),
                        {
                            "id": uuid.uuid4(),
                            "owner": user_a,
                            "tenant": tenant_b,
                            "iv": b"x",
                            "metadata": b"m",
                        },
                    )

        # The first transaction returned its connection to the pool with a
        # tenant context set via SET LOCAL. A fresh transaction must not inherit
        # that context, even when SQLAlchemy reuses the same physical session.
        async with engine.connect() as reused_conn, reused_conn.begin():
            await reused_conn.execute(text(f'SET LOCAL search_path TO "{schema}"'))
            assert (
                await reused_conn.execute(text("SELECT current_setting('app.tenant_id', true)"))
            ).scalar_one() in (None, "")
            assert (await reused_conn.execute(text("SELECT id FROM files"))).all() == []
            await reused_conn.execute(
                text("SELECT set_config('app.tenant_id', :tenant, true)"),
                {"tenant": str(tenant_b)},
            )
            visible = await reused_conn.execute(text("SELECT id FROM files ORDER BY id"))
            assert [row[0] for row in visible] == [file_b]
    except (OSError, OperationalError) as exc:
        _configuration_error(f"test database unavailable ({exc})")
    finally:
        try:
            async with engine.begin() as cleanup_conn:
                await cleanup_conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        except (OSError, OperationalError):
            pass
        await engine.dispose()
