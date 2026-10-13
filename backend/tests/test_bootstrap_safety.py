"""Regression coverage for non-destructive bootstrap behavior."""

from types import SimpleNamespace

import pytest

from app.main import seed_bootstrap_admin


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Session:
    def __init__(self, existing):
        self.existing = existing
        self.execute_calls = 0

    async def execute(self, _statement):
        self.execute_calls += 1
        return _Result(self.existing)


@pytest.mark.asyncio
async def test_existing_bootstrap_admin_is_not_rekeyed_or_reactivated():
    existing = SimpleNamespace(is_active=False)
    session = _Session(existing)

    created = await seed_bootstrap_admin(
        session,
        email="admin@example.com",
        password="a sufficiently strong bootstrap password",
    )

    assert created is False
    assert existing.is_active is False
    assert session.execute_calls == 1
