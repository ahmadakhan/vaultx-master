"""Unit coverage for tenant/quota invariants that do not require PostgreSQL."""

import uuid

import pytest

from app.core.exceptions import ValidationError
from app.core.tenant import release_storage, reserve_storage
from app.models import TenantQuota


def test_quota_model_rejects_negative_and_over_quota_usage():
    quota = TenantQuota(tenant_id=uuid.uuid4(), storage_quota_bytes=10)
    quota.storage_used_bytes = 0
    with pytest.raises(ValueError):
        quota.increment_usage(-1)
    with pytest.raises(ValueError):
        quota.increment_usage(11)


@pytest.mark.asyncio
async def test_reservation_rejects_missing_or_insufficient_quota():
    class Result:
        rowcount = 0

    class Database:
        async def execute(self, _statement):
            return Result()

    with pytest.raises(ValidationError):
        await reserve_storage(Database(), uuid.uuid4(), 1)
    with pytest.raises(ValidationError):
        await release_storage(Database(), uuid.uuid4(), 1)


def test_quota_model_rejects_negative_quota():
    quota = TenantQuota(tenant_id=uuid.uuid4(), storage_quota_bytes=10)
    with pytest.raises(ValueError):
        quota.update_quota(-1, uuid.uuid4())
