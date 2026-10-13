import pytest

from app.middleware.rate_limit import RateLimitMiddleware


class FakeRedis:
    def __init__(self, fail=False):
        self.count = 0
        self.fail = fail

    async def incr(self, key):
        if self.fail:
            raise ConnectionError("redis unavailable")
        self.count += 1
        return self.count

    async def expire(self, key, seconds):
        return True


@pytest.mark.asyncio
async def test_redis_counter_is_shared_and_enforces_capacity():
    middleware = RateLimitMiddleware(lambda s, r, send: None, rate=1, capacity=2, redis_url="redis://unused")
    middleware._redis = FakeRedis()
    assert await middleware._allow("client")
    assert await middleware._allow("client")
    assert not await middleware._allow("client")


@pytest.mark.asyncio
async def test_redis_failure_falls_back_to_local_bucket():
    middleware = RateLimitMiddleware(lambda s, r, send: None, rate=1, capacity=1, redis_url="redis://unused")
    middleware._redis = FakeRedis(fail=True)
    assert await middleware._allow("client")
    assert not await middleware._allow("client")
    assert middleware._redis_failed
