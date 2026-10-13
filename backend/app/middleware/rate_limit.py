"""Rate limiting middleware for the VaultX backend.

Implements IP-based rate limiting using a token bucket algorithm for
in-memory operation. For distributed deployments, replace with Redis-backed
storage.

The middleware is applied globally via ``app.add_middleware`` and returns
HTTP 429 when the client exceeds the configured request rate.

Client identity is derived via :mod:`app.core.net`, which ignores
``X-Forwarded-For`` unless the peer is a configured trusted proxy; otherwise
the header could be spoofed to obtain an unlimited number of fresh buckets.
"""

from __future__ import annotations

import time
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import settings
from app.core.net import IPNetwork, client_ip_from_scope
from app.middleware.observability import increment


class _TokenBucket:
    """In-memory token bucket with sliding refill.

    Not thread-safe; ASGI is single-threaded per request by default, but for
    multi-worker deployments use a shared store (e.g., Redis).
    """

    __slots__ = ("capacity", "last_refill", "rate", "tokens")

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate
        self.capacity = capacity
        self.tokens: float = capacity
        self.last_refill: float = time.monotonic()

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class RateLimitMiddleware:
    """ASGI middleware enforcing per-client rate limits.

    Args:
        app: The ASGI application to wrap.
        rate: Tokens per second to refill.
        capacity: Maximum burst size (bucket capacity).
        max_buckets: Hard upper bound on tracked clients; the oldest idle
            buckets are evicted first so the map cannot grow without limit.
        trusted_networks: Networks allowed to assert ``X-Forwarded-For``.
    """

    def __init__(
        self,
        app: ASGIApp,
        rate: float = 100.0,
        capacity: int = 200,
        max_buckets: int = 50_000,
        idle_seconds: float = 300.0,
        trusted_networks: tuple[IPNetwork, ...] | None = None,
        redis_url: str | None = None,
        redis_timeout_seconds: float = 0.15,
    ) -> None:
        self.app = app
        self.rate = rate
        self.capacity = capacity
        self.max_buckets = max_buckets
        self.idle_seconds = idle_seconds
        self.trusted_networks = (
            settings.trusted_proxy_networks if trusted_networks is None else trusted_networks
        )
        self._buckets: dict[str, _TokenBucket] = {}
        self._redis: Any = None
        self._redis_url = redis_url
        self._redis_timeout = redis_timeout_seconds
        self._redis_failed = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_ip = client_ip_from_scope(scope, self.trusted_networks)
        allowed = await self._allow(client_ip) if client_ip else True
        if client_ip and not allowed:
            await self._reject(send)
            return

        await self.app(scope, receive, send)

    async def _allow(self, key: str) -> bool:
        if self._redis_url and not self._redis_failed:
            try:
                if self._redis is None:
                    from redis.asyncio import Redis
                    self._redis = Redis.from_url(self._redis_url, socket_timeout=self._redis_timeout,
                                                 decode_responses=False)
                redis_key = f"vaultx:ratelimit:{key}"
                count = await self._redis.incr(redis_key)
                if count == 1:
                    await self._redis.expire(redis_key, max(1, int(self.capacity / self.rate)))
                increment("rate_limit_redis_requests_total")
                return count <= self.capacity
            except Exception:
                self._redis_failed = True
                increment("rate_limit_redis_failures_total")
                increment("rate_limit_fallback_total")
                self._redis = None
        return self._bucket(key).consume()

    def _bucket(self, key: str) -> _TokenBucket:
        """Return the bucket for ``key``, creating it within a bounded map."""
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket

        if len(self._buckets) >= self.max_buckets:
            self._evict_stale()
            if len(self._buckets) >= self.max_buckets:
                # Prefer losing rate-limit state over exhausting memory.
                self._buckets.clear()

        bucket = _TokenBucket(self.rate, self.capacity)
        self._buckets[key] = bucket
        return bucket

    def _evict_stale(self) -> None:
        """Drop buckets that have been idle for ``idle_seconds``."""
        cutoff = time.monotonic() - self.idle_seconds
        for key in [k for k, v in self._buckets.items() if v.last_refill < cutoff]:
            del self._buckets[key]

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail": "Rate limit exceeded. Please slow down."}'
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"retry-after", b"60"),
        ]

        async def send_wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["status"] = 429
                message["headers"] = headers
            elif message["type"] == "http.response.body":
                message["body"] = body
            await send(message)

        await send_wrapped({"type": "http.response.start", "status": 429, "headers": []})
        await send_wrapped({"type": "http.response.body", "body": body})
