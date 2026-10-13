"""Request correlation and low-cardinality operational metrics."""
from __future__ import annotations

import secrets
import time
from collections import Counter
from threading import Lock
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.logging import get_logger

logger = get_logger(__name__)
_metrics: Counter[str] = Counter()
_lock = Lock()


def increment(name: str, value: float = 1) -> None:
    with _lock:
        _metrics[name] += value


def prometheus() -> str:
    with _lock:
        values = dict(_metrics)
    lines = ["# HELP vaultx_events_total Operational event counters.", "# TYPE vaultx_events_total counter"]
    lines.extend(f"vaultx_{key} {value}" for key, value in sorted(values.items()))
    return "\n".join(lines) + "\n"


class ObservabilityMiddleware:
    """Attach request/trace IDs, emit structured access logs, and count outcomes."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        request_id = headers.get(b"x-request-id", b"").decode("ascii", "ignore")[:128] or secrets.token_hex(16)
        parts = headers.get(b"traceparent", b"").decode("ascii", "ignore").split("-")
        trace_id = parts[1] if len(parts) >= 4 and len(parts[1]) == 32 else secrets.token_hex(16)
        scope["vaultx.request_id"] = request_id
        scope["vaultx.trace_id"] = trace_id
        started = time.perf_counter()

        async def send_wrapped(message: Any) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [*list(message.get("headers", [])),
                    (b"x-request-id", request_id.encode()), (b"trace-id", trace_id.encode())]
                increment("http_responses_total")
            await send(message)

        try:
            await self.app(scope, receive, send_wrapped)
        finally:
            increment("http_requests_total")
            increment("http_request_duration_seconds_sum", time.perf_counter() - started)
            logger.info("Request completed", extra={"request_id": request_id, "trace_id": trace_id,
                "method": scope.get("method"), "path": scope.get("path"),
                "duration_ms": round((time.perf_counter() - started) * 1000, 2)})
