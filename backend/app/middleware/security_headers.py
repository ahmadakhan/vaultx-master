"""Security headers middleware for the VaultX backend.

Sets industry-standard HTTP response headers that protect against
common web vulnerabilities:

- ``X-Content-Type-Options: nosniff`` — prevents MIME-type sniffing.
- ``X-Frame-Options: DENY`` — prevents clickjacking.
- ``Strict-Transport-Security`` — enforces HTTPS.
- ``Content-Security-Policy`` — restricts resource loading.
- ``X-XSS-Protection`` — legacy XSS filter header.
- ``Referrer-Policy`` — controls referrer information leakage.
- ``Cache-Control`` — prevents caching of sensitive responses.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import settings

# Headers that are meaningful (and safe) over plain HTTP as well.
_BASE_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"x-xss-protection", b"1; mode=block"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store, no-cache, must-revalidate, max-age=0"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
]

_HSTS_HEADER: tuple[bytes, bytes] = (
    b"strict-transport-security",
    b"max-age=31536000; includeSubDomains",
)


def _build_security_headers() -> list[tuple[bytes, bytes]]:
    """Assemble the response headers for this environment.

    HSTS is only advertised in production: emitting it over plain HTTP in dev
    or in the reference compose stack (which terminates no TLS) would be a lie
    and can leave a browser pinned to HTTPS for a host that cannot serve it.

    A JSON API does not need ``'self'`` in ``default-src``, which is what the
    previous policy granted; tightening to ``'none'`` removes any implied
    permission should a response ever be rendered as a document.
    """
    headers = list(_BASE_SECURITY_HEADERS)
    if settings.app_env == "prod":
        headers.append(_HSTS_HEADER)
    return headers


_SECURITY_HEADERS: list[tuple[bytes, bytes]] = _build_security_headers()


class SecurityHeadersMiddleware:
    """ASGI middleware that injects security-related HTTP headers on every response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                # Replace the headers we own, but keep everything else intact.
                # Collapsing the list into a dict (as this used to do) silently
                # discards repeated headers such as multiple Set-Cookie values.
                managed = {name for name, _ in _SECURITY_HEADERS}
                kept = [(k, v) for k, v in headers if k.lower() not in managed]
                message["headers"] = [*kept, *_SECURITY_HEADERS]
            await send(message)

        await self.app(scope, receive, send_wrapped)
