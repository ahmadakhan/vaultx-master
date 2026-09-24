"""VaultX backend application package.

The application is built using the factory pattern (``create_app``
in ``app.main``). All sub-packages are organized by concern:

- ``app.api`` — API routers (endpoint handlers)
- ``app.core`` — Core utilities (security, auth, audit, logging)
- ``app.middleware`` — ASGI middleware (security headers, rate limiting)
- ``app.models`` — SQLAlchemy ORM models
- ``app.schemas`` — Pydantic request/response schemas

Entry point: ``app.main:create_app``
"""

from app.core.logging import setup_logging

setup_logging()
