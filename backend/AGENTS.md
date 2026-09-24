# VaultX Backend — Agent Guide

## Project Structure

```
backend/
├── app/
│   ├── __init__.py               # Package init, sets up logging
│   ├── main.py                   # FastAPI application factory
│   ├── config.py                 # Pydantic settings with validation
│   ├── db.py                     # Async DB engine, session, get_db dependency
│   ├── core/
│   │   ├── __init__.py
│   │   ├── exceptions.py         # Custom exception hierarchy + handler
│   │   ├── logging.py            # Structured JSON logging
│   │   ├── security.py           # Password hashing, JWT token management
│   │   ├── deps.py               # Authentication dependencies
│   │   ├── audit_log.py          # Hash-chained audit log recording
│   │   ├── audit_verify.py       # Audit chain verification
│   │   ├── audit_decorator.py    # @audit_event decorator
│   │   └── server_keys.py        # RSA key-pair management
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── rate_limit.py         # Token bucket rate limiting
│   │   └── security_headers.py   # Security response headers
│   ├── models/
│   │   ├── __init__.py           # Re-exports all models
│   │   ├── base.py               # DeclarativeBase, engine factory
│   │   ├── user.py               # User, Role, UserRole, Backup
│   │   ├── file.py               # File, FileShare
│   │   ├── index.py              # IndexEntry
│   │   └── audit.py              # TamperLog
│   ├── schemas/
│   │   ├── __init__.py           # Re-exports all schemas
│   │   ├── auth.py               # Auth request/response schemas
│   │   ├── file.py               # File request/response schemas
│   │   ├── share.py              # Share request/response schemas
│   │   ├── search.py             # Search request/response schemas
│   │   ├── user.py               # User request/response schemas
│   │   ├── admin.py              # Admin request/response schemas
│   │   └── audit.py              # Audit request/response schemas
│   └── api/
│       ├── __init__.py            # Aggregated router
│       └── routers/
│           ├── __init__.py
│           ├── auth.py           # /auth/* endpoints
│           ├── files.py           # /files/* endpoints
│           ├── shares.py          # /shares/* endpoints
│           ├── search.py          # /search endpoint
│           ├── user.py            # /user/* endpoints
│           ├── audit.py            # /audit/* endpoints
│           └── admin.py           # /admin/* endpoints (admin-only)
├── test.py                       # Integration test script
├── requirements.txt              # Pinned production dependencies
└── Dockerfile                    # Multi-stage build with gunicorn
```

## Key Commands

### Linting & Formatting
```bash
ruff check app/ test.py
ruff format app/ test.py
mypy app/ --ignore-missing-imports
```

### Running the server (development)
```bash
fastapi run app/main.py --reload
```

### Running the server (production)
```bash
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Running tests
```bash
# Ensure backend is running, then:
python test.py
```

### Installing dependencies
```bash
pip install -e ".[dev]"
```

## Environment Variables

Required for startup (no insecure defaults for secrets):

| Variable             | Description                          | Required |
|----------------------|--------------------------------------|----------|
| APP_SECRET_KEY       | Master secret for key derivation     | Yes (32+) |
| JWT_SECRET_KEY       | JWT signing secret                   | Yes (32+) |
| DB_HOST              | PostgreSQL host                      | Yes      |
| DB_NAME              | Database name                        | Yes      |
| DB_USER              | Database user                        | Yes      |
| DB_PASSWORD          | Database password                    | Yes      |
| MAIL_HOST            | SMTP server host                     | Yes      |
| MAIL_USERNAME        | SMTP username                        | Yes      |
| MAIL_PASSWORD        | SMTP password                        | Yes      |
| MAIL_FROM            | Sender email address                 | Yes      |
| KEYS_DIR             | RSA key storage directory            | Yes      |
| FALLBACK_KEYS_DIR    | Fallback key storage directory       | Yes      |

Optional:

| Variable             | Default                    | Description                  |
|----------------------|----------------------------|------------------------------|
| APP_ENV              | dev                        | Environment: dev/staging/prod|
| JWT_ALGORITHM        | HS256                      | JWT signing algorithm        |
| JWT_EXPIRE_MINUTES   | 60                         | Access token TTL             |
| JWT_REFRESH_EXPIRE_DAYS | 30                     | Refresh token TTL            |
| ALLOWED_ORIGINS      | http://localhost:3000      | CORS allowed origins (comma-sep)|
| RATE_LIMIT_RATE      | 100                        | Rate limit tokens/sec        |
| RATE_LIMIT_CAPACITY  | 200                        | Rate limit burst capacity    |
| MAX_UPLOAD_BYTES     | 11000000000 (11GB)         | Maximum single upload size   |
| STORAGE_DIR          | /var/vaultx/storage        | Filesystem storage for large file blobs |

## Security Practices

- **Never** commit secrets or `.env` files.
- All API routes are prefixed without `/api` (frontend rewrites `/api/*` → backend).
- Passwords are hashed with bcrypt; JWT tokens have short-lived access tokens + long-lived refresh tokens.
- Audit logs are hash-chained and RSA-signed for tamper detection.
- The server never handles plaintext encryption keys; all encryption is client-side.
