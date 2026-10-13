"""Application configuration with validation and secure defaults.

Centralizes all runtime settings loaded from environment variables
via Pydantic's ``BaseSettings``. Includes validation for critical
security parameters and computed properties for derived values
(e.g., database URL, encryption key segments).
"""

from __future__ import annotations

import ipaddress
from functools import cached_property
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.logging import get_logger

logger = get_logger(__name__)

# Resolved relative to this file so startup does not depend on the CWD.
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

_ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})

_PLACEHOLDER_SECRETS = frozenset(
    {
        "changeme",
        "change_me_to_a_strong_random_secret_key_32chars_min",
        "change_me_jwt_secret_key_min_32_characters_long",
        "supersecretkey_here",
        "supersecretjwtkey_here",
    }
)


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    All secrets (``app_secret_key``, ``jwt_secret_key``, database
    credentials) must be provided externally — no insecure defaults
    are used for sensitive values.
    """

    # --- Application ---
    app_env: str = Field("dev", alias="APP_ENV")
    app_secret_key: str = Field(..., alias="APP_SECRET_KEY", min_length=32, repr=False)
    jwt_secret_key: str = Field(..., alias="JWT_SECRET_KEY", min_length=32, repr=False)
    jwt_algorithm: str = Field("HS256", alias="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(60, alias="JWT_EXPIRE_MINUTES", ge=5, le=1440)
    jwt_refresh_expire_days: int = Field(30, alias="JWT_REFRESH_EXPIRE_DAYS", ge=1, le=365)
    # Soft-deleted files keep their ciphertext for this many days before the
    # trash reaper permanently removes blob + row.
    trash_retention_days: int = Field(30, alias="TRASH_RETENTION_DAYS", ge=1, le=3650)
    recovery_rpo_minutes: int = Field(1440, alias="RECOVERY_RPO_MINUTES", ge=1)
    recovery_rto_minutes: int = Field(240, alias="RECOVERY_RTO_MINUTES", ge=1)
    data_residency_region: str | None = Field(None, alias="DATA_RESIDENCY_REGION")
    # The server stores and returns only authenticated ciphertext envelopes.
    # There is intentionally no mode that accepts plaintext vault keys.
    key_bundle_mode: str = Field("server-blind-envelope", alias="KEY_BUNDLE_MODE")
    password_auth_mode: str = Field("legacy-bcrypt", alias="PASSWORD_AUTH_MODE")

    # --- CORS ---
    allowed_origins: str = Field("http://localhost:3000", alias="ALLOWED_ORIGINS")

    # --- Trusted proxies ---
    # Only peers inside these networks may set ``X-Forwarded-For``. Without
    # this restriction any client could spoof its source address and bypass
    # rate limiting or poison audit-log IP fields.
    trusted_proxy_cidrs: str = Field("127.0.0.1/32,::1/128", alias="TRUSTED_PROXY_CIDRS")

    # --- Database ---
    db_host: str = Field(..., alias="DB_HOST")
    db_port: int = Field(5432, alias="DB_PORT", ge=1, le=65535)
    db_name: str = Field(..., alias="DB_NAME")
    db_user: str = Field(..., alias="DB_USER")
    db_password: str = Field(..., alias="DB_PASSWORD", repr=False)
    database_url_override: str | None = Field(default=None, alias="DATABASE_URL", repr=False)

    # --- Mail ---
    mail_host: str = Field(..., alias="MAIL_HOST")
    mail_port: int = Field(587, alias="MAIL_PORT", ge=1, le=65535)
    mail_username: str = Field(..., alias="MAIL_USERNAME")
    mail_password: str = Field(..., alias="MAIL_PASSWORD", repr=False)
    mail_from: str = Field(..., alias="MAIL_FROM")
    mail_starttls: bool = Field(True, alias="MAIL_STARTTLS")
    mail_ssl_tls: bool = Field(False, alias="MAIL_SSL_TLS")

    # --- Key Storage ---
    keys_dir: str = Field(..., alias="KEYS_DIR")
    fallback_keys_dir: str = Field(..., alias="FALLBACK_KEYS_DIR")

    # --- Rate Limiting ---
    rate_limit_rate: float = Field(100.0, alias="RATE_LIMIT_RATE", ge=0.1)
    rate_limit_capacity: int = Field(200, alias="RATE_LIMIT_CAPACITY", ge=1)
    rate_limit_max_buckets: int = Field(50_000, alias="RATE_LIMIT_MAX_BUCKETS", ge=100)
    rate_limit_redis_url: str | None = Field(default=None, alias="RATE_LIMIT_REDIS_URL")
    rate_limit_redis_timeout_seconds: float = Field(
        0.15, alias="RATE_LIMIT_REDIS_TIMEOUT_SECONDS", gt=0, le=5
    )
    metrics_enabled: bool = Field(True, alias="METRICS_ENABLED")

    # --- Self-hosted Keycloak / SCIM provisioning (disabled unless complete) ---
    oidc_issuer_url: str | None = Field(None, alias="OIDC_ISSUER_URL")
    oidc_jwks_url: str | None = Field(None, alias="OIDC_JWKS_URL")
    oidc_audience: str | None = Field(None, alias="OIDC_AUDIENCE")
    scim_bearer_token: str | None = Field(None, alias="SCIM_BEARER_TOKEN", repr=False)
    scim_tenant_id: str | None = Field(None, alias="SCIM_TENANT_ID")

    # --- Login throttling ---
    login_max_attempts: int = Field(5, alias="LOGIN_MAX_ATTEMPTS", ge=1, le=100)
    login_lockout_seconds: int = Field(900, alias="LOGIN_LOCKOUT_SECONDS", ge=1)
    # --- Bootstrap admin (optional, for local dev or managed deployments) ---
    bootstrap_admin_email: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "BOOTSTRAP_ADMIN_EMAIL",
            "APP_ADMIN_EMAIL",
            "ADMIN_EMAIL",
        ),
    )
    bootstrap_admin_password: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "BOOTSTRAP_ADMIN_PASSWORD",
            "APP_ADMIN_PASSWORD",
            "ADMIN_PASSWORD",
        ),
    )
    # --- Upload ---
    max_upload_bytes: int = Field(11_000_000_000, alias="MAX_UPLOAD_BYTES", ge=1)
    storage_dir: str = Field("/var/vaultx/storage", alias="STORAGE_DIR")

    # S3-compatible recovery archive (MinIO in the self-hosted deployment).
    # Credentials are intentionally required only when the adapter is enabled.
    backup_enabled: bool = Field(False, alias="BACKUP_ENABLED")
    backup_endpoint: str | None = Field(None, alias="BACKUP_S3_ENDPOINT")
    backup_bucket: str = Field("vaultx-backups", alias="BACKUP_S3_BUCKET")
    backup_access_key: str | None = Field(None, alias="BACKUP_S3_ACCESS_KEY", repr=False)
    backup_secret_key: str | None = Field(None, alias="BACKUP_S3_SECRET_KEY", repr=False)
    backup_region: str = Field("us-east-1", alias="BACKUP_S3_REGION")
    backup_object_lock_days: int = Field(30, alias="BACKUP_OBJECT_LOCK_DAYS", ge=1)
    backup_work_dir: str = Field("/var/vaultx/backup", alias="BACKUP_WORK_DIR")
    backup_interval_minutes: int = Field(1440, alias="BACKUP_INTERVAL_MINUTES", ge=5)
    audit_delivery_interval_seconds: int = Field(30, alias="AUDIT_DELIVERY_INTERVAL_SECONDS", ge=5)

    # --- WebAuthn ---
    # These values are intentionally explicit and are used for both option
    # generation and verification.  Origins are never inferred from a request.
    webauthn_rp_id: str = Field("localhost", alias="WEBAUTHN_RP_ID")
    webauthn_rp_name: str = Field("VaultX", alias="WEBAUTHN_RP_NAME")
    webauthn_origin: str = Field("http://localhost:3000", alias="WEBAUTHN_ORIGIN")
    webauthn_challenge_ttl_seconds: int = Field(
        300, alias="WEBAUTHN_CHALLENGE_TTL_SECONDS", ge=30, le=900
    )

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=True,
        # Tolerate unrelated keys (e.g. ``PORT``) in a shared/root .env file
        # instead of aborting startup with ``extra_forbidden``.
        extra="ignore",
        hide_input_in_errors=True,
    )

    @field_validator("app_env")
    @classmethod
    def _validate_env(cls, v: str) -> str:
        """Ensure APP_ENV is one of the allowed values."""
        allowed = {"dev", "staging", "prod", "test"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}, got '{v}'")
        return v

    @field_validator("jwt_algorithm")
    @classmethod
    def _validate_jwt_algorithm(cls, v: str) -> str:
        """Restrict JWT signing to safe HMAC algorithms.

        Prevents configuration mistakes such as ``none`` (unsigned tokens) or
        algorithm-confusion via asymmetric algorithms.
        """
        normalized = v.strip().upper()
        if normalized not in _ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"JWT_ALGORITHM must be one of {sorted(_ALLOWED_JWT_ALGORITHMS)}, got '{v}'"
            )
        return normalized

    @model_validator(mode="after")
    def _validate_secrets(self) -> Any:
        """Reject placeholder/duplicate secrets and warn when they leak into dev."""
        if self.app_env == "prod":
            raise ValueError(
                "VaultX security prototype cannot start with APP_ENV=prod; "
                "complete the documented assurance gates before production deployment"
            )
        if self.app_secret_key == self.jwt_secret_key:
            raise ValueError("APP_SECRET_KEY and JWT_SECRET_KEY must be different values")
        if self.backup_enabled and not all(
            (self.backup_endpoint, self.backup_access_key, self.backup_secret_key)
        ):
            raise ValueError(
                "BACKUP_ENABLED requires BACKUP_S3_ENDPOINT, BACKUP_S3_ACCESS_KEY, "
                "and BACKUP_S3_SECRET_KEY"
            )

        weak = [
            name
            for name in ("app_secret_key", "jwt_secret_key")
            if getattr(self, name) in _PLACEHOLDER_SECRETS
        ]
        if weak:
            if self.app_env == "prod":
                raise ValueError(
                    "Placeholder secrets are not allowed when APP_ENV=prod: " + ", ".join(weak)
                )
            logger.warning(
                "Placeholder secrets detected; never deploy these to production",
                extra={"fields": weak, "environment": self.app_env},
            )
        return self

    @field_validator("key_bundle_mode")
    @classmethod
    def _validate_key_bundle_mode(cls, value: str) -> str:
        if value != "server-blind-envelope":
            raise ValueError(
                "KEY_BUNDLE_MODE must be server-blind-envelope; plaintext key transport is unsupported"
            )
        return value

    @field_validator("password_auth_mode")
    @classmethod
    def _validate_password_auth_mode(cls, value: str) -> str:
        if value not in {"legacy-bcrypt", "opaque-required"}:
            raise ValueError("PASSWORD_AUTH_MODE must be legacy-bcrypt or opaque-required")
        return value

    @property
    def database_url(self) -> str:
        """Construct the async database connection URL.

        If ``DATABASE_URL`` is set in the environment, it takes precedence
        (useful for testing with SQLite). Otherwise, constructs a PostgreSQL
        URL from the individual ``DB_*`` settings.
        """
        if self.database_url_override:
            return self.database_url_override
        return (
            f"postgresql+asyncpg://{quote(self.db_user, safe='')}:{quote(self.db_password, safe='')}"
            f"@{self.db_host}:{self.db_port}/{quote(self.db_name, safe='')}"
        )

    @cached_property
    def trusted_proxy_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        """Parsed form of :attr:`trusted_proxy_cidrs`.

        Returns:
            A tuple of network objects used to decide whether a directly
            connected peer is allowed to assert ``X-Forwarded-For``.
        """
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in self.trusted_proxy_cidrs.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logger.warning("Ignoring invalid TRUSTED_PROXY_CIDRS entry", extra={"entry": entry})
        return tuple(networks)

    @property
    def cors_origins(self) -> list[str]:
        """Parse comma-separated ``ALLOWED_ORIGINS`` into a list."""
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @model_validator(mode="after")
    def _validate_webauthn(self) -> Any:
        from urllib.parse import urlparse

        if not self.webauthn_rp_id or "*" in self.webauthn_rp_id or "/" in self.webauthn_rp_id:
            raise ValueError("WEBAUTHN_RP_ID must be a concrete host name")
        parsed = urlparse(self.webauthn_origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("WEBAUTHN_ORIGIN must be one absolute http(s) origin")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
            raise ValueError(
                "WEBAUTHN_ORIGIN must not contain a path, query, fragment, or credentials"
            )
        if parsed.hostname != self.webauthn_rp_id:
            raise ValueError("WEBAUTHN_ORIGIN hostname must exactly match WEBAUTHN_RP_ID")
        return self

    @model_validator(mode="after")
    def _validate_external_identity(self) -> Any:
        oidc = (self.oidc_issuer_url, self.oidc_jwks_url, self.oidc_audience)
        if any(oidc) and not all(oidc):
            raise ValueError(
                "OIDC_ISSUER_URL, OIDC_JWKS_URL and OIDC_AUDIENCE must be set together"
            )
        for name, value in (
            ("OIDC_ISSUER_URL", self.oidc_issuer_url),
            ("OIDC_JWKS_URL", self.oidc_jwks_url),
        ):
            if value:
                parsed = urlparse(value)
                if parsed.scheme != "https" and parsed.hostname not in {
                    "localhost",
                    "127.0.0.1",
                    "::1",
                }:
                    raise ValueError(f"{name} must use HTTPS outside localhost")
        if self.scim_bearer_token and len(self.scim_bearer_token) < 32:
            raise ValueError("SCIM_BEARER_TOKEN must be at least 32 characters")
        if self.scim_bearer_token and not self.scim_tenant_id:
            raise ValueError("SCIM_TENANT_ID is required when SCIM_BEARER_TOKEN is configured")
        return self


settings = Settings()  # type: ignore[call-arg]
