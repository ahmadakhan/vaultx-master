"""Structured logging configuration for the VaultX backend.

Provides a centralized logging setup that produces JSON-formatted log
records suitable for aggregation in production environments (e.g.,
ELK stack, Datadog, CloudWatch).

Usage::

    from app.core.logging import get_logger
    logger = get_logger(__name__)
    logger.info("User registered", extra={"user_id": user_id})
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any


class JsonFormatter(logging.Formatter):
    """Format log records as JSON for structured log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if hasattr(record, "module"):
            log_entry["module"] = record.module
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key not in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "process",
                "processName",
                "getMessage",
            }:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


class VaultXLogAdapter(logging.LoggerAdapter[Any]):
    """Logger adapter that injects contextual information into every record.

    Passes through ``extra`` metadata and merges it with the adapter's
    stored context (e.g., request ID, user ID) for comprehensive tracing.
    """

    def __init__(self, logger: logging.Logger, extra: dict[str, Any] | None = None) -> None:
        super().__init__(logger, extra or {})

    def process(self, msg: str, kwargs: Any) -> tuple[str, Any]:
        extra: dict[str, Any] = dict(self.extra) if self.extra else {}
        if "extra" in kwargs:
            extra.update(kwargs["extra"])
        kwargs["extra"] = extra
        return msg, kwargs


_LOGGER_CONFIGURED = False


def _configure_root_logger() -> None:
    """Configure the root logger with JSON formatting.

    Idempotent: safe to call multiple times.
    """
    global _LOGGER_CONFIGURED
    if _LOGGER_CONFIGURED:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    _LOGGER_CONFIGURED = True


def setup_logging() -> None:
    """Initialize structured logging for the application.

    Call this once at application startup before creating the FastAPI app.
    """
    _configure_root_logger()


def get_logger(name: str | None = None, **context: Any) -> VaultXLogAdapter:
    """Return a structured logger with optional contextual metadata.

    Args:
        name: Logger name (typically ``__name__`` of the calling module).
        **context: Key-value pairs to attach to every log entry from this
            logger (e.g., ``user_id=123``).

    Returns:
        A ``VaultXLogAdapter`` wrapping the named logger.
    """
    if not _LOGGER_CONFIGURED:
        _configure_root_logger()

    logger = logging.getLogger(name) if name else logging.getLogger("vaultx")
    return VaultXLogAdapter(logger, context)
